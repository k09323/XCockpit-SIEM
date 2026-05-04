from __future__ import annotations

"""XCockpit REST API client.

Authentication: Authorization: Token <api_key>
Base URL example: https://xcockpit.cycraft.ai

Pull flow:
1. GET /_api/<customer_key>/alert?created=<ISO_datetime>
   → returns list of {id, type, created} where type is CYCRAFT_E or CYCRAFT_C

2a. For CYCRAFT_E:
    GET /_api/<customer_key>/edr_alert/<id>/json

2b. For CYCRAFT_C:
    GET /_api/<customer_key>/cyber_situation_report/<id>/json

3. GET /_api/<customer_key>/incident?created_after=<ISO>&offset=0&limit=50
   → list of incidents

4. GET /_api/<customer_key>/incident/<uuid>
   → full incident detail

5. GET /_api/<customer_key>/act-log?source=xcockpit&stime=<ISO>&etime=<ISO>&offset=0&limit=50
   → activity logs
"""

import logging
import zipfile
import io
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)


class XCockpitClient:
    """Async client for the XCockpit REST API.

    Connection parameters (URL / customer_key / api_key) are read LIVE from the
    DB (with env/YAML fallback) on every request, so admins can edit them via
    the Settings UI and the next pull cycle picks up the new values without a
    service restart.
    """

    def __init__(self) -> None:
        self._verify_ssl = settings.xcockpit.verify_ssl
        self._page_size = settings.xcockpit.pull_page_size

    # ------------------------------------------------------------------
    # Live config getters (DB overrides env/YAML)
    # ------------------------------------------------------------------

    def _config(self) -> dict[str, str]:
        from backend.core.database import get_xcockpit_config
        return get_xcockpit_config()

    @property
    def _base_url(self) -> str:
        return self._config()["base_url"]

    @property
    def _customer_key(self) -> str:
        return self._config()["customer_key"]

    @property
    def _api_key(self) -> str:
        return self._config()["api_key"]

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Token {self._api_key}",
            "Accept": "application/json",
        }

    def _url(self, path: str) -> str:
        return f"{self._base_url}/_api/{self._customer_key}/{path}"

    # ------------------------------------------------------------------
    # Connection test (used by the Settings UI)
    # ------------------------------------------------------------------

    @staticmethod
    async def test_connection(
        base_url: str, customer_key: str, api_key: str, verify_ssl: bool = True
    ) -> tuple[bool, str]:
        """Try a lightweight call against the alert list endpoint.
        Returns (ok, message). Does NOT touch DB — caller can preview before saving.
        """
        if not (base_url and customer_key and api_key):
            return False, "URL / customer_key / api_key 都必須填寫"
        url = f"{base_url.rstrip('/')}/_api/{customer_key}/alert?created=2099-01-01T00:00:00"
        headers = {"Authorization": f"Token {api_key}", "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(verify=verify_ssl, timeout=10) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 401:
                    return False, "API key 驗證失敗 (401 Unauthorized)"
                if resp.status_code == 404:
                    return False, "URL 或 customer_key 不正確 (404 Not Found)"
                if resp.status_code >= 500:
                    return False, f"XCockpit server 錯誤 (HTTP {resp.status_code})"
                if resp.status_code >= 400:
                    return False, f"HTTP {resp.status_code}: {resp.text[:120]}"
                return True, f"連線成功 (HTTP {resp.status_code})"
        except httpx.ConnectError as e:
            return False, f"無法連線到 {base_url}: {e}"
        except httpx.TimeoutException:
            return False, "連線逾時 (10s)"
        except Exception as e:
            return False, f"錯誤：{e}"

    async def health_check(self) -> bool:
        if not self._base_url or not self._customer_key:
            return False
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=10) as client:
                resp = await client.get(
                    self._url("alert?created=2099-01-01T00:00:00"),
                    headers=self._headers,
                )
                return resp.status_code < 500
        except Exception as e:
            logger.warning("XCockpit health check failed: %s", e)
            return False

    # ------------------------------------------------------------------
    # Alert List API  (CYCRAFT_E + CYCRAFT_C combined)
    # ------------------------------------------------------------------

    async def get_alert_list(self, created_after: str) -> list[dict[str, Any]]:
        """Return list of {id, type, created} for alerts created after the given ISO timestamp."""
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=30) as client:
                resp = await client.get(
                    self._url(f"alert?created={created_after}"),
                    headers=self._headers,
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as e:
            logger.error("Alert list HTTP %s: %s", e.response.status_code, e.response.text[:200])
            return []
        except Exception as e:
            logger.error("Alert list request failed: %s", e)
            return []

    # ------------------------------------------------------------------
    # EDR Alert API  (CYCRAFT_E)
    # ------------------------------------------------------------------

    async def get_edr_alert(self, alert_id: str) -> Optional[dict[str, Any]]:
        """Fetch a single EDR alert detail (CYCRAFT_E type) in JSON format."""
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=30) as client:
                resp = await client.get(
                    self._url(f"edr_alert/{alert_id}/json"),
                    headers=self._headers,
                )
                resp.raise_for_status()
                data = resp.json()
                data["_xcockpit_type"] = "CYCRAFT_E"
                data["_xcockpit_alert_id"] = alert_id
                return data
        except Exception as e:
            logger.error("EDR alert %s fetch failed: %s", alert_id, e)
            return None

    # ------------------------------------------------------------------
    # Cyber Situation Report API  (CYCRAFT_C)
    # ------------------------------------------------------------------

    async def get_cyber_situation_report(self, report_id: str) -> Optional[dict[str, Any]]:
        """Fetch a single Cyber Situation Report (CYCRAFT_C type) in JSON format."""
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=30) as client:
                resp = await client.get(
                    self._url(f"cyber_situation_report/{report_id}/json"),
                    headers=self._headers,
                )
                resp.raise_for_status()
                data = resp.json()
                data["_xcockpit_type"] = "CYCRAFT_C"
                data["_xcockpit_report_id"] = report_id
                return data
        except Exception as e:
            logger.error("Cyber situation report %s fetch failed: %s", report_id, e)
            return None

    # ------------------------------------------------------------------
    # Incident API
    # ------------------------------------------------------------------

    async def get_incident_list(
        self,
        created_after: str,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Return incident list with pagination.
        Response: list of incident summary objects.
        """
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=30) as client:
                resp = await client.get(
                    self._url(f"incident"),
                    params={
                        "created_after": created_after,
                        "offset": offset,
                        "limit": limit,
                    },
                    headers=self._headers,
                )
                resp.raise_for_status()
                data = resp.json()
                # Response may be a list or {count, results, next, previous}
                if isinstance(data, list):
                    return {"results": data, "has_next": False, "total": len(data)}
                return {
                    "results": data.get("results", []),
                    "has_next": bool(data.get("next")),
                    "total": data.get("count", 0),
                }
        except Exception as e:
            logger.error("Incident list fetch failed: %s", e)
            return {"results": [], "has_next": False, "total": 0}

    async def get_incident_detail(self, incident_uuid: str) -> Optional[dict[str, Any]]:
        """Fetch full incident detail. Response may be a zip file → JSON."""
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=30) as client:
                resp = await client.get(
                    self._url(f"incident/{incident_uuid}"),
                    headers=self._headers,
                )
                resp.raise_for_status()

                # Some endpoints return a zip
                content_type = resp.headers.get("content-type", "")
                if "zip" in content_type or resp.content[:2] == b"PK":
                    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                        for name in zf.namelist():
                            if name.endswith(".json"):
                                import json
                                return json.loads(zf.read(name))
                    return None

                return resp.json()
        except Exception as e:
            logger.error("Incident detail %s fetch failed: %s", incident_uuid, e)
            return None

    # ------------------------------------------------------------------
    # Activity Log API
    # ------------------------------------------------------------------

    async def get_activity_logs(
        self,
        stime: str,
        etime: Optional[str] = None,
        source: str = "xcockpit",
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Return activity logs from XCockpit or Xensor."""
        params: dict[str, Any] = {
            "source": source,
            "stime": stime,
            "offset": offset,
            "limit": limit,
        }
        if etime:
            params["etime"] = etime
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=30) as client:
                resp = await client.get(
                    self._url("act-log"),
                    params=params,
                    headers=self._headers,
                )
                resp.raise_for_status()
                data = resp.json()
                if isinstance(data, list):
                    return {"results": data, "has_next": False}
                return {
                    "results": data.get("results", []),
                    "has_next": bool(data.get("next")),
                }
        except Exception as e:
            logger.error("Activity log fetch failed: %s", e)
            return {"results": [], "has_next": False}

    # ------------------------------------------------------------------
    # Dashboard / Statistics
    # ------------------------------------------------------------------

    async def get_mdr_statistic(self) -> Optional[dict[str, Any]]:
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=30) as client:
                resp = await client.get(self._url("mdr/statistic"), headers=self._headers)
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.warning("MDR statistic fetch failed: %s", e)
            return None


xcockpit_client = XCockpitClient()
