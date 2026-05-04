# XCockpit SIEM

> 自架資安分析平台，整合 CyCraft XCockpit API，提供查詢導向的分析能力、儀表板與告警機制

[![Version](https://img.shields.io/badge/version-v2.0-brightgreen.svg)](#版本紀錄)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61dafb.svg)](https://react.dev/)
[![DuckDB](https://img.shields.io/badge/DuckDB-0.10+-yellow.svg)](https://duckdb.org/)

---

## 版本紀錄

### v2.0 (2026-05-04) — UI 維運強化

第二版重點：把所有「需要 ssh / 改設定檔 / 重啟服務」的維運操作搬到 Web UI，並修掉 v1 的關鍵 bug。

#### 🐛 Bug 修正

| Bug | 影響 | 修法 |
|------|------|------|
| **Incident 狀態同步失效** | XCockpit 上將事件從 `InProgress` 改為 `Investigated` 後，Dashboard 圓餅圖仍顯示舊狀態。 | `_pull_incidents` 改為每次重抓最近 30 天（可調），靠 `uuid` UPSERT 同步 `state` 欄位。 |
| **Timechart GROUP BY alias 衝突** | `timechart span=1d count` 因 alias 與原欄位同名 → DuckDB 把 GROUP BY 解析成原欄位，每筆 alert 自成一群，曲線每次重新整理結果不穩定。 | 改用合成 alias `_time` 並直接 `GROUP BY` bucket 表達式。 |
| **SPA 路由重新整理 404** | 在 `/login`、`/alerts`、`/settings` 按 F5 → `{"detail":"Not Found"}`。 | FastAPI 加 catch-all：非 `/api/`、`/ws/`、`/assets/` 路徑一律 fallback 到 `index.html`。 |
| **切換 customer_key 後仍顯示舊資料** | 連線測試成功但 dashboard 不變 — 因為 `pull_cursors` 還停在舊客戶最後時間戳，新客戶較舊事件被略過；舊客戶資料也殘留。 | 偵測 `customer_key` 變更時自動 reset cursors，並可選清空 4 個 data tables；儲存後立刻觸發 pull。 |

#### ✨ 新功能

- **Web UI 編輯 XCockpit 連線參數**：「設定 → XCockpit 連線設定」可直接改 `XCOCKPIT_URL` / `XCOCKPIT_CUSTOMER_KEY` / `XCOCKPIT_API_KEY`，免再 `ssh + 改 .env + 重啟`。API Key 顯示為遮罩（`••••••••abcd`），留空＝不變更。內建「測試連線」按鈕。
- **可調整登入 Session 時間**：admin 在「設定 → 系統設定」可改 `登入有效時間（小時）`，範圍 1–720h，預設 24h。修改後對下次登入生效，不影響當前 session。
- **儀表板顯示客戶名稱**：標題旁顯示 `🏢 <CustomerName>`（取自最近一筆事件的 `CustomerName` 欄位），hover 看完整 `customer_key`。
- **儲存空間剩餘監控**：Dashboard 右上顯示磁碟剩餘百分比，≥25% 綠 / 10–25% 黃 / <10% 紅警示。
- **修改密碼 / 帳號管理 UI**：admin 可建立 / 刪除帳號（admin / analyst / viewer），所有使用者可改自己的密碼。

#### ⚙️ 部署改善

- `install.sh`：把 `npm ci` 改 `npm install`（不需要 lock file），`.env` 在 frontend build 之前生成
- `systemd` 服務：`--workers 2` → `--workers 1`（DuckDB 是 single-process file lock）
- 提供完整 README 與 GitHub repo（`k09323/xcockpit-siem`）

### v1.0 (2026-05-03) — 首版

- FastAPI + DuckDB + React 完整骨架
- SPL → DuckDB SQL 轉譯（tokenizer + parser + transpiler）
- XCockpit API 整合：CYCRAFT_E（EDR alerts）、CYCRAFT_C（Cyber reports）、incidents、activity logs
- 告警規則引擎 + APScheduler 定時評估
- JWT 認證、systemd 一鍵部署

---

## 專案簡介

XCockpit SIEM 是一套自架的資安分析框架，可自動從 CyCraft XCockpit 平台拉取 EDR 告警、資安報表、事件與操作日誌，並提供統一的查詢與分析介面。

功能特色
🔍 查詢語言引擎 — 支援類似管線式（pipeline-based）的查詢語法，並轉譯為 DuckDB SQL 執行
📊 即時儀表板 — 使用 ECharts 建立趨勢、分布與 Top N 視覺化分析
🚨 告警規則引擎 — 支援自訂查詢條件與排程執行，自動觸發告警事件
👥 多使用者管理 — 採用 JWT 認證，支援 admin / analyst / viewer 角色權限控管
🐧 Linux 單機部署 — 提供一鍵安裝腳本，整合 systemd 服務管理

---

## 架構

```
┌─────────────────────────────────────────────────────────────┐
│                    xcockpit-siem                             │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐                       │
│  │  APScheduler │───▶│  XCockpit    │                       │
│  │  (每 2 分鐘) │    │  Client      │                       │
│  └──────────────┘    └──────┬───────┘                       │
│                             ▼                                │
│                      ┌─────────────────────────────┐        │
│                      │   DuckDB (siem.duckdb)       │        │
│                      │  edr_alerts / cyber_reports  │        │
│                      │  incidents / activity_logs   │        │
│                      └─────────────────────────────┘        │
│                                    │                        │
│  ┌──────────────┐    ┌─────────────▼────────┐              │
│  │  React UI    │◀───│  FastAPI Backend      │              │
│  │  (Vite/      │    │  /api/query  (SPL)    │              │
│  │   ECharts)   │    │  /api/alerts          │              │
│  └──────────────┘    └──────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │ Authorization: Token <API_KEY>
                    ┌─────────────────────┐
                    │  XCockpit Platform  │
                    │  /_api/<cust_key>/  │
                    └─────────────────────┘
```

### 技術棧

| 層次 | 技術 |
|------|------|
| Backend | Python 3.11 + FastAPI + APScheduler |
| Storage | DuckDB (embedded OLAP) |
| Frontend | React 18 + Vite + ECharts |
| Auth | PyJWT + bcrypt |
| Deployment | systemd on Linux |

---

## 專案目錄

```
xcockpit-siem/
├── install.sh                    # 一鍵安裝腳本
├── requirements.txt
├── config/
│   ├── settings.yaml             # 主設定（port、DB 路徑、Pull 間隔）
│   └── alert_rules.yaml          # 預設告警規則（首次啟動自動載入）
├── backend/
│   ├── main.py                   # FastAPI 進入點
│   ├── config.py                 # 讀取 settings.yaml + .env
│   ├── dependencies.py           # JWT 驗證
│   ├── api/                      # REST API 路由
│   │   ├── auth.py               # 登入、改密碼、帳號管理
│   │   ├── query.py              # SPL 查詢
│   │   ├── alerts.py             # 告警規則 + incidents CRUD
│   │   ├── dashboards.py         # 儀表板設定
│   │   └── system.py             # 系統狀態、手動觸發 Pull
│   ├── core/
│   │   ├── database.py           # DuckDB schema + UPSERT
│   │   ├── query_engine.py       # SPL → SQL 轉譯
│   │   ├── scheduler.py          # APScheduler 定時工作
│   │   ├── alert_engine.py       # 告警規則評估
│   │   └── pipeline.py           # 事件後處理
│   └── integrations/
│       ├── xcockpit_client.py    # XCockpit REST API 呼叫
│       └── normalizer.py         # 欄位正規化
├── frontend/
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx               # 主框架 + 側邊欄
│       └── pages/
│           ├── Login.jsx
│           ├── Search.jsx        # SPL 查詢頁
│           ├── Dashboard.jsx     # 儀表板
│           ├── Alerts.jsx        # 告警規則管理
│           └── Settings.jsx      # 改密碼 + 帳號管理 + XCockpit 連線設定 + Session 設定
├── data/                         # DuckDB 資料（.gitignore）
├── logs/                         # 應用程式 log
└── systemd/
    └── xcockpit-siem.service     # systemd 服務定義
```

---

## 安裝

### 系統需求

- Linux（Ubuntu 22.04 LTS 測試過）
- Python 3.11+
- Node.js 20+
- 1 GB RAM 以上
- 10 GB 磁碟空間（依資料保留期決定）

### 一鍵安裝

**Step 1：取得程式碼**

```bash
# Clone 到 server
git clone https://github.com/k09323/xcockpit-siem.git /tmp/xcockpit-siem
cd /tmp/xcockpit-siem
```

**Step 2：安裝 Node.js（若尚未安裝）**

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

**Step 3：執行安裝腳本**

```bash
sudo bash install.sh
```

安裝腳本會自動完成：
- 建立系統帳號 `siem`
- 複製檔案到 `/opt/xcockpit-siem/`
- 建立 Python venv 並安裝套件
- 編譯前端 (`npm install && npm run build`)
- 產生 `.env`（含隨機 JWT Secret）
- 安裝 systemd service + logrotate
- 啟動服務

安裝完成後會顯示：
```
Web UI:        http://<server_ip>:8000
API docs:      http://<server_ip>:8000/docs
Default login: admin / admin
```

---

## 設定 XCockpit API 參數

安裝完成後，必須填入 XCockpit 連線資訊才能開始 Pull 資料：

```bash
sudo nano /opt/xcockpit-siem/.env
```

填入以下三個參數：

```ini
# JWT Secret（安裝時自動產生，勿修改）
JWT_SECRET=（自動產生）

# XCockpit 連線設定
XCOCKPIT_URL=https://xcockpit.cycraft.ai
XCOCKPIT_CUSTOMER_KEY=your-customer-key-here
XCOCKPIT_API_KEY=your-xcockpit-api-key-here
```

### 參數說明

| 參數 | 說明 | 取得方式 |
|------|------|---------|
| `XCOCKPIT_URL` | XCockpit 平台 URL | 依地區而定，例如 `https://xcockpit.cycraft.ai` |
| `XCOCKPIT_CUSTOMER_KEY` | URL 路徑中的客戶代碼 | 向 CyCraft support 索取 |
| `XCOCKPIT_API_KEY` | API 認證 Token | XCockpit → Security → **Create API Token** |

> API 呼叫的 Authorization header 會自動組合成：`Authorization: Token <XCOCKPIT_API_KEY>`

填完後重啟服務套用設定：

```bash
sudo systemctl restart xcockpit-siem
```

### 驗證連線

```bash
# 取得 JWT Token
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 檢查 XCockpit 是否連線成功
curl -s -H "Authorization: Token $TOKEN" \
  http://localhost:8000/api/system/status | python3 -m json.tool
```

若 `xcockpit.connected` 為 `true` 則表示連線正常，定時任務每 2 分鐘會自動 Pull 一次。

---

## 操作 SOP

### 1. 登入

瀏覽器開啟 `http://<server_ip>:8000`

| 項目 | 預設 |
|------|------|
| 帳號 | `admin` |
| 密碼 | `admin` |

> ⚠️ 登入後請立刻修改密碼（右上角 `👤 admin` 或側邊欄 `⚙ 設定`）

### 2. 修改密碼 & 新增帳號

側邊欄點選「⚙ 設定」：
- **修改密碼**：所有使用者可用
- **帳號管理**：admin 角色專屬，可新增/刪除其他帳號

#### 角色權限

| 角色 | 權限 |
|------|------|
| `admin` | 全部功能 + 帳號管理 |
| `analyst` | 查詢、告警規則管理 |
| `viewer` | 只能查詢與檢視 |

### 3. 使用 SPL 查詢

側邊欄 → **Search**

```
# 最新高風險 EDR 告警
source=edr_alerts severity >= 8 | sort -report_time | head 20

# 過去 7 天告警趨勢
source=edr_alerts | timechart span=1d count

# 未解決事件
source=incidents state = 0 | sort -created | head 20

# 高風險端點排名
source=incidents | stats count by computer_name | sort -count | head 10

# 最新 Cyber 報表
source=cyber_reports | sort -report_time | head 5

# 操作日誌
source=activity_logs | stats count by account, action | sort -count | head 20
```

#### SPL 支援指令

| 指令 | 說明 | 範例 |
|------|------|------|
| `search` | 欄位篩選（預設） | `severity >= 8 title!=""` |
| `where` | 後置篩選 | `\| where count > 10` |
| `stats` | 統計 | `\| stats count by host` |
| `timechart` | 時序統計 | `\| timechart span=5m count` |
| `sort` | 排序 | `\| sort -count +host` |
| `head` / `tail` | 限制筆數 | `\| head 20` |
| `fields` | 選擇欄位 | `\| fields host, severity` |
| `rename` | 欄位改名 | `\| rename report_time as time` |
| `eval` | 計算新欄位 | `\| eval risk=if(severity>=8,"high","low")` |

#### 資料來源

| `source=` | 說明 | 時間欄位 |
|-----------|------|---------|
| `edr_alerts` | CYCRAFT_E EDR 告警 | `report_time` |
| `cyber_reports` | CYCRAFT_C Cyber 情資報表 | `report_time` |
| `incidents` | XCockpit 事件 | `created` |
| `activity_logs` | 操作日誌 | `log_time` |

### 4. 設定告警規則

側邊欄 → **Alerts** → 切換到 **Rules** tab → 點 **+ 新增規則**

告警規則結構：

| 欄位 | 說明 | 範例 |
|------|------|------|
| 名稱 | 規則名稱 | `高風險 EDR 告警` |
| SPL 查詢 | 監控查詢（需回傳含計數欄位） | `source=edr_alerts severity >= 9 \| stats count` |
| 觸發條件 | 針對查詢結果欄位判斷 | `count > 0` |
| 嚴重度 | critical / high / medium / low / info | `high` |
| Throttle | 同規則再次觸發間隔（分鐘） | `30` |

告警引擎每 60 秒自動執行所有啟用中的規則，條件達成時建立 **Incident**，可在 Incidents tab 中 Acknowledge 或 Resolve。

### 5. 儀表板

側邊欄 → **Dashboards**

預設儀表板顯示：
- 4 個關鍵指標（24 小時 EDR 告警、未解決事件、7 天 Cyber 報表、惡意程式偵測數）
- EDR 告警 7 天趨勢
- 告警嚴重度分布
- 事件狀態分布
- 高風險端點 Top 10
- 惡意程式偵測趨勢
- 最新 Cyber 報表

### 6. 常用系統管理指令

```bash
# 服務狀態
sudo systemctl status xcockpit-siem

# 即時 log
sudo journalctl -u xcockpit-siem -f

# 重啟服務（修改 .env 後）
sudo systemctl restart xcockpit-siem

# 手動觸發 XCockpit Pull（不等排程）
curl -X POST -H "Authorization: Token $TOKEN" \
  http://localhost:8000/api/system/pull/trigger

# 查看資料庫統計
curl -H "Authorization: Token $TOKEN" \
  http://localhost:8000/api/system/status | python3 -m json.tool

# 備份資料庫
sudo cp /opt/xcockpit-siem/data/siem.duckdb \
        /opt/xcockpit-siem/backups/siem-$(date +%Y%m%d).duckdb
```

---

## 定時工作

| 工作 | 頻率 | 說明 |
|------|------|------|
| Pull Alerts | 每 2 分鐘 | 拉取 EDR 告警 + Cyber 報表 |
| Pull Incidents | 每 2 分鐘 | 拉取事件 |
| Pull Activity Logs | 每 10 分鐘 | 拉取操作日誌 |
| Alert Evaluation | 每 1 分鐘 | 評估告警規則 |
| Retention Cleanup | 每天凌晨 3 點 | 刪除超過保留期（預設 180 天）的舊資料 |

---

## 設定檔參數

編輯 `/opt/xcockpit-siem/config/settings.yaml`：

| 設定項 | 預設值 | 說明 |
|--------|--------|------|
| `server.port` | `8000` | Web 服務 Port |
| `server.workers` | `1` | Uvicorn workers（DuckDB 限制為 1） |
| `database.path` | `./data/siem.duckdb` | 資料庫檔案路徑 |
| `database.max_memory` | `2GB` | DuckDB 最大記憶體 |
| `database.retention_days` | `180` | 資料保留天數 |
| `xcockpit.pull_interval_seconds` | `120` | Pull 頻率 |
| `xcockpit.pull_page_size` | `50` | 每次 Pull 筆數 |
| `xcockpit.verify_ssl` | `true` | 自簽憑證時改為 `false` |
| `auth.access_token_expire_minutes` | `60` | JWT 有效期 |
| `alerts.evaluation_interval_seconds` | `60` | 告警規則評估頻率 |

修改後需重啟：`sudo systemctl restart xcockpit-siem`

---

## 故障排除

### 服務無法啟動

```bash
sudo journalctl -u xcockpit-siem -n 100 --no-pager
```

常見原因：
- **DuckDB file lock** — 確認 `server.workers` 為 1（DuckDB 不支援多 process 開啟同一檔案）
- **Port 8000 被占用** — 修改 `settings.yaml` 的 `server.port`
- **Python 套件缺失** — 重新執行 `venv/bin/pip install -r requirements.txt`

### XCockpit 連不上

```bash
curl -s -H "Authorization: Token $TOKEN" http://localhost:8000/api/system/status | python3 -m json.tool
```

看 `xcockpit.connected` 欄位：
- `false` → 檢查 `.env` 的三個參數是否正確
- SSL 錯誤 → 在 `settings.yaml` 設 `verify_ssl: false`
- 401 → API Key 錯誤或已失效，重新產生

### 資料沒進來

```bash
# 手動觸發一次 Pull，看錯誤訊息
curl -X POST -H "Authorization: Token $TOKEN" \
  http://localhost:8000/api/system/pull/trigger

# 查看 log
sudo journalctl -u xcockpit-siem -n 50 | grep -i "pull\|error"

# 查看游標
curl -H "Authorization: Token $TOKEN" \
  http://localhost:8000/api/system/xcockpit
```

### 忘記 admin 密碼

```bash
cd /opt/xcockpit-siem
sudo -u siem venv/bin/python3 -c "
import duckdb, bcrypt
conn = duckdb.connect('data/siem.duckdb')
pw = bcrypt.hashpw(b'newpassword123', bcrypt.gensalt()).decode()
conn.execute(\"UPDATE users SET password_hash=? WHERE username='admin'\", [pw])
print('admin password reset to: newpassword123')
"
sudo systemctl restart xcockpit-siem
```

### 前端修改後沒反應

瀏覽器快取問題。按 `Ctrl+Shift+R` 強制重新整理，或用無痕視窗測試。

---

## 擴充：接入其他資料來源

除了 XCockpit 外，也可擴充接入 CrowdStrike、Wazuh、Elastic 等資料源：

1. 在 `backend/core/database.py` 新增資料表
2. 在 `backend/integrations/` 新增 client 檔案
3. 在 `backend/core/scheduler.py` 新增 Pull job
4. 在 `backend/core/query_engine.py` 的 `_SOURCE_TABLE_MAP` 加入新來源

SPL 查詢自動支援：
```
source=crowdstrike severity = "High" | stats count by device_hostname
source=wazuh rule.level >= 10 | timechart span=1h count
```

---

## 開發

### 本機開發環境

```bash
# Backend (terminal 1)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000

# Frontend (terminal 2)
cd frontend
npm install
npm run dev   # http://localhost:5173
```

### API 文件

啟動後開啟 `http://<server_ip>:8000/docs` 查看 Swagger UI。

### 專案授權

Copyright © 2026 Larry Lai

Disclaimer:
This project is an independent work and is not affiliated with, endorsed by, or associated with any vendor, including CyCraft Technology Corporation.
All product names, trademarks, and registered trademarks are the property of their respective owners.

---

## 相關連結

- [CyCraft XCockpit](https://www.cycraft.com/)
- [FastAPI](https://fastapi.tiangolo.com/)
- [DuckDB](https://duckdb.org/)
- [Splunk SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/)
