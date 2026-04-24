from __future__ import annotations

import ast
import logging
import operator
from datetime import datetime, timedelta
from typing import Any

from backend.config import settings
from backend.core import database as db
from backend.core.query_engine import execute_query

logger = logging.getLogger(__name__)

_SAFE_OPS = {
    ast.Gt: operator.gt,
    ast.Lt: operator.lt,
    ast.GtE: operator.ge,
    ast.LtE: operator.le,
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
}


def _eval_condition(condition: str, result_rows: list[list[Any]], columns: list[str]) -> tuple[bool, float]:
    """Safely evaluate a condition string like 'count > 10' against query results.

    Returns (triggered: bool, metric_value: float).
    Supports conditions on columns present in the first result row.
    """
    if not result_rows:
        row_dict = {col: 0 for col in columns}
    else:
        row_dict = dict(zip(columns, result_rows[0]))

    # Parse the condition as a Python comparison expression
    try:
        tree = ast.parse(condition.strip(), mode="eval")
    except SyntaxError as e:
        logger.warning("Alert condition parse error '%s': %s", condition, e)
        return False, 0.0

    if not isinstance(tree.body, ast.Compare):
        logger.warning("Alert condition must be a comparison: %s", condition)
        return False, 0.0

    compare = tree.body
    if len(compare.ops) != 1 or len(compare.comparators) != 1:
        logger.warning("Alert condition must have exactly one comparator: %s", condition)
        return False, 0.0

    op_type = type(compare.ops[0])
    if op_type not in _SAFE_OPS:
        logger.warning("Unsupported operator in condition: %s", condition)
        return False, 0.0

    # Resolve left-hand side (must be a column name)
    lhs_node = compare.left
    if isinstance(lhs_node, ast.Name):
        lhs_val = row_dict.get(lhs_node.id, 0)
    elif isinstance(lhs_node, ast.Constant):
        lhs_val = lhs_node.value
    else:
        logger.warning("Unsupported LHS in condition: %s", condition)
        return False, 0.0

    # Resolve right-hand side (must be a constant)
    rhs_node = compare.comparators[0]
    if not isinstance(rhs_node, (ast.Constant, ast.UnaryOp)):
        logger.warning("Unsupported RHS in condition: %s", condition)
        return False, 0.0
    if isinstance(rhs_node, ast.UnaryOp) and isinstance(rhs_node.op, ast.USub):
        rhs_val = -rhs_node.operand.value
    else:
        rhs_val = rhs_node.value

    try:
        lhs_num = float(lhs_val) if lhs_val is not None else 0.0
        triggered = _SAFE_OPS[op_type](lhs_num, float(rhs_val))
        return triggered, lhs_num
    except (TypeError, ValueError):
        return False, 0.0


async def evaluate_alerts() -> None:
    rules = db.get_enabled_alert_rules()
    for rule in rules:
        try:
            await _evaluate_rule(rule)
        except Exception as e:
            logger.error("Error evaluating alert rule '%s': %s", rule["name"], e)


async def _evaluate_rule(rule: dict[str, Any]) -> None:
    rule_id = rule["id"]
    throttle_mins = rule.get("throttle_mins", 60)

    # Check throttle
    last_incident = db.get_last_incident_time(rule_id)
    if last_incident:
        elapsed = (datetime.utcnow() - last_incident).total_seconds() / 60
        if elapsed < throttle_mins:
            return

    try:
        result = execute_query(
            rule["query"],
            time_range=settings.alerts.default_eval_window,
            limit=100,
        )
    except Exception as e:
        logger.warning("Alert query failed for rule '%s': %s", rule["name"], e)
        return

    triggered, metric_value = _eval_condition(
        rule["condition"], result["rows"], result["columns"]
    )

    if triggered:
        incident_id = db.create_incident(
            rule_id=rule_id,
            metric_value=metric_value,
            details={"columns": result["columns"], "rows": result["rows"][:10]},
        )
        logger.warning(
            "Alert triggered: '%s' (value=%.2f) → incident %s",
            rule["name"], metric_value, incident_id,
        )
