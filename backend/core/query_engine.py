from __future__ import annotations

"""Simplified SPL (Splunk Processing Language) → DuckDB SQL transpiler.

Data sources (use source= to select):
  source=edr_alerts        — CYCRAFT_E EDR alerts
  source=cyber_reports     — CYCRAFT_C Cyber Situation Reports
  source=incidents         — XCockpit incidents
  source=activity_logs     — XCockpit activity logs
  (default)                — edr_alerts

Time field per table:
  edr_alerts    → report_time
  cyber_reports → report_time
  incidents     → created
  activity_logs → log_time

Example queries:
  source=edr_alerts severity >= 8 | sort -report_time | head 20
  source=incidents state = 0 | stats count by computer_os_type
  source=edr_alerts | timechart span=1d count
  source=cyber_reports | stats sum(suspicious_files) as total_files by customer_name
  source=incidents | where tags LIKE '%Malware%' | stats count by computer_name | sort -count | head 10

Supported pipe commands:
  search / bare filters   source=x severity>=8 title!=""
  where                   | where count > 10
  stats                   | stats count by host
  timechart               | timechart span=5m count by severity
  sort                    | sort -count +host
  head / tail             | head 20
  fields                  | fields host, severity
  rename                  | rename report_time as time
  eval                    | eval risk=if(severity>=8,"urgent","monitor")

Time qualifiers:
  earliest=-1h  latest=-0h  (relative: s/m/h/d/w)
  earliest=2024-01-01T00:00:00Z  (ISO)
"""

import ast
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import duckdb

from backend.core.database import get_conn

# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"'   # double-quoted string
    r"|'(?:[^'\\]|\\.)*'"  # single-quoted string
    r"|[A-Za-z_][\w.]*"    # identifier / keyword
    r"|[-+]?\d+(?:\.\d+)?" # number
    r"|[!=<>]=?"            # operators
    r"|\|"                  # pipe
    r"|\(|\)"               # parens
    r"|,"                   # comma
    , re.ASCII,
)


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.strip())


def _strip_quotes(s: str) -> str:
    if len(s) >= 2 and s[0] in ('"', "'") and s[-1] == s[0]:
        return s[1:-1]
    return s


# ---------------------------------------------------------------------------
# Relative-time parsing
# ---------------------------------------------------------------------------

_REL_RE = re.compile(r"^([+-]?\d+)([smhdw])$")

def _parse_time_expr(expr: str) -> str:
    """Return a DuckDB SQL time expression string."""
    expr = _strip_quotes(expr)
    if m := _REL_RE.match(expr):
        n, unit = int(m.group(1)), m.group(2)
        unit_map = {"s": "second", "m": "minute", "h": "hour", "d": "day", "w": "week"}
        if n >= 0:
            return f"now() + INTERVAL '{n} {unit_map[unit]}'"
        return f"now() - INTERVAL '{abs(n)} {unit_map[unit]}'"
    # Try ISO datetime
    return f"TIMESTAMPTZ '{expr}'"


# ---------------------------------------------------------------------------
# Table/source resolution
# ---------------------------------------------------------------------------

# Maps source= value → (table_name, time_column)
_SOURCE_TABLE_MAP: dict[str, tuple[str, str]] = {
    "edr_alerts":    ("edr_alerts",    "report_time"),
    "cyber_reports": ("cyber_reports", "report_time"),
    "incidents":     ("incidents",     "created"),
    "activity_logs": ("activity_logs", "log_time"),
    # aliases
    "edr":           ("edr_alerts",    "report_time"),
    "cyber":         ("cyber_reports", "report_time"),
    "incident":      ("incidents",     "created"),
    "activity":      ("activity_logs", "log_time"),
}
_DEFAULT_SOURCE = "edr_alerts"
_DEFAULT_TIME_COL = "report_time"


def _resolve_source(source_val: str) -> tuple[str, str]:
    """Return (table_name, time_column) for the given source= value."""
    return _SOURCE_TABLE_MAP.get(source_val.lower(), (_DEFAULT_SOURCE, _DEFAULT_TIME_COL))


# ---------------------------------------------------------------------------
# Query context accumulator
# ---------------------------------------------------------------------------

@dataclass
class QueryContext:
    where_clauses: list[str] = field(default_factory=list)
    group_by: list[str] = field(default_factory=list)
    select_exprs: list[str] = field(default_factory=list)
    order_by: list[str] = field(default_factory=list)
    limit: Optional[int] = None
    from_table: str = _DEFAULT_SOURCE
    time_col: str = _DEFAULT_TIME_COL
    earliest: Optional[str] = None
    latest: Optional[str] = None
    params: list[Any] = field(default_factory=list)
    timechart_sql: Optional[str] = None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class SPLParser:
    def __init__(self, tokens: list[str]) -> None:
        self._tokens = tokens
        self._pos = 0

    def peek(self) -> Optional[str]:
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return None

    def consume(self) -> str:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def expect(self, val: str) -> str:
        tok = self.consume()
        if tok.lower() != val.lower():
            raise ValueError(f"Expected '{val}', got '{tok}'")
        return tok

    def at_end(self) -> bool:
        return self._pos >= len(self._tokens)

    def at_pipe(self) -> bool:
        return self.peek() == "|"


# ---------------------------------------------------------------------------
# Search / filter parsing
# ---------------------------------------------------------------------------

_COMPARISON_OPS = {"=", "!=", "<", ">", "<=", ">="}
_SPECIAL_SEARCH_KEYS = {"earliest", "latest", "source", "sourcetype"}
_AGG_FUNCS = {"count", "sum", "avg", "min", "max", "dc", "values"}
_SQL_SAFE_FIELD = re.compile(r"^[A-Za-z_][\w.]*$")


def _safe_field(name: str) -> str:
    """Wrap field name in double-quotes if it contains special chars."""
    if name.startswith("_"):
        return f'"{name}"'
    if not _SQL_SAFE_FIELD.match(name):
        return f'"{name}"'
    return name


def _parse_filter_value(parser: SPLParser) -> tuple[str, Any]:
    """Parse the RHS of a filter: a quoted string, number, or bare word.
    Also handles  IN (a, b, c).
    Returns (sql_fragment, None) where the value is embedded, OR raises.
    """
    tok = parser.peek()
    if tok and tok.upper() == "IN":
        # caller handles IN; shouldn't reach here
        raise ValueError("IN handled upstream")
    val = parser.consume()
    return _strip_quotes(val)


def _parse_one_filter(parser: SPLParser, ctx: QueryContext) -> str:
    """Parse a single filter expression and return SQL fragment (with ? params)."""
    lhs = parser.consume()

    # Handle NOT
    if lhs.upper() == "NOT":
        inner = _parse_one_filter(parser, ctx)
        return f"NOT ({inner})"

    # Handle grouped expression
    if lhs == "(":
        parts = []
        while parser.peek() != ")":
            if parser.peek() and parser.peek().upper() == "AND":
                parser.consume()
                continue
            if parser.peek() and parser.peek().upper() == "OR":
                parser.consume()
                parts_op = "OR"
                continue
            parts.append(_parse_one_filter(parser, ctx))
        parser.expect(")")
        return " AND ".join(parts)

    # Check for time qualifiers
    if lhs.lower() in ("earliest", "latest"):
        op = parser.consume()  # should be '='
        val = _strip_quotes(parser.consume())
        time_sql = _parse_time_expr(val)
        if lhs.lower() == "earliest":
            ctx.earliest = time_sql
        else:
            ctx.latest = time_sql
        return ""  # no WHERE clause from this

    # Handle source= to switch the target table
    if lhs.lower() == "source":
        op = parser.peek()
        if op == "=":
            parser.consume()
            val = _strip_quotes(parser.consume())
            table, time_col = _resolve_source(val)
            ctx.from_table = table
            ctx.time_col = time_col
            return ""  # source= is metadata, not a SQL WHERE clause
        elif op == "!=":
            parser.consume()
            parser.consume()
            return ""  # ignore negative source filters

    # Check for IN operator
    next_tok = parser.peek()
    if next_tok and next_tok.upper() == "IN":
        parser.consume()  # consume IN
        parser.expect("(")
        values = []
        while parser.peek() != ")":
            if parser.peek() == ",":
                parser.consume()
                continue
            values.append(_strip_quotes(parser.consume()))
        parser.expect(")")
        placeholders = ", ".join(["?" for _ in values])
        ctx.params.extend(values)
        return f"{_safe_field(lhs)} IN ({placeholders})"

    # Check for binary operator
    if next_tok in _COMPARISON_OPS:
        op = parser.consume()
        rhs = _strip_quotes(parser.consume())
        ctx.params.append(rhs)
        op_map = {"=": "=", "!=": "!=", "<": "<", ">": ">", "<=": "<=", ">=": ">="}
        return f"{_safe_field(lhs)} {op_map[op]} ?"

    # Bare word: full-text match against message
    ctx.params.append(f"%{lhs}%")
    return f"message ILIKE ?"


def _parse_search_segment(parser: SPLParser, ctx: QueryContext) -> None:
    """Parse the initial search expression (before first |)."""
    # Optionally consume literal 'search' keyword
    if parser.peek() and parser.peek().lower() == "search":
        parser.consume()

    filters: list[str] = []
    while not parser.at_end() and not parser.at_pipe():
        tok = parser.peek()
        if tok and tok.upper() in ("AND", "OR"):
            parser.consume()
            continue
        f = _parse_one_filter(parser, ctx)
        if f:
            filters.append(f)

    if filters:
        ctx.where_clauses.extend(filters)


# ---------------------------------------------------------------------------
# Pipe command parsers
# ---------------------------------------------------------------------------

def _parse_where(parser: SPLParser, ctx: QueryContext) -> None:
    filters: list[str] = []
    while not parser.at_end() and not parser.at_pipe():
        tok = parser.peek()
        if tok and tok.upper() in ("AND", "OR"):
            parser.consume()
            continue
        f = _parse_one_filter(parser, ctx)
        if f:
            filters.append(f)
    if filters:
        ctx.where_clauses.extend(filters)


def _parse_agg_func(parser: SPLParser, ctx: QueryContext) -> tuple[str, str]:
    """Parse agg_func([field]) [AS alias]. Returns (sql_expr, alias)."""
    func = parser.consume().lower()
    if func == "dc":
        func_sql = "COUNT(DISTINCT"
        suffix = ")"
    elif func == "count":
        func_sql = "COUNT("
        suffix = ")"
    elif func == "values":
        func_sql = "LIST("
        suffix = ")"
    else:
        func_sql = func.upper() + "("
        suffix = ")"

    # Optional field arg
    field_arg = "*"
    if parser.peek() == "(":
        parser.consume()
        if parser.peek() != ")":
            field_arg = _safe_field(_strip_quotes(parser.consume()))
        parser.expect(")")

    sql_expr = f"{func_sql}{field_arg}{suffix}"
    alias = func if field_arg == "*" else f"{func}_{field_arg.strip('\"')}"

    # Optional AS alias
    if parser.peek() and parser.peek().upper() == "AS":
        parser.consume()
        alias = _strip_quotes(parser.consume())

    return sql_expr, alias


def _parse_stats(parser: SPLParser, ctx: QueryContext) -> None:
    aggs: list[tuple[str, str]] = []
    while not parser.at_end() and not parser.at_pipe() and (parser.peek() or "").lower() not in ("by",):
        if parser.peek() == ",":
            parser.consume()
            continue
        agg_sql, alias = _parse_agg_func(parser, ctx)
        aggs.append((agg_sql, alias))

    by_fields: list[str] = []
    if parser.peek() and parser.peek().lower() == "by":
        parser.consume()
        while not parser.at_end() and not parser.at_pipe():
            if parser.peek() == ",":
                parser.consume()
                continue
            by_fields.append(_safe_field(_strip_quotes(parser.consume())))

    ctx.select_exprs = [f"{expr} AS {alias}" for expr, alias in aggs]
    if by_fields:
        ctx.group_by = by_fields
        ctx.select_exprs = by_fields + ctx.select_exprs


def _parse_timechart(parser: SPLParser, ctx: QueryContext) -> None:
    """| timechart [span=5m] count [by field]"""
    span_interval = "1 hour"

    if parser.peek() and parser.peek().lower().startswith("span"):
        span_tok = parser.consume()
        # Could be "span=5m" as single token or span = 5m as three tokens
        if "=" in span_tok:
            _, val = span_tok.split("=", 1)
        else:
            parser.expect("=")
            val = parser.consume()  # e.g. "1"
            # Tokenizer splits "1d" into ["1", "d"] — rejoin if next token is a unit letter
            if parser.peek() and parser.peek().lower() in ("s", "m", "h", "d", "w"):
                val = val + parser.consume()  # → "1d"
        # Also handle the case where the value itself might be just a unit-less number
        if val and not val[-1].isalpha():
            # No unit letter at all — treat as seconds
            val = val + "s"
        m = _REL_RE.match(val.strip())
        if m:
            n, u = int(m.group(1)), m.group(2)
            unit_map = {"s": "second", "m": "minute", "h": "hour", "d": "day", "w": "week"}
            span_interval = f"{abs(n)} {unit_map[u]}"

    agg_sql, alias = _parse_agg_func(parser, ctx)

    by_field: Optional[str] = None
    if parser.peek() and parser.peek().lower() == "by":
        parser.consume()
        by_field = _safe_field(_strip_quotes(parser.consume()))

    tc = ctx.time_col
    time_bucket = f"time_bucket(INTERVAL '{span_interval}', \"{tc}\") AS \"{tc}\""
    if by_field:
        ctx.select_exprs = [time_bucket, by_field, f"{agg_sql} AS {alias}"]
        ctx.group_by = [f'"{tc}"', by_field]
    else:
        ctx.select_exprs = [time_bucket, f"{agg_sql} AS {alias}"]
        ctx.group_by = [f'"{tc}"']
    ctx.order_by = [f'"{tc}" ASC']


def _parse_sort(parser: SPLParser, ctx: QueryContext) -> None:
    order_terms: list[str] = []
    while not parser.at_end() and not parser.at_pipe():
        if parser.peek() == ",":
            parser.consume()
            continue
        tok = parser.consume()
        if tok == "-":
            field_tok = _safe_field(_strip_quotes(parser.consume()))
            order_terms.append(f"{field_tok} DESC")
        elif tok == "+":
            field_tok = _safe_field(_strip_quotes(parser.consume()))
            order_terms.append(f"{field_tok} ASC")
        else:
            order_terms.append(f"{_safe_field(_strip_quotes(tok))} ASC")
    ctx.order_by = order_terms


def _parse_head(parser: SPLParser, ctx: QueryContext) -> None:
    n = 10
    if parser.peek() and re.match(r"^\d+$", parser.peek() or ""):
        n = int(parser.consume())
    ctx.limit = n


def _parse_tail(parser: SPLParser, ctx: QueryContext) -> None:
    n = 10
    if parser.peek() and re.match(r"^\d+$", parser.peek() or ""):
        n = int(parser.consume())
    # Tail = reverse sort by _time then limit (rough approximation)
    ctx.order_by = ['"_time" DESC']
    ctx.limit = n


def _parse_fields(parser: SPLParser, ctx: QueryContext) -> None:
    # Optional + or - (include/exclude)
    mode = "+"
    if parser.peek() in ("+", "-"):
        mode = parser.consume()
    fields: list[str] = []
    while not parser.at_end() and not parser.at_pipe():
        if parser.peek() == ",":
            parser.consume()
            continue
        fields.append(_safe_field(_strip_quotes(parser.consume())))
    if mode == "+" and fields:
        ctx.select_exprs = fields


def _parse_rename(parser: SPLParser, ctx: QueryContext) -> None:
    # rename old_field AS new_alias
    old_f = _safe_field(_strip_quotes(parser.consume()))
    if parser.peek() and parser.peek().upper() == "AS":
        parser.consume()
    new_alias = _strip_quotes(parser.consume())
    # Replace in existing select_exprs
    if ctx.select_exprs:
        ctx.select_exprs = [
            e.replace(old_f, f"{old_f} AS {new_alias}") if old_f in e else e
            for e in ctx.select_exprs
        ]
    else:
        ctx.select_exprs = [f"{old_f} AS {new_alias}"]


def _parse_eval(parser: SPLParser, ctx: QueryContext) -> None:
    target = _strip_quotes(parser.consume())
    parser.expect("=")
    # Parse eval expression
    expr = _parse_eval_expr(parser, ctx)
    if ctx.select_exprs:
        ctx.select_exprs.append(f"{expr} AS {target}")
    else:
        ctx.select_exprs = [f"* , {expr} AS {target}"]


def _parse_eval_expr(parser: SPLParser, ctx: QueryContext) -> str:
    tok = parser.consume()
    # if( condition, true_val, false_val )
    if tok.lower() == "if":
        parser.expect("(")
        cond = _parse_one_filter(parser, ctx)
        parser.expect(",")
        true_val = _strip_quotes(parser.consume())
        parser.expect(",")
        false_val = _strip_quotes(parser.consume())
        parser.expect(")")
        ctx.params.extend([true_val, false_val])
        return f"CASE WHEN {cond} THEN ? ELSE ? END"
    # Simple field reference or literal
    return _safe_field(_strip_quotes(tok))


# ---------------------------------------------------------------------------
# SQL builder
# ---------------------------------------------------------------------------

def _build_sql(ctx: QueryContext, extra_limit: Optional[int] = None) -> str:
    select_part = ", ".join(ctx.select_exprs) if ctx.select_exprs else "*"

    where_parts = list(ctx.where_clauses)
    tc = ctx.time_col  # dynamic time column per table
    if ctx.earliest:
        where_parts.append(f'"{tc}" >= {ctx.earliest}')
    if ctx.latest:
        where_parts.append(f'"{tc}" <= {ctx.latest}')

    sql = f"SELECT {select_part} FROM {ctx.from_table}"
    if where_parts:
        sql += " WHERE " + " AND ".join(where_parts)
    if ctx.group_by:
        sql += " GROUP BY " + ", ".join(ctx.group_by)
    if ctx.order_by:
        sql += " ORDER BY " + ", ".join(ctx.order_by)

    limit = extra_limit or ctx.limit
    if limit:
        sql += f" LIMIT {int(limit)}"

    return sql


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def execute_query(
    spl: str,
    time_range: str = "-24h",
    earliest: Optional[str] = None,
    latest: Optional[str] = None,
    limit: int = 1000,
) -> dict[str, Any]:
    """Execute an SPL query against the DuckDB events table.
    Returns dict with columns, rows, total, duration_ms, sql.
    """
    tokens = _tokenize(spl)
    parser = SPLParser(tokens)
    ctx = QueryContext()

    # Apply default time range
    if earliest:
        ctx.earliest = _parse_time_expr(earliest)
    elif not ctx.earliest:
        ctx.earliest = _parse_time_expr(time_range)

    if latest:
        ctx.latest = _parse_time_expr(latest)

    # Parse initial search expression
    _parse_search_segment(parser, ctx)

    # Parse pipe commands
    while not parser.at_end():
        parser.expect("|")
        if parser.at_end():
            break
        cmd = parser.consume().lower()
        if cmd == "where":
            _parse_where(parser, ctx)
        elif cmd == "stats":
            _parse_stats(parser, ctx)
        elif cmd == "timechart":
            _parse_timechart(parser, ctx)
        elif cmd == "sort":
            _parse_sort(parser, ctx)
        elif cmd == "head":
            _parse_head(parser, ctx)
        elif cmd == "tail":
            _parse_tail(parser, ctx)
        elif cmd == "fields":
            _parse_fields(parser, ctx)
        elif cmd == "rename":
            _parse_rename(parser, ctx)
        elif cmd == "eval":
            _parse_eval(parser, ctx)
        else:
            raise ValueError(f"Unknown pipe command: {cmd!r}")

    sql = _build_sql(ctx, extra_limit=limit if ctx.limit is None else None)

    t0 = time.monotonic()
    conn = get_conn()
    relation = conn.execute(sql, ctx.params)
    rows = relation.fetchall()
    columns = [desc[0] for desc in relation.description]
    duration_ms = int((time.monotonic() - t0) * 1000)

    # Serialize datetime objects
    def _serialize(v: Any) -> Any:
        if isinstance(v, datetime):
            return v.isoformat()
        return v

    serialized_rows = [[_serialize(c) for c in row] for row in rows]

    return {
        "columns": columns,
        "rows": serialized_rows,
        "total": len(serialized_rows),
        "duration_ms": duration_ms,
        "sql": sql,
        "query_id": str(uuid.uuid4()),
    }
