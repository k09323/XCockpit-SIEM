import React, { useState } from 'react'
import api from '../api/client.js'

const TIME_PRESETS = ['-1h', '-6h', '-24h', '-7d', '-30d']

const EXAMPLE_QUERIES = [
  { label: 'EDR Alerts (高風險)', query: 'source=edr_alerts severity >= 8 | sort -report_time | head 20' },
  { label: 'EDR Alert 趨勢', query: 'source=edr_alerts | timechart span=1d count' },
  { label: 'Cyber Report 摘要', query: 'source=cyber_reports | sort -report_time | head 10' },
  { label: '未解決事件', query: 'source=incidents state = 0 | sort -created | head 20' },
  { label: '事件依主機統計', query: 'source=incidents | stats count by computer_name | sort -count | head 10' },
  { label: '惡意程式數量趨勢', query: 'source=edr_alerts | timechart span=1d sum(malware_count) as malware_total' },
  { label: '高風險報表', query: 'source=cyber_reports severity >= 7 | stats count by customer_name' },
  { label: 'Activity Log 操作', query: 'source=activity_logs | stats count by action | sort -count | head 10' },
]

const S = {
  queryBar: { display: 'flex', gap: 8, marginBottom: 8 },
  textarea: {
    flex: 1, padding: '10px 14px', background: '#0d1117', border: '1px solid #30363d',
    borderRadius: 6, color: '#e6edf3', fontSize: 13, fontFamily: 'monospace', resize: 'vertical',
    minHeight: 52,
  },
  controls: { display: 'flex', flexDirection: 'column', gap: 6 },
  select: {
    padding: '7px 10px', background: '#0d1117', border: '1px solid #30363d',
    borderRadius: 6, color: '#e6edf3', fontSize: 13,
  },
  btn: (color='#238636') => ({
    padding: '7px 18px', background: color, border: 'none',
    borderRadius: 6, color: '#fff', fontSize: 14, fontWeight: 600, cursor: 'pointer',
  }),
  examples: { display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 12 },
  exBtn: {
    padding: '3px 10px', background: '#21262d', border: '1px solid #30363d',
    borderRadius: 12, color: '#8b949e', fontSize: 11, cursor: 'pointer',
  },
  meta: { fontSize: 12, color: '#8b949e', marginBottom: 8 },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: 12 },
  th: { padding: '7px 10px', textAlign: 'left', background: '#161b22', borderBottom: '1px solid #30363d', color: '#8b949e', fontWeight: 500, position: 'sticky', top: 0 },
  td: { padding: '6px 10px', borderBottom: '1px solid #21262d', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', verticalAlign: 'top' },
  error: { color: '#f85149', background: '#2d1b1b', border: '1px solid #5c2626', borderRadius: 6, padding: '10px 14px', fontSize: 13 },
  sqlBlock: { background: '#0d1117', border: '1px solid #21262d', borderRadius: 4, padding: '8px 12px', fontFamily: 'monospace', fontSize: 11, color: '#79c0ff', marginBottom: 10, wordBreak: 'break-all' },
}

const SEVERITY_COLORS = {
  10: '#f85149', 9: '#f85149', 8: '#e3b341', 7: '#d29922',
  6: '#d29922', 5: '#3fb950', 4: '#3fb950', 3: '#79c0ff', 2: '#79c0ff', 1: '#8b949e',
}
const STATE_LABELS = { 0: 'InProgress', 1: 'Investigated', 2: 'Confirmed', 3: 'Closed', 4: 'Merged', 5: 'Reopened' }

function renderCell(col, val) {
  if (val === null || val === undefined) return <span style={{ color: '#484f58' }}>—</span>
  if (col === 'severity' && typeof val === 'number') {
    return <span style={{ color: SEVERITY_COLORS[val] || '#e6edf3', fontWeight: 600 }}>{val}</span>
  }
  if (col === 'state' && typeof val === 'number') {
    return <span style={{ color: val === 0 ? '#f85149' : val <= 2 ? '#e3b341' : '#3fb950' }}>{STATE_LABELS[val] || val}</span>
  }
  const s = String(val)
  if (s.length > 80) return <span title={s}>{s.slice(0, 80)}…</span>
  return s
}

export default function Search() {
  const [query, setQuery] = useState('source=edr_alerts | sort -report_time | head 20')
  const [timeRange, setTimeRange] = useState('-24h')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function run() {
    setLoading(true)
    setError('')
    try {
      const res = await api.post('/query', { query, time_range: timeRange, limit: 500 })
      setResult(res.data)
    } catch (e) {
      setError(e.response?.data?.detail || String(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h2 style={{ marginBottom: 12, fontSize: 18, fontWeight: 600 }}>Search</h2>

      {/* Example queries */}
      <div style={S.examples}>
        {EXAMPLE_QUERIES.map(ex => (
          <button key={ex.label} style={S.exBtn} onClick={() => setQuery(ex.query)} title={ex.query}>
            {ex.label}
          </button>
        ))}
      </div>

      <div style={S.queryBar}>
        <textarea
          style={S.textarea}
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={e => (e.ctrlKey || e.metaKey) && e.key === 'Enter' && run()}
          placeholder="source=edr_alerts severity >= 8 | sort -report_time | head 20"
          spellCheck={false}
        />
        <div style={S.controls}>
          <select style={S.select} value={timeRange} onChange={e => setTimeRange(e.target.value)}>
            {TIME_PRESETS.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <button style={S.btn()} onClick={run} disabled={loading}>
            {loading ? '查詢中…' : 'Run ▶'}
          </button>
        </div>
      </div>
      <div style={{ fontSize: 11, color: '#484f58', marginBottom: 12 }}>Ctrl+Enter 執行</div>

      {error && <div style={S.error}>{error}</div>}

      {result && (
        <>
          <div style={S.meta}>
            共 <strong style={{ color: '#e6edf3' }}>{result.total}</strong> 筆，查詢耗時 {result.duration_ms}ms
          </div>
          {result.sql && <div style={S.sqlBlock}>SQL: {result.sql}</div>}

          <div style={{ overflowX: 'auto', maxHeight: '60vh', overflowY: 'auto', border: '1px solid #21262d', borderRadius: 6 }}>
            <table style={S.table}>
              <thead>
                <tr>{result.columns.map(c => <th key={c} style={S.th}>{c}</th>)}</tr>
              </thead>
              <tbody>
                {result.rows.map((row, i) => (
                  <tr key={i} style={{ background: i % 2 === 0 ? 'transparent' : '#0d1117' }}>
                    {row.map((cell, j) => (
                      <td key={j} style={S.td}>
                        {renderCell(result.columns[j], cell)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}
