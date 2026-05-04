import React, { useEffect, useState } from 'react'
import ReactECharts from 'echarts-for-react'
import api from '../api/client.js'

const S = {
  header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, gap: 16 },
  headerRight: { display: 'flex', alignItems: 'center', gap: 14 },
  btn: { padding: '6px 16px', background: '#238636', border: 'none', borderRadius: 6, color: '#fff', fontSize: 13, cursor: 'pointer' },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(500px, 1fr))', gap: 16 },
  panel: { background: '#161b22', border: '1px solid #30363d', borderRadius: 8, padding: 16 },
  panelTitle: { fontSize: 14, fontWeight: 600, marginBottom: 12, color: '#e6edf3' },
  statsRow: { display: 'flex', gap: 12, marginBottom: 16 },
  statBox: { flex: 1, background: '#161b22', border: '1px solid #30363d', borderRadius: 8, padding: '14px 18px' },
  statNum: { fontSize: 28, fontWeight: 700 },
  statLabel: { fontSize: 12, color: '#8b949e', marginTop: 4 },
  diskBox: {
    display: 'flex', flexDirection: 'column', gap: 4,
    background: '#161b22', border: '1px solid #30363d', borderRadius: 6,
    padding: '6px 12px', minWidth: 200,
  },
  diskRow: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, fontSize: 12 },
  diskBar: { width: '100%', height: 4, background: '#21262d', borderRadius: 2, overflow: 'hidden' },
  diskBarFill: (color, pct) => ({ width: `${pct}%`, height: '100%', background: color, transition: 'width 0.3s' }),
}

const DISK_COLOR = { ok: '#3fb950', warn: '#e3b341', critical: '#f85149', unknown: '#8b949e' }
const DISK_ICON = { ok: '💾', warn: '⚠️', critical: '🚨', unknown: '❓' }

function DiskIndicator({ disk }) {
  if (!disk) return null
  const color = DISK_COLOR[disk.level] || DISK_COLOR.unknown
  const icon = DISK_ICON[disk.level] || DISK_ICON.unknown
  // Bar fills with USED %, color reflects FREE level
  const usedPct = Math.max(0, Math.min(100, 100 - disk.free_percent))
  return (
    <div
      style={S.diskBox}
      title={`${disk.path}\n總空間 ${disk.total_gb} GB\n已使用 ${disk.used_gb} GB\n剩餘 ${disk.free_gb} GB (${disk.free_percent}%)`}
    >
      <div style={S.diskRow}>
        <span style={{ color: '#8b949e' }}>{icon} 儲存空間剩餘</span>
        <span style={{ color, fontWeight: 700, fontSize: 13 }}>{disk.free_percent}%</span>
      </div>
      <div style={S.diskBar}>
        <div style={S.diskBarFill(color, usedPct)} />
      </div>
      <div style={{ ...S.diskRow, color: '#6e7681', fontSize: 11 }}>
        <span>已使用 {disk.used_gb} GB</span>
        <span>共 {disk.total_gb} GB</span>
      </div>
    </div>
  )
}

const PANELS = [
  { id: 'edr_trend', title: 'EDR 告警趨勢 (7天)', query: 'source=edr_alerts | timechart span=1d count', chart: 'line', time_range: '-7d' },
  { id: 'severity_dist', title: '告警嚴重度分布', query: 'source=edr_alerts | stats count by severity | sort -severity', chart: 'bar', time_range: '-30d' },
  { id: 'incident_state', title: '事件狀態分布', query: 'source=incidents | stats count by state', chart: 'pie', time_range: '-30d' },
  { id: 'top_hosts', title: '高風險端點 Top 10', query: 'source=incidents | stats count by computer_name | sort -count | head 10', chart: 'bar', time_range: '-30d' },
  { id: 'malware_trend', title: '惡意程式偵測趨勢', query: 'source=edr_alerts | timechart span=1d sum(malware_count) as malware', chart: 'line', time_range: '-14d' },
  { id: 'cyber_reports', title: 'Cyber 報表 (最新)', query: 'source=cyber_reports | fields report_id, severity, scanned_endpoints, suspicious_endpoints, ingested_at | sort -ingested_at | head 5', chart: 'table', time_range: '-30d' },
]

const STAT_QUERIES = [
  { id: 'edr', label: 'EDR Alerts (24h)', query: 'source=edr_alerts | stats count', color: '#f85149' },
  { id: 'incidents', label: '未解決事件', query: 'source=incidents state = 0 | stats count', color: '#e3b341' },
  { id: 'cyber', label: 'Cyber Reports (7d)', query: 'source=cyber_reports | stats count', color: '#79c0ff' },
  { id: 'malware', label: '惡意程式偵測 (24h)', query: 'source=edr_alerts | stats sum(malware_count) as total', color: '#bc8cff' },
]

const STATE_LABELS = { 0: 'InProgress', 1: 'Investigated', 2: 'Confirmed', 3: 'Closed', 4: 'Merged', 5: 'Reopened' }

function PanelChart({ panel, data }) {
  if (!data) return <div style={{ color: '#484f58', padding: 20, textAlign: 'center' }}>Loading…</div>
  if (data.status === 'error') return <div style={{ color: '#f85149', fontSize: 12 }}>{data.error}</div>
  const { columns, rows } = data

  if (panel.chart === 'line') {
    const timeIdx = 0
    const valIdx = columns.length - 1
    const option = {
      backgroundColor: 'transparent',
      grid: { top: 10, bottom: 30, left: 50, right: 10 },
      xAxis: { type: 'category', data: rows.map(r => r[timeIdx]?.toString().slice(0, 10) || ''), axisLabel: { color: '#8b949e', fontSize: 10 } },
      yAxis: { type: 'value', axisLabel: { color: '#8b949e', fontSize: 10 }, minInterval: 1 },
      series: [{ type: 'line', data: rows.map(r => r[valIdx] ?? 0), smooth: true, areaStyle: { opacity: 0.15 }, lineStyle: { color: '#58a6ff' }, itemStyle: { color: '#58a6ff' } }],
      tooltip: { trigger: 'axis' },
    }
    return <ReactECharts option={option} style={{ height: 200 }} />
  }

  if (panel.chart === 'bar') {
    const nameIdx = 0
    const valIdx = columns.indexOf('count') >= 0 ? columns.indexOf('count') : columns.length - 1
    const option = {
      backgroundColor: 'transparent',
      grid: { top: 10, bottom: 50, left: 60, right: 10 },
      xAxis: { type: 'category', data: rows.map(r => r[nameIdx] === null ? '—' : String(r[nameIdx])), axisLabel: { color: '#8b949e', fontSize: 10, rotate: 20 } },
      yAxis: { type: 'value', axisLabel: { color: '#8b949e', fontSize: 10 }, minInterval: 1 },
      series: [{ type: 'bar', data: rows.map(r => r[valIdx] ?? 0), itemStyle: { color: '#388bfd' } }],
      tooltip: { trigger: 'axis' },
    }
    return <ReactECharts option={option} style={{ height: 200 }} />
  }

  if (panel.chart === 'pie') {
    const nameIdx = 0
    const valIdx = columns.indexOf('count') >= 0 ? columns.indexOf('count') : columns.length - 1
    const labels = { 0: 'InProgress', 1: 'Investigated', 2: 'Confirmed', 3: 'Closed', 4: 'Merged', 5: 'Reopened' }
    const option = {
      backgroundColor: 'transparent',
      color: ['#f85149', '#e3b341', '#3fb950', '#8b949e', '#79c0ff', '#bc8cff'],
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      legend: { orient: 'vertical', right: 10, textStyle: { color: '#8b949e', fontSize: 11 } },
      series: [{ type: 'pie', radius: ['35%', '60%'], data: rows.map(r => ({ name: labels[r[nameIdx]] ?? String(r[nameIdx] ?? '—'), value: r[valIdx] ?? 0 })) }],
    }
    return <ReactECharts option={option} style={{ height: 200 }} />
  }

  // Table fallback
  return (
    <div style={{ overflowX: 'auto', maxHeight: 200, overflowY: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
        <thead>
          <tr>{columns.map(c => <th key={c} style={{ padding: '4px 8px', background: '#0d1117', color: '#8b949e', textAlign: 'left', position: 'sticky', top: 0 }}>{c}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j} style={{ padding: '4px 8px', borderBottom: '1px solid #21262d' }}>{String(c ?? '—')}</td>)}</tr>)}
        </tbody>
      </table>
    </div>
  )
}

export default function Dashboard() {
  const [panelData, setPanelData] = useState({})
  const [stats, setStats] = useState({})
  const [disk, setDisk] = useState(null)
  const [customer, setCustomer] = useState(null)
  const [loading, setLoading] = useState(false)

  async function loadAll() {
    setLoading(true)
    const [statsResults, panelResults, statusRes] = await Promise.all([
      Promise.all(STAT_QUERIES.map(async sq => {
        try {
          const res = await api.post('/query', { query: sq.query, time_range: '-24h', limit: 1 })
          const val = res.data.rows?.[0]?.[0] ?? 0
          return [sq.id, { value: val, color: sq.color, label: sq.label }]
        } catch { return [sq.id, { value: '—', color: '#8b949e', label: sq.label }] }
      })),
      Promise.all(PANELS.map(async p => {
        try {
          const res = await api.post('/query', { query: p.query, time_range: p.time_range, limit: 100 })
          return [p.id, { status: 'ok', ...res.data }]
        } catch (e) {
          return [p.id, { status: 'error', error: e.response?.data?.detail || String(e) }]
        }
      })),
      api.get('/system/status').then(r => r.data).catch(() => null),
    ])
    setStats(Object.fromEntries(statsResults))
    setPanelData(Object.fromEntries(panelResults))
    setDisk(statusRes?.disk || null)
    setCustomer(statusRes?.customer || null)
    setLoading(false)
  }

  useEffect(() => { loadAll() }, [])

  return (
    <div>
      <div style={S.header}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, flexWrap: 'wrap' }}>
          <h2 style={{ fontSize: 18, fontWeight: 600, margin: 0 }}>Dashboard</h2>
          {customer && (customer.name || customer.key_short) && (
            <span
              style={{
                fontSize: 13, color: '#79c0ff', fontWeight: 500,
                background: '#0d1117', border: '1px solid #1f6feb',
                padding: '2px 10px', borderRadius: 12,
              }}
              title={customer.key ? `customer_key: ${customer.key}` : ''}
            >
              🏢 {customer.name || `(尚未拉到事件 — ${customer.key_short})`}
            </span>
          )}
        </div>
        <div style={S.headerRight}>
          <DiskIndicator disk={disk} />
          <button style={S.btn} onClick={loadAll} disabled={loading}>{loading ? '重新整理…' : '重新整理'}</button>
        </div>
      </div>

      {/* Stats row */}
      <div style={S.statsRow}>
        {STAT_QUERIES.map(sq => {
          const s = stats[sq.id]
          return (
            <div key={sq.id} style={S.statBox}>
              <div style={{ ...S.statNum, color: s?.color || '#e6edf3' }}>{s?.value ?? '…'}</div>
              <div style={S.statLabel}>{sq.label}</div>
            </div>
          )
        })}
      </div>

      {/* Charts */}
      <div style={S.grid}>
        {PANELS.map(p => (
          <div key={p.id} style={S.panel}>
            <div style={S.panelTitle}>{p.title}</div>
            <PanelChart panel={p} data={panelData[p.id]} />
          </div>
        ))}
      </div>
    </div>
  )
}
