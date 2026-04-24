import React, { useEffect, useState } from 'react'
import api from '../api/client.js'

const SEVERITY_COLOR = { critical: '#f85149', high: '#e3b341', medium: '#d29922', low: '#3fb950', info: '#79c0ff' }
const STATUS_COLOR = { open: '#f85149', acknowledged: '#e3b341', resolved: '#3fb950' }

const S = {
  tabs: { display: 'flex', gap: 0, borderBottom: '1px solid #30363d', marginBottom: 16 },
  tab: (active) => ({
    padding: '8px 20px', background: 'none', border: 'none',
    borderBottom: active ? '2px solid #58a6ff' : '2px solid transparent',
    color: active ? '#e6edf3' : '#8b949e', cursor: 'pointer', fontSize: 14,
  }),
  card: { background: '#161b22', border: '1px solid #30363d', borderRadius: 8, padding: 16, marginBottom: 10 },
  cardRow: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 },
  badge: (color) => ({ display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600, background: color + '22', color }),
  label: { fontSize: 12, color: '#8b949e', marginBottom: 2 },
  code: { fontFamily: 'monospace', fontSize: 12, background: '#0d1117', padding: '6px 10px', borderRadius: 4, color: '#79c0ff' },
  btn: (color) => ({ padding: '4px 12px', background: 'none', border: `1px solid ${color}`, borderRadius: 4, color, cursor: 'pointer', fontSize: 12 }),
  addBtn: { padding: '6px 16px', background: '#238636', border: 'none', borderRadius: 6, color: '#fff', fontSize: 13, cursor: 'pointer' },
}

function IncidentCard({ incident, onUpdate }) {
  return (
    <div style={S.card}>
      <div style={S.cardRow}>
        <div>
          <strong style={{ fontSize: 14 }}>{incident.rule_name || incident.rule_id}</strong>
          <span style={{ ...S.badge(STATUS_COLOR[incident.status] || '#8b949e'), marginLeft: 8 }}>{incident.status}</span>
        </div>
        <div style={{ fontSize: 12, color: '#8b949e' }}>{new Date(incident.triggered_at).toLocaleString()}</div>
      </div>
      {incident.metric_value != null && (
        <div style={{ fontSize: 13, color: '#e3b341', marginBottom: 6 }}>Metric: {incident.metric_value}</div>
      )}
      <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
        {incident.status === 'open' && (
          <button style={S.btn('#e3b341')} onClick={() => onUpdate(incident.id, 'acknowledge')}>Acknowledge</button>
        )}
        {incident.status !== 'resolved' && (
          <button style={S.btn('#3fb950')} onClick={() => onUpdate(incident.id, 'resolve')}>Resolve</button>
        )}
      </div>
    </div>
  )
}

function RuleCard({ rule, onToggle }) {
  return (
    <div style={S.card}>
      <div style={S.cardRow}>
        <div>
          <strong style={{ fontSize: 14 }}>{rule.name}</strong>
          <span style={{ ...S.badge(SEVERITY_COLOR[rule.severity] || '#8b949e'), marginLeft: 8 }}>{rule.severity}</span>
          {!rule.enabled && <span style={{ ...S.badge('#8b949e'), marginLeft: 6 }}>disabled</span>}
        </div>
        <button style={S.btn(rule.enabled ? '#f85149' : '#3fb950')} onClick={() => onToggle(rule.id)}>
          {rule.enabled ? 'Disable' : 'Enable'}
        </button>
      </div>
      {rule.description && <div style={{ fontSize: 13, color: '#8b949e', marginBottom: 8 }}>{rule.description}</div>}
      <div style={S.label}>Query</div>
      <div style={S.code}>{rule.query}</div>
      <div style={{ fontSize: 12, color: '#8b949e', marginTop: 6 }}>
        Condition: <strong style={{ color: '#e6edf3' }}>{rule.condition}</strong>
        &nbsp;· Throttle: {rule.throttle_mins}m
      </div>
    </div>
  )
}

export default function Alerts() {
  const [tab, setTab] = useState('incidents')
  const [incidents, setIncidents] = useState([])
  const [rules, setRules] = useState([])

  async function loadIncidents() {
    const res = await api.get('/alerts/incidents')
    setIncidents(res.data)
  }
  async function loadRules() {
    const res = await api.get('/alerts/rules')
    setRules(res.data)
  }

  useEffect(() => { loadIncidents(); loadRules() }, [])

  async function handleIncidentAction(id, action) {
    await api.post(`/alerts/incidents/${id}/${action}`)
    loadIncidents()
  }

  async function handleToggleRule(id) {
    await api.patch(`/alerts/rules/${id}/toggle`)
    loadRules()
  }

  return (
    <div>
      <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>Alerts</h2>
      <div style={S.tabs}>
        <button style={S.tab(tab === 'incidents')} onClick={() => setTab('incidents')}>
          Incidents ({incidents.filter(i => i.status === 'open').length} open)
        </button>
        <button style={S.tab(tab === 'rules')} onClick={() => setTab('rules')}>
          Rules ({rules.length})
        </button>
      </div>

      {tab === 'incidents' && (
        incidents.length === 0
          ? <div style={{ color: '#8b949e', textAlign: 'center', paddingTop: 40 }}>No incidents</div>
          : incidents.map(i => <IncidentCard key={i.id} incident={i} onUpdate={handleIncidentAction} />)
      )}

      {tab === 'rules' && (
        rules.length === 0
          ? <div style={{ color: '#8b949e', textAlign: 'center', paddingTop: 40 }}>No rules configured</div>
          : rules.map(r => <RuleCard key={r.id} rule={r} onToggle={handleToggleRule} />)
      )}
    </div>
  )
}
