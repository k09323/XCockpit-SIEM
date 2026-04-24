import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

const S = {
  page: { display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: '#0d1117' },
  box: { background: '#161b22', border: '1px solid #30363d', borderRadius: 12, padding: 40, width: 360 },
  title: { fontSize: 24, fontWeight: 700, color: '#58a6ff', marginBottom: 8, textAlign: 'center' },
  sub: { color: '#8b949e', fontSize: 13, textAlign: 'center', marginBottom: 28 },
  label: { display: 'block', fontSize: 13, color: '#8b949e', marginBottom: 6 },
  input: {
    width: '100%', padding: '8px 12px', background: '#0d1117', border: '1px solid #30363d',
    borderRadius: 6, color: '#e6edf3', fontSize: 14, marginBottom: 16,
  },
  btn: {
    width: '100%', padding: '10px', background: '#238636', border: 'none',
    borderRadius: 6, color: '#fff', fontSize: 15, fontWeight: 600, cursor: 'pointer',
  },
  err: { color: '#f85149', fontSize: 13, marginTop: 12, textAlign: 'center' },
}

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  async function handleSubmit(e) {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await axios.post('/api/auth/login', { username, password })
      localStorage.setItem('access_token', res.data.access_token)
      localStorage.setItem('refresh_token', res.data.refresh_token)
      navigate('/search')
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={S.page}>
      <form style={S.box} onSubmit={handleSubmit}>
        <div style={S.title}>XCockpit SIEM</div>
        <div style={S.sub}>Security Analytics Platform</div>
        <label style={S.label}>Username</label>
        <input style={S.input} value={username} onChange={e => setUsername(e.target.value)} autoFocus />
        <label style={S.label}>Password</label>
        <input style={S.input} type="password" value={password} onChange={e => setPassword(e.target.value)} />
        <button style={S.btn} type="submit" disabled={loading}>{loading ? 'Signing in...' : 'Sign In'}</button>
        {error && <div style={S.err}>{error}</div>}
      </form>
    </div>
  )
}
