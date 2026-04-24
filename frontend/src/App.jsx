import React from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'

const S = {
  layout: { display: 'flex', height: '100vh', overflow: 'hidden' },
  sidebar: {
    width: 220, background: '#161b22', borderRight: '1px solid #30363d',
    display: 'flex', flexDirection: 'column', padding: '16px 0',
  },
  logo: { padding: '0 20px 20px', fontSize: 18, fontWeight: 700, color: '#58a6ff', borderBottom: '1px solid #30363d', marginBottom: 12 },
  nav: { display: 'flex', flexDirection: 'column', gap: 4, padding: '0 8px' },
  link: (active) => ({
    display: 'block', padding: '8px 12px', borderRadius: 6, textDecoration: 'none',
    color: active ? '#e6edf3' : '#8b949e', background: active ? '#21262d' : 'transparent',
    fontWeight: active ? 600 : 400, fontSize: 14,
  }),
  main: { flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column' },
  topbar: {
    padding: '10px 20px', borderBottom: '1px solid #30363d',
    display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 12,
    background: '#161b22',
  },
  logoutBtn: {
    background: 'none', border: '1px solid #30363d', color: '#8b949e',
    padding: '4px 12px', borderRadius: 6, cursor: 'pointer', fontSize: 13,
  },
  content: { flex: 1, padding: 20 },
}

export default function App() {
  const navigate = useNavigate()
  const user = (() => {
    try { return JSON.parse(atob(localStorage.getItem('access_token').split('.')[1])).username } catch { return 'user' }
  })()

  function logout() {
    localStorage.clear()
    navigate('/login')
  }

  return (
    <div style={S.layout}>
      <aside style={S.sidebar}>
        <div style={S.logo}>XCockpit SIEM</div>
        <nav style={S.nav}>
          {[['search', 'Search'], ['dashboards', 'Dashboards'], ['alerts', 'Alerts'], ['settings', '設定']].map(([path, label]) => (
            <NavLink key={path} to={`/${path}`} style={({ isActive }) => S.link(isActive)}>
              {label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div style={S.main}>
        <div style={S.topbar}>
          <span style={{ fontSize: 13, color: '#8b949e' }}>{user}</span>
          <button style={S.logoutBtn} onClick={logout}>Logout</button>
        </div>
        <div style={S.content}>
          <Outlet />
        </div>
      </div>
    </div>
  )
}
