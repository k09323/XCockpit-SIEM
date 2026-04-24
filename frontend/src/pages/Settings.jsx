import React, { useEffect, useState } from 'react'
import api from '../api/client.js'

const S = {
  section: { marginBottom: 32 },
  h3: { fontSize: 15, fontWeight: 600, marginBottom: 14, color: '#e6edf3', borderBottom: '1px solid #30363d', paddingBottom: 8 },
  form: { display: 'flex', flexDirection: 'column', gap: 10, maxWidth: 380 },
  label: { fontSize: 13, color: '#8b949e', marginBottom: 3 },
  input: {
    padding: '8px 12px', background: '#0d1117', border: '1px solid #30363d',
    borderRadius: 6, color: '#e6edf3', fontSize: 13, width: '100%',
  },
  row: { display: 'flex', gap: 8, alignItems: 'center' },
  btn: (color = '#238636') => ({
    padding: '7px 18px', background: color, border: 'none',
    borderRadius: 6, color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer',
  }),
  msg: (ok) => ({
    padding: '8px 12px', borderRadius: 6, fontSize: 13,
    background: ok ? '#0f2d16' : '#2d1b1b',
    border: `1px solid ${ok ? '#238636' : '#5c2626'}`,
    color: ok ? '#3fb950' : '#f85149',
  }),
  table: { width: '100%', borderCollapse: 'collapse', fontSize: 13 },
  th: { padding: '8px 12px', textAlign: 'left', background: '#161b22', borderBottom: '1px solid #30363d', color: '#8b949e', fontWeight: 500 },
  td: { padding: '8px 12px', borderBottom: '1px solid #21262d', verticalAlign: 'middle' },
  roleBadge: (role) => ({
    display: 'inline-block', padding: '2px 8px', borderRadius: 10, fontSize: 11, fontWeight: 600,
    background: role === 'admin' ? '#2d1f3d' : role === 'analyst' ? '#1a2d1f' : '#1a2233',
    color: role === 'admin' ? '#bc8cff' : role === 'analyst' ? '#3fb950' : '#79c0ff',
  }),
  select: {
    padding: '7px 10px', background: '#0d1117', border: '1px solid #30363d',
    borderRadius: 6, color: '#e6edf3', fontSize: 13,
  },
}

function getRole() {
  try { return JSON.parse(atob(localStorage.getItem('access_token').split('.')[1])).role } catch { return '' }
}
function getUserId() {
  try { return JSON.parse(atob(localStorage.getItem('access_token').split('.')[1])).sub } catch { return '' }
}

// ── Change Password ──────────────────────────────────────────────────────────
function ChangePassword() {
  const [form, setForm] = useState({ current_password: '', new_password: '', confirm: '' })
  const [msg, setMsg] = useState(null)
  const [loading, setLoading] = useState(false)

  async function submit(e) {
    e.preventDefault()
    if (form.new_password !== form.confirm) {
      setMsg({ ok: false, text: '新密碼與確認密碼不一致' }); return
    }
    setLoading(true); setMsg(null)
    try {
      await api.put('/auth/password', { current_password: form.current_password, new_password: form.new_password })
      setMsg({ ok: true, text: '密碼已更新，請重新登入' })
      setTimeout(() => { localStorage.clear(); window.location.href = '/login' }, 1500)
    } catch (e) {
      setMsg({ ok: false, text: e.response?.data?.detail || String(e) })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={S.section}>
      <div style={S.h3}>修改密碼</div>
      <form style={S.form} onSubmit={submit}>
        {[
          ['current_password', '目前密碼', 'password'],
          ['new_password', '新密碼（至少 6 字元）', 'password'],
          ['confirm', '確認新密碼', 'password'],
        ].map(([key, label, type]) => (
          <div key={key}>
            <div style={S.label}>{label}</div>
            <input
              style={S.input} type={type} required
              value={form[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
            />
          </div>
        ))}
        {msg && <div style={S.msg(msg.ok)}>{msg.text}</div>}
        <div>
          <button style={S.btn()} type="submit" disabled={loading}>
            {loading ? '更新中…' : '更新密碼'}
          </button>
        </div>
      </form>
    </div>
  )
}

// ── User Management (admin only) ─────────────────────────────────────────────
function UserManagement() {
  const [users, setUsers] = useState([])
  const [form, setForm] = useState({ username: '', password: '', role: 'analyst' })
  const [msg, setMsg] = useState(null)
  const [loading, setLoading] = useState(false)
  const myId = getUserId()

  async function loadUsers() {
    try {
      const res = await api.get('/auth/users')
      setUsers(res.data)
    } catch { }
  }

  useEffect(() => { loadUsers() }, [])

  async function createUser(e) {
    e.preventDefault()
    setLoading(true); setMsg(null)
    try {
      await api.post('/auth/users', form)
      setMsg({ ok: true, text: `帳號 "${form.username}" 建立成功` })
      setForm({ username: '', password: '', role: 'analyst' })
      loadUsers()
    } catch (e) {
      setMsg({ ok: false, text: e.response?.data?.detail || String(e) })
    } finally {
      setLoading(false)
    }
  }

  async function deleteUser(id, username) {
    if (!confirm(`確定刪除帳號 "${username}"？`)) return
    try {
      await api.delete(`/auth/users/${id}`)
      loadUsers()
    } catch (e) {
      alert(e.response?.data?.detail || String(e))
    }
  }

  return (
    <div style={S.section}>
      <div style={S.h3}>帳號管理</div>

      {/* User list */}
      <div style={{ overflowX: 'auto', marginBottom: 24 }}>
        <table style={S.table}>
          <thead>
            <tr>
              {['帳號', '角色', '建立時間', '最後登入', ''].map(h => <th key={h} style={S.th}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {users.map(u => (
              <tr key={u.id}>
                <td style={S.td}>{u.username}{u.id === myId && <span style={{ color: '#8b949e', fontSize: 11, marginLeft: 6 }}>(我)</span>}</td>
                <td style={S.td}><span style={S.roleBadge(u.role)}>{u.role}</span></td>
                <td style={S.td}>{u.created_at?.slice(0, 16).replace('T', ' ') || '—'}</td>
                <td style={S.td}>{u.last_login?.slice(0, 16).replace('T', ' ') || '從未登入'}</td>
                <td style={S.td}>
                  {u.id !== myId && (
                    <button
                      style={{ ...S.btn('#b62324'), fontSize: 12, padding: '4px 10px' }}
                      onClick={() => deleteUser(u.id, u.username)}
                    >刪除</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Create user form */}
      <div style={S.h3}>新增帳號</div>
      <form style={S.form} onSubmit={createUser}>
        <div>
          <div style={S.label}>帳號名稱</div>
          <input style={S.input} required value={form.username}
            onChange={e => setForm(f => ({ ...f, username: e.target.value }))} />
        </div>
        <div>
          <div style={S.label}>密碼（至少 6 字元）</div>
          <input style={S.input} type="password" required value={form.password}
            onChange={e => setForm(f => ({ ...f, password: e.target.value }))} />
        </div>
        <div>
          <div style={S.label}>角色</div>
          <select style={S.select} value={form.role}
            onChange={e => setForm(f => ({ ...f, role: e.target.value }))}>
            <option value="admin">admin（管理員）</option>
            <option value="analyst">analyst（分析師）</option>
            <option value="viewer">viewer（唯讀）</option>
          </select>
        </div>
        {msg && <div style={S.msg(msg.ok)}>{msg.text}</div>}
        <div>
          <button style={S.btn()} type="submit" disabled={loading}>
            {loading ? '建立中…' : '建立帳號'}
          </button>
        </div>
      </form>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────
export default function Settings() {
  const role = getRole()
  return (
    <div>
      <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 24 }}>設定</h2>
      <ChangePassword />
      {role === 'admin' && <UserManagement />}
      {role !== 'admin' && (
        <div style={{ color: '#8b949e', fontSize: 13 }}>
          帳號管理功能僅限 admin 角色使用。
        </div>
      )}
    </div>
  )
}
