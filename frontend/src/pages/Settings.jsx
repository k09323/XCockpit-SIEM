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

// ── XCockpit Connection (admin only) ─────────────────────────────────────────
function XCockpitConfig() {
  const [form, setForm] = useState({ base_url: '', customer_key: '', api_key: '' })
  const [saved, setSaved] = useState({ api_key_masked: '', api_key_set: false, customer_key: '' })
  const [clearOnSwitch, setClearOnSwitch] = useState(true)
  const [msg, setMsg] = useState(null)
  const [loading, setLoading] = useState(false)
  const [testing, setTesting] = useState(false)

  async function load() {
    try {
      const res = await api.get('/system/xcockpit-config')
      setForm({
        base_url: res.data.base_url || '',
        customer_key: res.data.customer_key || '',
        api_key: '', // never pre-fill — user types only when changing
      })
      setSaved({
        api_key_masked: res.data.api_key_masked,
        api_key_set: res.data.api_key_set,
        customer_key: res.data.customer_key || '',
      })
    } catch { }
  }

  useEffect(() => { load() }, [])

  const customerChanging = saved.customer_key && form.customer_key && form.customer_key !== saved.customer_key

  async function test() {
    setTesting(true); setMsg(null)
    try {
      const res = await api.put('/system/xcockpit-config', { ...form, test_only: true })
      setMsg({ ok: res.data.ok, text: res.data.message })
    } catch (e) {
      setMsg({ ok: false, text: e.response?.data?.detail || String(e) })
    } finally {
      setTesting(false)
    }
  }

  async function save(e) {
    e.preventDefault()
    if (customerChanging && clearOnSwitch) {
      if (!confirm(
        `將切換 customer_key 為「${form.customer_key}」。\n\n` +
        `本地將清空：edr_alerts / cyber_reports / incidents / activity_logs。\n` +
        `Pull cursors 將重置，新客戶資料會在下一個 pull cycle (≤ 2 分鐘) 開始拉取。\n\n` +
        `確定要繼續？`
      )) return
    }
    setLoading(true); setMsg(null)
    try {
      const res = await api.put('/system/xcockpit-config', {
        ...form,
        clear_data_on_customer_change: clearOnSwitch,
      })
      let text
      if (res.data.customer_changed) {
        const cleared = res.data.cleared_rows
        if (cleared) {
          const total = Object.entries(cleared)
            .filter(([k]) => k !== 'pull_cursors')
            .reduce((s, [, n]) => s + (n > 0 ? n : 0), 0)
          text = `已切換 customer_key，清空 ${total} 筆舊資料、重置 cursors。新客戶 pull 已觸發。`
        } else {
          text = `已切換 customer_key，重置 ${res.data.cursors_reset} 個 cursor。舊資料保留。`
        }
        if (!res.data.verified) text += `（注意：連線驗證失敗 — ${res.data.message}）`
      } else {
        text = res.data.verified
          ? `儲存成功，連線驗證通過：${res.data.message}`
          : `已儲存，但連線驗證失敗：${res.data.message}`
      }
      setMsg({ ok: res.data.verified, text })
      setForm(f => ({ ...f, api_key: '' })) // clear typed key after save
      load()
    } catch (e) {
      setMsg({ ok: false, text: e.response?.data?.detail || String(e) })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={S.section}>
      <div style={S.h3}>XCockpit 連線設定</div>
      <form style={S.form} onSubmit={save}>
        <div>
          <div style={S.label}>XCOCKPIT_URL</div>
          <input
            style={S.input} type="url" required
            placeholder="https://xcockpit.cycraft.ai"
            value={form.base_url}
            onChange={e => setForm(f => ({ ...f, base_url: e.target.value }))}
          />
        </div>
        <div>
          <div style={S.label}>XCOCKPIT_CUSTOMER_KEY</div>
          <input
            style={S.input} required
            placeholder="例：3a7b1c8d…（XCockpit 提供）"
            value={form.customer_key}
            onChange={e => setForm(f => ({ ...f, customer_key: e.target.value }))}
          />
        </div>
        <div>
          <div style={S.label}>
            XCOCKPIT_API_KEY
            {saved.api_key_set && (
              <span style={{ color: '#3fb950', marginLeft: 8, fontSize: 11 }}>
                目前：{saved.api_key_masked}（留空＝不變更）
              </span>
            )}
          </div>
          <input
            style={S.input} type="password" autoComplete="new-password"
            placeholder={saved.api_key_set ? '••••••••（不修改就留空）' : 'XCockpit → Security → Create API Token'}
            value={form.api_key}
            onChange={e => setForm(f => ({ ...f, api_key: e.target.value }))}
          />
          <div style={{ fontSize: 11, color: '#6e7681', marginTop: 4 }}>
            Header 格式：<code style={{ color: '#79c0ff' }}>Authorization: Token &lt;API_KEY&gt;</code>
            。儲存後下一次 pull cycle（≤ 2 分鐘）會自動套用新值，免重啟服務。
          </div>
        </div>

        {customerChanging && (
          <div style={{
            background: '#2d1b1b', border: '1px solid #5c2626', borderRadius: 6,
            padding: '10px 12px', fontSize: 12, color: '#f0c674',
          }}>
            ⚠️ 偵測到 customer_key 變更：<code>{saved.customer_key}</code> → <code>{form.customer_key}</code>
            <label style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 8, color: '#e6edf3' }}>
              <input
                type="checkbox"
                checked={clearOnSwitch}
                onChange={e => setClearOnSwitch(e.target.checked)}
              />
              <span>儲存時清空舊客戶的本地資料（推薦）</span>
            </label>
            <div style={{ fontSize: 11, color: '#8b949e', marginTop: 6, lineHeight: 1.5 }}>
              不勾選 → 只重置 pull cursors，舊資料保留（會跟新客戶資料混在一起）。<br/>
              勾選 → 清空 edr_alerts / cyber_reports / incidents / activity_logs，新客戶從零開始。
            </div>
          </div>
        )}

        {msg && <div style={S.msg(msg.ok)}>{msg.text}</div>}
        <div style={{ display: 'flex', gap: 8 }}>
          <button style={S.btn()} type="submit" disabled={loading || testing}>
            {loading ? '儲存中…' : '儲存'}
          </button>
          <button
            style={{ ...S.btn('#1f6feb') }} type="button"
            onClick={test} disabled={loading || testing}
          >
            {testing ? '測試中…' : '測試連線'}
          </button>
        </div>
      </form>
    </div>
  )
}

// ── System Settings (admin only) ─────────────────────────────────────────────
function SystemSettings() {
  const [hours, setHours] = useState(24)
  const [bounds, setBounds] = useState({ min: 1, max: 720 })
  const [msg, setMsg] = useState(null)
  const [loading, setLoading] = useState(false)

  async function load() {
    try {
      const res = await api.get('/auth/system-settings')
      setHours(res.data.session_hours)
      setBounds({ min: res.data.session_hours_min, max: res.data.session_hours_max })
    } catch { }
  }

  useEffect(() => { load() }, [])

  async function save(e) {
    e.preventDefault()
    setLoading(true); setMsg(null)
    try {
      const res = await api.put('/auth/system-settings', { session_hours: Number(hours) })
      setMsg({ ok: true, text: `登入有效時間已更新為 ${res.data.session_hours} 小時（下次登入起生效）` })
    } catch (e) {
      setMsg({ ok: false, text: e.response?.data?.detail || String(e) })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={S.section}>
      <div style={S.h3}>系統設定</div>
      <form style={S.form} onSubmit={save}>
        <div>
          <div style={S.label}>登入有效時間（小時）</div>
          <input
            style={S.input} type="number"
            min={bounds.min} max={bounds.max} required
            value={hours}
            onChange={e => setHours(e.target.value)}
          />
          <div style={{ fontSize: 11, color: '#6e7681', marginTop: 4 }}>
            範圍 {bounds.min}–{bounds.max} 小時。預設 24 小時。
            修改後僅對「下次登入」生效，目前已登入的 session 不受影響。
          </div>
        </div>
        {msg && <div style={S.msg(msg.ok)}>{msg.text}</div>}
        <div>
          <button style={S.btn()} type="submit" disabled={loading}>
            {loading ? '儲存中…' : '儲存'}
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
      {role === 'admin' && <XCockpitConfig />}
      {role === 'admin' && <SystemSettings />}
      {role === 'admin' && <UserManagement />}
      {role !== 'admin' && (
        <div style={{ color: '#8b949e', fontSize: 13 }}>
          帳號管理、XCockpit 連線設定與系統設定功能僅限 admin 角色使用。
        </div>
      )}
    </div>
  )
}
