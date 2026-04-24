import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import App from './App.jsx'
import Login from './pages/Login.jsx'
import Search from './pages/Search.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Alerts from './pages/Alerts.jsx'
import Settings from './pages/Settings.jsx'

function PrivateRoute({ children }) {
  return localStorage.getItem('access_token') ? children : <Navigate to="/login" replace />
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <BrowserRouter>
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<PrivateRoute><App /></PrivateRoute>}>
        <Route index element={<Navigate to="/search" replace />} />
        <Route path="search" element={<Search />} />
        <Route path="dashboards" element={<Dashboard />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  </BrowserRouter>
)
