import { Layout, Menu, Switch } from 'antd'
import {
  DashboardOutlined,
  DatabaseOutlined,
  FileTextOutlined,
  LogoutOutlined,
  SettingOutlined,
  TeamOutlined,
} from '@ant-design/icons'
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import DashboardPage from './pages/DashboardPage'
import DbPage from './pages/DbPage'
import LoginPage from './pages/LoginPage'
import LogsPage from './pages/LogsPage'
import SettingsPage from './pages/SettingsPage'
import UsersPage from './pages/UsersPage'
import { useTheme } from './theme'
import { tokens } from './api'

function RequireAuth({ children }: { children: React.ReactNode }) {
  if (!tokens.access) return <Navigate to="/login" replace />
  return <>{children}</>
}

function Shell({ children }: { children: React.ReactNode }) {
  const nav = useNavigate()
  const loc = useLocation()
  const { mode, toggle } = useTheme()
  const selected =
    loc.pathname.startsWith('/users') ? ['users']
    : loc.pathname.startsWith('/db') ? ['db']
    : loc.pathname.startsWith('/logs') ? ['logs']
    : loc.pathname.startsWith('/settings') ? ['settings']
    : loc.pathname.startsWith('/login') ? []
    : ['dashboard']

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Layout.Sider theme="dark" width={200}>
        <div
          style={{
            color: '#fff',
            padding: '18px 16px',
            fontWeight: 600,
            fontSize: 16,
          }}
        >
          Rovortex Admin
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={selected}
          items={[
            { key: 'dashboard', icon: <DashboardOutlined />, label: '仪表盘' },
            { key: 'users', icon: <TeamOutlined />, label: '用户管理' },
            { key: 'logs', icon: <FileTextOutlined />, label: '日志' },
            { key: 'db', icon: <DatabaseOutlined />, label: '数据库' },
            { key: 'settings', icon: <SettingOutlined />, label: '服务配置' },
          ]}
          onClick={({ key }) => nav(key === 'dashboard' ? '/' : `/${key}`)}
        />
        <Menu
          theme="dark"
          mode="inline"
          selectable={false}
          style={{ position: 'absolute', bottom: 48, width: 200 }}
          items={[{ key: 'logout', icon: <LogoutOutlined />, label: '退出登录' }]}
          onClick={() => {
            tokens.clear()
            nav('/login')
          }}
        />
        <div
          style={{
            position: 'absolute',
            bottom: 0,
            width: 200,
            padding: '12px 16px',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <span style={{ color: 'rgba(255,255,255,0.65)', fontSize: 12 }}>暗色</span>
          <Switch size="small" checked={mode === 'dark'} onChange={toggle} />
        </div>
      </Layout.Sider>
      <Layout.Content style={{ padding: 24 }}>{children}</Layout.Content>
    </Layout>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <Shell>
              <DashboardPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/users"
        element={
          <RequireAuth>
            <Shell>
              <UsersPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/db"
        element={
          <RequireAuth>
            <Shell>
              <DbPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/logs"
        element={
          <RequireAuth>
            <Shell>
              <LogsPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/settings"
        element={
          <RequireAuth>
            <Shell>
              <SettingsPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
