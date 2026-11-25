import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { App as AntApp, ConfigProvider, theme } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { ThemeProvider, useTheme } from './theme'
import './index.css'
import App from './App.tsx'

function ThemedConfig({ children }: { children: React.ReactNode }) {
  const { mode } = useTheme()
  return (
    <ConfigProvider
      locale={zhCN}
      theme={{
        algorithm: mode === 'dark' ? theme.darkAlgorithm : theme.defaultAlgorithm,
      }}
    >
      {children}
    </ConfigProvider>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider>
      <ThemedConfig>
        <AntApp>
          <BrowserRouter basename="/admin">
            <App />
          </BrowserRouter>
        </AntApp>
      </ThemedConfig>
    </ThemeProvider>
  </StrictMode>,
)
