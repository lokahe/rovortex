import { Button, Card, Form, Input, Typography, App as AntApp } from 'antd'
import { useNavigate } from 'react-router-dom'
import { apiError, login, tokens } from '../api'
import { useTheme } from '../theme'
import { useEffect, useState } from 'react'

export default function LoginPage() {
  const nav = useNavigate()
  const { message } = AntApp.useApp()
  const { mode } = useTheme()
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    // 已有 token 直接进（有效性由后续请求的 401 拦截兜底）
    if (tokens.access) nav('/')
  }, [nav])

  const onFinish = async (values: { login: string; password: string }) => {
    setLoading(true)
    try {
      const res = await login(values.login, values.password)
      message.success(`欢迎，${res.user.username}`)
      nav('/')
    } catch (err) {
      message.error(apiError(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: mode === 'dark' ? '#000' : '#f5f5f5',
      }}
    >
      <Card style={{ width: 380 }}>
        <Typography.Title level={3} style={{ textAlign: 'center' }}>
          Rovortex Admin
        </Typography.Title>
        <Form onFinish={onFinish} layout="vertical" requiredMark={false}>
          <Form.Item name="login" rules={[{ required: true, message: '请输入用户名或邮箱' }]}>
            <Input placeholder="用户名或邮箱" size="large" />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password placeholder="密码" size="large" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block size="large" loading={loading}>
            登录
          </Button>
        </Form>
        <Typography.Text
          type="secondary"
          style={{ display: 'block', textAlign: 'center', marginTop: 12, fontSize: 12 }}
        >
          仅管理员账号可登录后台
        </Typography.Text>
      </Card>
    </div>
  )
}
