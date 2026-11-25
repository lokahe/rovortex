import { Card, Col, Row, Statistic, Table, Typography } from 'antd'
import { useEffect, useState } from 'react'
import { adminApi, apiError } from '../api'
import { App as AntApp } from 'antd'

interface Stats {
  since: string
  total_users: number
  events: [string, number][]
}

const ACTION_LABELS: Record<string, string> = {
  register: '注册',
  login_success: '登录成功',
  login_failure: '登录失败',
  logout: '登出',
  refresh_success: '刷新成功',
  refresh_failure: '刷新失败',
  password_changed: '密码变更',
  email_verification_requested: '验证邮件请求',
  email_verified: '邮箱已验证',
  email_change_requested: '改邮箱请求',
  email_changed: '邮箱已变更',
  magic_link_requested: 'Magic Link 请求',
}

export default function DashboardPage() {
  const { message } = AntApp.useApp()
  const [stats, setStats] = useState<Stats | null>(null)

  useEffect(() => {
    adminApi
      .stats()
      .then(setStats)
      .catch((err) => message.error(apiError(err)))
  }, [message])

  return (
    <>
      <Typography.Title level={4}>仪表盘</Typography.Title>
      <Row gutter={16}>
        <Col span={8}>
          <Card>
            <Statistic title="用户总数" value={stats?.total_users ?? '—'} />
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <Statistic
              title="统计窗口起点"
              value={stats ? new Date(stats.since).toLocaleString() : '—'}
              formatter={(v) => <span style={{ fontSize: 18 }}>{v}</span>}
            />
          </Card>
        </Col>
      </Row>
      <Typography.Title level={4} style={{ marginTop: 24 }}>
        近 7 天事件
      </Typography.Title>
      <Card>
        <Table
          rowKey="action"
          pagination={false}
          dataSource={stats?.events.map(([action, count]) => ({ action, count })) ?? []}
          columns={[
            { title: '事件', dataIndex: 'action', render: (a: string) => ACTION_LABELS[a] ?? a },
            { title: '次数', dataIndex: 'count' },
          ]}
        />
      </Card>
    </>
  )
}
