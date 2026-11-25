import { Button, Drawer, Input, Space, Table, Tag, Typography, App as AntApp } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { useCallback, useEffect, useState } from 'react'
import { adminApi, apiError } from '../api'
import type { AdminUser } from '../api'
import dayjs from 'dayjs'

interface Identity {
  provider: string
  provider_uid: string
  email: string | null
  created_at: string
}

interface AuditEntry {
  action: string
  detail: string
  client_ip: string
  created_at: string
}

interface Detail extends AdminUser {
  identities: Identity[]
  audit_logs: AuditEntry[]
}

const PROVIDER_COLORS: Record<string, string> = {
  github: 'purple',
  magic: 'geekblue',
}

const ACTION_LABELS: Record<string, string> = {
  register: '注册',
  login_success: '登录成功',
  login_failure: '登录失败',
  logout: '登出',
  password_changed: '密码变更',
  email_verification_requested: '验证邮件请求',
  email_verified: '邮箱已验证',
  magic_link_requested: 'Magic Link 请求',
}

export default function UsersPage() {
  const { message, modal } = AntApp.useApp()
  const [users, setUsers] = useState<AdminUser[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [perPage] = useState(20)
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(false)
  const [detail, setDetail] = useState<Detail | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)

  const load = useCallback(
    async (q: string, p: number) => {
      setLoading(true)
      try {
        const res = await adminApi.listUsers(q || undefined, p, perPage)
        setUsers(res.users)
        setTotal(res.total)
      } catch (err) {
        message.error(apiError(err))
      } finally {
        setLoading(false)
      }
    },
    [perPage, message],
  )

  useEffect(() => {
    load(search, page)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page])

  const openDetail = async (id: string) => {
    try {
      const full = await adminApi.userDetail(id)
      setDetail(full as Detail)
      setDetailOpen(true)
    } catch (err) {
      message.error(apiError(err))
    }
  }

  const toggleBan = (u: AdminUser) => {
    modal.confirm({
      title: u.banned ? `解封 ${u.username}？` : `封禁 ${u.username}？`,
      content: u.banned ? '该用户将可重新登录。' : '该用户将被拒绝登录并踢出所有会话。',
      onOk: async () => {
        try {
          await adminApi.setBan(u.id, !u.banned)
          message.success(u.banned ? '已解封' : '已封禁')
          load(search, page)
        } catch (err) {
          message.error(apiError(err))
        }
      },
    })
  }

  const columns: ColumnsType<AdminUser> = [
    { title: '用户名', dataIndex: 'username' },
    { title: '邮箱', dataIndex: 'email' },
    {
      title: '邮箱验证',
      dataIndex: 'email_verified',
      render: (v: boolean) => (v ? <Tag color="green">已验证</Tag> : <Tag>未验证</Tag>),
    },
    {
      title: '角色',
      dataIndex: 'is_admin',
      render: (v: boolean) => (v ? <Tag color="gold">管理员</Tag> : null),
    },
    {
      title: '状态',
      dataIndex: 'banned',
      render: (v: boolean) => (v ? <Tag color="red">已封禁</Tag> : <Tag color="green">正常</Tag>),
    },
    {
      title: '注册时间',
      dataIndex: 'created_at',
      render: (v: string) => dayjs(v).format('YYYY-MM-DD HH:mm'),
    },
    {
      title: '操作',
      render: (_, u) => (
        <Space>
          <Button size="small" onClick={() => openDetail(u.id)}>
            详情
          </Button>
          <Button size="small" danger={!u.banned} onClick={() => toggleBan(u)}>
            {u.banned ? '解封' : '封禁'}
          </Button>
        </Space>
      ),
    },
  ]

  return (
    <>
      <Typography.Title level={4}>用户管理</Typography.Title>
      <Space style={{ marginBottom: 16 }}>
        <Input.Search
          placeholder="搜索用户名 / 邮箱"
          allowClear
          onSearch={(v) => {
            setSearch(v)
            setPage(1)
            load(v, 1)
          }}
          style={{ width: 300 }}
        />
      </Space>
      <Table
        rowKey="id"
        loading={loading}
        columns={columns}
        dataSource={users}
        pagination={{
          current: page,
          pageSize: perPage,
          total,
          showTotal: (t) => `共 ${t} 个用户`,
          onChange: (p) => setPage(p),
        }}
      />

      <Drawer
        title="用户详情"
        width={520}
        open={detailOpen}
        onClose={() => setDetailOpen(false)}
      >
        {detail && (
          <>
            <Typography.Title level={5}>身份绑定</Typography.Title>
            <Space direction="vertical" style={{ width: '100%' }}>
              {detail.identities?.length ? (
                detail.identities.map((i) => (
                  <Tag key={i.provider + i.provider_uid} color={PROVIDER_COLORS[i.provider]}>
                    {i.provider}: {i.provider_uid}
                  </Tag>
                ))
              ) : (
                <Typography.Text type="secondary">无外部身份（密码账号）</Typography.Text>
              )}
            </Space>
            <Typography.Title level={5} style={{ marginTop: 16 }}>
              审计记录（最近 20 条）
            </Typography.Title>
            <Table
              rowKey={(r) => r.action + r.created_at}
              size="small"
              pagination={false}
              dataSource={detail.audit_logs ?? []}
              columns={[
                {
                  title: '动作',
                  dataIndex: 'action',
                  render: (a: string) => ACTION_LABELS[a] ?? a,
                },
                { title: '详情', dataIndex: 'detail', ellipsis: true },
                {
                  title: '时间',
                  dataIndex: 'created_at',
                  render: (v: string) => dayjs(v).format('MM-DD HH:mm:ss'),
                },
              ]}
            />
          </>
        )}
      </Drawer>
    </>
  )
}
