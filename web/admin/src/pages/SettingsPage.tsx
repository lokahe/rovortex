import {
  Alert,
  Button,
  Card,
  Input,
  Modal,
  Space,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { CheckOutlined, EditOutlined, ReloadOutlined, SaveOutlined } from '@ant-design/icons'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { adminApi, apiError } from '../api'

interface ConfigEntry {
  key: string
  value: string
  secret: boolean
  doc: string
  wired: boolean
  group: string
}

interface ConfigResponse {
  entries: ConfigEntry[]
  available_keys: string[]
  modified_at: string | null
}

/// 分组展示顺序（与后端 KEY_GROUPS 语义对应）；「其他」固定最后。
const GROUP_ORDER = ['安全凭据', '邮件', 'OAuth 登录', '会话与账号', '安全与限流', '运行参数', '其他']

export default function SettingsPage() {
  const [data, setData] = useState<ConfigResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [editing, setEditing] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)
  const [restartOpen, setRestartOpen] = useState(false)
  const [restarting, setRestarting] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await adminApi.config()
      setData(res)
      setEditing({})
    } catch (e) {
      message.error(apiError(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const dirty = Object.keys(editing).filter((k) => editing[k] !== undefined)

  const grouped = useMemo(() => {
    const map = new Map<string, ConfigEntry[]>()
    for (const e of data?.entries ?? []) {
      const list = map.get(e.group) ?? []
      list.push(e)
      map.set(e.group, list)
    }
    // 「其他」固定最后；其余按 GROUP_ORDER，未知组插在「其他」前。
    const known = GROUP_ORDER.filter((g) => map.has(g))
    const unknown = [...map.keys()].filter((g) => !GROUP_ORDER.includes(g))
    return [...known, ...unknown].map((g) => ({ group: g, entries: map.get(g)! }))
  }, [data])

  const dirtyIn = (entries: ConfigEntry[]) => entries.filter((e) => editing[e.key] !== undefined).length

  const save = async () => {
    if (!data || dirty.length === 0) return
    setSaving(true)
    try {
      const values: Record<string, string> = {}
      for (const k of dirty) {
        values[k] = editing[k] ?? ''
      }
      const res = await adminApi.updateConfig(values)
      message.success(`已写入 ${res.updated} 项，需重启容器生效`)
      await load()
    } catch (e) {
      message.error(apiError(e))
    } finally {
      setSaving(false)
    }
  }

  const restart = async () => {
    setRestarting(true)
    // 自身重启会掐断连接：发出即视为成功，靠轮询确认恢复。
    try {
      await adminApi.restartConfig()
    } catch {
      // 网络错误（容器重启中断连接）也在预期内
    }
    setRestartOpen(false)
    setRestarting(false)
    message.info('重启指令已发出，等待服务恢复…')
    pollAfterRestart()
  }

  const pollAfterRestart = () => {
    let attempts = 0
    const timer = setInterval(async () => {
      attempts++
      try {
        await adminApi.config()
        clearInterval(timer)
        message.success('服务已恢复，新配置已生效')
        await load()
      } catch {
        if (attempts >= 30) {
          clearInterval(timer)
          message.error('30 次探测未恢复，请上服务器看日志')
        }
      }
    }, 3000)
  }

  const columns: ColumnsType<ConfigEntry> = [
    {
      title: '键',
      dataIndex: 'key',
      width: 320,
      render: (k: string, row) => (
        <Space direction="vertical" size={0}>
          <Typography.Text code>{k}</Typography.Text>
          {row.doc && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {row.doc}
            </Typography.Text>
          )}
        </Space>
      ),
    },
    {
      title: '值',
      dataIndex: 'value',
      render: (v: string, row) => {
        if (editing[row.key] !== undefined) {
          return (
            <Input
              value={editing[row.key]}
              onChange={(e) => setEditing((prev) => ({ ...prev, [row.key]: e.target.value }))}
              style={{ maxWidth: 480 }}
            />
          )
        }
        return row.secret ? (
          <Space>
            <Tag color="warning">已脱敏</Tag>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {v}
            </Typography.Text>
          </Space>
        ) : (
          <Typography.Text code copyable={v ? { text: v } : false}>
            {v || <Typography.Text type="secondary">（未配置）</Typography.Text>}
          </Typography.Text>
        )
      },
    },
    {
      title: '状态',
      key: 'status',
      width: 140,
      render: (_, row) => (
        <Space size={4} wrap>
          {row.secret && <Tag color="purple">secret</Tag>}
          {!row.wired && <Tooltip title="docker-compose.yml 未透传该键，修改后不会生效"><Tag color="red">未透传</Tag></Tooltip>}
          {editing[row.key] !== undefined && <Tag color="blue">待保存</Tag>}
        </Space>
      ),
    },
    {
      title: '',
      key: 'actions',
      width: 90,
      render: (_, row) =>
        editing[row.key] !== undefined ? (
          <Space>
            <Button
              size="small"
              icon={<CheckOutlined />}
              onClick={() => setEditing((prev) => ({ ...prev }))}
            />
            <Button
              size="small"
              onClick={() =>
                setEditing((prev) => {
                  const next = { ...prev }
                  delete next[row.key]
                  return next
                })
              }
            >
              取消
            </Button>
          </Space>
        ) : (
          <Button
            size="small"
            icon={<EditOutlined />}
            onClick={() => setEditing((prev) => ({ ...prev, [row.key]: row.value }))}
          >
            编辑
          </Button>
        ),
    },
  ]

  return (
    <Card
      title="服务配置"
      extra={
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => void load()} loading={loading}>
            刷新
          </Button>
          <Button
            icon={<SaveOutlined />}
            type="primary"
            disabled={dirty.length === 0}
            loading={saving}
            onClick={() => void save()}
          >
            保存{dirty.length > 0 ? `（${dirty.length} 项）` : ''}
          </Button>
          <Button danger onClick={() => setRestartOpen(true)}>
            重启容器生效
          </Button>
        </Space>
      }
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="修改写入服务器 .env，点「重启容器生效」后应用。secret 值不回显；编辑 secret 保存时留占位符 = 保留原值。"
      />
      <Tabs
        items={grouped.map(({ group, entries }) => ({
          key: group,
          label: (
            <span>
              {group}
              {dirtyIn(entries) > 0 && (
                <Tag color="blue" style={{ marginLeft: 6 }}>
                  {dirtyIn(entries)}
                </Tag>
              )}
            </span>
          ),
          children: (
            <Table
              rowKey="key"
              loading={loading}
              dataSource={entries}
              columns={columns}
              pagination={false}
              size="middle"
            />
          ),
        }))}
      />
      <Typography.Paragraph type="secondary" style={{ marginTop: 12, fontSize: 12 }}>
        {data?.modified_at
          ? `.env 最后修改：${new Date(data.modified_at).toLocaleString()}`
          : ''}
      </Typography.Paragraph>

      <Modal
        title="重启 rovortex 容器？"
        open={restartOpen}
        onOk={() => void restart()}
        confirmLoading={restarting}
        onCancel={() => setRestartOpen(false)}
        okText="重启"
        cancelText="取消"
      >
        <Typography.Paragraph>
          重启期间 API 与所有登录请求会中断约 3-10 秒，确认继续？
        </Typography.Paragraph>
      </Modal>
    </Card>
  )
}
