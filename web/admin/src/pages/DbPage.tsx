import { Button, Card, Checkbox, Dropdown, Form, Input, Modal, Popconfirm, Space, Switch, Table, Tabs, Tag, Typography } from 'antd'
import type { ColumnsType, TablePaginationConfig } from 'antd/es/table'
import type { FilterValue, SorterResult } from 'antd/es/table/interface'
import { useCallback, useEffect, useState } from 'react'
import { CaretDownOutlined, DeleteOutlined, EditOutlined, PlusOutlined, SettingOutlined, TableOutlined } from '@ant-design/icons'
import { Resizable } from 'react-resizable'
import 'react-resizable/css/styles.css'
import { adminApi, apiError } from '../api'
import { App as AntApp } from 'antd'
import dayjs from 'dayjs'

interface TableInfo {
  name: string
  rows: number
}

interface BrowseResult {
  columns: { name: string; data_type: string }[]
  rows: Record<string, unknown>[]
  total: number
}

interface SortState {
  column: string
  order: 'asc' | 'desc'
}

const TYPE_COLORS: Record<string, string> = {
  'timestamp with time zone': 'blue',
  uuid: 'purple',
  boolean: 'green',
  integer: 'orange',
  smallint: 'orange',
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** 列宽拖拽：包住 antd 表头的可拖拽把手。 */
type ResizeCb = (e: React.SyntheticEvent, data: { size: { width: number } }) => void

function ResizableTitle(
  props: React.HTMLAttributes<HTMLElement> & { onResize?: ResizeCb; width?: number },
) {
  const { onResize, width, ...rest } = props
  if (!width || !onResize) return <th {...rest} />
  return (
    <Resizable
      width={width}
      height={0}
      handle={<span className="rejs-col-handle" />}
      onResize={onResize as never}
      draggableOpts={{ enableUserSelectHack: false }}
    >
      <th {...rest} />
    </Resizable>
  )
}

/** 默认收起的列：主键/外键/GENERATED 噪音列，可从"列设置"下拉里打开。哈希列按需求原样展示。 */
const HIDDEN_BY_DEFAULT = new Set(['id', 'user_id', 'username_key', 'email_key'])

/** 后端唯一不收的列：GENERATED ALWAYS（PG 拒绝直接写）。其余浏览到的列全部可编辑。 */
const NON_WRITABLE: Record<string, Set<string>> = {
  users: new Set(['username_key', 'email_key']),
}

/** BrowseResult.columns 没有 is_nullable 信息；后端展示行里 null 即可空列曾有值，
 *  但 NOT NULL 列不会是 null。用"该列在所有行都非 null 且表里出现过 null 值列"不可靠，
 *  直接维护各表 NOT NULL 列（与迁移 schema 对齐），决定清空输入是否允许（写 NULL）。 */
const NOT_NULL_COLUMNS: Record<string, Set<string>> = {
  users: new Set(['id', 'username', 'username_key', 'email', 'email_key', 'status', 'created_at', 'updated_at', 'email_verified', 'is_admin']),
  refresh_tokens: new Set(['id', 'user_id', 'token_hash', 'expires_at', 'created_at', 'last_used_at']),
  email_verifications: new Set(['id', 'email', 'token_hash', 'purpose', 'expires_at', 'created_at']),
  audit_logs: new Set(['id', 'action', 'detail', 'client_ip', 'created_at']),
  user_identities: new Set(['id', 'user_id', 'provider', 'provider_uid', 'created_at']),
}

/** 长文本列（哈希等）默认更宽，且单元格内换行展示全文、不省略。 */
const WRAP_COLUMNS = new Set(['password_hash', 'token_hash'])

function renderCell(v: unknown): React.ReactNode {
  if (v === null || v === undefined) return <Typography.Text type="secondary">NULL</Typography.Text>
  if (typeof v === 'boolean')
    return v ? <Tag color="green">true</Tag> : <Tag>false</Tag>
  if (typeof v === 'string') {
    if (UUID_RE.test(v)) return <Typography.Text copyable style={{ fontSize: 12 }}>{v}</Typography.Text>
    if (/^\d{4}-\d{2}-\d{2}T/.test(v)) return dayjs(v).format('YYYY-MM-DD HH:mm:ss')
    return v
  }
  return JSON.stringify(v)
}

export default function DbPage() {
  const { message } = AntApp.useApp()
  const [tables, setTables] = useState<TableInfo[]>([])
  const [active, setActive] = useState<string>()
  const [data, setData] = useState<BrowseResult | null>(null)
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(20)
  const [sort, setSort] = useState<SortState | null>(null)
  const [search, setSearch] = useState('')
  const [appliedSearch, setAppliedSearch] = useState('')
  const [loading, setLoading] = useState(false)
  /** 用户手动打开的列（叠加在 HIDDEN_BY_DEFAULT 之上）；切表时重置。 */
  const [revealed, setRevealed] = useState<Set<string>>(new Set())
  /** 表结构卡片展开状态（默认收起）；切表保持——结构信息各表都有用。 */
  const [schemaOpen, setSchemaOpen] = useState(false)
  /** 手动拖出的列宽（列名 → px）；切表时重置。 */
  const [colWidths, setColWidths] = useState<Record<string, number>>({})
  /** 行编辑弹窗：editing.row 为 null 表示新增。 */
  const [editing, setEditing] = useState<{ table: string; row: Record<string, unknown> | null } | null>(null)
  const [form] = Form.useForm()
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    adminApi
      .dbTables()
      .then((t) => {
        setTables(t)
        setActive((cur) => cur ?? t[0]?.name)
      })
      .catch((err) => message.error(apiError(err)))
  }, [message])

  const load = useCallback(
    (table: string, p: number, size: number, s: SortState | null, q: string) => {
      setLoading(true)
      adminApi
        .dbBrowse(table, p, size, {
          sort: s?.column,
          order: s?.order,
          q: q || undefined,
        })
        .then(setData)
        .catch((err) => message.error(apiError(err)))
        .finally(() => setLoading(false))
    },
    [message],
  )

  useEffect(() => {
    if (!active) return
    load(active, page, perPage, sort, appliedSearch)
  }, [active, page, perPage, sort, appliedSearch, load])

  const switchTable = (k: string) => {
    setActive(k)
    setPage(1)
    setSort(null)
    setSearch('')
    setAppliedSearch('')
    setRevealed(new Set())
    setColWidths({})
  }

  const onTableChange = (
    _pagination: TablePaginationConfig,
    _filters: Record<string, FilterValue | null>,
    sorter: SorterResult<Record<string, unknown>> | SorterResult<Record<string, unknown>>[],
  ) => {
    const s = Array.isArray(sorter) ? sorter[0] : sorter
    if (s?.order) {
      setSort({ column: s.field as string, order: s.order === 'descend' ? 'desc' : 'asc' })
    } else {
      setSort(null)
    }
    setPage(1)
  }

  const columns: ColumnsType<Record<string, unknown>> =
    data?.columns.map((c) => {
      // 全部列给初始宽度（可拖拽的前提）；uuid/长文本哈希列更宽。
      const wrap = WRAP_COLUMNS.has(c.name)
      const width = colWidths[c.name] ?? (c.data_type === 'uuid' ? 240 : wrap ? 420 : 200)
      return {
        title: (
          <span>
            {c.name}{' '}
            <Tag color={TYPE_COLORS[c.data_type]} style={{ fontSize: 10, lineHeight: '16px' }}>
              {c.data_type}
            </Tag>
          </span>
        ),
        dataIndex: c.name,
        key: c.name,
        // 哈希列不省略，word-break 换行完整展示；其余列照旧单行省略
        ellipsis: !wrap,
        width,
        sorter: true,
        sortDirections: ['ascend', 'descend'],
        hidden: HIDDEN_BY_DEFAULT.has(c.name) && !revealed.has(c.name),
        onHeaderCell: () => ({ width, onResize: mkResize(c.name) }),
        onBodyCell: wrap
          ? () => ({ style: { wordBreak: 'break-all' as const, whiteSpace: 'normal' as const } })
          : undefined,
        render: renderCell,
      }
    }) ?? []

  /** 生成某列的 onResize 回调（react-resizable 给的是拖动后的绝对宽度）。 */
  function mkResize(name: string) {
    return (_e: React.SyntheticEvent, { size }: { size: { width: number } }) => {
      setColWidths((prev) => ({ ...prev, [name]: Math.max(60, size.width) }))
    }
  }

  const toggleColumn = (name: string, visible: boolean) => {
    setRevealed((prev) => {
      const next = new Set(prev)
      if (visible) next.add(name)
      else next.delete(name)
      return next
    })
  }

  // ---- 行级增删改（全表全列可编辑，仅 GENERATED 列除外） ----

  const openEdit = (table: string, row: Record<string, unknown> | null) => {
    setEditing({ table, row })
    const blocked = NON_WRITABLE[table]
    const initial: Record<string, unknown> = {}
    if (row) {
      for (const c of data?.columns ?? []) {
        if (blocked?.has(c.name)) continue
        initial[c.name] = row[c.name] ?? undefined
      }
    }
    form.setFieldsValue(initial)
  }

  const deleteRow = async (table: string, id: string) => {
    try {
      const res = await adminApi.dbDeleteRow(table, id)
      message.success(`已删除 ${res.deleted} 行`)
      load(table, page, perPage, sort, appliedSearch)
    } catch (err) {
      message.error(apiError(err))
    }
  }

  const submitEdit = async () => {
    if (!editing) return
    const { table, row } = editing
    try {
      const values = await form.validateFields()
      // 只提交有值的字段；空串对可空列当作 null，非空列由后端/PG 报错提示
      const columns: Record<string, unknown> = {}
      for (const [name, v] of Object.entries(values)) {
        if (v === undefined || v === null || v === '') continue
        columns[name] = v
      }
      // 显式 null：编辑时清空可空列（值原本存在但被删掉的场景）
      if (row) {
        for (const name of Object.keys(values)) {
          const isNullable = !NOT_NULL_COLUMNS[table]?.has(name)
          if ((values[name] === null || values[name] === '' || values[name] === undefined) && row[name] != null && isNullable) {
            columns[name] = null
          }
        }
      }
      setSaving(true)
      if (row) {
        const res = await adminApi.dbUpdateRow(table, String(row.id), columns)
        message.success(`已更新 ${res.updated} 行`)
      } else {
        await adminApi.dbInsertRow(table, columns)
        message.success('已插入 1 行')
      }
      setEditing(null)
      load(table, page, perPage, sort, appliedSearch)
    } catch (err) {
      // validateFields 的校验错误已由 Form 内联展示，不重复弹
      if (err && typeof err === 'object' && 'errorFields' in err) return
      message.error(apiError(err))
    } finally {
      setSaving(false)
    }
  }

  const pagination: TablePaginationConfig = {
    current: page,
    pageSize: perPage,
    total: data?.total ?? 0,
    showSizeChanger: true,
    pageSizeOptions: [10, 20, 50, 100],
    showTotal: (t) => `共 ${t} 行`,
    onChange: (p, size) => {
      setPage(p)
      setPerPage(size)
    },
  }

  /** 编辑/新增操作列。 */
  const actionColumn: ColumnsType<Record<string, unknown>>[number] = {
    title: '操作',
    key: '__actions',
    fixed: 'right',
    width: 100,
    render: (_, row) => (
      <Space size={4}>
        <Button
          type="link"
          size="small"
          icon={<EditOutlined />}
          onClick={() => openEdit(active!, row)}
        />
        <Popconfirm
          title="删除这一行？"
          description="操作会写入审计日志，不可恢复"
          okButtonProps={{ danger: true }}
          onConfirm={() => deleteRow(active!, String(row.id))}
        >
          <Button type="link" size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      </Space>
    ),
  }

  /** 表单控件按列类型分派：bool→Switch，整数→数字输入，jsonb→文本（JSON），时间→文本（ISO 格式提示），其余→文本。 */
  const formWidget = (_name: string, dataType: string) => {
    if (dataType === 'boolean') return <Switch />
    if (dataType === 'smallint' || dataType === 'integer' || dataType === 'bigint')
      return <Input type="number" />
    if (dataType.includes('timestamp'))
      return <Input placeholder="ISO 8601，如 2026-12-31T00:00:00Z；留空 = NULL" />
    if (dataType === 'uuid') return <Input placeholder="UUID" />
    if (dataType === 'jsonb') return <Input.TextArea placeholder='JSON，如 {"k": "v"}' autoSize={{ minRows: 1, maxRows: 6 }} />
    return <Input />
  }

  const editingTable = editing ? NON_WRITABLE[editing.table] : undefined
  const editingCols = editing
    ? (data?.columns ?? []).filter((c) => !editingTable?.has(c.name))
    : []

  return (
    <>
      <Typography.Title level={4}>数据库</Typography.Title>
      <Tabs
        activeKey={active}
        onChange={switchTable}
        items={tables.map((t) => ({
          key: t.name,
          label: `${t.name} (${t.rows})`,
        }))}
      />
      <Card
        size="small"
        style={{ marginBottom: 16 }}
        styles={{ body: { padding: schemaOpen ? '12px 24px' : '6px 24px' } }}
        title={
          <span
            onClick={() => setSchemaOpen((v) => !v)}
            style={{ cursor: 'pointer', userSelect: 'none', fontSize: 13, fontWeight: 400 }}
          >
            <TableOutlined style={{ marginRight: 6 }} />
            {active} 表结构（{data?.columns.length ?? 0} 列）
            <Typography.Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>
              {schemaOpen ? '点击收起' : '点击展开'}
            </Typography.Text>
          </span>
        }
      >
        {schemaOpen && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px 24px' }}>
            {(data?.columns ?? []).map((c) => (
              <Space key={c.name} size={6} style={{ minWidth: 220 }}>
                <Typography.Text code style={{ fontSize: 12 }}>
                  {c.name}
                </Typography.Text>
                <Tag color={TYPE_COLORS[c.data_type]} style={{ fontSize: 10, lineHeight: '16px' }}>
                  {c.data_type}
                </Tag>
                {NOT_NULL_COLUMNS[active ?? '']?.has(c.name) ? (
                  <Tag style={{ fontSize: 10, lineHeight: '16px' }}>NOT NULL</Tag>
                ) : (
                  <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                    可空
                  </Typography.Text>
                )}
                {HIDDEN_BY_DEFAULT.has(c.name) && (
                  <Tag color="warning" style={{ fontSize: 10, lineHeight: '16px' }}>
                    默认隐藏
                  </Tag>
                )}
              </Space>
            ))}
          </div>
        )}
      </Card>
      <Card>
        <Space style={{ marginBottom: 16 }} wrap>
          <Input.Search
            placeholder="全字段搜索（对当前表所有列做模糊匹配）"
            allowClear
            enterButton
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onSearch={(v) => {
              setAppliedSearch(v)
              setPage(1)
            }}
            style={{ width: 380 }}
          />
          <Dropdown
            trigger={['click']}
            menu={{
              selectable: true,
              multiple: true,
              items: data?.columns.map((c) => ({
                key: c.name,
                label: (
                  <Checkbox
                    checked={!HIDDEN_BY_DEFAULT.has(c.name) || revealed.has(c.name)}
                    onClick={(e) => {
                      e.stopPropagation()
                      toggleColumn(c.name, HIDDEN_BY_DEFAULT.has(c.name) && !revealed.has(c.name))
                    }}
                  >
                    {c.name}
                  </Checkbox>
                ),
              })),
            }}
          >
            <Button icon={<SettingOutlined />}>
              列设置 <CaretDownOutlined />
            </Button>
          </Dropdown>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => openEdit(active!, null)}
          >
            新增行
          </Button>
        </Space>
        <Table
          rowKey={(_, i) => String(i)}
          loading={loading}
          columns={[...columns, actionColumn]}
          dataSource={data?.rows}
          scroll={{ x: 'max-content' }}
          size="small"
          pagination={pagination}
          onChange={onTableChange}
          components={{ header: { cell: ResizableTitle } }}
        />
        <Modal
          open={!!editing}
          title={editing?.row ? `编辑行 · ${editing.table}` : `新增行 · ${editing?.table}`}
          confirmLoading={saving}
          okText={editing?.row ? '保存' : '插入'}
          onOk={submitEdit}
          onCancel={() => setEditing(null)}
          width={520}
        >
          <Form form={form} layout="vertical" style={{ marginTop: 12 }}>
            {editingCols.map((c) => (
              <Form.Item
                key={c.name}
                name={c.name}
                label={
                  <span>
                    {c.name}{' '}
                    <Tag color={TYPE_COLORS[c.data_type]} style={{ fontSize: 10, lineHeight: '16px' }}>
                      {c.data_type}
                    </Tag>
                    {!NOT_NULL_COLUMNS[editing!.table]?.has(c.name) && (
                      <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                        可空
                      </Typography.Text>
                    )}
                  </span>
                }
                valuePropName={c.data_type === 'boolean' ? 'checked' : 'value'}
              >
                {formWidget(c.name, c.data_type)}
              </Form.Item>
            ))}
          </Form>
        </Modal>
      </Card>
    </>
  )
}
