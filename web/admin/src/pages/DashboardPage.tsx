import { Card, Col, Row, Select, Statistic, Switch, Table, Typography } from 'antd'
import { useEffect, useMemo, useRef, useState } from 'react'
import { adminApi, apiError, tokens } from '../api'
import { App as AntApp } from 'antd'

interface Stats {
  since: string
  total_users: number
  events: [string, number][]
}

interface Point {
  ts: number
  total: number
  errors: number
  avg_ms: number
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

/** 请求量折线 SVG：简单缩放 + 网格 + 悬停提示；不引第三方图表库。 */
function LineChart({ points, errors }: { points: Point[]; errors: boolean }) {
  const [hover, setHover] = useState<number | null>(null)
  const W = 860
  const H = 180
  const P = { l: 34, r: 10, t: 10, b: 18 }
  const iw = W - P.l - P.r
  const ih = H - P.t - P.b

  const series = useMemo(
    () => points.map((p) => ({ ts: p.ts, v: errors ? p.errors : p.total })),
    [points, errors],
  )
  const max = Math.max(1, ...series.map((s) => s.v))
  const x = (i: number) => P.l + (series.length <= 1 ? iw / 2 : (i * iw) / (series.length - 1))
  const y = (v: number) => P.t + ih - (v / max) * ih

  const path = series.map((s, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(s.v).toFixed(1)}`).join(' ')
  const area = `${path} L${x(series.length - 1).toFixed(1)},${(P.t + ih).toFixed(1)} L${x(0).toFixed(1)},${(P.t + ih).toFixed(1)} Z`

  const stroke = errors ? '#f87171' : '#6366f1'

  const fmtTime = (ts: number) =>
    new Date(ts * 1000).toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit' })

  const gridYs = [0, 0.5, 1].map((f) => P.t + ih - f * ih)
  const gridVals = [max, max / 2, 0]

  return (
    <div style={{ position: 'relative' }}>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        style={{ width: '100%', display: 'block' }}
        onMouseLeave={() => setHover(null)}
        onMouseMove={(e) => {
          const rect = (e.target as SVGElement).ownerSVGElement?.getBoundingClientRect() ??
            (e.currentTarget as unknown as SVGElement).getBoundingClientRect()
          const px = ((e.clientX - rect.left) / rect.width) * W
          const idx = Math.round(((px - P.l) / iw) * (series.length - 1))
          setHover(Math.max(0, Math.min(series.length - 1, idx)))
        }}
      >
        {gridYs.map((gy, i) => (
          <g key={i}>
            <line x1={P.l} x2={W - P.r} y1={gy} y2={gy} stroke="rgba(128,128,128,0.2)" strokeDasharray="3,4" />
            <text x={P.l - 6} y={gy + 4} textAnchor="end" fontSize={10} fill="rgba(128,128,128,0.8)">
              {Math.round(gridVals[i])}
            </text>
          </g>
        ))}
        {series.length > 1 && (
          <>
            <path d={area} fill={stroke} opacity={0.12} />
            <path d={path} fill="none" stroke={stroke} strokeWidth={1.6} />
          </>
        )}
        {hover !== null && series[hover] && (
          <g>
            <line x1={x(hover)} x2={x(hover)} y1={P.t} y2={P.t + ih} stroke="rgba(128,128,128,0.5)" />
            <circle cx={x(hover)} cy={y(series[hover].v)} r={3} fill={stroke} />
          </g>
        )}
        {series.length > 0 && (
          <>
            <text x={P.l} y={H - 4} fontSize={10} fill="rgba(128,128,128,0.8)">
              {fmtTime(series[0].ts)}
            </text>
            <text x={W - P.r} y={H - 4} textAnchor="end" fontSize={10} fill="rgba(128,128,128,0.8)">
              {fmtTime(series[series.length - 1].ts)}
            </text>
          </>
        )}
      </svg>
      {hover !== null && series[hover] && (
        <div
          style={{
            position: 'absolute',
            top: 4,
            right: 12,
            fontSize: 12,
            fontFamily: 'monospace',
            background: 'rgba(0,0,0,0.55)',
            color: '#fff',
            padding: '2px 8px',
            borderRadius: 4,
            pointerEvents: 'none',
          }}
        >
          {fmtTime(series[hover].ts)} · {errors ? '错误' : '请求'} {series[hover].v} · 均{' '}
          {points[hover]?.avg_ms ?? 0}ms
        </div>
      )}
    </div>
  )
}

/** 仪表盘请求折线：history 拉底 + SSE live 追加当前分钟点。 */
function TrafficChart() {
  const { message } = AntApp.useApp()
  const [minutes, setMinutes] = useState(60)
  const [points, setPoints] = useState<Point[]>([])
  const [live, setLive] = useState(true)
  const [showErrors, setShowErrors] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    adminApi
      .metricsHistory(minutes)
      .then((d) => setPoints(d.points))
      .catch((err) => message.error(apiError(err)))
  }, [minutes, message])

  useEffect(() => {
    if (!live) {
      esRef.current?.close()
      esRef.current = null
      return
    }
    const base = import.meta.env.VITE_API_BASE ?? 'http://localhost:8080'
    const es = new EventSource(
      `${base}/api/admin/metrics/live?access_token=${encodeURIComponent(tokens.access ?? '')}`,
    )
    es.addEventListener('point', (ev) => {
      const p = JSON.parse((ev as MessageEvent).data) as Point
      setPoints((prev) => {
        // 当前分钟点已在（history 末尾含当前桶）则替换，否则追加。
        if (prev.length && prev[prev.length - 1].ts === p.ts) {
          return [...prev.slice(0, -1), p]
        }
        const next = [...prev, p]
        return next.length > minutes ? next.slice(next.length - minutes) : next
      })
    })
    esRef.current = es
    return () => es.close()
  }, [live, minutes])

  // history 末尾可能含「当前桶」+ live 追加同 ts 点，按 ts 去重合并。
  const merged = useMemo(() => {
    const m = new Map<number, Point>()
    for (const p of points) m.set(p.ts, p)
    return [...m.values()].sort((a, b) => a.ts - b.ts)
  }, [points])

  const totalRecent = merged.reduce((s, p) => s + p.total, 0)
  const errRecent = merged.reduce((s, p) => s + p.errors, 0)

  return (
    <Card
      size="small"
      title={
        <span style={{ fontSize: 13, fontWeight: 400 }}>HTTP 请求（每分钟，进程内存指标，重启清零）</span>
      }
      extra={
        <span style={{ display: 'inline-flex', gap: 16, alignItems: 'center', fontSize: 12 }}>
          <span>
            错误线 <Switch size="small" checked={showErrors} onChange={setShowErrors} />
          </span>
          <span>
            实时 <Switch size="small" checked={live} onChange={setLive} />
          </span>
          <Select
            size="small"
            value={minutes}
            onChange={setMinutes}
            style={{ width: 84 }}
            options={[
              { value: 60, label: '1 小时' },
              { value: 360, label: '6 小时' },
              { value: 1440, label: '24 小时' },
            ]}
          />
        </span>
      }
    >
      <div style={{ display: 'flex', gap: 24, marginBottom: 8 }}>
        <Statistic title={`窗口请求`} value={totalRecent} />
        <Statistic title="窗口错误" value={errRecent} valueStyle={errRecent > 0 ? { color: '#f87171' } : undefined} />
      </div>
      <LineChart points={merged} errors={showErrors} />
    </Card>
  )
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
      <div style={{ marginTop: 24 }}>
        <TrafficChart />
      </div>
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
