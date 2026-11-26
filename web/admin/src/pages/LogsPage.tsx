import { Button, Select, Switch, Tooltip, Typography } from 'antd'
import {
  ArrowDownOutlined,
  ClearOutlined,
  FontSizeOutlined,
} from '@ant-design/icons'
import { useEffect, useMemo, useRef, useState } from 'react'
import { adminApi, tokens } from '../api'

export interface LogEntry {
  ts: string
  level: string
  target: string
  message: string
  request_id?: string
  method?: string
  path?: string
  status?: number
  elapsed_ms?: number
}

const MAX_ENTRIES = 5000

// logcat 风格：单字母级别 + 颜色
const levelLetter: Record<string, string> = {
  ERROR: 'E',
  WARN: 'W',
  INFO: 'I',
  DEBUG: 'D',
  TRACE: 'T',
}
const levelColor: Record<string, string> = {
  ERROR: '#f87171',
  WARN: '#fbbf24',
  INFO: '#34d399',
  DEBUG: '#60a5fa',
  TRACE: '#94a3b8',
}
const levelOrder: Record<string, number> = {
  TRACE: 0,
  DEBUG: 1,
  INFO: 2,
  WARN: 3,
  ERROR: 4,
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function fmtTime(ts: string): string {
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return ts.slice(11, 23)
  return (
    d.toLocaleTimeString('en-GB', { hour12: false }) +
    '.' +
    String(d.getMilliseconds()).padStart(3, '0')
  )
}

/** 构造搜索匹配器：正则/大小写/全词三种开关组合；正则非法时返回错误。 */
function buildMatcher(
  q: string,
  useRegex: boolean,
  caseSensitive: boolean,
  wholeWord: boolean,
): { test: (hay: string) => boolean; error: string | null } {
  if (!q) return { test: () => true, error: null }
  try {
    if (useRegex) {
      const pattern = wholeWord ? `\\b(?:${q})\\b` : q
      const r = new RegExp(pattern, caseSensitive ? '' : 'i')
      return { test: (hay) => r.test(hay), error: null }
    }
    if (wholeWord) {
      const r = new RegExp(`\\b(?:${escapeRe(q)})\\b`, caseSensitive ? '' : 'i')
      return { test: (hay) => r.test(hay), error: null }
    }
    const needle = caseSensitive ? q : q.toLowerCase()
    return { test: (hay) => (caseSensitive ? hay : hay.toLowerCase()).includes(needle), error: null }
  } catch (e) {
    return { test: () => false, error: e instanceof Error ? e.message : String(e) }
  }
}

function ToggleButton({
  active,
  onClick,
  title,
  children,
}: {
  active: boolean
  onClick: () => void
  title: string
  children: React.ReactNode
}) {
  return (
    <Tooltip title={title}>
      <Button
        size="small"
        type={active ? 'primary' : 'default'}
        onClick={onClick}
        style={{ padding: '0 8px' }}
      >
        {children}
      </Button>
    </Tooltip>
  )
}

export default function LogsPage() {
  const [entries, setEntries] = useState<LogEntry[]>([])
  const [lagged, setLagged] = useState(0)
  const [query, setQuery] = useState('')
  const [useRegex, setUseRegex] = useState(false)
  const [caseSensitive, setCaseSensitive] = useState(false)
  const [wholeWord, setWholeWord] = useState(false)
  const [minLevel, setMinLevel] = useState<string>('TRACE')
  const [autoScroll, setAutoScroll] = useState(true)
  const [atBottom, setAtBottom] = useState(true)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())

  const boxRef = useRef<HTMLDivElement>(null)
  const autoRef = useRef(autoScroll)
  autoRef.current = autoScroll

  // 历史 + 实时流都全量拉，筛选全部在浏览器端做（切换开关即时生效，不打服务端）。
  useEffect(() => {
    adminApi.logs('?limit=1000').then((d) => setEntries(d.logs.slice(-MAX_ENTRIES)))
    const base = import.meta.env.VITE_API_BASE ?? 'http://localhost:8080'
    const es = new EventSource(
      `${base}/api/admin/logs/stream?access_token=${encodeURIComponent(tokens.access ?? '')}`,
    )
    es.addEventListener('log', (ev) => {
      const entry = JSON.parse((ev as MessageEvent).data) as LogEntry
      setEntries((prev) => {
        const next = [...prev, entry]
        return next.length > MAX_ENTRIES ? next.slice(next.length - MAX_ENTRIES) : next
      })
    })
    es.addEventListener('lagged', () => setLagged((n) => n + 1))
    return () => es.close()
  }, [])

  const { test, error: regexError } = useMemo(
    () => buildMatcher(query, useRegex, caseSensitive, wholeWord),
    [query, useRegex, caseSensitive, wholeWord],
  )

  const filtered = useMemo(() => {
    const min = levelOrder[minLevel] ?? 0
    return entries.filter((e) => {
      if ((levelOrder[e.level] ?? 0) < min) return false
      return test(`${e.message} ${e.target} ${e.path ?? ''} ${e.method ?? ''} ${e.status ?? ''}`)
    })
  }, [entries, test, minLevel])

  useEffect(() => {
    if (autoRef.current && boxRef.current) {
      boxRef.current.scrollTop = boxRef.current.scrollHeight
    }
  }, [filtered.length])

  const onScroll = () => {
    const el = boxRef.current
    if (el) setAtBottom(el.scrollHeight - el.scrollTop - el.clientHeight < 48)
  }

  const toggleExpand = (i: number) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(i)) next.delete(i)
      else next.add(i)
      return next
    })
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 48px)' }}>
      {/* 工具栏：搜索 + 三开关 + 级别 + 跟随 + 清屏 */}
      <div
        style={{
          display: 'flex',
          gap: 8,
          alignItems: 'center',
          flexWrap: 'wrap',
          marginBottom: 8,
        }}
      >
        <Typography.Text strong style={{ marginRight: 4 }}>
          服务端日志
        </Typography.Text>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="搜索（支持正则）"
          spellCheck={false}
          style={{
            flex: '0 1 320px',
            minWidth: 200,
            padding: '4px 10px',
            fontFamily: 'monospace',
            fontSize: 13,
            border: '1px solid ' + (regexError ? '#f87171' : 'rgba(128,128,128,0.4)'),
            borderRadius: 6,
            background: 'transparent',
            color: 'inherit',
            outline: 'none',
          }}
        />
        <ToggleButton active={useRegex} onClick={() => setUseRegex((v) => !v)} title="正则表达式">
          <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{'.*'}</span>
        </ToggleButton>
        <ToggleButton
          active={caseSensitive}
          onClick={() => setCaseSensitive((v) => !v)}
          title="区分大小写"
        >
          <FontSizeOutlined />
        </ToggleButton>
        <ToggleButton active={wholeWord} onClick={() => setWholeWord((v) => !v)} title="全词匹配">
          <span style={{ fontFamily: 'monospace', fontSize: 12 }}>ab|</span>
        </ToggleButton>
        <Select
          size="small"
          value={minLevel}
          onChange={setMinLevel}
          style={{ width: 100 }}
          options={Object.keys(levelOrder)
            .reverse()
            .map((l) => ({ value: l, label: `≥ ${l}` }))}
        />
        <span style={{ color: 'rgba(128,128,128,0.8)', fontSize: 12 }}>
          {filtered.length}/{entries.length}
        </span>
        <span style={{ flex: 1 }} />
        <span style={{ fontSize: 12, color: 'rgba(128,128,128,0.9)' }}>滚动到底部</span>
        <Switch size="small" checked={autoScroll} onChange={setAutoScroll} />
        <Button size="small" icon={<ClearOutlined />} onClick={() => setEntries([])}>
          清屏
        </Button>
      </div>

      {regexError && (
        <Typography.Text type="danger" style={{ fontSize: 12, marginBottom: 4 }}>
          正则无效：{regexError}
        </Typography.Text>
      )}
      {lagged > 0 && (
        <Typography.Text type="warning" style={{ fontSize: 12, marginBottom: 4 }}>
          实时流跳帧 {lagged} 次（速度过快，stdout 日志完整）。
        </Typography.Text>
      )}

      {/* logcat 主体 */}
      <div
        ref={boxRef}
        onScroll={onScroll}
        style={{
          flex: 1,
          overflowY: 'auto',
          fontFamily:
            "'JetBrains Mono', 'Cascadia Code', Consolas, 'Courier New', monospace",
          fontSize: 12.5,
          lineHeight: '20px',
          borderRadius: 8,
          border: '1px solid rgba(128,128,128,0.25)',
          padding: '6px 10px',
          userSelect: 'text',
          position: 'relative',
        }}
      >
        {filtered.length === 0 && (
          <div style={{ color: 'rgba(128,128,128,0.6)', padding: 16 }}>暂无匹配日志</div>
        )}
        {filtered.map((e, i) => {
          const isExpanded = expanded.has(i)
          return (
            <div
              key={i}
              onClick={() => toggleExpand(i)}
              style={{
                display: 'flex',
                gap: 8,
                cursor: 'pointer',
                borderBottom: '1px solid rgba(128,128,128,0.08)',
                padding: '0 2px',
                whiteSpace: isExpanded ? 'pre-wrap' : 'nowrap',
                overflow: isExpanded ? 'visible' : 'hidden',
              }}
            >
              <span style={{ color: 'rgba(128,128,128,0.55)', flexShrink: 0 }}>
                {fmtTime(e.ts)}
              </span>
              <span
                style={{
                  color: levelColor[e.level] ?? 'inherit',
                  fontWeight: 700,
                  flexShrink: 0,
                  width: 12,
                  textAlign: 'center',
                }}
              >
                {levelLetter[e.level] ?? '?'}
              </span>
              <span
                style={{
                  color: 'rgba(128,128,128,0.65)',
                  flexShrink: 0,
                  maxWidth: 260,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {e.target}
              </span>
              {e.method && (
                <span style={{ color: '#818cf8', flexShrink: 0 }}>
                  {e.method} {e.path} {e.status} ({e.elapsed_ms}ms)
                </span>
              )}
              <span style={{ whiteSpace: 'inherit', wordBreak: 'break-all' }}>{e.message}</span>
            </div>
          )
        })}
      </div>

      {!atBottom && (
        <Button
          size="small"
          icon={<ArrowDownOutlined />}
          onClick={() => {
            const el = boxRef.current
            if (el) {
              el.scrollTop = el.scrollHeight
              setAtBottom(true)
            }
          }}
          style={{
            position: 'absolute',
            bottom: 40,
            right: 48,
            boxShadow: '0 2px 8px rgba(0,0,0,0.3)',
          }}
        >
          底部
        </Button>
      )}
    </div>
  )
}
