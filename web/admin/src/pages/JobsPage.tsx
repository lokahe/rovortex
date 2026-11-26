import { Button, Card, Input, Popconfirm, Switch, Typography } from 'antd'
import { CaretRightOutlined } from '@ant-design/icons'
import { useEffect, useState } from 'react'
import { adminApi, apiError } from '../api'
import { App as AntApp } from 'antd'

interface JobParam {
  name: string
  doc: string
  value: number
  default: number
  min: number
  max: number
  unit: string
}

interface Job {
  name: string
  doc: string
  interval_secs: number
  enabled: boolean
  last_run?: { at: string; elapsed_ms: number; ok?: string; err?: string }
  params: JobParam[]
}

function fmtAgo(at: string): string {
  const s = Math.max(0, (Date.now() - new Date(at).getTime()) / 1000)
  if (s < 60) return `${Math.floor(s)} 秒前`
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`
  return `${Math.floor(s / 86400)} 天前`
}

export default function JobsPage() {
  const { message } = AntApp.useApp()
  const [jobs, setJobs] = useState<Job[]>([])
  const [intervalDraft, setIntervalDraft] = useState<Record<string, string>>({})
  const [paramDraft, setParamDraft] = useState<Record<string, string>>({})

  const reload = () =>
    adminApi
      .jobs()
      .then(setJobs)
      .catch((err) => message.error(apiError(err)))

  useEffect(() => {
    reload()
  }, [])

  const toggle = async (job: Job, enabled: boolean) => {
    try {
      await adminApi.setJobEnabled(job.name, enabled)
      message.success(`${job.name} 已${enabled ? '恢复' : '暂停'}`)
      reload()
    } catch (err) {
      message.error(apiError(err))
    }
  }

  const runNow = async (job: Job) => {
    try {
      const run = await adminApi.runJob(job.name)
      if (run.err) message.error(`执行失败：${run.err}`)
      else message.success(run.ok ?? '执行完成')
      reload()
    } catch (err) {
      message.error(apiError(err))
    }
  }

  const applyInterval = async (job: Job) => {
    const raw = (intervalDraft[job.name] ?? '').trim()
    if (!raw) return
    const secs = Number(raw)
    if (!Number.isInteger(secs) || secs < 60) {
      message.error('间隔需为 ≥60 的整数秒')
      return
    }
    try {
      await adminApi.setJobInterval(job.name, secs)
      message.success(`${job.name} 间隔已改为 ${secs}s`)
      setIntervalDraft((d) => ({ ...d, [job.name]: '' }))
      reload()
    } catch (err) {
      message.error(apiError(err))
    }
  }

  const applyParam = async (job: Job, p: JobParam) => {
    const draftKey = `${job.name}.${p.name}`
    const raw = (paramDraft[draftKey] ?? '').trim()
    if (!raw) return
    const v = Number(raw)
    if (!Number.isInteger(v) || v < p.min || v > p.max) {
      message.error(`${p.name} 需为 ${p.min}-${p.max} 的整数`)
      return
    }
    try {
      await adminApi.setJobParam(job.name, p.name, v)
      message.success(`${job.name}.${p.name} 已改为 ${v}${p.unit}，下次执行生效`)
      setParamDraft((d) => ({ ...d, [draftKey]: '' }))
      reload()
    } catch (err) {
      message.error(apiError(err))
    }
  }

  return (
    <>
      <Typography.Title level={4}>定时任务</Typography.Title>
      <Typography.Paragraph type="secondary" style={{ marginBottom: 16 }}>
        任务逻辑编译期内置于服务端（管理页是遥控器，不是 IDE）；开关、间隔与业务参数持久化在
        app_settings，改完下次执行生效，无需重启。account_purge 的冷静期在
        「服务配置 → 会话与账号」（ROVORTEX_DELETION_GRACE_DAYS，需重启）。
      </Typography.Paragraph>
      {jobs.map((job) => (
        <Card key={job.name} size="small" style={{ marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
            <div style={{ minWidth: 260, flex: '0 0 auto' }}>
              <Typography.Text strong style={{ fontFamily: 'monospace' }}>
                {job.name}
              </Typography.Text>
              <div style={{ color: 'rgba(128,128,128,0.9)', fontSize: 12 }}>{job.doc}</div>
            </div>
            <div>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                间隔（秒）
              </Typography.Text>
              <div style={{ display: 'flex', gap: 4 }}>
                <Input
                  size="small"
                  style={{ width: 90, fontFamily: 'monospace' }}
                  placeholder={String(job.interval_secs)}
                  value={intervalDraft[job.name] ?? ''}
                  onChange={(e) => setIntervalDraft((d) => ({ ...d, [job.name]: e.target.value }))}
                  onPressEnter={() => applyInterval(job)}
                />
                <Button size="small" onClick={() => applyInterval(job)}>
                  改
                </Button>
              </div>
            </div>
            {job.params.map((p) => (
              <div key={p.name}>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {p.doc}（{p.name}，{p.min}-{p.max} {p.unit}）
                </Typography.Text>
                <div style={{ display: 'flex', gap: 4 }}>
                  <Input
                    size="small"
                    style={{ width: 90, fontFamily: 'monospace' }}
                    placeholder={String(p.value)}
                    value={paramDraft[`${job.name}.${p.name}`] ?? ''}
                    onChange={(e) =>
                      setParamDraft((d) => ({ ...d, [`${job.name}.${p.name}`]: e.target.value }))
                    }
                    onPressEnter={() => applyParam(job, p)}
                  />
                  <Button size="small" onClick={() => applyParam(job, p)}>
                    改
                  </Button>
                </div>
              </div>
            ))}
            <div style={{ minWidth: 220, flex: '1 1 auto' }}>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                上次执行
              </Typography.Text>
              <div style={{ fontSize: 13 }}>
                {job.last_run ? (
                  <>
                    {fmtAgo(job.last_run.at)} · {job.last_run.elapsed_ms}ms ·{' '}
                    {job.last_run.err ? (
                      <Typography.Text type="danger">失败</Typography.Text>
                    ) : (
                      <Typography.Text type="success">成功</Typography.Text>
                    )}
                    <div style={{ color: 'rgba(128,128,128,0.8)', fontSize: 12, fontFamily: 'monospace' }}>
                      {job.last_run.err ?? job.last_run.ok}
                    </div>
                  </>
                ) : (
                  <Typography.Text type="secondary">尚未执行</Typography.Text>
                )}
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Popconfirm
                title="立即执行一次该任务？"
                onConfirm={() => runNow(job)}
                okText="执行"
                cancelText="取消"
              >
                <Button size="small" icon={<CaretRightOutlined />} disabled={!job.enabled}>
                  立即运行
                </Button>
              </Popconfirm>
              <Switch
                checked={job.enabled}
                checkedChildren="运行"
                unCheckedChildren="暂停"
                onChange={(v) => toggle(job, v)}
              />
            </div>
          </div>
        </Card>
      ))}
    </>
  )
}
