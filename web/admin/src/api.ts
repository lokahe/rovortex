import axios, { AxiosError } from 'axios'

const api = axios.create({
  // 同源相对路径：dev 由 Vite 代理转发（vite.config.ts 的 VITE_PROXY_TARGET 选后端），
  // 生产构建同源部署到网关；避免 CORS 预检白名单问题。
  baseURL: '',
})

const ACCESS_KEY = 'rovortex_admin_access'
const REFRESH_KEY = 'rovortex_admin_refresh'

export const tokens = {
  get access() {
    return localStorage.getItem(ACCESS_KEY)
  },
  get refresh() {
    return localStorage.getItem(REFRESH_KEY)
  },
  set(access: string, refresh: string) {
    localStorage.setItem(ACCESS_KEY, access)
    localStorage.setItem(REFRESH_KEY, refresh)
  },
  clear() {
    localStorage.removeItem(ACCESS_KEY)
    localStorage.removeItem(REFRESH_KEY)
  },
}

api.interceptors.request.use((config) => {
  if (tokens.access) {
    config.headers.Authorization = `Bearer ${tokens.access}`
  }
  return config
})

let refreshing: Promise<boolean> | null = null

async function tryRefresh(): Promise<boolean> {
  const refresh = tokens.refresh
  if (!refresh) return false
  try {
    const res = await axios.post(`/api/auth/refresh`, { refresh_token: refresh })
    tokens.set(res.data.token, res.data.refresh_token)
    return true
  } catch {
    tokens.clear()
    return false
  }
}

api.interceptors.response.use(
  (res) => res,
  async (err: AxiosError) => {
    const original = err.config as (typeof err.config & { _retried?: boolean }) | undefined
    const isAuthEndpoint =
      original?.url?.includes('/api/users/login') || original?.url?.includes('/api/auth/refresh')
    if (err.response?.status === 401 && original && !original._retried && !isAuthEndpoint) {
      original._retried = true
      refreshing ??= tryRefresh()
      const ok = await refreshing
      refreshing = null
      if (ok) {
        return api(original)
      }
      window.location.href = '/admin/login'
    }
    return Promise.reject(err)
  },
)

export function apiError(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const msg = err.response?.data?.error?.message
    if (typeof msg === 'string') return msg
    return err.message
  }
  return String(err)
}

export interface LoginResult {
  user: { id: string; username: string; email: string; email_verified: boolean }
  token: string
  refresh_token: string
  refresh_expires_at: string
}

export async function login(login: string, password: string): Promise<LoginResult> {
  const res = await api.post<LoginResult>('/api/users/login', { login, password })
  tokens.set(res.data.token, res.data.refresh_token)
  return res.data
}

export interface AdminUser {
  id: string
  username: string
  email: string
  email_verified: boolean
  is_admin: boolean
  banned: boolean
  created_at: string
  updated_at: string
}

export interface ListUsersResult {
  users: AdminUser[]
  total: number
  page: number
  per_page: number
}

export const adminApi = {
  listUsers: (q: string | undefined, page: number, perPage: number) =>
    api
      .get<ListUsersResult>('/api/admin/users', {
        params: { q, page, per_page: perPage },
      })
      .then((r) => r.data),

  userDetail: (id: string) =>
    api.get<AdminUser & { identities: { provider: string; provider_uid: string; email: string | null; created_at: string }[]; audit_logs: { action: string; detail: string; client_ip: string; created_at: string }[] }>(
      `/api/admin/users/${id}`,
    ).then((r) => r.data),

  setBan: (id: string, banned: boolean) =>
    api.put(`/api/admin/users/${id}/ban`, { banned }),

  stats: () =>
    api
      .get<{ since: string; total_users: number; events: [string, number][] }>(
        '/api/admin/stats',
      )
      .then((r) => r.data),

  logs: (query: string) =>
    api
      .get<{ logs: { ts: string; level: string; target: string; message: string; request_id?: string; method?: string; path?: string; status?: number; elapsed_ms?: number }[] }>(
        `/api/admin/logs${query}`,
      )
      .then((r) => r.data),

  dbTables: () =>
    api
      .get<{ name: string; rows: number }[]>('/api/admin/db/tables')
      .then((r) => r.data),

  dbBrowse: (
    table: string,
    page: number,
    perPage: number,
    opts?: { sort?: string; order?: 'asc' | 'desc'; q?: string },
  ) =>
    api
      .get<{
        table: string
        columns: { name: string; data_type: string }[]
        rows: Record<string, unknown>[]
        total: number
        page: number
        per_page: number
      }>(`/api/admin/db/tables/${table}`, {
        params: {
          page,
          per_page: perPage,
          sort: opts?.sort,
          order: opts?.order,
          q: opts?.q || undefined,
        },
      })
      .then((r) => r.data),

  dbInsertRow: (table: string, columns: Record<string, unknown>) =>
    api
      .post<{ id: string }>(`/api/admin/db/tables/${table}`, { columns })
      .then((r) => r.data),

  dbUpdateRow: (table: string, id: string, columns: Record<string, unknown>) =>
    api
      .put<{ updated: number }>(`/api/admin/db/tables/${table}/${id}`, { columns })
      .then((r) => r.data),

  dbDeleteRow: (table: string, id: string) =>
    api
      .delete<{ deleted: number }>(`/api/admin/db/tables/${table}/${id}`)
      .then((r) => r.data),

  config: () =>
    api
      .get<{
        entries: { key: string; value: string; secret: boolean; doc: string; wired: boolean; group: string }[]
        available_keys: string[]
        modified_at: string | null
      }>('/api/admin/config')
      .then((r) => r.data),

  updateConfig: (values: Record<string, string>) =>
    api
      .put<{ updated: number }>('/api/admin/config', { values })
      .then((r) => r.data),

  restartConfig: () =>
    api
      .post<{ restarted: boolean }>('/api/admin/config/restart', null, { timeout: 8000 })
      .then((r) => r.data),

  jobs: () =>
    api
      .get<{
        name: string
        doc: string
        interval_secs: number
        enabled: boolean
        last_run?: { at: string; elapsed_ms: number; ok?: string; err?: string }
        params: { name: string; doc: string; value: number; default: number; min: number; max: number; unit: string }[]
      }[]>('/api/admin/jobs')
      .then((r) => r.data),

  setJobEnabled: (name: string, enabled: boolean) =>
    api.put<{ name: string; enabled: boolean }>(`/api/admin/jobs/${name}/enabled`, { enabled }).then((r) => r.data),

  setJobInterval: (name: string, interval_secs: number) =>
    api
      .put<{ name: string; interval_secs: number }>(`/api/admin/jobs/${name}/interval`, { interval_secs })
      .then((r) => r.data),

  setJobParam: (name: string, param: string, value: number) =>
    api
      .put<{ name: string; param: string; value: number }>(`/api/admin/jobs/${name}/param`, { name: param, value })
      .then((r) => r.data),

  runJob: (name: string) =>
    api
      .post<{ at: string; elapsed_ms: number; ok?: string; err?: string }>(`/api/admin/jobs/${name}/run`)
      .then((r) => r.data),

  metricsHistory: (minutes: number) =>
    api
      .get<{ points: { ts: number; total: number; errors: number; avg_ms: number }[] }>(
        '/api/admin/metrics/history',
        { params: { minutes } },
      )
      .then((r) => r.data),
}
