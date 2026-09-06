import { SessionClient, type ModuleClient } from 'tlsclientwrapper'
import { acquireModuleClient } from './tlsClientPool'
import { fetch as undiciFetch, type RequestInit as UndiciRequestInit } from 'undici'
import { RegistrationConfig } from './config'
import { BrowserIdentity, randomIdentity } from './browser-identity'
import { ChainProxyRelay } from './chainProxy'
import { FingerprintContext, newFPContext, resetPerfTiming, generateFingerprint } from './fingerprint'
import { encryptPassword } from './jwe'
import { refreshAppJSConfig } from './xxtea'
import {
  visitorId, awsccc, ubidGen, newUUID, gmtDate,
  extractParam, splitAfter, saveCookies,
  getNestedMap, getNestedStringMap
} from './http-utils'
import {
  TempEmailService, MoEmailService, TempMailPlusService, ProtonWebviewService, GptMailService,
  ICloudFeedService, parseOutlookLines, parseICloudLines, getInboxCount, waitForOTP
} from './email-service'
import { solveAmsCaptcha } from './ams-captcha-window'
import {
  webVisorJWT, newVisitorUUID, postFingerprintMetricSafe, postD2CEventSafe,
  postKatalNexusSafe, katalSignupBatch, katalVerificationBatch,
  type TelemetryContext
} from './telemetry'
import { getSystemProxy, safeCreateProxyAgent } from '../proxy/systemProxy'
import { redactString } from '../utils/redact'
// 验活用量查询与账号管理器共用同一套 UA / 端点，避免版本号漂移导致 Builder ID 403
import { getKiroUserAgent, getKiroAmzUserAgent, qServiceEndpoint } from '../kiroEndpoints'
import { KIRO_BUILDER_ID_PLACEHOLDER_ARN } from '../kiroAuthSync'

export type LogFn = (message: string) => void

/**
 * 发往 AWS（signin / profile / portal）的 Accept-Language。
 *
 * 必须以英文为首语言：AWS WAF 会对**主语言为中文**的请求下发 challenge ——
 * `/platform/<dir>/api/execute` 返回 `202` + 空 body + `x-amzn-waf-action: challenge`，
 * 注册流在 WorkflowInit / SubmitEmail 直接卡死。
 *
 * 实测（同一出口 IP、同一 JA3 指纹，每个取值重复 3 次）：
 *   zh-CN,zh;q=0.9,en;q=0.8  → 3/3 challenge   ← 修复前的取值
 *   zh-CN / zh-CN,zh;q=0.9   → 3/3 challenge
 *   en-US,en;q=0.9           → 3/3 通过 (200)
 *   en-US,en;q=0.9,zh-CN;q=0.8 → 3/3 通过（中文可作为次语言保留）
 *   ja-JP,ja;q=0.9           → 3/3 通过（可见并非"非英文即拦"，是专门针对中文首语言）
 *   删除该 header            → 3/3 通过
 *
 * 注意：只改发往 AWS 的请求。取码源（assurivo / GPTmail 等中文站点）仍用 zh-CN，
 * 那边不存在这条规则，改成英文反而与其站点语境不符。
 * 另外 `i18next=zh-CN` cookie 实测无影响（AL=en-US 时带上仍 3/3 通过），故保留不动。
 */
const AWS_ACCEPT_LANGUAGE = 'en-US,en;q=0.9'

/**
 * SetPassword 的整体超时。
 * 其余非幂等步骤统一 55s，但这一步可能内含 AMS 人机校验：静默通过通常几秒，
 * 一旦脚本判定需要人工点选，就得留出真人操作时间，否则窗口刚弹出就被判超时。
 * 与 AMS 求解自身的超时（solveAmsCaptcha 默认 120s）留出余量。
 */
const SET_PASSWORD_TIMEOUT = 180000

export interface FingerprintSnapshot {
  chromeVer: string
  ua: string
  gpuVendor: string
  gpuModel: string
  canvasHash: number
  screen: { width: number; height: number }
  /** 注册时使用的出口代理 URL（脱敏前缀） */
  proxyUrl?: string
  /** 探测到的出口 IP（注册时实际用的公网 IP） */
  exitIP?: string
}

export interface RegistrationResult {
  status: 'success' | 'failed'
  email: string
  password?: string
  error?: string
  clientId?: string
  clientSecret?: string
  refreshToken?: string
  accessToken?: string
  region?: string
  provider?: string
  verify?: Record<string, unknown>
  /** 本次注册使用的指纹摘要（用于审计与后续复用） */
  fingerprint?: FingerprintSnapshot
  /**
   * 本次失败是因为 AMS 人机校验拦截。
   *
   * 实测：是否下发校验与出口 IP 强相关且带随机性 —— 同一账号换出口后常可直接放行
   * （两组各 5/8 次探测里都出现过免校验的出口）。因此外层拿到这个标记时，
   * 应当换一个出口代理重跑，而不是当成普通失败计入重试上限或直接放弃。
   */
  captchaBlocked?: boolean
}

type StepFn = () => Promise<void>

/** 注册流程的可观察「阶段」标识，供前端按 taskId 实时显示进度 */
export type RegStepName =
  | 'init' | 'proxy-chain-ready' | 'tls-ready' | 'exit-ip'
  | 'oidc' | 'device' | 'email-created'
  | 'portal' | 'workflow-init' | 'submit-email'
  | 'signup' | 'send-otp' | 'waiting-otp' | 'otp-received'
  | 'create-identity' | 'set-password' | 'sso-workflow' | 'sso-token'
  // AMS 人机校验：captcha-solving 为开始求解，captcha-interactive 表示需要用户手工完成
  | 'captcha-solving' | 'captcha-interactive'
  // 邮箱已存在时改走验证码登录找回
  | 'email-otp-login'
  | 'verify-alive' | 'done'

export interface RegStepEvent {
  name: RegStepName
  ts: number
  email?: string
  exitIp?: string
  extra?: Record<string, unknown>
}

export type StepFn2 = (event: RegStepEvent) => void

export class Registrar {
  private cfg: RegistrationConfig
  private session: SessionClient | null = null
  /** 共享的 ModuleClient（来自 tlsClientPool）；不在 cleanup 中 terminate，由进程退出时统一释放 */
  private moduleClient: ModuleClient | null = null
  private cookies = new Map<string, string>()
  private identity: BrowserIdentity
  private fpCtx: FingerprintContext
  private vid: string

  private email = ''
  private emailSvc: TempEmailService | null = null
  private clientId = ''
  private clientSecret = ''
  private deviceCode = ''
  private userCode = ''
  private workflowHandle = ''
  private workflowId = ''
  private workflowState = ''
  private ubid = ''
  private regCode = ''
  private signState = ''
  private authCode = ''
  private ssoState = ''
  private wdcCSRFToken = ''
  private ssoToken = ''
  private outlookMailCount = 0
  /** step6 在「邮箱已存在」时返回的 stepId，决定能否走邮箱 OTP 登录找回 */
  private loginStepId = ''
  // 遥测用耗时锚点：真实浏览器上报的是各阶段真实耗时，写死常量容易成为特征
  private lastD2CFetchMs = 0
  private profilePageStartedAt = 0
  private profileEmailStartedAt = 0
  private profileVerificationStartedAt = 0

  private log: LogFn
  private onStep: StepFn2
  private abortController = new AbortController()
  private chainRelay: ChainProxyRelay | null = null
  private chainTargetProxy = ''
  private exitIP = ''
  private readonly tlsSessionId = newUUID() // 固定：整个 Registrar 生命周期内 DLL 中只注册一个 session

  constructor(cfg: RegistrationConfig, log?: LogFn, onStep?: StepFn2) {
    this.cfg = cfg
    this.identity = randomIdentity()
    this.fpCtx = newFPContext(this.identity)
    this.vid = visitorId()
    // 注册日志会推送到 UI / 控制台，统一脱敏代理账密、token 等敏感片段
    const rawLog = log || ((msg: string): void => console.log(msg))
    this.log = (msg: string): void => rawLog(redactString(msg))
    this.onStep = onStep || ((): void => {})
  }

  /** 触发 step 事件：上层（前端 UI）可据此实时展示注册到了哪一步。失败时静默以不影响主流程。 */
  private emitStep(name: RegStepName, info?: Partial<RegStepEvent>): void {
    try {
      this.onStep({ name, ts: Date.now(), email: this.email || undefined, exitIp: this.exitIP || undefined, ...info })
    } catch { /* ignore */ }
  }

  /** 基于当前 identity 的 sec-ch-ua 头（动态生成，跟 chromeVer 对齐） */
  private get secUA(): string {
    const major = this.identity.chromeVer.split('.')[0]
    return `"Chromium";v="${major}", "Not/A)Brand";v="24", "Google Chrome";v="${major}"`
  }

  /** 中止当前注册流程 */
  abort(): void {
    this.abortController.abort()
  }

  /**
   * 启用代理链：若同时配置了 upstreamProxy(上游中转) 与 proxy(目标代理)，
   * 在本机起一个中继把链路串成「本机 → 中继 → 上游中转(非大陆) → 目标代理 → 目标站点」，
   * 并把 cfg.proxy 指向本地中继，使后续所有请求自动走链路。
   */
  private async setupProxyChain(): Promise<void> {
    const target = (this.cfg.proxy || '').trim()
    const upstream = (this.cfg.upstreamProxy || '').trim()
    if (!target || !upstream) return
    try {
      this.chainRelay = new ChainProxyRelay(upstream, target, (m) => this.log(m))
      const relayUrl = await this.chainRelay.start()
      this.chainTargetProxy = target
      this.cfg.proxy = relayUrl
      this.log('[ProxyChain] 已启用代理链：本机 → 上游中转 → 目标代理 → 目标站点')
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      this.chainRelay = null
      // 严格代理模式下，链路失败必须立刻中止，防止"回退仅用目标代理"时大陆 IP 被目标拒绝
      if (this.cfg.strictProxy) {
        throw new Error(`[ProxyChain] 启用失败，严格代理模式已中止: ${msg}`)
      }
      this.log(`[ProxyChain] 启用失败，回退为直接使用目标代理: ${msg}`)
    }
  }

  private checkAborted(): void {
    if (this.abortController.signal.aborted) throw new Error('注册已取消')
  }

  /**
   * 探测当前代理的出口 IP 并写入日志。
   * 如果探测失败且代理 URL 是参数化格式（bestproxy 等），自动换 session 重建代理链重试。
   * 最多重试 maxRetries 次（默认 2），保证拿到可用出口再继续注册。
   */
  private async detectExitIP(maxRetries = 2): Promise<void> {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const proxyUrl = this.sessionOpts.proxyUrl
      try {
        const agent = safeCreateProxyAgent(proxyUrl)
        const resp = await undiciFetch('https://api.ipify.org?format=json', {
          method: 'GET',
          dispatcher: agent || undefined,
          signal: AbortSignal.timeout(10000),
          headers: { 'User-Agent': this.identity.ua }
        } as UndiciRequestInit)
        if (resp.ok) {
          const body = await resp.json() as Record<string, unknown>
          const ip = String(body.ip || body.query || body.origin || '').trim()
          if (ip) {
            this.exitIP = ip
            this.emitStep('exit-ip', { exitIp: ip })
          }
          const via = proxyUrl ? proxyUrl.replace(/:([^:@/]+)@/, ':***@') : undefined
          this.log(`[✓ IP] 出口 IP: ${ip || '未知'}${via ? ` (via ${via})` : ' (直连)'}`)
          return // 成功，退出
        }
        this.log(`[IP] 出口 IP 检测失败: HTTP ${resp.status}`)
      } catch (err) {
        this.log(`[IP] 出口 IP 检测失败: ${err instanceof Error ? err.message : String(err)}`)
      }

      // 失败后尝试换 session 重建代理链
      if (attempt < maxRetries && this.canRefreshProxySession()) {
        this.log(`[IP] 换 session 重试 (${attempt + 1}/${maxRetries})...`)
        await this.refreshProxySession()
      }
    }
    // 所有重试都失败，继续注册（可能代理暂时不稳定但 TLS Client 走不同路径能通）
    this.log('[IP] 出口 IP 检测全部失败，继续注册流程')
  }

  /** 判断当前代理是否支持 session 轮换（参数化格式 + 含 _session- 或含 _area-/_life- 等） */
  private canRefreshProxySession(): boolean {
    const target = this.chainTargetProxy || this.cfg.proxy || ''
    return /_(area|life|city|state|region|country)-/i.test(target)
  }

  /** 重新随机 session 并重建代理链 */
  private async refreshProxySession(): Promise<void> {
    // 还原到原始目标代理 URL（代理链会把 cfg.proxy 替换为本地中继地址）
    const original = this.chainTargetProxy || this.cfg.proxy || ''
    if (!original) return

    // 替换或追加 _session-随机值
    const session = Array.from({ length: 8 }, () =>
      'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[Math.floor(Math.random() * 62)]
    ).join('')

    let newTarget: string
    if (/_session-[^_:@/]*/i.test(original)) {
      // 已有 _session-xxx → 替换
      newTarget = original.replace(/(_session-)[^_:@/]*/i, `$1${session}`)
    } else {
      // 没有 _session- → 在 : 或 @ 之前插入
      const atIdx = original.indexOf('@')
      const colonIdx = original.indexOf(':', original.indexOf('://') + 3)
      const insertPos = colonIdx > 0 && colonIdx < atIdx ? colonIdx : atIdx
      newTarget = original.slice(0, insertPos) + `_session-${session}` + original.slice(insertPos)
    }

    this.log(`[IP] 新 session: ${newTarget.replace(/:([^:@/]+)@/, ':***@')}`)

    // 停掉旧代理链
    if (this.chainRelay) {
      await this.chainRelay.stop()
      this.chainRelay = null
    }

    // 重建
    this.cfg.proxy = newTarget
    this.chainTargetProxy = ''
    await this.setupProxyChain()
  }

  /** TLS SessionClient 选项 */
  private get sessionOpts() {
    const explicit = (this.cfg.proxy && this.cfg.proxy.trim()) || undefined
    // 严格模式：必须有显式代理，禁止回退到环境变量/系统代理，防止裸奔真实 IP
    if (this.cfg.strictProxy) {
      if (!explicit) {
        throw new Error('严格代理模式：cfg.proxy 为空，已中止以防止裸奔直连')
      }
    }
    const proxyUrl = this.cfg.strictProxy
      ? explicit
      : (explicit
        || process.env.HTTPS_PROXY || process.env.https_proxy
        || process.env.HTTP_PROXY || process.env.http_proxy
        || getSystemProxy() || undefined)
    return {
      tlsClientIdentifier: 'chrome_146' as const,
      // 25s：AWS 注册 API 正常响应 1-5s，慢住宅代理 10-15s；超过基本是挂起。
      // 配合 sendRequest 的 3 次重试，单步最坏 ~75s（旧值 60s 会到 ~180s，是批量卡 1-5 分钟主因）
      timeoutSeconds: 25,
      followRedirects: true,
      insecureSkipVerify: true,
      // 多线程隔离：固定 sessionId 隔离 DLL 层面共享的 TLS session cache
      // 整个 Registrar 生命周期内用同一个 ID，避免 rebuildTlsClient 产生僵尸 session
      sessionId: this.tlsSessionId,
      proxyUrl
    }
  }

  /**
   * 初始化 TLS 客户端
   *
   * DLL 存储策略（按优先级，从高到低）：
   *   1. userData/tls-client/ — 应用用户数据目录（系统不会清理，**永久复用**）
   *   2. resources/ — 应用安装目录（打包资源，开发版可能不存在）
   *   3. tmpdir → 自动迁移到 userData（老版本兼容）
   *   4. GitHub 下载到 userData（最后兜底，仅首次）
   */
  private async initTlsClient(): Promise<void> {
    const { existingPath, downloadDir } = this.ensureTlsLib()
    const opts = existingPath
      ? { customLibraryPath: existingPath }
      : { customLibraryDownloadPath: downloadDir }
    // 共享池：首次注册才真正 open(DLL+worker pool)，之后所有注册秒级复用
    this.moduleClient = await acquireModuleClient(opts)
    this.log('[TLS] using shared ModuleClient, pool stats: ' + JSON.stringify(this.moduleClient.getPoolStats()))
    this.session = new SessionClient(this.moduleClient, this.sessionOpts)
  }

  /**
   * 确保 tls-client 共享库可用
   * @returns existingPath 已经存在的完整 DLL 文件路径（如有，传 customLibraryPath）
   *          downloadDir  需要下载到的目录（如未找到，传 customLibraryDownloadPath 让 tlsclientwrapper 自动下载）
   *
   * 优先放到 userData，避免被系统临时目录清理工具误删（之前用 tmpdir 会被清理）
   */
  private ensureTlsLib(): { existingPath?: string; downloadDir: string } {
    const os = require('os')
    const path = require('path')
    const fs = require('fs')
    const { app } = require('electron')

    const platform = os.platform()
    const arch = os.arch()
    let filename = 'tls-client-xgo-1.14.0-'
    if (platform === 'win32') {
      filename += (arch.includes('64') ? 'windows-amd64' : 'windows-386') + '.dll'
    } else if (platform === 'darwin') {
      filename += (arch === 'arm64' ? 'darwin-arm64' : 'darwin-amd64') + '.dylib'
    } else {
      filename += (arch === 'arm64' ? 'linux-arm64' : 'linux-amd64') + '.so'
    }

    // 1. userData 永久目录（首选）
    const userDataDir = app.getPath('userData')
    const tlsClientDir = path.join(userDataDir, 'tls-client')
    const finalPath = path.join(tlsClientDir, filename)

    // 确保目录存在
    try { fs.mkdirSync(tlsClientDir, { recursive: true }) } catch { /* ignore */ }

    // 已存在 → 直接复用
    if (fs.existsSync(finalPath)) {
      this.log('[TLS] Library reused from userData (persistent): ' + finalPath)
      return { existingPath: finalPath, downloadDir: tlsClientDir }
    }

    // 2. 从打包资源复制（安装包自带）
    const resourcePath = path.join(process.resourcesPath || '', filename)
    if (fs.existsSync(resourcePath)) {
      this.log('[TLS] Copying library from resources to userData (one-time): ' + resourcePath + ' -> ' + finalPath)
      try {
        fs.copyFileSync(resourcePath, finalPath)
        return { existingPath: finalPath, downloadDir: tlsClientDir }
      } catch (err) {
        this.log('[TLS] Failed to copy from resources: ' + (err as Error).message)
      }
    }

    // 3. 兼容老版本：检测 tmpdir 副本并迁移到 userData
    const tmpPath = path.join(os.tmpdir(), filename)
    if (fs.existsSync(tmpPath)) {
      this.log('[TLS] Migrating library from tmpdir to userData: ' + tmpPath + ' -> ' + finalPath)
      try {
        fs.copyFileSync(tmpPath, finalPath)
        return { existingPath: finalPath, downloadDir: tlsClientDir }
      } catch (err) {
        this.log('[TLS] Migration failed, will use tmpdir as fallback: ' + (err as Error).message)
        return { existingPath: tmpPath, downloadDir: tlsClientDir }
      }
    }

    // 4. 都没有 → 返回 downloadDir，让 tlsclientwrapper open() 自动下载到此目录（永久保存）
    this.log('[TLS] Library not found, will download from GitHub to userData (one-time): ' + tlsClientDir)
    return { downloadDir: tlsClientDir }
  }

  private async rebuildTlsClient(): Promise<void> {
    // 只重建轻量级的 SessionClient（新 TLS 连接），复用重量级的 ModuleClient（worker pool + DLL）
    // 之前的实现会 terminate + 重新 open ModuleClient，导致每次注册创建 2 个 worker pool
    try { await this.session?.destroySession() } catch { /* ignore */ }
    if (!this.moduleClient) {
      await this.initTlsClient()
      return
    }
    this.session = new SessionClient(this.moduleClient, this.sessionOpts)
  }

  /**
   * 用 undici 直接 fetch 静态资源（如 AWS signin app.js），绕过 tls-client。
   * 原因：tls-client 的 dll 是进程级单例，失败请求会污染其全局状态，
   * 导致后续重建 SessionClient 后仍报 "no tls client for modification check"。
   * 静态资源不需要 TLS 指纹伪装，直接用 Node/undici fetch 即可。
   */
  private async fetchAppJS(url: string, init?: RequestInit): Promise<Response> {
    const proxyUrl = (this.cfg.proxy && this.cfg.proxy.trim())
      || process.env.HTTPS_PROXY || process.env.https_proxy
      || process.env.HTTP_PROXY || process.env.http_proxy
      || getSystemProxy() || undefined
    const agent = safeCreateProxyAgent(proxyUrl)
    if (agent) {
      const resp = await undiciFetch(url, { ...(init as UndiciRequestInit), dispatcher: agent })
      return resp as unknown as Response
    }
    return await fetch(url, init)
  }

  private isRecoverableTlsClientError(err: unknown): boolean {
    if (!(err instanceof Error)) return false
    return err.message.includes('EOF')
      || err.message.includes('no tls client for modification check')
      || err.message.includes('failed to modify existing client')
  }

  /** 清理 TLS 客户端资源：仅销毁 SessionClient；ModuleClient 是进程级共享池，不再每次 terminate */
  private async cleanup(): Promise<void> {
    if (this.chainRelay) {
      try { await this.chainRelay.stop() } catch { /* ignore */ }
      this.chainRelay = null
    }
    if (this.session) {
      // destroySession 带 3 秒超时：Go runtime 的 idle connections 可能要等 60 秒才关闭
      const s = this.session
      this.session = null
      try {
        await Promise.race([
          s.destroySession(),
          new Promise(resolve => setTimeout(resolve, 3000))
        ])
      } catch { /* ignore */ }
    }
    // moduleClient 是共享引用，不能 terminate（会影响其它正在跑的注册）
    this.moduleClient = null
  }

  /** 公共销毁方法，供外部调用释放资源。同时 abort 所有进行中的异步操作。 */
  async destroy(): Promise<void> {
    this.abortController.abort()
    await this.cleanup()
  }

  // ============ HTTP 工具方法 ============

  private cookieString(): string {
    return Array.from(this.cookies.entries()).map(([k, v]) => `${k}=${v}`).join('; ')
  }

  private buildHeaders(referer: string, origin: string): Record<string, string> {
    const h: Record<string, string> = {
      'Accept': 'application/json, text/plain, */*',
      'Accept-Language': AWS_ACCEPT_LANGUAGE,
      'Accept-Encoding': 'gzip, deflate, br',
      'Content-Type': 'application/json',
      'User-Agent': this.identity.ua,
      'sec-ch-ua': this.secUA,
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors',
      'sec-fetch-site': 'same-origin'
    }
    if (referer) h['Referer'] = referer
    if (origin) h['Origin'] = origin
    if (this.cookies.size > 0) h['Cookie'] = this.cookieString()
    return h
  }

  private buildProfileHeaders(referer: string): Record<string, string> {
    const h: Record<string, string> = {
      'Accept': '*/*',
      'Accept-Language': AWS_ACCEPT_LANGUAGE,
      'Content-Type': 'application/json;charset=UTF-8',
      'User-Agent': this.identity.ua,
      'Origin': this.cfg.profileBase,
      'Referer': referer,
      'sec-ch-ua': this.secUA,
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors',
      'sec-fetch-site': 'same-origin',
      'priority': 'u=1, i'
    }
    const keys = ['awsccc', 'aws-user-profile-ubid', 'i18next']
    if (this.cookies.has('awsd2c-token')) keys.push('awsd2c-token', 'awsd2c-token-c')
    const parts = keys.filter((k) => this.cookies.has(k)).map((k) => `${k}=${this.cookies.get(k)}`)
    if (parts.length) h['Cookie'] = parts.join('; ')
    return h
  }

  private async doGet(url: string, headers: Record<string, string>): Promise<{ body: string; status: number; headers: Record<string, string | string[]> }> {
    return this.sendRequest('GET', url, headers)
  }

  private async doPost(url: string, payload: unknown, headers: Record<string, string>): Promise<{ body: string; status: number; headers: Record<string, string | string[]> }> {
    return this.sendRequest('POST', url, headers, JSON.stringify(payload))
  }

  /** 网络层退避时长：指数 + 抖动（约 0.8s / 1.6s / 3.2s，封顶 8s） */
  private netBackoffMs(attempt: number): number {
    const base = Math.min(800 * Math.pow(2, attempt - 1), 8000)
    return base + Math.floor(Math.random() * 400)
  }

  /**
   * 判断响应是否为「瞬时失败」需要重试。
   * 关键：tlsclientwrapper 会把连接层失败（EOF / 重置 / 超时）包装成 status=0 + body 错误描述，
   * 并不抛异常；若不在响应层识别，会被上层当成业务失败直接判死号（如 #9 的「未获取到加密公钥」）。
   */
  private isTransientResponse(status: number, body: string): boolean {
    if (status === 0 || status === 429 || status === 502 || status === 503 || status === 504) return true
    const lower = body.toLowerCase()
    return lower.includes('failed to do request') || lower.includes('eof')
      || lower.includes('connection reset') || lower.includes('timeout')
  }

  /**
   * 判断是否为「超时类」失败（出口 IP 慢 / 被限流 / 隧道挂起）。
   * 这类失败重建 TLS（同 IP 重连）无用，应换 proxy session 切换出口 IP。
   */
  private isTimeoutResponse(status: number, body: string): boolean {
    if (status === 504) return true
    if (status !== 0) return false
    const lower = body.toLowerCase()
    return lower.includes('timeout') || lower.includes('deadline')
      || lower.includes('client.timeout') || lower.includes('failed to do request')
  }

  /**
   * 统一的 TLS 请求发送：对瞬时网络失败（status=0 / EOF / 5xx / 429）自动「重建 TLS + 指数退避」重试。
   * 连接类失败才重建客户端，限流类仅退避；cookies 存于 this.cookies，不随重建丢失。
   */
  private async sendRequest(
    method: 'GET' | 'POST',
    url: string,
    headers: Record<string, string>,
    body?: string
  ): Promise<{ body: string; status: number; headers: Record<string, string | string[]> }> {
    if (!this.session) throw new Error('TLS 客户端未初始化')
    const maxAttempts = 3
    let lastErr: unknown = null
    let sessionRefreshed = false // 整个请求最多换 1 次 proxy session，避免频繁停建代理链
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const resp = method === 'GET'
          ? await this.session!.get(url, { headers })
          : await this.session!.post(url, body ?? '', { headers })
        const decoded = this.decodeBody(resp.body)
        const status = resp.status
        if (attempt < maxAttempts && this.isTransientResponse(status, decoded)) {
          const broken = status === 0 || /eof|reset|failed to do request/i.test(decoded)
          // 超时类（出口 IP 慢/被限/隧道挂起）：重建 TLS 同 IP 无用，换 proxy session 切换出口 IP
          if (this.isTimeoutResponse(status, decoded) && !sessionRefreshed && this.canRefreshProxySession()) {
            this.log(`[Net] ${method} 超时(status=${status})，换 proxy session 切换出口 IP 重试 ${attempt}/${maxAttempts - 1}`)
            try {
              await this.refreshProxySession()
              await this.rebuildTlsClient()
              sessionRefreshed = true
            } catch (e) {
              this.log(`[Net] 换 session 失败，回退普通重建: ${e instanceof Error ? e.message : String(e)}`)
              await this.rebuildTlsClient()
            }
          } else {
            this.log(`[Net] ${method} 瞬时失败 status=${status}，${broken ? '重建 TLS + ' : ''}退避重试 ${attempt}/${maxAttempts - 1}`)
            if (broken) await this.rebuildTlsClient()
          }
          await this.abortableSleep(this.netBackoffMs(attempt))
          continue
        }
        return { body: decoded, status, headers: (resp.headers || {}) as Record<string, string | string[]> }
      } catch (err: unknown) {
        lastErr = err
        if (attempt < maxAttempts && this.isRecoverableTlsClientError(err)) {
          this.log(`[TLS] ${method} 可恢复错误：${err instanceof Error ? err.message : String(err)}，重建 TLS 退避重试 ${attempt}/${maxAttempts - 1}`)
          await this.rebuildTlsClient()
          await this.abortableSleep(this.netBackoffMs(attempt))
          continue
        }
        throw err
      }
    }
    if (lastErr) throw lastErr
    throw new Error(`${method} ${url} 重试 ${maxAttempts} 次仍失败`)
  }

  /** 可被中止打断的 sleep：停止注册时立即结束等待，让 abort 即时生效 */
  private abortableSleep(ms: number): Promise<void> {
    const signal = this.abortController.signal
    return new Promise((resolve, reject) => {
      if (signal.aborted) { reject(new Error('注册已取消')); return }
      let timer: ReturnType<typeof setTimeout>
      const onAbort = (): void => { clearTimeout(timer); reject(new Error('注册已取消')) }
      timer = setTimeout(() => { signal.removeEventListener('abort', onAbort); resolve() }, ms)
      signal.addEventListener('abort', onAbort, { once: true })
    })
  }

  /** 拟人随机延迟：步骤之间停顿，降低机械化节奏特征 */
  private async humanDelay(min = 280, max = 1200): Promise<void> {
    await this.abortableSleep(min + Math.floor(Math.random() * Math.max(1, max - min)))
  }

  /**
   * 整体超时看门狗：给任意步骤 Promise 加上限，超时后 reject（原 Promise 在后台自生自灭）。
   * 用于批量场景快速释放卡住的线程，避免单个账号占用并发槽 1-5 分钟。支持 abort 即时中断。
   */
  private withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
    const signal = this.abortController.signal
    return new Promise<T>((resolve, reject) => {
      if (signal.aborted) { reject(new Error('注册已取消')); return }
      let done = false
      const settle = (fn: () => void): void => {
        if (done) return
        done = true
        clearTimeout(timer)
        signal.removeEventListener('abort', onAbort)
        fn()
      }
      const timer = setTimeout(() => settle(() => reject(new Error(`${label} 整体超时 ${Math.round(ms / 1000)}s`))), ms)
      const onAbort = (): void => settle(() => reject(new Error('注册已取消')))
      signal.addEventListener('abort', onAbort, { once: true })
      p.then(
        (v) => settle(() => resolve(v)),
        (e) => settle(() => reject(e))
      )
    })
  }

  /**
   * 幂等步骤重试：失败后退避重试（仅用于无副作用的前置步骤，如 OIDC / Device / Portal / WorkflowInit）。
   * - timeoutMs：每次尝试加整体超时看门狗，超时即判失败进入下一次（防止单次卡满 3×25s）
   * - refreshSession：失败后若代理支持，换 proxy session 切换出口 IP 再退避（避开慢/被限的 IP）
   */
  private async retryStep(
    name: string,
    fn: StepFn,
    attempts: number,
    opts?: { timeoutMs?: number; refreshSession?: boolean }
  ): Promise<void> {
    let lastErr: unknown = null
    for (let i = 1; i <= attempts; i++) {
      try {
        if (opts?.timeoutMs) await this.withTimeout(fn(), opts.timeoutMs, name)
        else await fn()
        return
      } catch (err) {
        lastErr = err
        if (i < attempts) {
          // 幂等步骤失败：若支持换 session，先切换出口 IP 再退避（针对慢/被限的住宅 IP）
          if (opts?.refreshSession && this.canRefreshProxySession()) {
            try {
              await this.refreshProxySession()
              await this.rebuildTlsClient()
              this.log(`[${name}] 已换 proxy session 切换出口 IP`)
            } catch { /* 换 session 失败则继续普通重试 */ }
          }
          const wait = 1500 * i + Math.floor(Math.random() * 800)
          this.log(`[${name}] 第 ${i}/${attempts} 次失败：${(err as Error).message}，${wait}ms 后重试`)
          await this.abortableSleep(wait)
        }
      }
    }
    throw lastErr
  }

  /**
   * tls-client 返回的 body 是字节透传字符串（latin1）；
   * 如果响应实际是 UTF-8 编码（含中文等多字节），需要二次解码。
   * 实现：把 string 当作 latin1 字节读回，再用 UTF-8 解码；
   * 若解码后含 U+FFFD 替换字符比原文多很多，则回退原值（说明原本就是 latin1 / ASCII）。
   */
  private decodeBody(body: string | undefined | null): string {
    if (!body) return ''
    try {
      // 快速路径：纯 ASCII 直接返回
      // eslint-disable-next-line no-control-regex
      if (/^[\x00-\x7F]*$/.test(body)) return body
      const buf = Buffer.from(body, 'latin1')
      const utf8 = buf.toString('utf-8')
      // 检测 mojibake：原文如果在 latin1 解码 UTF-8 字节，会出现大量字符在 \u00a0-\u00ff 区间
      // 重解后如果替换字符数量明显多于原文，说明不是 UTF-8，回退原值
      const replaceInOriginal = (body.match(/\uFFFD/g) || []).length
      const replaceInUtf8 = (utf8.match(/\uFFFD/g) || []).length
      if (replaceInUtf8 > replaceInOriginal + 2) return body
      return utf8
    } catch {
      return body
    }
  }

  private parseBody(body: string): Record<string, unknown> {
    try { return JSON.parse(body) } catch { return {} }
  }

  /**
   * 识别 AWS 风控触发的错误响应，返回人类可读的标签
   * @returns 风控类型标签（如 'AWS-RISK-CONTROL'），不是风控返回 null
   */
  private detectRiskControl(body: string, status: number): string | null {
    if (status !== 400) return null
    const lower = body.toLowerCase()
    // 中文消息（已正确解码）
    if (body.includes('请稍后再试') && body.includes('管理员')) return 'AWS-RISK-CONTROL'
    if (body.includes('发生意外错误')) return 'AWS-RISK-CONTROL'
    // 英文消息
    if (lower.includes('try again later') && lower.includes('administrator')) return 'AWS-RISK-CONTROL'
    if (lower.includes('unexpected error') && lower.includes('contact')) return 'AWS-RISK-CONTROL'
    return null
  }

  /** 把响应错误格式化为更友好的消息（含风控识别） */
  private formatErrorBody(body: string, status: number): string {
    const risk = this.detectRiskControl(body, status)
    if (risk) {
      return `${risk}（AWS 风控，建议：1) 启用代理池 N:1 分桶；2) 启用限速 + 风控自动暂停；3) 避免同邮箱域名大量注册）`
    }
    return `status=${status} body=${body.substring(0, 200)}`
  }

  private async fetchD2CToken(origin: string, referer: string): Promise<void> {
    const headers: Record<string, string> = {
      'Accept': '*/*', 'Content-Type': 'application/json',
      'User-Agent': this.identity.ua, 'Origin': origin, 'Referer': referer,
      'sec-ch-ua': this.secUA, 'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors', 'sec-fetch-site': 'cross-site', 'priority': 'u=1, i'
    }
    const parts: string[] = []
    if (this.cookies.has('awsccc')) parts.push('awsccc=' + this.cookies.get('awsccc'))
    if (this.cookies.has('awsd2c-token')) {
      const old = this.cookies.get('awsd2c-token')!
      parts.push('awsd2c-token=' + old, 'awsd2c-token-c=' + old)
    }
    if (parts.length) headers['Cookie'] = parts.join('; ')

    // 真实浏览器（HAR 34/63）每次都本地生成一个自签 ES256 JWT {vid, iss:"s_p"} 提交，
    // 并把其中的 vid 作为后续所有 api/execute 的 visitorId。
    // 此前首次调用提交空 body（没有 awsd2c-token 时 payload 为 {}），与浏览器行为不一致，
    // 是可被风控识别的差异点 —— 会推高 SetPassword 被下发人机校验的概率。
    const vid = newVisitorUUID()
    const payload: Record<string, string> = { token: webVisorJWT(vid) }

    const t0 = Date.now()
    const resp = await this.doPost('https://vs.aws.amazon.com/token', payload, headers)
    this.lastD2CFetchMs = Date.now() - t0
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    const data = this.parseBody(resp.body)
    const tok = data.token as string
    if (tok) {
      this.cookies.set('awsd2c-token', tok)
      this.cookies.set('awsd2c-token-c', tok)
    }
    // visitorId 采用本地生成的 vid（与浏览器一致：后续请求复用同一 vid）
    this.vid = vid
  }

  /** 发送已序列化的请求体（供遥测发 form-urlencoded / text-plain 用） */
  private async doPostBody(
    url: string,
    body: string,
    headers: Record<string, string>
  ): Promise<{ body: string; status: number; headers: Record<string, string | string[]> }> {
    return this.sendRequest('POST', url, headers, body)
  }

  /** 组装遥测所需的上下文（复用注册链路的 tls-client 通道与请求头口径） */
  private telemetryCtx(): TelemetryContext {
    return {
      signinBase: this.cfg.signinBase,
      profileBase: this.cfg.profileBase,
      directoryId: this.cfg.directoryId,
      ua: this.identity.ua,
      secUA: this.secUA,
      email: this.email,
      workflowHandle: this.workflowHandle,
      workflowId: this.workflowId,
      regCode: this.regCode,
      signState: this.signState,
      postJson: async (url, payload, headers) => {
        const r = await this.doPost(url, payload, headers)
        return { status: r.status, body: r.body }
      },
      postRaw: async (url, body, headers) => {
        const r = await this.doPostBody(url, body, headers)
        return { status: r.status, body: r.body }
      },
      genFP: (page, eventType, inputLen, text) => this.genFP(page, eventType, inputLen, text),
      buildHeaders: (referer, origin) => this.buildHeaders(referer, origin),
      log: (m) => this.log(m)
    }
  }

  // ============ 指纹生成 ============

  private genFP(pageType: string, eventType: string, emailLen: number, emailAddr: string): string {
    return this.genFPWithTime(pageType, eventType, 0, emailLen, emailAddr)
  }

  private genFPWithTime(pageType: string, eventType: string, timeOnPage: number, emailLen: number, emailAddr: string): string {
    const did = this.cfg.directoryId
    let loc = '', ref = ''

    switch (pageType) {
      case 'signin':
        loc = `${this.cfg.signinBase}/platform/${did}/login?workflowStateHandle=${this.workflowHandle}`
        break
      case 'signup':
        loc = `${this.cfg.signinBase}/platform/${did}/signup?workflowStateHandle=${this.workflowHandle}`
        break
      default: // profile
        if (eventType === 'PageSubmit') {
          loc = `${this.cfg.profileBase}/?workflowID=${this.workflowId}#/signup/enter-email`
        } else {
          loc = `${this.cfg.profileBase}/?workflowID=${this.workflowId}#/signup/start`
        }
        if (!this.workflowId) loc = this.cfg.profileBase + '/'
    }

    if (pageType === 'profile') {
      ref = `${this.cfg.signinBase}/platform/${did}/signup?workflowStateHandle=${this.workflowHandle}`
    } else {
      ref = this.cfg.viewBase + '/'
    }

    return generateFingerprint(this.identity, loc, ref, this.fpCtx, pageType, eventType, timeOnPage, emailLen, emailAddr)
  }

  // ============ 注册步骤 ============

  private async step1OIDC(): Promise<void> {
    this.emitStep('oidc')
    this.log('[1] OIDC 注册')
    const payload = {
      clientName: 'Amazon Q Developer for command line',
      clientType: 'public',
      scopes: ['codewhisperer:completions', 'codewhisperer:analysis', 'codewhisperer:conversations', 'codewhisperer:transformations', 'codewhisperer:taskassist']
    }
    const headers = { 'Content-Type': 'application/json' }

    let resp: { body: string; status: number; headers: Record<string, string | string[]> } | null = null
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        resp = await this.doPost(this.cfg.oidcBase + '/client/register', payload, headers)
        if (resp.status === 200) break
      } catch (err: unknown) {
        if (attempt < 2) {
          this.log(`[1] OIDC 重试 (${attempt + 1}/3)...`)
          await this.abortableSleep(2000 * (attempt + 1))
          await this.rebuildTlsClient()
          continue
        }
        throw err
      }
    }
    if (!resp) throw new Error('OIDC 注册失败: 所有重试均失败')
    const data = this.parseBody(resp.body)
    this.clientId = (data.clientId as string) || ''
    this.clientSecret = (data.clientSecret as string) || ''
    if (!this.clientId) throw new Error(`OIDC 注册失败: ${resp.body.slice(0, 200)}`)
  }

  private async step2Device(): Promise<void> {
    this.emitStep('device')
    this.log('[2] 设备授权')
    const resp = await this.doPost(this.cfg.oidcBase + '/device_authorization', {
      clientId: this.clientId, clientSecret: this.clientSecret,
      startUrl: this.cfg.startURL
    }, { 'Content-Type': 'application/json' })
    const data = this.parseBody(resp.body)
    this.deviceCode = (data.deviceCode as string) || ''
    this.userCode = (data.userCode as string) || ''
    this.log(`user_code=${this.userCode}`)
  }

  private async step3Email(): Promise<void> {
    if (this.cfg.manualMode) return // 手动模式在外部设置

    if (this.cfg.useOutlook && this.cfg.outlookData) {
      this.log('[3] 使用 Outlook 邮箱')
      const accounts = parseOutlookLines(this.cfg.outlookData)
      if (accounts.length === 0) throw new Error('无可用的 Outlook 账号')
      // 单行 → 直接用（批量并发时前端已为每个 task 切一行，避免并发抢占）
      // 多行（单次注册）→ 随机挑一行
      const acc = accounts.length === 1
        ? accounts[0]
        : accounts[Math.floor(Math.random() * accounts.length)]
      this.email = acc.email
      this.emitStep('email-created')
      this.log(`email=${this.email}`)
      return
    }

    if (this.cfg.useTempMailPlus) {
      this.log('[3] 使用自建域名邮箱 (TempMail.Plus)')
      if (!this.cfg.tempMailPlusEmail || !this.cfg.tempMailPlusEpin || !this.cfg.tempMailPlusDomain) {
        throw new Error('TempMail.Plus 配置不完整')
      }
      this.emailSvc = new TempMailPlusService(
        this.cfg.tempMailPlusEmail, this.cfg.tempMailPlusEpin, this.cfg.tempMailPlusDomain
      )
      this.email = await this.emailSvc.create()
      if (!this.email) throw new Error('生成邮箱地址失败')
      this.emitStep('email-created')
      this.log(`email=${this.email}`)
      return
    }

    if (this.cfg.useProton) {
      this.log('[3] 使用 Proton 邮箱 (点号别名)')
      if (!this.cfg.protonEmail) {
        throw new Error('Proton 邮箱地址未配置')
      }
      this.emailSvc = new ProtonWebviewService(this.cfg.protonEmail, (m) => this.log(m))
      this.email = await this.emailSvc.create()
      if (!this.email) throw new Error('Proton 邮箱地址为空')
      this.emitStep('email-created')
      this.log(`email=${this.email}`)
      return
    }

    if (this.cfg.useGptMail) {
      const mode = this.cfg.gptMailInboxEmail
        ? `CF 转发 → ${this.cfg.gptMailInboxEmail}`
        : this.cfg.gptMailPrivatePassword ? '私有域名直收（带密码）' : '私有域名直收'
      this.log(`[3] 使用 GPTmail (${mode}) → mail.chatgpt.org.uk`)
      if (!this.cfg.gptMailDomain) {
        throw new Error('GPTmail 域名未配置')
      }
      // 复用注册流程已经初始化的 TLS SessionClient（伪装 Chrome 146 JA3 + 注入代理），
      // 否则 GPTmail 后端通过 TLS 指纹校验会返回 401 "Browser session required"
      if (!this.session) throw new Error('TLS SessionClient 未初始化，无法启动 GPTmail（请检查代理）')
      this.emailSvc = new GptMailService({
        baseURL: this.cfg.gptMailBaseURL,
        inboxEmail: this.cfg.gptMailInboxEmail,
        domain: this.cfg.gptMailDomain,
        prefix: this.cfg.gptMailPrefix,
        privatePassword: this.cfg.gptMailPrivatePassword,
        // 传 getter 而非快照：Registrar 后续 rebuildTlsClient() 会换 session 实例，
        // GptMailService 每次请求都读这里的最新引用，避免用到已 destroyed 的旧 session
        getSession: () => this.session
      })
      this.email = await this.emailSvc.create()
      if (!this.email) throw new Error('生成 GPTmail 注册邮箱失败')
      this.emitStep('email-created')
      this.log(`email=${this.email}`)
      return
    }

    if (this.cfg.useICloud) {
      this.log('[3] 使用 iCloud 邮箱 (assurivo 取件)')
      const accounts = parseICloudLines(this.cfg.icloudData)
      if (accounts.length === 0) throw new Error('无可用的 iCloud 账号（格式应为 邮箱----查询码）')
      // 单行 → 直接用（批量并发时前端已为每个 task 切一行，避免并发抢占）
      // 多行（单次注册）→ 随机挑一行
      const acc = accounts.length === 1
        ? accounts[0]
        : accounts[Math.floor(Math.random() * accounts.length)]
      this.emailSvc = new ICloudFeedService({
        baseURL: this.cfg.icloudBaseURL,
        email: acc.email,
        pwd: acc.pwd,
        limit: this.cfg.icloudLimit,
        log: (m) => this.log(m)
      })
      // create() 会打一次 feed.php：既校验查询码，又记录基线邮件
      this.email = await this.emailSvc.create()
      if (!this.email) throw new Error('iCloud 邮箱地址为空')
      this.emitStep('email-created')
      this.log(`email=${this.email}`)
      return
    }

    this.log('[3] 创建临时邮箱')
    if (!this.cfg.moEmailBaseURL) throw new Error('MoEmail 未配置')
    this.emailSvc = new MoEmailService(this.cfg.moEmailBaseURL, this.cfg.moEmailAPIKey)
    this.email = await this.emailSvc.create()
    if (!this.email) throw new Error('创建临时邮箱失败')
    this.emitStep('email-created')
    this.log(`email=${this.email}`)
  }

  private async step4Portal(): Promise<void> {
    this.emitStep('portal')
    this.log('[4] Portal 初始化')
    this.cookies.set('awsccc', awsccc())
    const redirect = `${this.cfg.viewBase}/start/#/device?user_code=${this.userCode}`
    const url = `${this.cfg.portalBase}/login?directory_id=view&redirect_url=${redirect}`

    const h: Record<string, string> = {
      'Accept': 'application/json, text/plain, */*',
      'Content-Type': 'application/json',
      'Origin': this.cfg.viewBase,
      'Referer': this.cfg.viewBase + '/',
      'User-Agent': this.identity.ua
    }
    const resp = await this.doGet(url, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    const data = this.parseBody(resp.body)

    const rurl = (data.redirectUrl as string) || ''
    if (rurl.includes('workflowStateHandle=')) {
      this.workflowHandle = splitAfter(rurl, 'workflowStateHandle=')
    }
    if (data.csrfToken) this.cookies.set('loginCsrfToken', data.csrfToken as string)
    if (!this.workflowHandle) throw new Error('Portal 未返回 workflow handle')

    const loginURL = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${this.workflowHandle}`
    await this.fetchD2CToken(this.cfg.signinBase, loginURL)
  }

  private async step5WorkflowInit(): Promise<void> {
    this.emitStep('workflow-init')
    this.log('[5] 工作流初始化')
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${this.workflowHandle}`

    let fp = this.genFP('signin', 'first_load', 0, '')
    let rid = newUUID()
    let h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    let resp = await this.doPost(api, {
      stepId: '', workflowStateHandle: this.workflowHandle,
      inputs: [{ input_type: 'FingerPrintRequestInput', fingerPrint: fp }],
      requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)

    // 真实浏览器在此处必发（HAR entry 21）：指纹已生成
    await postFingerprintMetricSafe(
      this.telemetryCtx(),
      'IsFingerprintGenerated:Success',
      this.genFP('signin', 'first_load', 0, ''),
      'AWSSignin:FingerprintMetrics:start'
    )

    let data = this.parseBody(resp.body)
    if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string

    if (data.stepId === 'start') {
      fp = this.genFP('signin', 'PageLoad', 0, '')
      rid = newUUID()
      h = this.buildHeaders(ref, this.cfg.signinBase)
      h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

      resp = await this.doPost(api, {
        stepId: 'start', workflowStateHandle: this.workflowHandle,
        inputs: [{ input_type: 'FingerPrintRequestInput', fingerPrint: fp }],
        requestId: rid
      }, h)
      saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
      data = this.parseBody(resp.body)
      if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string
    }

    // HAR entry 27：指纹文件已加载
    await postFingerprintMetricSafe(
      this.telemetryCtx(),
      'IsFingerprintFileLoaded:Success',
      '1',
      'AWSSignin:FingerprintMetrics:OnLoad_Username_Page'
    )
    // HAR entries 34/35/37：D2C visitor token 获取耗时（token 本身在 step4Portal 已取）
    await postD2CEventSafe(
      this.telemetryCtx(),
      `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${this.workflowHandle}`,
      this.lastD2CFetchMs
    )
  }

  private async step6SubmitEmail(): Promise<'signup' | 'login'> {
    this.emitStep('submit-email')
    this.log(`[6] 提交邮箱 ${this.email}`)
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${this.workflowHandle}`
    const fp = this.genFP('signin', 'PageSubmit', this.email.length, this.email)
    const rid = newUUID()
    const h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    const resp = await this.doPost(api, {
      stepId: 'get-identity-user', workflowStateHandle: this.workflowHandle,
      actionId: 'SUBMIT',
      inputs: [
        { input_type: 'UserRequestInput', username: this.email },
        { input_type: 'ApplicationTypeRequestInput', applicationType: 'SSO_INDIVIDUAL_ID' },
        {
          input_type: 'UserEventRequestInput', directoryId: this.cfg.directoryId,
          userName: this.email,
          userEvents: [{ input_type: 'UserEvent', eventType: 'PAGE_SUBMIT', pageName: 'IDENTIFICATION', timeSpentOnPage: 5000 }]
        },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      visitorId: this.vid, requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    const data = this.parseBody(resp.body)
    if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string
    // 已存在账号时服务端会告知该走哪种登录方式，记下来供 recoverByEmailOtp 判断
    this.loginStepId = (data.stepId as string) || ''

    if (resp.status === 400) return 'signup'
    if (resp.status === 200) return 'login'
    throw new Error(`提交邮箱失败: ${resp.status} - ${resp.body.slice(0, 200)}`)
  }

  /**
   * 邮箱 OTP 登录（找回已存在账号）。
   *
   * 场景：邮箱在 AWS 侧已建好身份（step6 返回 200 而非 400），此时走不了注册，
   * 但只要我们能收这个邮箱的验证码，就能直接登录拿到 token —— 对「注册中断留下的号」
   * 或「已注册但凭据丢失的号」都适用，等价于把它救回成可用账号。
   *
   * 协议（据线上 signin app.js）：
   *   step6 返回 stepId=get-email-otp-login-credential + workflowResponseData.mfaLoginOptionsResponse
   *   → 服务端此时**已自动发出**验证码邮件（无需我们再触发）
   *   → 提交 {actionId:'SUBMIT', inputs:[{input_type:'EmailOTPLoginRequestInput', emailOTPLoginResponseCode:<6位>}]}
   *   → 成功后 stepId=end-of-workflow-success + redirect.url（与注册流程 completeSignup 的产物一致）
   * 之后即可复用 step12_8SSOWorkflow / step13SSOToken 换 token。
   */

  /**
   * 判断某次失败是否由 AMS 人机校验造成。
   * 外层据此改为「换出口重试」而非计入普通重试次数。
   */
  private isCaptchaBlocked(msg: string): boolean {
    return /AMS captcha|人机校验|captcha 需要人工|图形验证码/.test(msg)
  }

  private async recoverByEmailOtp(): Promise<void> {
    this.emitStep('email-otp-login')
    this.log('[6.5] 该邮箱已存在账号，改走邮箱验证码登录找回')

    // 已设好密码的账号走密码登录（本项目生成的密码是确定的，可直接用）
    if (this.loginStepId === 'get-password') {
      await this.loginWithPassword()
      return
    }

    if (this.loginStepId !== 'get-email-otp-login-credential') {
      throw new Error(
        `该邮箱已注册过，且当前登录方式不是邮箱验证码（stepId=${this.loginStepId || '未知'}），无法自动找回`
      )
    }
    if (!this.emailSvc) {
      throw new Error('该邮箱已注册过；自动找回需要可取码的邮箱源（Outlook 模式暂不支持找回）')
    }

    // step6 的响应即代表验证码已发出，直接轮询取码
    this.log('[6.5] 等待登录验证码…')
    const otp = await this.emailSvc.waitForCode(180, 5, this.abortController.signal)
    this.log(`[6.5] 登录验证码: ${otp}`)

    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${this.workflowHandle}`
    const fp = this.genFP('signin', 'PageSubmit', otp.length, otp)
    const rid = newUUID()
    const h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    const resp = await this.doPost(api, {
      stepId: 'get-email-otp-login-credential',
      workflowStateHandle: this.workflowHandle,
      actionId: 'SUBMIT',
      inputs: [
        { input_type: 'EmailOTPLoginRequestInput', emailOTPLoginResponseCode: otp },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      visitorId: this.vid, requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    const data = this.parseBody(resp.body)

    if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string

    // 登录环节同样可能被要求人机校验
    const captchaRequest = await this.resolveCaptcha(data)
    if (captchaRequest) {
      const rid2 = newUUID()
      const h2 = this.buildHeaders(ref, this.cfg.signinBase)
      h2['x-amzn-requestid'] = rid2; h2['x-amz-date'] = gmtDate(); h2['priority'] = 'u=1, i'
      const retry = await this.doPost(api, {
        stepId: 'get-email-otp-login-credential',
        workflowStateHandle: this.workflowHandle,
        actionId: 'SUBMIT',
        inputs: [
          { input_type: 'EmailOTPLoginRequestInput', emailOTPLoginResponseCode: otp },
          { input_type: 'FingerPrintRequestInput', fingerPrint: this.genFP('signin', 'PageSubmit', otp.length, otp) }
        ],
        captchaRequest,
        visitorId: this.vid, requestId: rid2
      }, h2)
      saveCookies(this.cookies, retry.headers as Record<string, string | string[] | undefined>)
      Object.assign(data, this.parseBody(retry.body))
    }

    const redir = data.redirect as Record<string, unknown> | undefined
    const rurl = (redir?.url as string) || ''

    // 情形 A：该账号注册时中断在「未设密码」，服务端要求先补设密码再继续。
    // redirect 指向 /signup?workflowStateHandle=...，与注册流程 12a 的入口同构，
    // 因此换上这个 handle 直接复用 step12SetPassword 即可（它内部也会处理人机校验）。
    if (data.stepId === 'resume-signup-create-password') {
      this.log('[6.5] 该账号未设置密码，先补设密码')
      const wh = extractParam(rurl, 'workflowStateHandle')
      if (!wh) throw new Error('resume-signup 未返回 workflowStateHandle')
      this.workflowHandle = wh
      // step12a 用 registrationCode+state 换公钥；续注册路径没有这两者，
      // 改用 workflowStateHandle 直接进入「设置新密码」步骤。
      await this.step12SetPasswordResume()
      return
    }

    // 情形 B：账号完整，OTP 登录直接成功
    if (data.stepId !== 'end-of-workflow-success') {
      throw new Error(`邮箱验证码登录失败: stepId=${data.stepId || '未知'} ${this.formatErrorBody(resp.body, resp.status)}`)
    }
    if (!rurl) throw new Error('邮箱验证码登录未返回 redirect')
    this.authCode = extractParam(rurl, 'workflowResultHandle')
    this.ssoState = extractParam(rurl, 'state')
    this.wdcCSRFToken = extractParam(rurl, 'wdc_csrf_token')
    this.log('[6.5] 登录成功，继续换取 Token')
  }

  /**
   * 密码登录（承接 step6 返回 stepId=get-password）。
   *
   * 适用于「已完整注册、密码已设好」的账号。本项目为每个账号生成的密码是已知的，
   * 所以能直接登录换 token —— 这是最省事的找回路径，不用取码。
   *
   * 注意：密码由服务端下发的公钥现场加密，公钥在 step6 响应的
   * workflowResponseData.encryptionContextResponse 里；若该响应没带公钥，
   * 需要先推进一步拿到。
   */
  private async loginWithPassword(): Promise<void> {
    this.log('[6.5] 该账号已设密码，改走密码登录')
    // cfg.password 默认是本次随机生成的，对「历史已注册账号」而言必然不对。
    // 只有调用方显式传入该账号当初的密码（knownPassword）才可能成功。
    if (!this.cfg.knownPassword) {
      throw new Error(
        '该账号已设置密码，需提供原密码才能登录找回（配置 knownPassword）；' +
        '若密码已丢失，只能通过 AWS 官方「忘记密码」流程重置'
      )
    }
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${this.workflowHandle}`

    // 取加密公钥：先看 step6 的响应有没有；没有就推进一步
    let rid = newUUID()
    let h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'
    let resp = await this.doPost(api, {
      stepId: 'get-password', workflowStateHandle: this.workflowHandle,
      inputs: [{ input_type: 'FingerPrintRequestInput', fingerPrint: this.genFP('signin', 'PageLoad', 0, '') }],
      requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    let data = this.parseBody(resp.body)
    if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string

    const encCtx = getNestedMap(data as Record<string, unknown>, 'workflowResponseData', 'encryptionContextResponse')
    const pubKeyMap = encCtx ? getNestedStringMap(encCtx, 'publicKey') : null
    if (!pubKeyMap?.n) {
      throw new Error(`密码登录未获取到加密公钥: ${this.formatErrorBody(resp.body, resp.status)}`)
    }
    const encrypted = encryptPassword(
      this.cfg.knownPassword,
      pubKeyMap,
      (encCtx?.issuer as string) || 'signin',
      (encCtx?.audience as string) || 'AWSPasswordService',
      (encCtx?.region as string) || 'us-east-1'
    )

    const captchaRequest = await this.resolveCaptcha(data)

    rid = newUUID()
    h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'
    const payload: Record<string, unknown> = {
      stepId: 'get-password', workflowStateHandle: this.workflowHandle, actionId: 'SUBMIT',
      inputs: [
        { input_type: 'PasswordRequestInput', password: encrypted, successfullyEncrypted: 'SUCCESSFUL' },
        { input_type: 'UserPreferencesRequestInput', trustDevice: false },
        { input_type: 'FingerPrintRequestInput', fingerPrint: this.genFP('signin', 'PageSubmit', 0, '') }
      ],
      visitorId: this.vid, requestId: rid
    }
    if (captchaRequest) payload.captchaRequest = captchaRequest

    resp = await this.doPost(api, payload, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    data = this.parseBody(resp.body)

    if (data.stepId !== 'end-of-workflow-success') {
      throw new Error(`密码登录失败: stepId=${data.stepId || '未知'} ${this.formatErrorBody(resp.body, resp.status)}`)
    }
    const redir = data.redirect as Record<string, unknown> | undefined
    const rurl = (redir?.url as string) || ''
    if (!rurl) throw new Error('密码登录未返回 redirect')
    this.authCode = extractParam(rurl, 'workflowResultHandle')
    this.ssoState = extractParam(rurl, 'state')
    this.wdcCSRFToken = extractParam(rurl, 'wdc_csrf_token')
    this.log('[6.5] 密码登录成功，继续换取 Token')
  }

  /**
   * 续注册补设密码（承接 resume-signup-create-password）。
   *
   * 与 step12SetPassword 的差别：那条路径来自新注册，用 registrationCode + signInState
   * 换加密公钥；这里只有 workflowStateHandle，故 12a 请求体形态不同。
   * 12b 提交密码的形态、以及人机校验的处理完全一致。
   */
  private async step12SetPasswordResume(): Promise<void> {
    this.emitStep('set-password')
    this.log('[12*] 补设密码（续注册）')
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/signup/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/signup?workflowStateHandle=${this.workflowHandle}`

    // 12a*: 用 workflowStateHandle 拿加密公钥
    let rid = newUUID()
    let h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    let resp = await this.doPost(api, {
      stepId: '', workflowStateHandle: this.workflowHandle,
      inputs: [{ input_type: 'FingerPrintRequestInput', fingerPrint: this.genFP('signup', 'PageSubmit', 0, '') }],
      requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    let data = this.parseBody(resp.body)
    if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string

    // 与新注册的 signup 工作流一致：首次请求只回 stepId="start"，
    // 需再推进一步（actionId 缺省）服务端才下发 encryptionContextResponse。
    if (data.stepId === 'start') {
      rid = newUUID()
      h = this.buildHeaders(ref, this.cfg.signinBase)
      h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'
      resp = await this.doPost(api, {
        stepId: 'start', workflowStateHandle: this.workflowHandle,
        inputs: [
          { input_type: 'UserRequestInput', username: this.email },
          { input_type: 'FingerPrintRequestInput', fingerPrint: this.genFP('signup', 'PageSubmit', 0, '') }
        ],
        requestId: rid
      }, h)
      saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
      data = this.parseBody(resp.body)
      if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string
    }

    const encCtx = getNestedMap(data as Record<string, unknown>, 'workflowResponseData', 'encryptionContextResponse')
    const pubKeyMap = encCtx ? getNestedStringMap(encCtx, 'publicKey') : null
    if (!pubKeyMap?.n) {
      throw new Error(`续注册未获取到加密公钥: stepId=${data.stepId} ${this.formatErrorBody(resp.body, resp.status)}`)
    }
    const encrypted = encryptPassword(
      this.cfg.password,
      pubKeyMap,
      (encCtx?.issuer as string) || 'signin',
      (encCtx?.audience as string) || 'AWSPasswordService',
      (encCtx?.region as string) || 'us-east-1'
    )

    const captchaRequest = await this.resolveCaptcha(data)

    // 12b*: 提交密码（与新注册同形）
    rid = newUUID()
    h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    const payload: Record<string, unknown> = {
      stepId: (data.stepId as string) || 'get-new-password-for-password-creation',
      workflowStateHandle: this.workflowHandle, actionId: 'SUBMIT',
      inputs: [
        { input_type: 'PasswordRequestInput', password: encrypted, successfullyEncrypted: 'SUCCESSFUL' },
        { input_type: 'UserRequestInput', username: this.email },
        { input_type: 'FingerPrintRequestInput', fingerPrint: this.genFP('signup', 'PageSubmit', 0, '') }
      ],
      visitorId: this.vid, requestId: rid
    }
    if (captchaRequest) payload.captchaRequest = captchaRequest

    resp = await this.doPost(api, payload, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    data = this.parseBody(resp.body)

    const redir2 = data.redirect as Record<string, unknown> | undefined
    const rurl2 = (redir2?.url as string) || ''
    if (!rurl2) throw new Error(`续注册设置密码未返回 redirect: ${this.formatErrorBody(resp.body, resp.status)}`)

    await this.completeSignup(
      extractParam(rurl2, 'workflowStateHandle'),
      extractParam(rurl2, 'state'),
      extractParam(rurl2, 'workflowResultHandle')
    )
  }

  private async step7Signup(): Promise<void> {
    this.emitStep('signup')
    this.log('[7] 注册 (SIGNUP)')
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${this.workflowHandle}`
    const fp = this.genFP('signup', 'PageSubmit', 0, '')
    const rid = newUUID()
    const h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    const resp = await this.doPost(api, {
      stepId: 'get-identity-user', workflowStateHandle: this.workflowHandle,
      actionId: 'SIGNUP',
      inputs: [
        { input_type: 'UserRequestInput', username: this.email },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      visitorId: this.vid, requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    const data = this.parseBody(resp.body)
    const redir = data.redirect as Record<string, unknown> | undefined
    const rurl = redir?.url as string
    if (rurl?.includes('workflowStateHandle=')) {
      this.workflowHandle = splitAfter(rurl, 'workflowStateHandle=')
    }
  }

  private async step7_5SignupInit(): Promise<void> {
    this.log('[7.5] Signup API 初始化')
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/signup/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/signup?workflowStateHandle=${this.workflowHandle}`

    let fp = this.genFP('signup', 'first_load', 0, '')
    let rid = newUUID()
    let h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    let resp = await this.doPost(api, {
      stepId: '', workflowStateHandle: this.workflowHandle,
      inputs: [
        { input_type: 'UserRequestInput', username: this.email },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      visitorId: this.vid, requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    let data = this.parseBody(resp.body)
    if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string
    if (data.stepId !== 'start') throw new Error(`Signup init 失败: ${this.formatErrorBody(resp.body, resp.status)}`)

    fp = this.genFP('signup', 'PageLoad', 0, '')
    rid = newUUID()
    h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    resp = await this.doPost(api, {
      stepId: 'start', workflowStateHandle: this.workflowHandle,
      inputs: [
        { input_type: 'UserRequestInput', username: this.email },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      visitorId: this.vid, requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    data = this.parseBody(resp.body)
    if (data.workflowStateHandle) this.workflowHandle = data.workflowStateHandle as string
    const redir = data.redirect as Record<string, unknown> | undefined
    const rurl = redir?.url as string
    if (rurl?.includes('workflowID=')) {
      let wid = splitAfter(rurl, 'workflowID=')
      const hashIdx = wid.indexOf('#')
      if (hashIdx >= 0) wid = wid.slice(0, hashIdx)
      this.workflowId = wid
    }
    if (!this.workflowId) throw new Error('Signup init 未返回 workflowID')
  }

  private async step7_8ProfileInit(): Promise<void> {
    this.log('[7.8] Profile 页面初始化')
    this.ubid = ubidGen()
    this.cookies.set('aws-user-profile-ubid', this.ubid)
    this.cookies.set('i18next', 'zh-CN')
    if (!this.cookies.has('awsccc')) this.cookies.set('awsccc', awsccc())

    const url = `${this.cfg.profileBase}/?workflowID=${this.workflowId}`
    // 这是加载 Profile 应用的文档请求。真实浏览器在这一跳同样会带上当前 AWS cookie，
    // 带着它们能让随后的 FWCIM 指纹与 D2C token 状态归属同一个会话；
    // 此前只发了三个 header、完全不带 cookie，是会话割裂的自动化特征。
    const navHeaders: Record<string, string> = {
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': AWS_ACCEPT_LANGUAGE,
      'User-Agent': this.identity.ua,
      'sec-ch-ua': this.secUA,
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'document',
      'sec-fetch-mode': 'navigate',
      'sec-fetch-site': 'cross-site',
      'Upgrade-Insecure-Requests': '1'
    }
    const navCookie = ['awsccc', 'aws-user-profile-ubid', 'awsd2c-token', 'awsd2c-token-c', 'i18next']
      .filter((k) => (this.cookies.get(k) || '').trim())
      .map((k) => `${k}=${this.cookies.get(k)}`)
      .join('; ')
    if (navCookie) navHeaders['Cookie'] = navCookie

    const resp = await this.doGet(url, navHeaders)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    resetPerfTiming(this.fpCtx)
    this.profilePageStartedAt = Date.now()
    await this.fetchD2CToken(this.cfg.profileBase, url)
  }

  private async step8ProfileStart(): Promise<void> {
    this.log('[8] Profile 启动')
    const ref = `${this.cfg.profileBase}/?workflowID=${this.workflowId}`
    const fp = this.genFP('profile', 'PageLoad', 0, '')

    const resp = await this.doPost(this.cfg.profileBase + '/api/start', {
      workflowID: this.workflowId,
      browserData: {
        attributes: {
          fingerprint: fp,
          eventTimestamp: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'),
          timeSpentOnPage: '38', eventType: 'PageLoad',
          ubid: this.ubid, visitorId: this.vid
        },
        cookies: {}
      }
    }, this.buildProfileHeaders(ref))
    const data = this.parseBody(resp.body)
    this.workflowState = (data.workflowState as string) || ''
    if (!this.workflowState) throw new Error(`Profile start 未返回 workflowState: ${resp.body.slice(0, 200)}`)
    this.profileEmailStartedAt = Date.now()

    // HAR entry 66：profile 页的 D2C 耗时遥测
    await postD2CEventSafe(
      this.telemetryCtx(),
      `${this.cfg.profileBase}/?workflowID=${this.workflowId}#/signup/start?workflowID=${this.workflowId}`,
      this.lastD2CFetchMs
    )
  }

  private async step9SendOTP(): Promise<void> {
    this.emitStep('send-otp')
    this.log('[9] 发送验证码')

    if (this.cfg.useOutlook && this.cfg.outlookData) {
      const accounts = parseOutlookLines(this.cfg.outlookData)
      const acc = accounts.find((a) => a.email === this.email)
      if (acc) {
        try {
          this.outlookMailCount = await getInboxCount(acc)
          this.log(`发送前邮件数: ${this.outlookMailCount}`)
        } catch (err) {
          this.log(`获取邮件数量失败: ${err}, 默认为0`)
        }
      }
    }

    const ref = `${this.cfg.profileBase}/?workflowID=${this.workflowId}`
    const timeOnPage = 5000 + Math.floor(Math.random() * 3001)
    const fp = this.genFPWithTime('profile', 'PageSubmit', timeOnPage, this.email.length, this.email)
    const tsp = String(timeOnPage)

    const payload = {
      workflowState: this.workflowState,
      email: this.email,
      browserData: {
        attributes: {
          fingerprint: fp,
          eventTimestamp: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'),
          timeSpentOnPage: tsp, pageName: 'EMAIL_COLLECTION',
          eventType: 'PageSubmit', ubid: this.ubid, visitorId: this.vid
        },
        cookies: {}
      }
    }

    const resp = await this.doPost(this.cfg.profileBase + '/api/send-otp', payload, this.buildProfileHeaders(ref))
    if (resp.status !== 200) throw new Error(`send-otp 失败 (${resp.status}), body: ${resp.body.substring(0, 300)}`)
    this.profileVerificationStartedAt = Date.now()
    this.log('验证码已发送')

    // HAR entry 69：SendOTP 完成后浏览器必发的 katal 批次。
    // 上报真实阶段耗时；锚点缺失时用 HAR 里的典型值兜底（避免出现 0 这种不真实的值）。
    const getConfigMs = this.elapsedSince(this.profilePageStartedAt) || 577
    const sendOTPMs = this.elapsedSince(this.profileEmailStartedAt) || 672
    await postKatalNexusSafe(this.telemetryCtx(), katalSignupBatch(getConfigMs, sendOTPMs))
  }

  private async step10GetOTP(): Promise<string> {
    if (this.cfg.manualMode) throw new Error('手动模式需外部提供验证码')

    this.emitStep('waiting-otp')
    this.log('[10] 等待验证码')
    const signal = this.abortController.signal
    if (this.cfg.useOutlook && this.cfg.outlookData) {
      const accounts = parseOutlookLines(this.cfg.outlookData)
      const acc = accounts.find((a) => a.email === this.email)
      if (!acc) throw new Error('未找到对应 Outlook 账号')
      return await waitForOTP(acc, this.outlookMailCount, 120, 5, signal)
    }
    if (!this.emailSvc) throw new Error('邮箱服务未初始化')
    // iCloud 走 Apple 侧投递 + 站点侧抓取两跳，到站比临时邮箱慢；
    // 放宽到 180s 并把间隔拉到 5s，避免对 feed.php 打太密。
    if (this.cfg.useICloud) return await this.emailSvc.waitForCode(180, 5, signal)
    return await this.emailSvc.waitForCode(120, 3, signal)
  }

  private async step11CreateIdentity(otp: string): Promise<void> {
    this.emitStep('otp-received')
    this.emitStep('create-identity')
    this.log('[11] 创建身份')
    const ref = `${this.cfg.profileBase}/?workflowID=${this.workflowId}`
    const fp = this.genFP('profile', 'EmailVerification', 0, '')

    const resp = await this.doPost(this.cfg.profileBase + '/api/create-identity', {
      workflowState: this.workflowState,
      userData: { email: this.email, fullName: this.cfg.fullName },
      otpCode: otp,
      browserData: {
        attributes: {
          fingerprint: fp,
          eventTimestamp: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'),
          timeSpentOnPage: '45000', pageName: 'EMAIL_VERIFICATION',
          eventType: 'EmailVerification', ubid: this.ubid, visitorId: this.vid
        },
        cookies: {}
      }
    }, this.buildProfileHeaders(ref))
    const data = this.parseBody(resp.body)
    this.regCode = (data.registrationCode as string) || ''
    this.signState = (data.signInState as string) || ''
    if (!this.regCode) throw new Error(`create-identity 未返回 registrationCode: ${resp.body.slice(0, 200)}`)

    // HAR entry 72：CreateIdentity 完成后浏览器必发的 katal 批次
    const verificationMs = this.elapsedSince(this.profileVerificationStartedAt) || 15539
    const createIdentityMs = this.elapsedSince(this.profileEmailStartedAt) || 603
    await postKatalNexusSafe(this.telemetryCtx(), katalVerificationBatch(verificationMs, createIdentityMs))
  }

  /** 距锚点的毫秒数；锚点未设置或时钟异常时返回 0（由调用方用 HAR 典型值兜底） */
  private elapsedSince(anchor: number): number {
    if (!anchor) return 0
    const d = Date.now() - anchor
    return d > 0 ? d : 0
  }

  private async step12SetPassword(): Promise<void> {
    this.emitStep('set-password')
    this.log('[12] 设置密码')
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/signup/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/signup?registrationCode=${this.regCode}&state=${this.signState}`
    let fp = this.genFP('signup', 'PageSubmit', 0, '')

    // 12a: 获取加密公钥
    let rid = newUUID()
    let h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    let resp = await this.doPost(api, {
      stepId: '', state: this.signState,
      inputs: [
        { input_type: 'UserRegistrationRequestInput', registrationCode: this.regCode, state: this.signState },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    let data = this.parseBody(resp.body)
    this.workflowHandle = (data.workflowStateHandle as string) || ''

    const encCtx = getNestedMap(data as Record<string, unknown>, 'workflowResponseData', 'encryptionContextResponse')
    const pubKeyMap = encCtx ? getNestedStringMap(encCtx, 'publicKey') : null
    if (!pubKeyMap?.n) throw new Error(`未获取到加密公钥: ${this.formatErrorBody(resp.body, resp.status)}`)

    const issuer = (encCtx?.issuer as string) || 'signin'
    const audience = (encCtx?.audience as string) || 'AWSPasswordService'
    const region = (encCtx?.region as string) || 'us-east-1'

    const encrypted = encryptPassword(this.cfg.password, pubKeyMap, issuer, audience, region)

    // 12a 的响应可能带人机校验要求：只要 captchaToken 非空，12b 就**必须**回传过关凭证，
    // 否则服务端返回 400 + AUTHENTICATION_FAILED（文案伪装成 "unexpected error"，
    // 且重试会升级为 AWS-RISK-CONTROL）。详见 ams-captcha-window.ts 顶部说明。
    const captchaRequest = await this.resolveCaptcha(data)

    // 12b: 提交密码
    fp = this.genFP('signup', 'PageSubmit', 0, '')
    rid = newUUID()
    h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    const submitPayload: Record<string, unknown> = {
      stepId: 'get-new-password-for-password-creation',
      workflowStateHandle: this.workflowHandle, actionId: 'SUBMIT',
      inputs: [
        { input_type: 'PasswordRequestInput', password: encrypted, successfullyEncrypted: 'SUCCESSFUL' },
        { input_type: 'UserRequestInput', username: this.email },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      visitorId: this.vid, requestId: rid
    }
    // 与官方前端一致：captchaRequest 是**顶层字段**，不是 inputs 里的一项
    if (captchaRequest) submitPayload.captchaRequest = captchaRequest

    resp = await this.doPost(api, submitPayload, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    data = this.parseBody(resp.body)

    const redir = data.redirect as Record<string, unknown> | undefined
    const rurl = redir?.url as string
    if (!rurl) throw new Error(`密码设置未返回 redirect: ${resp.body.slice(0, 200)}`)

    const wh = extractParam(rurl, 'workflowStateHandle')
    const st = extractParam(rurl, 'state')
    const rh = extractParam(rurl, 'workflowResultHandle')
    await this.completeSignup(wh, st, rh)
  }

  /**
   * 解析服务端下发的人机校验要求，返回要挂在请求顶层的 captchaRequest（无需校验时返回 null）。
   *
   * 两类（据线上 signin app.js 的 AMSCaptcha 组件）：
   *   - AMS：captchaToken + captchaCDN → 借隐藏窗口跑官方 CDN 脚本拿 accessCode，可自动化
   *   - ACS：仅 captchaURL           → 传统图形题，需人工识图，当前不支持，抛出明确错误
   */
  private async resolveCaptcha(data: Record<string, unknown>): Promise<Record<string, unknown> | null> {
    const cap = data.captchaResponse as Record<string, unknown> | undefined
    if (!cap) return null

    const token = typeof cap.captchaToken === 'string' ? cap.captchaToken : ''
    const cdn = typeof cap.captchaCDN === 'string' ? cap.captchaCDN : ''
    const url = typeof cap.captchaURL === 'string' ? cap.captchaURL : ''
    const ces = typeof cap.captchaCES === 'string' ? cap.captchaCES : ''

    if (token && cdn) {
      this.log('[12a] 服务端要求人机校验 (AMS)，启动求解…')
      this.emitStep('captcha-solving')
      const solved = await solveAmsCaptcha({
        captchaToken: token,
        captchaCDN: cdn,
        // 需要人工点选时向上冒泡，让前端能提示用户（批量场景否则会静默卡住）
        onInteractive: () => {
          this.log(
            this.cfg.captchaUnattended
              ? '[12a] 人机校验需要人工完成，无人值守模式下跳过本次'
              : '[12a] 人机校验需要手工完成，请在弹出的窗口内操作'
          )
          this.emitStep('captcha-interactive')
        },
        // 无人值守（批量）时不干等真人，立即失败让外层换下一个任务
        failFastOnInteractive: this.cfg.captchaUnattended === true,
        // 必须与注册链路同出口：凭证核验绑定来源 IP。
        // 注意这里要的是「实际连接端点」而非审计用的目标代理：启用代理链时
        // cfg.proxy 是本地中继地址，窗口必须连中继才能复用同一出口。
        proxy: this.captchaWindowProxy(),
        log: (m) => this.log(m),
        signal: this.abortController.signal
      })
      const req: Record<string, unknown> = { captchaAccessCode: solved.accessCode }
      // CES 若下发则一并回传（官方前端在 ACS/AMS 混合场景会同时带）
      if (ces) req.captchaCES = ces
      return req
    }

    if (url) {
      throw new Error(
        'AWS 要求图形验证码 (ACS)，当前不支持自动识别。建议：更换出口代理后重试，' +
        '或降低注册频率/启用限速以避免触发风控'
      )
    }

    // 有 captchaResponse 但三个字段都空 → 无需校验（实测正常流程也会带这种空壳）
    return null
  }

  private async completeSignup(wh: string, state: string, rh: string): Promise<void> {
    this.log('[12.5] 完成注册工作流')
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${wh}&state=${state}&workflowResultHandle=${rh}`
    const fp = this.genFP('signin', 'PageLoad', 0, '')
    const rid = newUUID()
    const h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    const resp = await this.doPost(api, {
      stepId: '', workflowStateHandle: wh,
      workflowResultHandle: rh, state,
      inputs: [
        { input_type: 'UserRequestInput', username: this.email },
        { input_type: 'FingerPrintRequestInput', fingerPrint: fp }
      ],
      visitorId: this.vid, requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    const data = this.parseBody(resp.body)
    if (data.stepId !== 'end-of-workflow-success') throw new Error(`完成工作流失败: ${data.stepId || 'undefined'} ${this.formatErrorBody(resp.body, resp.status)}`)

    const redir = data.redirect as Record<string, unknown> | undefined
    const rurl = redir?.url as string
    if (rurl) {
      this.authCode = extractParam(rurl, 'workflowResultHandle')
      this.ssoState = extractParam(rurl, 'state')
      this.wdcCSRFToken = extractParam(rurl, 'wdc_csrf_token')
    }
  }

  // ============ SSO 授权 (Step12.8-13) ============

  private async step12_8SSOWorkflow(): Promise<void> {
    this.emitStep('sso-workflow')
    this.log('[12.8] SSO 工作流')
    const redirectURL = encodeURIComponent(this.cfg.viewBase + '/start/#/')
    const loginURL = `${this.cfg.portalBase}/login?directory_id=view&redirect_url=${redirectURL}`

    const h: Record<string, string> = {
      'Accept': '*/*', 'User-Agent': this.identity.ua,
      'Origin': this.cfg.viewBase, 'Referer': this.cfg.viewBase + '/',
      'sec-ch-ua': this.secUA, 'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors', 'sec-fetch-site': 'cross-site', 'priority': 'u=1, i'
    }
    if (this.cookies.has('awsccc')) h['Cookie'] = 'awsccc=' + this.cookies.get('awsccc')

    const resp = await this.doGet(loginURL, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    const data = this.parseBody(resp.body)
    if (data.csrfToken) this.cookies.set('loginCsrfToken', data.csrfToken as string)

    const rurl = (data.redirectUrl as string) || ''
    let wh = ''
    if (rurl.includes('workflowStateHandle=')) {
      wh = splitAfter(rurl, 'workflowStateHandle=')
    }
    if (!wh) throw new Error('SSO 无法获取 workflowStateHandle')

    await this.completeSSOWorkflow(wh)
  }

  private async completeSSOWorkflow(wh: string): Promise<void> {
    const api = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/api/execute`
    const ref = `${this.cfg.signinBase}/platform/${this.cfg.directoryId}/login?workflowStateHandle=${wh}`
    let fp = this.genFP('signin', 'PageLoad', 0, '')
    let rid = newUUID()
    let h = this.buildHeaders(ref, this.cfg.signinBase)
    h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

    let resp = await this.doPost(api, {
      stepId: '', workflowStateHandle: wh,
      inputs: [{ input_type: 'FingerPrintRequestInput', fingerPrint: fp }],
      requestId: rid
    }, h)
    saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
    let data = this.parseBody(resp.body)
    let newWH = (data.workflowStateHandle as string) || wh

    if (data.stepId === 'start') {
      fp = this.genFP('signin', 'PageLoad', 0, '')
      rid = newUUID()
      h = this.buildHeaders(ref, this.cfg.signinBase)
      h['x-amzn-requestid'] = rid; h['x-amz-date'] = gmtDate(); h['priority'] = 'u=1, i'

      resp = await this.doPost(api, {
        stepId: 'start', workflowStateHandle: newWH,
        inputs: [{ input_type: 'FingerPrintRequestInput', fingerPrint: fp }],
        requestId: rid
      }, h)
      saveCookies(this.cookies, resp.headers as Record<string, string | string[] | undefined>)
      data = this.parseBody(resp.body)
    }

    if (data.stepId === 'end-of-workflow-success') {
      const redir = data.redirect as Record<string, unknown> | undefined
      const rurl = redir?.url as string
      if (rurl) {
        this.authCode = extractParam(rurl, 'workflowResultHandle')
        this.ssoState = extractParam(rurl, 'state')
        this.wdcCSRFToken = extractParam(rurl, 'wdc_csrf_token')
      }
    }

    // 访问 start 页面
    const params = new URLSearchParams()
    if (this.ssoState) params.set('state', this.ssoState)
    params.set('workflowResultHandle', this.authCode)
    if (this.wdcCSRFToken) params.set('wdc_csrf_token', this.wdcCSRFToken)
    const startURL = this.cfg.viewBase + '/start/?' + params.toString()

    const cookieParts: string[] = []
    if (this.cookies.has('loginCsrfToken')) cookieParts.push('loginCsrfToken=' + this.cookies.get('loginCsrfToken'))
    if (this.cookies.has('awsccc')) cookieParts.push('awsccc=' + this.cookies.get('awsccc'))

    await this.doGet(startURL, {
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'User-Agent': this.identity.ua,
      'Referer': this.cfg.signinBase + '/',
      'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate',
      ...(cookieParts.length ? { Cookie: cookieParts.join('; ') } : {})
    })
  }

  private async step13SSOToken(): Promise<Record<string, unknown>> {
    this.emitStep('sso-token')
    this.log('[13] 获取 SSO Token')
    const csrf = this.cookies.get('loginCsrfToken')
    if (!csrf) throw new Error('缺少 loginCsrfToken')

    const h: Record<string, string> = {
      'Accept': 'application/json, text/plain, */*',
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': this.identity.ua, 'Origin': this.cfg.viewBase,
      'Referer': this.cfg.viewBase + '/',
      'x-amz-sso-csrf-token': csrf,
      'sec-ch-ua': this.secUA, 'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors', 'sec-fetch-site': 'cross-site', 'priority': 'u=1, i'
    }
    const formData = `authCode=${encodeURIComponent(this.authCode)}&state=${encodeURIComponent(this.ssoState)}&orgId=view`

    // 使用新客户端轮询 SSO Token
    const ssoSession = new SessionClient(this.moduleClient!, this.sessionOpts)

    try {
      for (let retry = 0; retry < 5; retry++) {
        const resp = await ssoSession.post(this.cfg.portalBase + '/auth/sso-token', formData, { headers: h })
        const data = JSON.parse(resp.body || '{}')

        if (data.token) {
          this.ssoToken = data.token
          break
        }
        const errMsg = (data.errorMessage || '') as string
        if (errMsg.toLowerCase().includes('not authorized')) {
          await this.abortableSleep(3000)
          continue
        }
        throw new Error(`SSO Token 失败: ${resp.body?.slice(0, 200)}`)
      }
    } finally {
      try { await ssoSession.destroySession() } catch { /* ignore */ }
    }

    if (!this.ssoToken) throw new Error('SSO Token 重试 5 次仍失败')

    // Accept device + Associate token
    let resp = await this.doPost(this.cfg.oidcBase + '/device_authorization/accept_user_code', {
      userCode: this.userCode, userSessionId: this.ssoToken
    }, { 'Content-Type': 'application/json' })
    const dcData = this.parseBody(resp.body)
    const dc = dcData.deviceContext

    await this.doPost(this.cfg.oidcBase + '/device_authorization/associate_token', {
      deviceContext: dc, userSessionId: this.ssoToken
    }, { 'Content-Type': 'application/json' })

    // 轮询 token
    for (let i = 0; i < 30; i++) {
      resp = await this.doPost(this.cfg.oidcBase + '/token', {
        clientId: this.clientId, clientSecret: this.clientSecret,
        deviceCode: this.deviceCode,
        grantType: 'urn:ietf:params:oauth:grant-type:device_code'
      }, { 'Content-Type': 'application/json' })

      if (resp.status === 200) return this.parseBody(resp.body)
      await this.abortableSleep(2000)
    }
    throw new Error('Token 轮询超时')
  }

  // ============ 验活 ============

  private async verifyAlive(awsToken: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.log('[验活] 刷新 Token + 查用量')
    const refreshToken = (awsToken.refreshToken as string) || ''

    const resp = await this.doPost('https://oidc.us-east-1.amazonaws.com/token', {
      clientId: this.clientId, clientSecret: this.clientSecret,
      refreshToken, grantType: 'refresh_token'
    }, { 'Content-Type': 'application/json' })

    if (resp.status !== 200) {
      this.log(`Token 刷新失败: ${resp.status}`)
      return { alive: false, error: `refresh failed: ${resp.status}` }
    }

    const tok = this.parseBody(resp.body)
    const access = (tok.accessToken as string) || ''

    /*
     * 注册产出的账号一律是 Builder ID，这条链路踩满了服务端 2026-08 改的两个口径：
     *   1. UA 里的版本号被用作准入条件，报 KiroIDE-0.6.18 会一律 403
     *      "User is not authorized to make this call."（社交账号不受影响，所以只在这里暴露）
     *   2. profileArn 从可选变必填，不带同样 403。Builder ID 没有 profile 概念，
     *      必须原样带 Kiro IDE 那个硬编码占位符
     * 两处都改了才能拿到 200，只改一个仍然验活失败。
     */
    const usageUA = getKiroUserAgent()
    const params = new URLSearchParams({
      origin: 'AI_EDITOR',
      resourceType: 'AGENTIC_REQUEST',
      isEmailRequired: 'true',
      profileArn: KIRO_BUILDER_ID_PLACEHOLDER_ARN
    })

    for (const region of ['us-east-1', 'eu-central-1']) {
      const usageURL = `${qServiceEndpoint(region)}/getUsageLimits?${params.toString()}`
      const usageResp = await this.doGet(usageURL, {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + access,
        'User-Agent': usageUA,
        'x-amz-user-agent': getKiroAmzUserAgent()
      })

      if (usageResp.status === 403 && usageResp.body.toLowerCase().includes('suspended')) {
        return { alive: false, suspended: true, error: 'suspended' }
      }
      if (usageResp.status === 200) {
        return this.parseUsage(usageResp.body)
      }
      this.log(`[验活] 用量查询 ${region} → ${usageResp.status}: ${usageResp.body.slice(0, 160)}`)
    }
    return { alive: false, error: 'usage query failed' }
  }

  private parseUsage(body: string): Record<string, unknown> {
    const usage = this.parseBody(body)
    const userInfo = (usage.userInfo as Record<string, unknown>) || {}
    const emailAddr = (userInfo.email as string) || ''
    const subInfo = (usage.subscriptionInfo as Record<string, unknown>) || {}
    let sub = (subInfo.subscriptionTitle as string) || 'Free'

    let totalLimit = 0, totalUsed = 0
    const breakdown = usage.usageBreakdownList as Array<Record<string, unknown>> | undefined
    if (breakdown) {
      for (const item of breakdown) {
        const rt = item.resourceType as string
        const dn = item.displayName as string
        if (rt === 'CREDIT' || dn === 'Credits') {
          totalLimit = (item.usageLimitWithPrecision as number) || (item.usageLimit as number) || 0
          totalUsed = (item.currentUsageWithPrecision as number) || (item.currentUsage as number) || 0

          const ft = item.freeTrialInfo as Record<string, unknown> | undefined
          if (ft?.freeTrialStatus === 'ACTIVE') {
            totalLimit += (ft.usageLimitWithPrecision as number) || 0
            totalUsed += (ft.currentUsageWithPrecision as number) || 0
          }
          break
        }
      }
    }

    this.log(`验活成功! 邮箱=${emailAddr} 订阅=${sub} Credit=${totalUsed}/${totalLimit}`)
    return { alive: true, email: emailAddr, subscription: sub, credit_used: totalUsed, credit_limit: totalLimit }
  }

  // ============ 主流程 ============

  /** 执行完整注册流程（自动模式） */
  async run(): Promise<RegistrationResult> {
    this.emitStep('init')
    try {
      await this.setupProxyChain()
      if (this.chainRelay) this.emitStep('proxy-chain-ready')
      await this.initTlsClient()
      this.emitStep('tls-ready')
      await this.detectExitIP()
      await refreshAppJSConfig((url, init) => this.fetchAppJS(url, init))
      await this.rebuildTlsClient()

      // 幂等只读步骤：retry 次数 + 整体超时看门狗 + 失败换出口 IP。
      // OIDC 为首步（失败即废号）保留自带 3 次重试不快速超时；Email 创建有副作用不重试。
      const initSteps: Array<{ name: string; fn: StepFn; retry?: number; timeoutMs?: number; refreshSession?: boolean }> = [
        { name: 'OIDC', fn: () => this.step1OIDC() },
        { name: 'Device', fn: () => this.step2Device(), retry: 2, timeoutMs: 30000, refreshSession: true },
        { name: 'Email', fn: () => this.step3Email() },
        { name: 'Portal', fn: () => this.step4Portal(), retry: 3, timeoutMs: 35000, refreshSession: true },
        { name: 'WorkflowInit', fn: () => this.step5WorkflowInit(), retry: 2, timeoutMs: 35000, refreshSession: true }
      ]
      for (const s of initSteps) {
        this.checkAborted()
        try {
          if (s.retry) await this.retryStep(s.name, s.fn, s.retry, { timeoutMs: s.timeoutMs, refreshSession: s.refreshSession })
          else await s.fn()
        } catch (err) {
          return { status: 'failed', email: this.email, error: `[${s.name}] ${(err as Error).message}`, captchaBlocked: this.isCaptchaBlocked((err as Error).message) }
        }
        await this.humanDelay()
      }

      this.checkAborted()
      // 非幂等步骤统一加整体超时看门狗（默认 55s）：卡住时快速失败释放并发槽，不死等 3×25s
      const STEP_TIMEOUT = 55000
      const emailStatus = await this.withTimeout(this.step6SubmitEmail(), STEP_TIMEOUT, 'SubmitEmail')

      if (emailStatus === 'signup') {
        const signupSteps: Array<{ name: string; fn: StepFn }> = [
          { name: 'Signup', fn: () => this.step7Signup() },
          { name: 'SignupInit', fn: () => this.step7_5SignupInit() },
          { name: 'ProfileInit', fn: () => this.step7_8ProfileInit() },
          { name: 'ProfileStart', fn: () => this.step8ProfileStart() },
          { name: 'SendOTP', fn: () => this.step9SendOTP() }
        ]
        for (const s of signupSteps) {
          this.checkAborted()
          try { await this.withTimeout(s.fn(), STEP_TIMEOUT, s.name) } catch (err) {
            return { status: 'failed', email: this.email, error: `[${s.name}] ${(err as Error).message}`, captchaBlocked: this.isCaptchaBlocked((err as Error).message) }
          }
          await this.humanDelay()
        }

        this.checkAborted()
        let otp: string
        try { otp = await this.step10GetOTP() } catch (err) {
          return { status: 'failed', email: this.email, error: `[GetOTP] ${(err as Error).message}` }
        }

        for (const s of [
          { name: 'CreateIdentity', fn: () => this.step11CreateIdentity(otp), timeoutMs: STEP_TIMEOUT },
          // SetPassword 可能内含 AMS 人机校验：静默通过只要几秒，但脚本判定需要人工点选时
          // 得留出真人操作时间，55s 会把窗口刚弹出来的注册直接判超时。
          { name: 'SetPassword', fn: () => this.step12SetPassword(), timeoutMs: SET_PASSWORD_TIMEOUT }
        ] as Array<{ name: string; fn: StepFn; timeoutMs: number }>) {
          this.checkAborted()
          try { await this.withTimeout(s.fn(), s.timeoutMs, s.name) } catch (err) {
            return { status: 'failed', email: this.email, error: `[${s.name}] ${(err as Error).message}`, captchaBlocked: this.isCaptchaBlocked((err as Error).message) }
          }
          await this.humanDelay()
        }
      } else {
        // 邮箱在 AWS 侧已有账号：注册走不通，但只要能收这个邮箱的验证码就能登录找回，
        // 拿到的 token 与新注册等价。默认开启（recoverExisting 未显式关闭时）。
        if (this.cfg.recoverExisting === false) {
          return { status: 'failed', email: this.email, error: '该邮箱已注册过' }
        }
        try {
          await this.withTimeout(this.recoverByEmailOtp(), 240000, 'EmailOtpLogin')
        } catch (err) {
          return { status: 'failed', email: this.email, error: `[EmailOtpLogin] ${(err as Error).message}`, captchaBlocked: this.isCaptchaBlocked((err as Error).message) }
        }
      }

      // ====== 后期步骤（SSO + Token）======
      // 到这里账号已创建（Step 11-12 成功），后续只是获取登录凭证。
      // 如果因网络波动失败，在同一个 Registrar 内重试（复用已有注册状态），
      // 避免让外层从头开始白白浪费已完成的注册流程。
      this.checkAborted()
      let awsToken: Record<string, unknown> | null = null
      const SSO_MAX_RETRIES = 2
      for (let ssoAttempt = 0; ssoAttempt <= SSO_MAX_RETRIES; ssoAttempt++) {
        try {
          // SSO 含 token 轮询，单次尝试加整体超时（卡死时切断进入下一次重试）
          await this.withTimeout(this.step12_8SSOWorkflow(), 60000, 'SSOWorkflow')
          await this.abortableSleep(2000)
          this.checkAborted()
          awsToken = await this.withTimeout(this.step13SSOToken(), 90000, 'SSOToken')
          break // SSO 成功
        } catch (err) {
          const errMsg = (err as Error).message
          if (ssoAttempt < SSO_MAX_RETRIES) {
            this.log(`[SSO] 后期步骤失败，内部重试 (${ssoAttempt + 1}/${SSO_MAX_RETRIES}): ${errMsg}`)
            await this.abortableSleep(3000 + Math.floor(Math.random() * 2000))
          } else {
            // 最终失败：账号已创建但拿不到 Token
            return { status: 'failed', email: this.email, error: `[SSOToken] ${errMsg} (账号已创建，可手动导入刷新)` }
          }
        }
      }

      const token = awsToken!
      this.emitStep('verify-alive')
      const verify = await this.withTimeout(this.verifyAlive(token), 60000, 'VerifyAlive')
      if (verify.suspended) {
        return { status: 'failed', email: this.email, error: 'suspended' }
      }

      this.emitStep('done')
      return {
        status: 'success',
        email: this.email,
        password: this.cfg.password,
        clientId: this.clientId,
        clientSecret: this.clientSecret,
        refreshToken: (token.refreshToken as string) || '',
        accessToken: (token.accessToken as string) || '',
        region: 'us-east-1',
        provider: 'BuilderId',
        verify,
        fingerprint: this.fingerprintSnapshot()
      }
    } finally {
      await this.cleanup()
    }
  }

  /**
   * captcha 窗口应连接的代理端点。
   *
   * 与 resolvedProxyUrl() 的区别：后者是**审计用**，代理链启用时返回真正的目标代理；
   * 这里要的是**实际连接端点** —— 启用代理链时必须连本地中继（cfg.proxy），
   * 这样窗口流量才和注册请求走同一条链、同一出口 IP。
   * AMS 凭证的签发与核验绑定来源 IP，出口不一致会被判为另一个访客。
   */
  private captchaWindowProxy(): string | undefined {
    const p = (this.cfg.proxy || '').trim()
    if (p) return p
    return (
      process.env.HTTPS_PROXY || process.env.https_proxy ||
      process.env.HTTP_PROXY || process.env.http_proxy ||
      getSystemProxy() || undefined
    )
  }

  /**
   * 返回本次注册实际生效的代理 URL（按 sessionOpts 同样的优先级解析），
   * 用于在指纹摘要里准确显示是直连还是走代理。
   */
  private resolvedProxyUrl(): string | undefined {
    // 代理链启用时 cfg.proxy 是本地中继地址，审计应显示真正的目标代理
    return (this.chainTargetProxy && this.chainTargetProxy.trim())
      || (this.cfg.proxy && this.cfg.proxy.trim())
      || process.env.HTTPS_PROXY || process.env.https_proxy
      || process.env.HTTP_PROXY || process.env.http_proxy
      || getSystemProxy() || undefined
  }

  /** 输出本次注册使用的指纹摘要（用于审计与后续复用） */
  private fingerprintSnapshot(): FingerprintSnapshot {
    const resolved = this.resolvedProxyUrl()
    return {
      chromeVer: this.identity.chromeVer,
      ua: this.identity.ua,
      gpuVendor: this.identity.gpuVendor,
      gpuModel: this.identity.gpuModel,
      canvasHash: this.identity.canvasHash,
      screen: { width: this.identity.screen.width, height: this.identity.screen.height },
      // 脱敏后保存（隐藏密码部分），同时确保系统/环境变量代理也被捕获
      proxyUrl: resolved ? resolved.replace(/:([^:@/]+)@/, ':***@') : undefined,
      exitIP: this.exitIP || undefined
    }
  }

  /** 手动模式注册 - Step1-2 自动，Step3 等待外部设置邮箱，Step4-9 自动，Step10 等待外部 OTP */
  async runManualPhase1(): Promise<{ success: boolean; error?: string }> {
    try {
      await this.setupProxyChain()
      await this.initTlsClient()
      await this.detectExitIP()
      await refreshAppJSConfig((url, init) => this.fetchAppJS(url, init))
      await this.rebuildTlsClient()

      await this.step1OIDC()
      await this.withTimeout(this.step2Device(), 30000, 'Device')
      return { success: true }
    } catch (err) {
      return { success: false, error: (err as Error).message }
    }
  }

  /** 手动模式 - 设置邮箱后继续注册流程到发送 OTP */
  async runManualPhase2(email: string, fullName?: string): Promise<{ success: boolean; error?: string }> {
    this.email = email
    if (fullName) this.cfg.fullName = fullName

    try {
      // 幂等只读步骤：retry + 超时看门狗 + 失败换出口 IP；后续非幂等步骤仅加超时快速失败
      const STEP_TIMEOUT = 55000
      await this.retryStep('Portal', () => this.step4Portal(), 3, { timeoutMs: 35000, refreshSession: true })
      await this.retryStep('WorkflowInit', () => this.step5WorkflowInit(), 2, { timeoutMs: 35000, refreshSession: true })

      const status = await this.withTimeout(this.step6SubmitEmail(), STEP_TIMEOUT, 'SubmitEmail')
      if (status !== 'signup') return { success: false, error: '该邮箱已注册过' }

      await this.withTimeout(this.step7Signup(), STEP_TIMEOUT, 'Signup')
      await this.withTimeout(this.step7_5SignupInit(), STEP_TIMEOUT, 'SignupInit')
      await this.withTimeout(this.step7_8ProfileInit(), STEP_TIMEOUT, 'ProfileInit')
      await this.withTimeout(this.step8ProfileStart(), STEP_TIMEOUT, 'ProfileStart')
      await this.withTimeout(this.step9SendOTP(), STEP_TIMEOUT, 'SendOTP')
      return { success: true }
    } catch (err) {
      return { success: false, error: (err as Error).message }
    }
  }

  /** 手动模式 - 输入 OTP 后完成注册 */
  async runManualPhase3(otp: string): Promise<RegistrationResult> {
    try {
      // 非幂等步骤加整体超时看门狗，卡住时快速失败
      await this.withTimeout(this.step11CreateIdentity(otp), 55000, 'CreateIdentity')
      // 同自动模式：这一步可能内含需人工完成的 AMS 人机校验，不能用 55s 通用超时
      await this.withTimeout(this.step12SetPassword(), SET_PASSWORD_TIMEOUT, 'SetPassword')

      // SSO + Token：账号已创建，网络波动时在同一 Registrar 内重试（复用已有注册状态），避免白费已完成的注册
      let awsToken: Record<string, unknown> | null = null
      const SSO_MAX_RETRIES = 2
      for (let ssoAttempt = 0; ssoAttempt <= SSO_MAX_RETRIES; ssoAttempt++) {
        try {
          await this.withTimeout(this.step12_8SSOWorkflow(), 60000, 'SSOWorkflow')
          await this.abortableSleep(2000)
          this.checkAborted()
          awsToken = await this.withTimeout(this.step13SSOToken(), 90000, 'SSOToken')
          break
        } catch (err) {
          const errMsg = (err as Error).message
          if (ssoAttempt < SSO_MAX_RETRIES) {
            this.log(`[SSO] 后期步骤失败，内部重试 (${ssoAttempt + 1}/${SSO_MAX_RETRIES}): ${errMsg}`)
            await this.abortableSleep(3000 + Math.floor(Math.random() * 2000))
          } else {
            return { status: 'failed', email: this.email, error: `[SSOToken] ${errMsg} (账号已创建，可手动导入刷新)` }
          }
        }
      }

      const token = awsToken!
      const verify = await this.withTimeout(this.verifyAlive(token), 60000, 'VerifyAlive')
      if (verify.suspended) {
        return { status: 'failed', email: this.email, error: 'suspended' }
      }

      return {
        status: 'success',
        email: this.email,
        password: this.cfg.password,
        clientId: this.clientId,
        clientSecret: this.clientSecret,
        refreshToken: (token.refreshToken as string) || '',
        accessToken: (token.accessToken as string) || '',
        region: 'us-east-1',
        provider: 'BuilderId',
        verify,
        fingerprint: this.fingerprintSnapshot()
      }
    } catch (err) {
      return { status: 'failed', email: this.email, error: (err as Error).message }
    } finally {
      await this.cleanup()
    }
  }
}
