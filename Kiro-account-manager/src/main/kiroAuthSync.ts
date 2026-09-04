// Kiro IDE Auth Token 同步层
//
// Kiro IDE 桌面端把 token 持久化在 ~/.aws/sso/cache/kiro-auth-token.json，
// 并对该文件做 fs.watchFile 监听 + 内部 refresh loop。
//
// 反代和 IDE 必须以这个文件作为 single source of truth，否则会出现：
//   反代 store 里 refreshToken_v2，磁盘里 refreshToken_v1（已被服务端轮换作废）
//   → IDE 一小时后用 v1 调 OIDC → 401 → logoutAndForget()
//
// 本模块提供：
//   writeKiroAuthTokenFile  — 以 Kiro IDE 兼容格式写入 token 文件（+ IdC 客户端注册）
//   readKiroAuthTokenFile   — 读取当前磁盘 token
//   parseAccessTokenClaims  — 解 accessToken 的 JWT 拿到 sub/email，用于反向匹配账号
//   watchKiroAuthTokenFile  — 监听文件变化（IDE 自己 refresh 时用于反向同步到反代 store）

import * as fs from 'fs/promises'
import * as fsSync from 'fs'
import * as path from 'path'
import * as os from 'os'
import * as crypto from 'crypto'

export const KIRO_SSO_CACHE_DIR = path.join(os.homedir(), '.aws', 'sso', 'cache')
export const KIRO_AUTH_TOKEN_PATH = path.join(KIRO_SSO_CACHE_DIR, 'kiro-auth-token.json')

const KIRO_DEFAULT_START_URL = 'https://view.awsapps.com/start'
const KIRO_OIDC_SCOPES = [
  'codewhisperer:completions',
  'codewhisperer:analysis',
  'codewhisperer:conversations',
  'codewhisperer:transformations',
  'codewhisperer:taskassist'
]

// =============== profileArn 决策中心 ===============
//
// 占位符 ARN：Kiro IDE 源码 FixedProfileArns 里给 BuilderId 硬编码的值。
//
// 两个用途，别混：
//   1. Kiro IDE 内部逻辑依赖 token 文件里存在该字段，移除会导致 IDE 功能异常
//   2. runtime 接口（getUsageLimits / ListAvailableModels / generateAssistantResponse）
//      已把 profileArn 从可选改成必填，Builder ID 账号必须原样带上它才回 200，
//      不带就是 403 "User is not authorized to make this call."
//      （用量 403 / 模型列表 400 "Invalid profileArn" / 对话 400 "profileArn is required"）
export const KIRO_BUILDER_ID_PLACEHOLDER_ARN = 'arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX'
// Social 登录（Github/Google）共用的 Kiro 后端固定 profileArn
export const KIRO_SOCIAL_PROFILE_ARN = 'arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK'

// Enterprise 备用 profileArn（自动获取失败时使用，区域动态替换）
const ENTERPRISE_FALLBACK_PROFILE_ID = 'VNECVYCYYAWN'
const ENTERPRISE_FALLBACK_ACCOUNT_ID = '610548660232'
export function getEnterpriseFallbackArn(region?: string): string {
  const r = region?.startsWith('eu-') ? 'eu-central-1' : 'us-east-1'
  return `arn:aws:codewhisperer:${r}:${ENTERPRISE_FALLBACK_ACCOUNT_ID}:profile/${ENTERPRISE_FALLBACK_PROFILE_ID}`
}

const PLACEHOLDER_PROFILE_ARNS = new Set<string>([KIRO_BUILDER_ID_PLACEHOLDER_ARN])

/** 检查给定 ARN 是不是已知占位符（旧版反代 / Kiro IDE 自身可能写入的脏数据） */
export function isPlaceholderProfileArn(arn: string | undefined | null): boolean {
  if (!arn) return false
  return PLACEHOLDER_PROFILE_ARNS.has(arn)
}

/**
 * 写入 token 文件前对 profileArn 的"应该写啥"做统一决策。
 *
 * 规则（优先级）：
 *   1. 调用方显式给出 profileArn 且非已知占位符 → 直接用
 *   2. social/Github/Google → 用固定 Kiro Social profileArn
 *   3. BuilderId / 其它 → 使用 Kiro IDE 官方占位符 ARN（IDE 内部逻辑依赖此字段存在）
 */
export function resolveProfileArnForWrite(input: {
  profileArn?: string
  authMethod?: string
  provider?: string
  region?: string
}): string | undefined {
  if (input.profileArn && !isPlaceholderProfileArn(input.profileArn)) {
    return input.profileArn
  }
  if (input.authMethod === 'social' || input.provider === 'Github' || input.provider === 'Google') {
    return KIRO_SOCIAL_PROFILE_ARN
  }
  // Enterprise 不能用 BuilderId 占位符（IDE 调接口会 Invalid token）
  if (input.provider === 'Enterprise' || input.authMethod === 'external_idp') {
    return getEnterpriseFallbackArn(input.region)
  }
  return KIRO_BUILDER_ID_PLACEHOLDER_ARN
}

/** 判断是不是社交登录（Github / Google）：后端认一个固定 ARN，没有 profile 概念 */
export function isSocialLogin(input: { authMethod?: string; provider?: string }): boolean {
  return input.authMethod === 'social' || input.provider === 'Github' || input.provider === 'Google'
}

/** 判断是不是 Enterprise / 外部 IdP：只有这类账号有真实 profile 可查 */
export function isEnterpriseLogin(input: { authMethod?: string; provider?: string }): boolean {
  return (
    input.provider === 'Enterprise' ||
    input.provider === 'ExternalIdp' ||
    input.authMethod === 'external_idp'
  )
}

export interface ProfileArnIdentity {
  profileArn?: string
  authMethod?: string
  provider?: string
  region?: string
}

/**
 * 按成功率给出「可以依次实测」的 profileArn 候选。
 *
 * 背景：profileArn 现在是必填，不带会被拒。但「补一个」不能瞎补——
 * Enterprise 必须用它自己 profile 的真实 ARN，getEnterpriseFallbackArn 那个
 * 内置兜底值属于另一个组织，拿别家 profile 查自己的用量，上游回
 * 403 "Invalid token"（与 Builder ID 那句 "User is not authorized to make this call."
 * 是两条不同的错误，前者专指 profileArn 不对）。
 *
 * 所以 Enterprise 的真实 ARN 只能由调用方先向 ListAvailableProfiles 查出来，
 * 通过 resolvedEnterpriseArn 传进来；其余登录方式用固定 ARN 即可。
 *
 * 末位保留一个「不带」的兜底：当前它只会换来 400，而 400 不是授权类错误，
 * 调用方会就此中断不浪费请求；留着纯粹为了后端哪天改回去时还有条路走。
 */
export function profileArnCandidates(
  input: ProfileArnIdentity,
  resolvedEnterpriseArn?: string
): (string | undefined)[] {
  const out: (string | undefined)[] = []
  const push = (arn?: string): void => {
    if (!out.includes(arn)) out.push(arn)
  }

  // 账号已存的 ARN 最可信：它要么来自上游，要么是此前实测过并回写的
  if (input.profileArn && !isPlaceholderProfileArn(input.profileArn)) push(input.profileArn)

  // 社交账号后端固定一个 profile，且该字段必填，没有「不带」这个选项
  if (isSocialLogin(input)) {
    push(KIRO_SOCIAL_PROFILE_ARN)
    return out
  }

  // Enterprise：ListAvailableProfiles 查到的真实 ARN 优先于内置兜底
  if (isEnterpriseLogin(input)) {
    if (resolvedEnterpriseArn) push(resolvedEnterpriseArn)
    push(getEnterpriseFallbackArn(input.region))
  } else {
    // Builder ID / 其它 IdC：没有 profile 概念，用 Kiro IDE 那个硬编码占位符
    push(KIRO_BUILDER_ID_PLACEHOLDER_ARN)
  }

  push(undefined)
  return out
}

/**
 * 判断错误是否属于「token / 授权维度不匹配」。
 * profileArn 写错时接口回的就是 403 User is not authorized 或 invalid token，
 * 这类错误换一个候选重试有意义；网络错误则没有。
 *
 * 状态码用词边界匹配而非 includes：错误文案里常夹着 ARN、请求 ID 这类长串数字，
 * 裸 includes('400') 会被 "…:1400…" 之类的片段误命中。
 */
export function isAuthScopeError(message: string): boolean {
  if (/\b(400|401|403)\b/.test(message)) return true
  const m = message.toLowerCase()
  return (
    m.includes('not authorized') ||
    m.includes('invalid token') ||
    m.includes('bearer token') ||
    m.includes('accessdenied')
  )
}

/** ARN 不被接受的判据：授权维度的错误，或上游明确点名 profileArn */
export function isProfileArnRejection(message: string): boolean {
  return isAuthScopeError(message) || /profilearn/i.test(message)
}

/** 判断错误是否代表账号被封禁：换 ARN 也是同样结果，不值得再试 */
export function isAccountBannedError(message: string): boolean {
  return message.includes('AccountSuspended') || message.includes('423')
}

export interface KiroAuthTokenFile {
  accessToken: string
  refreshToken: string
  expiresAt: string
  authMethod?: 'IdC' | 'social' | string
  provider?: string
  region?: string
  clientIdHash?: string
  profileArn?: string
}

export interface WriteKiroAuthTokenInput {
  accessToken: string
  refreshToken: string
  /** ISO 字符串。建议用 OIDC 返回的真实 expiresIn 算 */
  expiresAtIso: string
  authMethod: 'IdC' | 'social'
  provider: string
  region?: string
  startUrl?: string
  /** IdC 必填：会一起写客户端注册文件 */
  clientId?: string
  clientSecret?: string
  profileArn?: string
}

export interface WriteKiroAuthTokenResult {
  tokenPath: string
  clientRegPath?: string
}

function computeClientIdHash(startUrl?: string): string {
  return crypto
    .createHash('sha1')
    .update(JSON.stringify({ startUrl: startUrl || KIRO_DEFAULT_START_URL }))
    .digest('hex')
}

/**
 * 以与 Kiro IDE 完全兼容的格式写入 ~/.aws/sso/cache/kiro-auth-token.json
 * - mode 0o600：与 IDE 保持一致（writeTokenToDisk 用 0o600 即 384）
 * - social 与 IdC 字段顺序对齐 Kiro IDE 序列化结果，便于人工 diff
 * - IdC 同时写客户端注册文件 {clientIdHash}.json
 */
export async function writeKiroAuthTokenFile(
  input: WriteKiroAuthTokenInput
): Promise<WriteKiroAuthTokenResult> {
  await fs.mkdir(KIRO_SSO_CACHE_DIR, { recursive: true })

  const clientIdHash = computeClientIdHash(input.startUrl)

  const tokenData: Record<string, unknown> =
    input.authMethod === 'social'
      ? {
          accessToken: input.accessToken,
          refreshToken: input.refreshToken,
          profileArn: input.profileArn,
          expiresAt: input.expiresAtIso,
          authMethod: input.authMethod,
          provider: input.provider
        }
      : {
          accessToken: input.accessToken,
          refreshToken: input.refreshToken,
          expiresAt: input.expiresAtIso,
          clientIdHash,
          authMethod: input.authMethod,
          provider: input.provider,
          region: input.region || 'us-east-1',
          profileArn: input.profileArn
        }

  await fs.writeFile(KIRO_AUTH_TOKEN_PATH, JSON.stringify(tokenData, null, 2), {
    mode: 0o600
  })
  // Windows 上 chmod 对 0o600 是 no-op 但不抛错；Linux/macOS 上保证权限正确
  try {
    await fs.chmod(KIRO_AUTH_TOKEN_PATH, 0o600)
  } catch {
    /* ignore */
  }

  let clientRegPath: string | undefined
  if (input.authMethod !== 'social' && input.clientId && input.clientSecret) {
    clientRegPath = path.join(KIRO_SSO_CACHE_DIR, `${clientIdHash}.json`)
    // IDE 客户端注册有效期 90 天（Kiro IDE 原版做法），格式为去掉 Z 的 ISO 字符串
    const clientExpiresAt = new Date(Date.now() + 90 * 24 * 3600 * 1000).toISOString().replace('Z', '')
    const clientData = {
      clientId: input.clientId,
      clientSecret: input.clientSecret,
      expiresAt: clientExpiresAt,
      scopes: KIRO_OIDC_SCOPES
    }
    await fs.writeFile(clientRegPath, JSON.stringify(clientData, null, 2), { mode: 0o600 })
    try {
      await fs.chmod(clientRegPath, 0o600)
    } catch {
      /* ignore */
    }
  }

  return { tokenPath: KIRO_AUTH_TOKEN_PATH, clientRegPath }
}

export async function readKiroAuthTokenFile(): Promise<KiroAuthTokenFile | null> {
  try {
    const content = await fs.readFile(KIRO_AUTH_TOKEN_PATH, 'utf-8')
    const parsed = JSON.parse(content) as KiroAuthTokenFile
    if (!parsed.accessToken || !parsed.refreshToken) return null
    return parsed
  } catch {
    return null
  }
}

/**
 * 解 accessToken 的 JWT 第二段（payload）拿 sub / email / aud / preferred_username。
 * - 如果不是 JWT 格式返回 null
 * - 不验证签名（只用于反向匹配账号）
 */
export interface AccessTokenClaims {
  sub?: string
  email?: string
  aud?: string
  preferredUsername?: string
}

export function parseAccessTokenClaims(accessToken: string): AccessTokenClaims | null {
  if (!accessToken) return null
  const parts = accessToken.split('.')
  if (parts.length < 2) return null
  try {
    let b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    while (b64.length % 4) b64 += '='
    const json = Buffer.from(b64, 'base64').toString('utf-8')
    const claims = JSON.parse(json) as Record<string, unknown>
    const audRaw = claims.aud
    const aud = typeof audRaw === 'string' ? audRaw : Array.isArray(audRaw) && typeof audRaw[0] === 'string' ? (audRaw[0] as string) : undefined
    return {
      sub: typeof claims.sub === 'string' ? (claims.sub as string) : undefined,
      email: typeof claims.email === 'string' ? (claims.email as string) : undefined,
      aud,
      preferredUsername:
        typeof claims['preferred_username'] === 'string'
          ? (claims['preferred_username'] as string)
          : undefined
    }
  } catch {
    return null
  }
}

/**
 * 监听 Kiro IDE 的 token 文件变化。
 * - 使用 fs.watchFile（polling）以保证跨平台一致性
 * - 内部做内容防抖（同一对 accessToken+refreshToken 不重复触发）
 * - 返回 dispose 函数
 */
export type WatchCallback = (token: KiroAuthTokenFile) => void | Promise<void>

export function watchKiroAuthTokenFile(onChange: WatchCallback, intervalMs = 2000): () => void {
  let debounceTimer: NodeJS.Timeout | null = null
  let lastSeenSig = ''
  let disposed = false

  const tick = async (): Promise<void> => {
    if (disposed) return
    try {
      const token = await readKiroAuthTokenFile()
      if (!token) return
      const sig = `${token.accessToken}|${token.refreshToken}`
      if (sig === lastSeenSig) return
      lastSeenSig = sig
      await onChange(token)
    } catch (e) {
      // 静默：watcher 不应该 throw 影响主进程
      console.warn('[kiroAuthSync] watcher tick failed:', e)
    }
  }

  const listener = (): void => {
    if (debounceTimer) clearTimeout(debounceTimer)
    debounceTimer = setTimeout(() => {
      debounceTimer = null
      void tick()
    }, 600)
  }

  // 先做一次基线读，避免启动后第一次"虚假变更"
  void readKiroAuthTokenFile().then((t) => {
    if (t) lastSeenSig = `${t.accessToken}|${t.refreshToken}`
  })

  fsSync.watchFile(KIRO_AUTH_TOKEN_PATH, { interval: intervalMs }, listener)

  return () => {
    disposed = true
    if (debounceTimer) clearTimeout(debounceTimer)
    fsSync.unwatchFile(KIRO_AUTH_TOKEN_PATH, listener)
  }
}
