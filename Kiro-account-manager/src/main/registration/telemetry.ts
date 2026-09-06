// AWS signin / profile 前端遥测（真实浏览器在注册流程中必发，风控相关性高）
//
// 背景：AWS 的风控会比对「这个访客是否表现得像真实浏览器」。真浏览器在注册过程中
// 除了业务接口，还会打一批遥测端点；纯 HTTP 复刻若一条都不发，就成了显著的自动化特征，
// 表现为在 SetPassword(step12b) 被下发 AMS 人机校验（captchaToken 非空），
// 甚至直接 AWS-RISK-CONTROL。
//
// 本模块对照参考实现（KiroX，逐条对齐 app.kiro.dev.har）补齐这些调用：
//   - POST {signinBase}/metrics/fingerprint            指纹生成/加载指标（HAR 21/27/101）
//   - POST https://d2c.aws.amazon.com/csds/collector/v1/events/batch  D2C 耗时（HAR 37/66）
//   - POST https://unagi-na.amazon.com/1/events/...katal.metrics.core.nexus  katal 指标（HAR 69/72）
//
// 全部 best-effort：失败只记日志，绝不中断注册主流程 —— 遥测本身不影响业务结果，
// 但「发过」这件事会影响风控评分。

import crypto from 'crypto'
import { newUUID } from './http-utils'

export type TelemetryLog = (msg: string) => void

/** 调用方（Registrar）需要提供的最小上下文 */
export interface TelemetryContext {
  signinBase: string
  profileBase: string
  directoryId: string
  ua: string
  secUA: string
  email: string
  /** 供 Referer 拼接 */
  workflowHandle: string
  workflowId: string
  regCode: string
  signState: string
  /** 发 POST：直接复用 Registrar 的 tls-client 通道，保证指纹/代理一致 */
  postJson: (url: string, payload: unknown, headers: Record<string, string>) => Promise<{ status: number; body: string }>
  /** 发表单/纯文本 POST（Content-Type 由 headers 指定） */
  postRaw: (url: string, body: string, headers: Record<string, string>) => Promise<{ status: number; body: string }>
  /** 生成指纹串 */
  genFP: (page: string, eventType: string, inputLen: number, text: string) => string
  buildHeaders: (referer: string, origin: string) => Record<string, string>
  log: TelemetryLog
}

const KATAL_NEXUS_URL = 'https://unagi-na.amazon.com/1/events/com.amazon.eel.katal.metrics.core.nexus'
const D2C_BATCH_URL = 'https://d2c.aws.amazon.com/csds/collector/v1/events/batch'

/**
 * WebVisor 客户端自签 ES256 JWT。
 *
 * 真实浏览器在 POST https://vs.aws.amazon.com/token 时**总是**带一个本地生成的
 * 自签 JWT：header {kid:<uuid>, alg:"ES256"}，payload {vid:<uuid>, iss:"s_p", exp:<unix>}，
 * 并把其中的 vid 作为后续所有 api/execute 的 visitorId。
 *
 * 我们此前首次调用提交空 body（拿不到 token 时 payload 为 {}），与浏览器行为不一致 ——
 * 这是可被风控识别的差异点。签名需与 WebCrypto ES256 一致：r|s 各定长 32 字节大端拼接
 * （即 IEEE P1363 格式），不能用 Node 默认的 DER。
 */
export function webVisorJWT(vid: string): string {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const header = { kid: newUUID(), alg: 'ES256' }
  const payload = { vid, iss: 's_p', exp: Math.floor(Date.now() / 1000) + 3600 }
  const signingInput =
    Buffer.from(JSON.stringify(header)).toString('base64url') +
    '.' +
    Buffer.from(JSON.stringify(payload)).toString('base64url')

  // dsaEncoding: 'ieee-p1363' 直接产出 64 字节 r|s，与 WebCrypto 输出一致
  const sig = crypto.sign('sha256', Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363'
  })
  return `${signingInput}.${sig.toString('base64url')}`
}

/** UUID v4 风格的 visitor id */
export function newVisitorUUID(): string {
  return crypto.randomUUID()
}

/**
 * 上报指纹指标（application/x-www-form-urlencoded）。
 * metricName 形如 "IsFingerprintGenerated:Success"；operation 形如
 * "AWSSignin:FingerprintMetrics:start"。
 */
export async function postFingerprintMetric(
  ctx: TelemetryContext,
  metricName: string,
  value: string,
  operation: string
): Promise<void> {
  const api = `${ctx.signinBase}/metrics/fingerprint`
  const ref = `${ctx.signinBase}/platform/${ctx.directoryId}/login?workflowStateHandle=${ctx.workflowHandle}`

  const form = new URLSearchParams({ name: metricName, value, operation })
  const h = ctx.buildHeaders(ref, ctx.signinBase)
  h['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8'

  const resp = await ctx.postRaw(api, form.toString(), h)
  if (resp.status !== 200) {
    throw new Error(`metrics/fingerprint HTTP ${resp.status}: ${resp.body.slice(0, 120)}`)
  }
}

export async function postFingerprintMetricSafe(
  ctx: TelemetryContext,
  metricName: string,
  value: string,
  operation: string
): Promise<void> {
  try {
    await postFingerprintMetric(ctx, metricName, value, operation)
  } catch (err) {
    ctx.log(`[遥测] ${metricName} 上报失败: ${err instanceof Error ? err.message : String(err)}`)
  }
}

/** 上报 D2C 遥测事件 timeTakenToFetchVID（HAR entries 37/66） */
export async function postD2CEventSafe(
  ctx: TelemetryContext,
  pageURL: string,
  fetchDurationMs: number
): Promise<void> {
  try {
    const origin = pageURL.startsWith(ctx.profileBase) ? ctx.profileBase : ctx.signinBase
    const h: Record<string, string> = {
      'Accept': 'application/json',
      // 与发往 AWS 的其它请求保持一致：主语言必须是英文，中文首语言会触发 WAF challenge
      'Accept-Language': 'en-US,en;q=0.9',
      'Content-Type': 'application/json',
      'User-Agent': ctx.ua,
      'Origin': origin,
      'Referer': pageURL,
      'sec-ch-ua': ctx.secUA,
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors',
      'sec-fetch-site': 'cross-site',
      'priority': 'u=1, i'
    }

    const resp = await ctx.postJson(D2C_BATCH_URL, {
      batchId: 'D2CLogger',
      schemaVersion: '1.0.0',
      batchEvents: [
        {
          pageURL,
          eventType: 'logEvent',
          eventTimestamp: Date.now(),
          customData: {
            timeTakenToFetchVID: fetchDurationMs.toFixed(1),
            logLevel: 'info'
          },
          orgId: 'awsme_scode'
        }
      ]
    }, h)
    if (resp.status !== 200 && resp.status !== 202) {
      throw new Error(`d2c HTTP ${resp.status}: ${resp.body.slice(0, 120)}`)
    }
  } catch (err) {
    ctx.log(`[遥测] d2c 上报失败: ${err instanceof Error ? err.message : String(err)}`)
  }
}

// ===== katal / unagi 遥测（真实浏览器在 profile 页必经）=====

interface KatalEntry {
  key: string
  schema: string
  value: number
}

interface KatalGroup {
  producer: string
  metrics: KatalEntry[]
}

/**
 * 上报一批 katal 指标。
 *
 * 这个端点的 body 是「字典压缩」格式：`cs.dct` 把所有重复出现的字符串抽成 `#N` 槽位，
 * `events[].data` 里再用槽位号互相引用。槽位编号与官方前端一致（#0..#17 固定语义，
 * 多余的 metricKey/schemaId 从 #18 起依次分配），否则服务端解不出来。
 */
export async function postKatalNexusSafe(ctx: TelemetryContext, groups: KatalGroup[]): Promise<void> {
  const usable = groups.filter((g) => g.metrics.length > 0)
  if (usable.length === 0) return

  try {
    const now = new Date()
    const dct: Record<string, unknown> = {
      '#0': 'site', '#1': 'AWSUserProfileFrontEnd', '#2': 'serviceName',
      '#3': 'actionId', '#5': 'cloudWatchDimensions', '#6': 'methodName',
      '#8': 'metricKey', '#10': 'value', '#11': 'isMonitor',
      '#12': 'producerId', '#13': 'katal', '#14': 'schemaId',
      '#16': 'timestamp', '#17': 'messageId'
    }
    const events: unknown[] = []
    let slot = 18

    for (const g of usable) {
      dct['#4'] = newUUID()
      dct['#7'] = g.producer
      dct['#9'] = g.metrics[0].key
      dct['#15'] = g.metrics[0].schema

      // 第一条指标固定复用 #9/#15，其余从 #18 起成对分配 key/schema 槽位
      const slots: Array<{ key: string; schema: string }> = [{ key: '#9', schema: '#15' }]
      for (let i = 1; i < g.metrics.length; i++) {
        const keySlot = `#${slot++}`
        const schemaSlot = `#${slot++}`
        dct[keySlot] = g.metrics[i].key
        dct[schemaSlot] = g.metrics[i].schema
        slots.push({ key: keySlot, schema: schemaSlot })
      }

      for (let i = 0; i < g.metrics.length; i++) {
        events.push({
          data: {
            '#0': '#1', '#2': '#1', '#3': '#4', '#6': '#7',
            '#8': slots[i].key, '#10': g.metrics[i].value, '#11': true,
            '#12': '#13', '#14': slots[i].schema,
            '#16': now.toISOString().replace(/\.\d{3}Z$/, '.000Z'),
            '#17': `1-${now.getTime()}-${1000000000 + Math.floor(Math.random() * 9000000000)}`
          }
        })
      }
    }

    const h: Record<string, string> = {
      'Accept': '*/*',
      // 注意是 text/plain：这个端点不接受 application/json
      'Content-Type': 'text/plain;charset=UTF-8',
      'User-Agent': ctx.ua,
      'Origin': ctx.profileBase,
      'sec-ch-ua': ctx.secUA,
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'no-cors',
      'sec-fetch-site': 'cross-site',
      'priority': 'u=1, i'
    }

    const resp = await ctx.postRaw(KATAL_NEXUS_URL, JSON.stringify({ cs: { dct }, events }), h)
    if (resp.status !== 200 && resp.status !== 202 && resp.status !== 204) {
      throw new Error(`katal HTTP ${resp.status}: ${resp.body.slice(0, 120)}`)
    }
  } catch (err) {
    ctx.log(`[遥测] katal 上报失败: ${err instanceof Error ? err.message : String(err)}`)
  }
}

const COUNTER = 'katal.client.metrics.Counter.3'
const TIMER = 'katal.client.metrics.Timer.2'

/** SendOTP 成功后浏览器必发的批次（HAR entry 69） */
export function katalSignupBatch(getConfigMs: number, sendOTPMs: number): KatalGroup[] {
  return [
    {
      producer: 'AppContextProvider',
      metrics: [
        { key: 'HTTPRequest.GetConfig.StatusCode.200', schema: COUNTER, value: 1 },
        { key: 'HTTPRequest.GetConfig.StatusCode.2XX', schema: COUNTER, value: 1 },
        { key: 'HTTPRequest.GetConfig.Latency', schema: TIMER, value: getConfigMs },
        { key: 'HTTPRequest.GetConfig.Failure', schema: COUNTER, value: 0 },
        // 真实浏览器这里确实是 404（GetAppContext 端点不存在），照抄以保持一致
        { key: 'HTTPRequest.GetAppContext.StatusCode.404', schema: COUNTER, value: 1 },
        { key: 'HTTPRequest.GetAppContext.StatusCode.4XX', schema: COUNTER, value: 1 },
        { key: 'HTTPRequest.GetAppContext.Latency', schema: TIMER, value: getConfigMs },
        { key: 'HTTPRequest.GetAppContext.Failure', schema: COUNTER, value: 1 }
      ]
    },
    {
      producer: 'Steps',
      metrics: [{ key: 'StartSignUp', schema: TIMER, value: getConfigMs }]
    },
    {
      producer: 'SignUpContextProvider',
      metrics: [
        { key: 'HTTPRequest.SendOTP.StatusCode.200', schema: COUNTER, value: 1 },
        { key: 'HTTPRequest.SendOTP.StatusCode.2XX', schema: COUNTER, value: 1 },
        { key: 'HTTPRequest.SendOTP.Latency', schema: TIMER, value: sendOTPMs },
        { key: 'HTTPRequest.SendOTP.Failure', schema: COUNTER, value: 0 }
      ]
    }
  ]
}

/** CreateIdentity 成功后浏览器必发的批次（HAR entry 72） */
export function katalVerificationBatch(verificationMs: number, createIdentityMs: number): KatalGroup[] {
  return [
    {
      producer: 'Steps',
      metrics: [{ key: 'SignUpEmailVerificationStep', schema: TIMER, value: verificationMs }]
    },
    {
      producer: 'SignUpContextProvider',
      metrics: [
        { key: 'HTTPRequest.CreateIdentity.StatusCode.200', schema: COUNTER, value: 1 },
        { key: 'HTTPRequest.CreateIdentity.StatusCode.2XX', schema: COUNTER, value: 1 },
        { key: 'HTTPRequest.CreateIdentity.Latency', schema: TIMER, value: createIdentityMs },
        { key: 'HTTPRequest.CreateIdentity.Failure', schema: COUNTER, value: 0 }
      ]
    }
  ]
}
