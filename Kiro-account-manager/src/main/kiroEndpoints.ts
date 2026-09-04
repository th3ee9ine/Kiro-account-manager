// Kiro / AWS 端点与请求头常量（主进程唯一出口）
//
// token 刷新、用量查询、模型列表、对话测活、注册验活分散在多个模块里，
// 但它们用的是同一套 UA 与同一套区域映射规则。此前 src/main/index.ts 与
// src/main/proxy/kiroApi.ts 各写一份，版本号漂移到 0.6.18 / 0.12.155 两个值，
// 导致「反代能出字但刷新用量 403」这类只在 Builder ID 上暴露的问题。
// 统一收在这里，任何新调用点都从本模块取 UA。

import * as os from 'os'

/**
 * 对齐 Kiro IDE 的版本号与 SDK 版本。
 *
 * 这不只是「像不像官方客户端」的问题，服务端会按 UA 里的版本号做准入：
 * 实测同一个 Builder ID token，UA 报 KiroIDE-0.6.18 / aws-sdk-js/1.0.18 时
 * getUsageLimits / ListAvailableModels / generateAssistantResponse 一律回
 * 403 "User is not authorized to make this call."；只把版本换成下面这组即 200。
 * 社交账号（Github / Google）不受该门槛影响，两组 UA 都通——所以这个坑只在
 * Builder ID / IdC 上暴露出来。
 *
 * 升级时这几个值要一起动，混搭（新版本号 + 旧 SDK）没有验证过。
 */
export const KIRO_IDE_VERSION = '0.12.155'
export const AWS_SDK_VERSION = '1.0.34'
export const AWS_STREAMING_API_VERSION = '1.0.34'

/** os / node 指纹按本机真实值填，固定写 os/windows 反而是个显眼的破绽 */
const UA_OS = process.platform === 'win32' ? 'win32' : process.platform === 'darwin' ? 'macos' : 'linux'
const UA_OS_RELEASE = (() => {
  try {
    return os.release()
  } catch {
    return '10.0.0'
  }
})()
const UA_NODE_VERSION = process.versions.node || '22.22.0'

/**
 * 完整 UA，AWS SDK 风格 + Kiro IDE 版本。
 *
 * machineId 存在时以 `KiroIDE-{版本}-{machineId}` 结尾：K-Proxy 的 mitm 会用
 * /KiroIDE[-\s][\d.]+[-\s]([a-f0-9]{64})/ 从这里回读设备 ID，改格式会让设备绑定失效。
 */
export function getKiroUserAgent(machineId?: string): string {
  const suffix = machineId ? `KiroIDE-${KIRO_IDE_VERSION}-${machineId}` : `KiroIDE-${KIRO_IDE_VERSION}`
  return (
    `aws-sdk-js/${AWS_SDK_VERSION} ua/2.1 os/${UA_OS}#${UA_OS_RELEASE} lang/js ` +
    `md/nodejs#${UA_NODE_VERSION} api/codewhispererstreaming#${AWS_STREAMING_API_VERSION} m/E ${suffix}`
  )
}

/** x-amz-user-agent 用的短 UA */
export function getKiroAmzUserAgent(machineId?: string): string {
  const suffix = machineId ? `KiroIDE ${KIRO_IDE_VERSION} ${machineId}` : `KiroIDE-${KIRO_IDE_VERSION}`
  return `aws-sdk-js/${AWS_SDK_VERSION} ${suffix}`
}

/** 接口只在这两个区域有部署，其它区域按地理位置就近归并 */
export type KiroServiceRegion = 'us-east-1' | 'eu-central-1'

/** 把任意 AWS 区域归并到最近的服务区域 */
export function kiroServiceRegion(region?: string): KiroServiceRegion {
  return region?.startsWith('eu-') ? 'eu-central-1' : 'us-east-1'
}

/** Amazon Q 端点：用量、模型列表、订阅 */
export function qServiceEndpoint(region?: string): string {
  return `https://q.${kiroServiceRegion(region)}.amazonaws.com`
}

/** 主端点 403 时换另一个区域再试 */
export function qServiceFallbackEndpoint(region?: string): string {
  return `https://q.${kiroServiceRegion(region) === 'eu-central-1' ? 'us-east-1' : 'eu-central-1'}.amazonaws.com`
}

/** CodeWhisperer Runtime 端点：profile 列表、对话 */
export function codeWhispererEndpoint(region?: string): string {
  return `https://codewhisperer.${kiroServiceRegion(region)}.amazonaws.com`
}

/** AWS SDK 通用重试头：本应用自己控制重试，固定单次 */
export const AWS_SINGLE_ATTEMPT_HEADERS: Readonly<Record<string, string>> = {
  'amz-sdk-request': 'attempt=1; max=1'
}
