// 本地 HTTP CONNECT → 上游代理 的最小桥接，专供 AMS captcha 的 BrowserWindow 使用。
//
// 为什么需要：Electron 的 session.setProxy({proxyRules}) **不支持带用户名密码的 socks5**
// （实测报 ERR_NO_SUPPORTED_PROXIES），而注册用的住宅代理几乎都是 socks5 + 认证。
// captcha 凭证的签发与核验绑定来源 IP，窗口必须和注册请求走同一出口，不能退化为直连。
//
// 做法：在 127.0.0.1 起一个只处理 CONNECT 的 TCP 服务，把隧道转发给上游代理
// （socks5/socks4 经 socks 库；http/https 经二次 CONNECT），然后把
// `http://127.0.0.1:<port>` 交给 Electron —— 无认证的本地 http 代理它完全支持。
//
// 与 chainProxy.ts 的区别：那个是「上游中转 + 目标代理」两跳链路，用于隐藏真实来源；
// 这里只需要一跳（就是注册当前用的那个代理），职责更小，故单独实现。

import * as net from 'net'
import { URL } from 'url'

export interface CaptchaProxyBridge {
  /** 交给 Electron 的本地代理地址，形如 http://127.0.0.1:54321 */
  url: string
  stop: () => Promise<void>
}

type UpstreamKind = 'socks' | 'http'

interface Upstream {
  kind: UpstreamKind
  host: string
  port: number
  socksType?: 4 | 5
  user?: string
  pass?: string
}

function parseUpstream(raw: string): Upstream | null {
  const t = (raw || '').trim()
  if (!t) return null
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? t : `http://${t}`
  let u: URL
  try {
    u = new URL(withScheme)
  } catch {
    return null
  }
  const user = u.username ? decodeURIComponent(u.username) : undefined
  const pass = u.password ? decodeURIComponent(u.password) : undefined
  const p = u.protocol

  if (p === 'socks5:' || p === 'socks5h:' || p === 'socks4:' || p === 'socks4a:') {
    return {
      kind: 'socks',
      host: u.hostname,
      port: Number(u.port) || 1080,
      socksType: p === 'socks4:' || p === 'socks4a:' ? 4 : 5,
      user,
      pass
    }
  }
  if (p === 'http:' || p === 'https:') {
    return { kind: 'http', host: u.hostname, port: Number(u.port) || (p === 'https:' ? 443 : 80), user, pass }
  }
  return null
}

/** 经 socks 库建立到目标的隧道 */
async function connectViaSocks(up: Upstream, host: string, port: number): Promise<net.Socket> {
  // socks 是既有依赖（systemProxy.ts 的 socks dispatcher 同样按需 require）。
  // 保持 require 而非顶层 import：与该文件一致，避免未走 socks 的场景也加载这个原生模块。
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { SocksClient } = require('socks') as typeof import('socks')
  const { socket } = await SocksClient.createConnection({
    proxy: { host: up.host, port: up.port, type: up.socksType ?? 5, userId: up.user, password: up.pass },
    command: 'connect',
    destination: { host, port }
  })
  return socket
}

/** 对上游 http 代理再做一次 CONNECT */
function connectViaHttp(up: Upstream, host: string, port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const sock = net.connect(up.port, up.host)
    const onErr = (e: Error): void => {
      sock.destroy()
      reject(e)
    }
    sock.once('error', onErr)
    sock.once('connect', () => {
      const lines = [`CONNECT ${host}:${port} HTTP/1.1`, `Host: ${host}:${port}`]
      if (up.user) {
        const cred = Buffer.from(`${up.user}:${up.pass ?? ''}`).toString('base64')
        lines.push(`Proxy-Authorization: Basic ${cred}`)
      }
      lines.push('Connection: keep-alive', '', '')
      sock.write(lines.join('\r\n'))

      let buf = ''
      const onData = (chunk: Buffer): void => {
        buf += chunk.toString('latin1')
        const end = buf.indexOf('\r\n\r\n')
        if (end < 0) return
        sock.removeListener('data', onData)
        sock.removeListener('error', onErr)
        const status = Number((buf.match(/^HTTP\/1\.[01]\s+(\d{3})/) || [])[1] || 0)
        if (status !== 200) {
          sock.destroy()
          reject(new Error(`上游代理 CONNECT 失败: HTTP ${status || '无响应'}`))
          return
        }
        // 若响应之后还粘了数据，回填给调用方
        const rest = buf.slice(end + 4)
        if (rest) sock.unshift(Buffer.from(rest, 'latin1'))
        resolve(sock)
      }
      sock.on('data', onData)
    })
  })
}

/**
 * 启动桥接。proxyUrl 为空时返回 null（调用方据此走系统代理/直连）。
 */
export async function startCaptchaProxyBridge(
  proxyUrl: string | undefined,
  log?: (m: string) => void
): Promise<CaptchaProxyBridge | null> {
  const up = parseUpstream(proxyUrl || '')
  if (!up) return null

  // 上游本身就是无认证的本地 http 代理时无需桥接（如代理链已起的中继）
  if (up.kind === 'http' && !up.user && /^(127\.0\.0\.1|localhost|::1)$/i.test(up.host)) {
    return { url: `http://${up.host}:${up.port}`, stop: async () => {} }
  }

  const sockets = new Set<net.Socket>()

  const server = net.createServer((client) => {
    sockets.add(client)
    client.on('close', () => sockets.delete(client))
    client.on('error', () => client.destroy())

    client.once('data', async (chunk) => {
      const head = chunk.toString('latin1')
      const m = head.match(/^CONNECT\s+([^\s:]+):(\d+)\s+HTTP\/1\.[01]/i)
      if (!m) {
        // 只支持 CONNECT：captcha 窗口全程 https，普通 GET/POST 不会走到这里
        client.end('HTTP/1.1 405 Method Not Allowed\r\n\r\n')
        return
      }
      const host = m[1]
      const port = Number(m[2])
      try {
        const upstreamSock = up.kind === 'socks'
          ? await connectViaSocks(up, host, port)
          : await connectViaHttp(up, host, port)

        sockets.add(upstreamSock)
        upstreamSock.on('close', () => sockets.delete(upstreamSock))
        upstreamSock.on('error', () => upstreamSock.destroy())

        client.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        client.pipe(upstreamSock)
        upstreamSock.pipe(client)
      } catch (err) {
        log?.(`[CaptchaProxy] 隧道到 ${host}:${port} 失败: ${err instanceof Error ? err.message : String(err)}`)
        try { client.end('HTTP/1.1 502 Bad Gateway\r\n\r\n') } catch { /* ignore */ }
      }
    })
  })

  const url = await new Promise<string>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address()
      if (addr && typeof addr === 'object') {
        server.removeListener('error', reject)
        resolve(`http://127.0.0.1:${addr.port}`)
      } else {
        reject(new Error('captcha 代理桥接启动失败：无法获取端口'))
      }
    })
  })

  return {
    url,
    stop: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) {
          try { s.destroy() } catch { /* ignore */ }
        }
        sockets.clear()
        server.close(() => resolve())
        setTimeout(resolve, 500)
      })
  }
}
