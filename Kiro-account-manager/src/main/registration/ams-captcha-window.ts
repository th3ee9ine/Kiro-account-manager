// AWS AMS Captcha 求解（隐藏 BrowserWindow 借壳官方 CDN 脚本）
//
// 背景：AWS 注册链路在「设置密码」(step12b) 会按风控下发人机校验。响应形如：
//   { captchaResponse: { captchaToken: "<base64>", captchaCDN: "https://cdn.us-east-1.threat-mitigation.aws.amazon.com/...", captchaURL: "", captchaCES: "" } }
// 只要 captchaToken 存在，提交时就**必须**带上过关凭证 accessCode，否则服务端返回
// HTTP 400 + errorCode: AUTHENTICATION_FAILED（表面文案是 "An unexpected error has occurred"，
// 极易误判为偶发故障；实测重试只会让风控升级成 AWS-RISK-CONTROL）。
//
// 两类 captcha（据线上 signin app.js 的 AMSCaptcha 组件反推）：
//   - AMS：captchaToken + captchaCDN → 浏览器加载 CDN 脚本，window.initAMS 初始化后
//          在 challengeCompleted 事件里拿到 accessCode。本模块处理这一类。
//   - ACS：仅 captchaURL → 传统图形验证码，需人工填 captchaGuess。本模块不处理。
//
// 官方 DOM 契约（照抄，缺一不可）：
//   1) 页面存在 <div id="captcha" data-callback="initAMS">
//   2) window.initAMS = (initializer) => initializer.init({ redemptionToken, locale, ... })
//   3) 通过 <script src="{captchaCDN}"> 加载，脚本 onload 后会去找上面那个元素与回调
//   4) init 参数里 showChallengeOnLoad:false —— 官方默认值，意味着多数低风险场景
//      脚本能静默判定通过、直接回调 challengeCompleted，无需人工点选
//
// 因此本模块默认用**隐藏窗口静默求解**；仅当脚本主动要求展示挑战
// (onChallengeDisplay) 时才把窗口显示出来让用户完成，兼顾自动化与可用性。
//
// WARN: 标注「AMS 契约依赖点」的部分随 AWS 改版可能失效，届时只需更新本文件。

import { BrowserWindow, session, type Session } from 'electron'
import { startCaptchaProxyBridge, type CaptchaProxyBridge } from './captcha-proxy-bridge'

/** 非持久化分区：captcha 不需要跨次登录态，每次干净环境反而更像新访客 */
const PARTITION = 'ams-captcha'
/** AMS 契约依赖点：官方页面固定用 id="captcha" 承载挑战 UI */
const CAPTCHA_ELEMENT_ID = 'captcha'
/** AMS 契约依赖点：data-callback 的值，脚本会取 window[该值] 作为初始化回调 */
const CALLBACK_NAME = 'initAMS'
/** 宿主页 origin 必须与 signin 同源语义一致，否则脚本内部的 postMessage 校验可能拒绝 */
const HOST_ORIGIN = 'https://us-east-1.signin.aws'
const HOST_URL = `${HOST_ORIGIN}/platform/captcha-host`

export type AmsLogger = (msg: string) => void

export interface AmsSolveResult {
  /** 过关凭证；提交密码时作为 captchaRequest.captchaAccessCode 回传 */
  accessCode: string
  /** 是否需要用户手工完成（脚本触发了 onChallengeDisplay） */
  interactive: boolean
}

/**
 * 给 captcha 窗口配代理。
 *
 * 必须与注册链路走同一出口：captcha 凭证的签发与核验绑定来源 IP，
 * 若这里直连而注册走代理，服务端会认为凭证来自另一个访客。
 *
 * Electron 的 proxyRules **不支持带认证的 socks5**（实测 ERR_NO_SUPPORTED_PROXIES），
 * 而住宅代理基本都是这种形态，所以统一经本地 CONNECT 桥接转成无认证 http 代理。
 */
async function applyProxy(sess: Session, proxy: string | undefined, log: AmsLogger): Promise<CaptchaProxyBridge | null> {
  const bridge = await startCaptchaProxyBridge(proxy, log)
  if (bridge) {
    log(`[AMS] captcha 窗口经本地桥接复用注册出口: ${bridge.url}`)
    await sess.setProxy({ proxyRules: bridge.url })
    return bridge
  }
  await sess.setProxy({ mode: 'system' })
  return null
}

/**
 * 宿主页 HTML：最小化复刻官方 signin 页面的 AMS 挂载点。
 * 不引入任何第三方内容，只有一个挂载 div + 一个把初始化器桥接到主进程的回调。
 */
function buildHostHtml(): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Verification</title>
<style>html,body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#fff}
#wrap{padding:16px}#hint{color:#444;font-size:13px;margin-bottom:12px}</style>
</head>
<body>
<div id="wrap">
  <div id="hint">正在完成安全验证…（若出现验证题目，请手动完成）</div>
  <!-- AMS 契约依赖点：id + data-callback 必须与官方一致 -->
  <div id="${CAPTCHA_ELEMENT_ID}" data-callback="${CALLBACK_NAME}"></div>
</div>
<script>
  window.__amsResult = null;
  window.__amsError = null;
  window.__amsDisplayed = false;
  window.__amsScriptLoaded = false;

  // AMS 契约依赖点：脚本 onload 后取 window[data-callback] 并传入初始化器
  window.${CALLBACK_NAME} = function (initializer) {
    try {
      initializer.init({
        redemptionToken: window.__amsToken,
        locale: 'en-us',
        // 官方默认 false：低风险时脚本静默判定通过，不弹题目
        showChallengeOnLoad: false,
        onChallengeDisplay: function () { window.__amsDisplayed = true; },
        onChallengeComplete: function (e) {
          window.__amsResult = (e && e.accessCode) ? e.accessCode : '';
        },
        onError: function (e) {
          window.__amsError = (e && (e.errorMessage || e.message)) ? String(e.errorMessage || e.message) : 'unknown AMS error';
        }
      });
    } catch (err) {
      window.__amsError = 'init threw: ' + String(err && err.message ? err.message : err);
    }
  };

  // 由主进程注入 token 后再插入 CDN 脚本，确保 init 时 token 已就绪
  window.__amsBoot = function (token, cdn) {
    window.__amsToken = token;
    var s = document.createElement('script');
    s.src = cdn;
    s.defer = true;
    s.id = 'captcha-client-script-cdn';
    s.onload = function () { window.__amsScriptLoaded = true; };
    s.onerror = function () { window.__amsError = 'CDN 脚本加载失败: ' + cdn; };
    document.body.appendChild(s);
  };
</script>
</body></html>`
}

/** 加载宿主页并等 dom-ready（带超时兜底） */
function loadAndWait(w: BrowserWindow, url: string, timeoutMs = 30000): Promise<void> {
  return new Promise((resolve) => {
    let done = false
    const finish = (): void => {
      if (done) return
      done = true
      w.webContents.removeListener('dom-ready', finish)
      resolve()
    }
    w.webContents.once('dom-ready', finish)
    w.loadURL(url).catch(() => finish())
    setTimeout(finish, timeoutMs)
  })
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

/**
 * 单窗口串行化：AMS 挑战与窗口内的全局回调（window.initAMS / __amsResult）是单例，
 * 并发求解会互相覆盖结果。批量注册时多个任务都可能同时要 captcha，故强制排队。
 */
let solveQueue: Promise<unknown> = Promise.resolve()

export function solveAmsCaptcha(opts: SolveOptions): Promise<AmsSolveResult> {
  const run = solveQueue.then(
    () => runSolve(opts),
    () => runSolve(opts)
  )
  solveQueue = run.catch(() => undefined)
  return run
}

export interface SolveOptions {
  /** 服务端下发的 captchaToken（base64，内含 redemptionToken/apiRoot/region） */
  captchaToken: string
  /** 服务端下发的 CDN 脚本地址 */
  captchaCDN: string
  /** 必须与注册链路同一出口代理，否则凭证来源 IP 不匹配 */
  proxy?: string
  /** 总超时（秒）：静默场景通常几秒内完成；需人工时留足时间 */
  timeoutSec?: number
  log?: AmsLogger
  signal?: AbortSignal
  /** 脚本要求人工点选时回调一次（用于向前端提示，批量场景否则会静默卡住） */
  onInteractive?: () => void
  /**
   * 需要人工完成时立即失败，而不是等满 timeoutSec。
   * 批量/无人值守场景应设为 true：干等一个不存在的人只是浪费并发槽。
   */
  failFastOnInteractive?: boolean
}

async function runSolve(opts: SolveOptions): Promise<AmsSolveResult> {
  const log = opts.log ?? ((): void => {})
  const timeoutSec = opts.timeoutSec ?? 120

  if (!opts.captchaToken) throw new Error('AMS captcha: captchaToken 为空')
  if (!opts.captchaCDN) throw new Error('AMS captcha: captchaCDN 为空')

  const sess = session.fromPartition(PARTITION)
  const bridge = await applyProxy(sess, opts.proxy, log)

  const win = new BrowserWindow({
    width: 520,
    height: 620,
    show: false,
    title: '安全验证',
    autoHideMenuBar: true,
    webPreferences: {
      partition: PARTITION,
      backgroundThrottling: false,
      contextIsolation: false,
      nodeIntegration: false,
      sandbox: false
    }
  })

  // 用真实 Chrome UA：带 Electron 标识容易被风控判定为自动化环境
  win.webContents.setUserAgent(
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'
  )
  // captcha 窗口内不允许开新窗口
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))

  const html = buildHostHtml()
  let shown = false
  try {
    // 宿主页必须运行在 https://us-east-1.signin.aws 这个 origin 下：
    // data:/file: 是不透明 origin，AMS 脚本内部的 postMessage 校验会拒绝。
    // 做法：先导航到 signin.aws 下任一真实路径取得同源上下文（内容不重要，
    // 404 页也可以），再用 document.write 整页替换成宿主页 —— origin 保持不变。
    await loadAndWait(win, HOST_URL)

    // 整页替换为宿主页（保持 origin = https://us-east-1.signin.aws）
    await win.webContents.executeJavaScript(
      `(() => { document.open(); document.write(${JSON.stringify(html)}); document.close(); return true })()`,
      true
    )
    await sleep(300)

    // 注入 token 并加载 CDN 脚本
    await win.webContents.executeJavaScript(
      `window.__amsBoot(${JSON.stringify(opts.captchaToken)}, ${JSON.stringify(opts.captchaCDN)}), true`,
      true
    )
    log('[AMS] 已注入 redemptionToken 并加载 CDN 脚本，等待求解…')

    const deadline = Date.now() + timeoutSec * 1000
    let loggedDisplayed = false

    while (Date.now() < deadline) {
      if (opts.signal?.aborted) throw new Error('注册已取消')
      await sleep(500)

      const state = (await win.webContents.executeJavaScript(
        `({ code: window.__amsResult, err: window.__amsError, shown: window.__amsDisplayed, loaded: window.__amsScriptLoaded })`,
        true
      )) as { code: string | null; err: string | null; shown: boolean; loaded: boolean }

      if (state.code) {
        log(`[AMS] 求解成功${state.shown ? '（人工完成）' : '（静默通过）'}，accessCode 长度 ${state.code.length}`)
        return { accessCode: state.code, interactive: Boolean(state.shown) }
      }
      if (state.err) {
        throw new Error(`AMS captcha 失败: ${state.err}`)
      }
      // 脚本要求展示题目 → 把窗口显示出来让用户完成
      if (state.shown && !shown) {
        shown = true
        loggedDisplayed = true
        try { opts.onInteractive?.() } catch { /* 回调异常不影响求解 */ }
        if (opts.failFastOnInteractive) {
          throw new Error('AMS captcha 需要人工完成（当前为无人值守模式，已跳过）')
        }
        win.show()
        win.focus()
        log('[AMS] 需要人工完成验证，已弹出窗口')
      }
      if (!loggedDisplayed && !state.loaded && Date.now() > deadline - (timeoutSec - 10) * 1000) {
        log('[AMS] CDN 脚本仍未就绪，检查代理是否可访问 threat-mitigation.aws.amazon.com')
      }
    }

    throw new Error(`AMS captcha 求解超时 (${timeoutSec}s)`)
  } finally {
    if (!win.isDestroyed()) win.destroy()
    // 桥接随窗口一起回收，避免每次求解泄漏一个监听端口
    if (bridge) await bridge.stop()
  }
}
