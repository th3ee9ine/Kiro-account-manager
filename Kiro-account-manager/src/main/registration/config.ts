import { randomFullName } from './browser-identity'

export interface RegistrationConfig {
  // AWS
  oidcBase: string
  signinBase: string
  profileBase: string
  viewBase: string
  portalBase: string
  directoryId: string
  startURL: string

  // 默认值
  password: string
  fullName: string

  // 运行时
  proxy: string
  /** 上游中转代理（可选，用于代理链）：让对 proxy(目标代理) 的连接经非大陆中转发起 */
  upstreamProxy: string
  /**
   * 严格代理模式：开启后任何「代理缺失/代理链失败/回退环境变量」情况都立即抛错中止注册，
   * 杜绝静默回退到本机真实 IP 直连。批量注册启用代理池时由前端强制开启。
   */
  strictProxy: boolean

  // MoEmail 配置
  moEmailBaseURL: string
  moEmailAPIKey: string

  // Outlook 模式
  useOutlook: boolean
  outlookData: string

  // TempMail.Plus + 自建域名
  useTempMailPlus: boolean
  tempMailPlusEmail: string  // tempmail.plus 用户名（不含 @mailto.plus）
  tempMailPlusEpin: string
  tempMailPlusDomain: string // 自建域名

  // Proton 点号别名（webview 借壳官方网页取码，需先在应用内登录 Proton）
  useProton: boolean
  protonEmail: string // 本次注册使用的 Proton 邮箱地址（母邮箱或其点号变体，由前端生成）

  // GPTmail (mail.chatgpt.org.uk) — 域名邮箱取码，支持两种玩法：
  //   A. 私有域名直收：MX 解析到 GPTmail，inboxEmail 留空（私有域名需密码解锁则填 privatePassword）
  //   B. CF Email Routing 转发：inboxEmail 填一个固定 GPTmail 邮箱
  useGptMail: boolean
  gptMailBaseURL: string      // 可选，默认 https://mail.chatgpt.org.uk；私有部署可改
  gptMailInboxEmail: string   // 可选：填了 = CF 转发模式（所有 prefix@domain 转发到此邮箱）；留空 = 私有域名直收
  gptMailDomain: string       // 必填：用户自己的域名池，多个用空格/逗号
  gptMailPrefix: string       // 可选：固定前缀，留空则 randomEmailPrefix() 生成
  gptMailPrivatePassword: string  // 可选：仅私有域名模式有效。在 GPTmail 设私有域名时设的密码

  // iCloud 取件（assurivo「取件链接」）—— 买来的 iCloud 邮箱池，格式 `邮箱----查询码`
  // 与 Outlook 同为"池化"模式：前端按行分配，每个任务独占一行避免并发抢号
  useICloud: boolean
  icloudData: string      // 多行 `邮箱----查询码`（批量时前端已切成单行）
  icloudBaseURL: string   // 可选，默认 https://assurivo.com
  icloudLimit: number     // 可选，单次取件封数（1..20，默认 10）

  /**
   * 邮箱已在 AWS 注册过时，是否自动走「邮箱验证码登录」把该账号找回（默认开启）。
   * 适用于注册中断留下的号，或已注册但凭据丢失的号 —— 拿到的 token 与新注册等价。
   * 需要邮箱源支持取码（Outlook 模式暂不支持）。
   */
  recoverExisting: boolean

  /**
   * 无人值守模式：AMS 人机校验需要人工点选时立即失败，而不是弹窗干等。
   * 批量注册应开启 —— 干等一个不在场的人只是白占并发槽。
   * 单次手动注册保持关闭，这样偶发的校验用户可以自己过掉。
   */
  captchaUnattended: boolean

  /**
   * 已知的原密码：仅用于「邮箱已注册且已设密码」时的密码登录找回。
   * password 字段每次随机生成，对历史账号必然不匹配，故需单独提供。
   */
  knownPassword: string

  // 手动模式
  manualMode: boolean
}

export function genPassword(): string {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  const lower = 'abcdefghijklmnopqrstuvwxyz'
  const digits = '0123456789'
  const special = '!@#$%^&*'

  let pw = ''
  for (let i = 0; i < 3; i++) pw += upper[Math.floor(Math.random() * upper.length)]
  for (let i = 0; i < 6; i++) pw += lower[Math.floor(Math.random() * lower.length)]
  for (let i = 0; i < 3; i++) pw += digits[Math.floor(Math.random() * digits.length)]
  for (let i = 0; i < 2; i++) pw += special[Math.floor(Math.random() * special.length)]

  const arr = pw.split('')
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[arr[i], arr[j]] = [arr[j], arr[i]]
  }
  return arr.join('')
}

export function newConfig(overrides?: Partial<RegistrationConfig>): RegistrationConfig {
  return {
    oidcBase: 'https://oidc.us-east-1.amazonaws.com',
    signinBase: 'https://us-east-1.signin.aws',
    profileBase: 'https://profile.aws.amazon.com',
    viewBase: 'https://view.awsapps.com',
    portalBase: 'https://portal.sso.us-east-1.amazonaws.com',
    directoryId: 'd-9067642ac7',
    startURL: 'https://view.awsapps.com/start',
    password: genPassword(),
    fullName: randomFullName(),
    proxy: '',
    upstreamProxy: '',
    strictProxy: false,
    moEmailBaseURL: '',
    moEmailAPIKey: '',
    useOutlook: false,
    outlookData: '',
    useTempMailPlus: false,
    tempMailPlusEmail: '',
    tempMailPlusEpin: '',
    tempMailPlusDomain: '',
    useProton: false,
    protonEmail: '',
    useGptMail: false,
    gptMailBaseURL: '',
    gptMailInboxEmail: '',
    gptMailDomain: '',
    gptMailPrefix: '',
    gptMailPrivatePassword: '',
    useICloud: false,
    icloudData: '',
    icloudBaseURL: '',
    icloudLimit: 10,
    recoverExisting: true,
    captchaUnattended: false,
    knownPassword: '',
    manualMode: false,
    ...overrides
  }
}
