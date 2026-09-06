const DELTA = 0x9e3779b9 >>> 0
const FALLBACK_KEY: [number, number, number, number] = [1888420705, 2576816180, 2347232058, 874813317]
const FALLBACK_VER = '4.0.0'
const FALLBACK_IDENTIFIER = 'ECdITeCs'

let cachedKey: [number, number, number, number] | null = null
let cachedVersion = ''
let cachedIdentifier = ''
let refreshPromise: Promise<void> | null = null

function extractFromAppJS(js: string): {
  key: [number, number, number, number] | null
  identifier: string
  version: string
} {
  let key: [number, number, number, number] | null = null
  let identifier = ''
  let version = ''

  // 线上 app.js（2026-09 实测）里 keyProvider 的形态是：
  //   var e=[2576816180,1888420705,2347232058,"ECdITeCs",874813317,29115,32807];
  //   return{identifier:e[3],material:[e[1],e[0],e[2],e[4]]}
  // 即：先声明一个混合了数字与 identifier 的常量数组，再按下标重排出 4 个 key。
  // 下标顺序会随构建变化，所以这里**跟着 material 的下标去取**，而不是假定固定顺序。
  //
  // 旧正则假定形如 `var x=[num,"id",num,num,num]`（identifier 固定在第 2 位、只有 4 个数字），
  // 与线上形态不符 → 长期静默失配、一直回退 fallback。
  // （注：当前 fallback 的取值与线上完全一致，所以此前功能未受影响，只是日志误导。）
  const providerMatch = js.match(
    /var\s+(\w+)\s*=\s*\[([^\]]*"[A-Za-z0-9]{4,}"[^\]]*)\]\s*;\s*return\s*\{\s*identifier\s*:\s*\1\[(\d+)\]\s*,\s*material\s*:\s*\[\s*\1\[(\d+)\]\s*,\s*\1\[(\d+)\]\s*,\s*\1\[(\d+)\]\s*,\s*\1\[(\d+)\]\s*\]/
  )
  if (providerMatch) {
    // 拆常量数组：元素或是十进制数字，或是带引号的 identifier
    const items = providerMatch[2].split(',').map((s) => s.trim())
    const idIdx = Number(providerMatch[3])
    const matIdx = [4, 5, 6, 7].map((g) => Number(providerMatch[g]))

    const idRaw = items[idIdx]
    const idVal = idRaw && /^"([^"]+)"$/.test(idRaw) ? idRaw.slice(1, -1) : ''

    const nums = matIdx.map((i) => {
      const raw = items[i]
      return raw !== undefined && /^\d+$/.test(raw) ? Number(raw) : NaN
    })

    if (idVal && nums.every((n) => Number.isFinite(n))) {
      key = [nums[0], nums[1], nums[2], nums[3]]
      identifier = idVal
    }
  }

  const verMatch = js.match(/FWCIM_VERSION\s*=\s*"(\d+\.\d+\.\d+)"/)
  if (verMatch) {
    version = verMatch[1]
  }

  return { key, identifier, version }
}

export async function refreshAppJSConfig(
  fetchFn: (url: string, init?: RequestInit) => Promise<Response>
): Promise<void> {
  if (cachedKey) return
  if (refreshPromise) return refreshPromise

  refreshPromise = (async () => {
    if (cachedKey) return
    try {
      const resp = await fetchFn('https://us-east-1.signin.aws/assets/js/app.js', {
        headers: {
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
          Accept: '*/*',
          Referer: 'https://us-east-1.signin.aws/'
        }
      })
      const js = await resp.text()
      if (js) {
        const result = extractFromAppJS(js)
        if (result.key) cachedKey = result.key
        if (result.identifier) cachedIdentifier = result.identifier
        if (result.version) cachedVersion = result.version
      }
    } catch (err) {
      console.log('[xxtea] 下载 app.js 失败:', err)
    }

    if (!cachedKey) {
      console.log('[xxtea] 使用 fallback 密钥')
      cachedKey = [...FALLBACK_KEY] as [number, number, number, number]
    }
    if (!cachedVersion) cachedVersion = FALLBACK_VER
    if (!cachedIdentifier) cachedIdentifier = FALLBACK_IDENTIFIER
  })()

  return refreshPromise
}

export function getTESVersion(): string {
  return cachedVersion || FALLBACK_VER
}

export function getIdentifier(): string {
  return cachedIdentifier || FALLBACK_IDENTIFIER
}

export function getActiveKey(): [number, number, number, number] {
  return cachedKey
    ? ([...cachedKey] as [number, number, number, number])
    : ([...FALLBACK_KEY] as [number, number, number, number])
}

function xxteaEncryptCore(plaintext: string, key: [number, number, number, number]): Buffer {
  if (!plaintext.length) return Buffer.alloc(0)

  const n = Math.ceil(plaintext.length / 4)
  const v = new Uint32Array(n)
  for (let i = 0; i < n; i++) {
    let b0 = 0, b1 = 0, b2 = 0, b3 = 0
    if (4 * i < plaintext.length) b0 = plaintext.charCodeAt(4 * i)
    if (4 * i + 1 < plaintext.length) b1 = plaintext.charCodeAt(4 * i + 1)
    if (4 * i + 2 < plaintext.length) b2 = plaintext.charCodeAt(4 * i + 2)
    if (4 * i + 3 < plaintext.length) b3 = plaintext.charCodeAt(4 * i + 3)
    v[i] = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0
  }

  const rounds = 6 + Math.floor(52 / n)
  let z = v[n - 1]
  let total = 0

  for (let r = 0; r < rounds; r++) {
    total = (total + DELTA) >>> 0
    const e = (total >>> 2) & 3
    for (let p = 0; p < n; p++) {
      const y = v[(p + 1) % n]
      const part1 = ((z >>> 5) ^ (y << 2)) >>> 0
      const part2 = ((y >>> 3) ^ (z << 4)) >>> 0
      const group1 = (part1 + part2) >>> 0
      const part3 = (total ^ y) >>> 0
      const part4 = (key[(p & 3) ^ e] ^ z) >>> 0
      const group2 = (part3 + part4) >>> 0
      const mx = (group1 ^ group2) >>> 0
      v[p] = (v[p] + mx) >>> 0
      z = v[p]
    }
  }

  const result = Buffer.alloc(n * 4)
  for (let i = 0; i < n; i++) {
    result[4 * i] = v[i] & 0xff
    result[4 * i + 1] = (v[i] >>> 8) & 0xff
    result[4 * i + 2] = (v[i] >>> 16) & 0xff
    result[4 * i + 3] = (v[i] >>> 24) & 0xff
  }
  return result
}

/** 加密指纹 JSON: JSON -> CRC32前缀 -> XXTEA加密 -> base64 -> identifier:结果 */
export function encryptFingerprint(jsonStr: string): string {
  const crc = crc32(jsonStr)
  const crcHex = crc.toString(16).toUpperCase().padStart(8, '0')
  const plaintext = crcHex + '#' + jsonStr

  const key = getActiveKey()
  const encrypted = xxteaEncryptCore(plaintext, key)
  const encoded = encrypted.toString('base64')
  return getIdentifier() + ':' + encoded
}

/** CRC32 (IEEE) */
function crc32(str: string): number {
  const table = crc32Table()
  let crc = 0xffffffff >>> 0
  for (let i = 0; i < str.length; i++) {
    crc = ((crc >>> 8) ^ table[(crc ^ str.charCodeAt(i)) & 0xff]) >>> 0
  }
  return (crc ^ 0xffffffff) >>> 0
}

let _crc32Table: Uint32Array | null = null
function crc32Table(): Uint32Array {
  if (_crc32Table) return _crc32Table
  _crc32Table = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i >>> 0
    for (let j = 0; j < 8; j++) {
      c = c & 1 ? (0xedb88320 ^ (c >>> 1)) >>> 0 : c >>> 1
    }
    _crc32Table[i] = c
  }
  return _crc32Table
}
