/**
 * ChaCha20-Poly1305 (RFC 8439), in plain TypeScript: the mod's environment has
 * no WebCrypto cipher and no WebAssembly, only `crypto.getRandomValues`.
 * Checked against the RFC's test vector and Node's own implementation.
 */

const rotl = (v: number, c: number): number => ((v << c) | (v >>> (32 - c))) >>> 0

const le32 = (b: Uint8Array, i: number): number =>
  ((b[i] ?? 0) | ((b[i + 1] ?? 0) << 8) | ((b[i + 2] ?? 0) << 16) | ((b[i + 3] ?? 0) << 24)) >>> 0

function quarter(s: Uint32Array, a: number, b: number, c: number, d: number) {
  s[a] = ((s[a] ?? 0) + (s[b] ?? 0)) >>> 0
  s[d] = rotl((s[d] ?? 0) ^ (s[a] ?? 0), 16)
  s[c] = ((s[c] ?? 0) + (s[d] ?? 0)) >>> 0
  s[b] = rotl((s[b] ?? 0) ^ (s[c] ?? 0), 12)
  s[a] = ((s[a] ?? 0) + (s[b] ?? 0)) >>> 0
  s[d] = rotl((s[d] ?? 0) ^ (s[a] ?? 0), 8)
  s[c] = ((s[c] ?? 0) + (s[d] ?? 0)) >>> 0
  s[b] = rotl((s[b] ?? 0) ^ (s[c] ?? 0), 7)
}

function chachaBlock(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  const state = new Uint32Array(16)
  state[0] = 0x61707865
  state[1] = 0x3320646e
  state[2] = 0x79622d32
  state[3] = 0x6b206574
  for (let i = 0; i < 8; i++) state[4 + i] = le32(key, 4 * i)
  state[12] = counter >>> 0
  for (let i = 0; i < 3; i++) state[13 + i] = le32(nonce, 4 * i)

  const work = state.slice()
  for (let round = 0; round < 10; round++) {
    quarter(work, 0, 4, 8, 12)
    quarter(work, 1, 5, 9, 13)
    quarter(work, 2, 6, 10, 14)
    quarter(work, 3, 7, 11, 15)
    quarter(work, 0, 5, 10, 15)
    quarter(work, 1, 6, 11, 12)
    quarter(work, 2, 7, 8, 13)
    quarter(work, 3, 4, 9, 14)
  }

  const out = new Uint8Array(64)
  for (let i = 0; i < 16; i++) {
    const word = ((work[i] ?? 0) + (state[i] ?? 0)) >>> 0
    out[4 * i] = word & 0xff
    out[4 * i + 1] = (word >>> 8) & 0xff
    out[4 * i + 2] = (word >>> 16) & 0xff
    out[4 * i + 3] = (word >>> 24) & 0xff
  }
  return out
}

function chacha20(key: Uint8Array, counter: number, nonce: Uint8Array, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length)
  for (let offset = 0, block = counter; offset < data.length; offset += 64, block++) {
    const stream = chachaBlock(key, block, nonce)
    for (let i = 0; i < 64 && offset + i < data.length; i++) out[offset + i] = (data[offset + i] ?? 0) ^ (stream[i] ?? 0)
  }
  return out
}

function leToBigInt(bytes: Uint8Array): bigint {
  let n = 0n
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i] ?? 0)
  return n
}

function bigIntToLe(n: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    out[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return out
}

const P1305 = (1n << 130n) - 5n
const CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffffn

function poly1305(oneTimeKey: Uint8Array, message: Uint8Array): Uint8Array {
  const r = leToBigInt(oneTimeKey.subarray(0, 16)) & CLAMP
  const s = leToBigInt(oneTimeKey.subarray(16, 32))
  let acc = 0n
  for (let i = 0; i < message.length; i += 16) {
    const chunk = message.subarray(i, i + 16)
    acc = ((acc + leToBigInt(chunk) + (1n << BigInt(8 * chunk.length))) * r) % P1305
  }
  return bigIntToLe((acc + s) & ((1n << 128n) - 1n), 16)
}

const pad16 = (length: number): Uint8Array => new Uint8Array((16 - (length % 16)) % 16)

function macData(aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const parts = [aad, pad16(aad.length), ciphertext, pad16(ciphertext.length), bigIntToLe(BigInt(aad.length), 8), bigIntToLe(BigInt(ciphertext.length), 8)]
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0))
  let at = 0
  for (const part of parts) {
    out.set(part, at)
    at += part.length
  }
  return out
}

/** Encrypts and authenticates: the ciphertext with its 16-byte tag appended. */
export function seal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  const oneTimeKey = chachaBlock(key, 0, nonce).subarray(0, 32)
  const ciphertext = chacha20(key, 1, nonce, plaintext)
  const tag = poly1305(oneTimeKey, macData(aad, ciphertext))
  const out = new Uint8Array(ciphertext.length + 16)
  out.set(ciphertext)
  out.set(tag, ciphertext.length)
  return out
}

/** Checks the tag and decrypts; throws when the box was altered or the key, nonce or aad is wrong. */
export function open(key: Uint8Array, nonce: Uint8Array, box: Uint8Array, aad: Uint8Array): Uint8Array {
  if (box.length < 16) throw new Error('vault: the box is too short')
  const ciphertext = box.subarray(0, box.length - 16)
  const tag = box.subarray(box.length - 16)
  const expected = poly1305(chachaBlock(key, 0, nonce).subarray(0, 32), macData(aad, ciphertext))
  let difference = 0
  for (let i = 0; i < 16; i++) difference |= (expected[i] ?? 0) ^ (tag[i] ?? 0)
  if (difference !== 0) throw new Error('vault: the box does not open with this key')
  return chacha20(key, 1, nonce, ciphertext)
}

export const randomBytes = (length: number): Uint8Array => crypto.getRandomValues(new Uint8Array(length))

export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text)

export const fromUtf8 = (bytes: Uint8Array): string => new TextDecoder('utf-8').decode(bytes)

export function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

export function fromBase64(text: string): Uint8Array {
  const binary = atob(text.trim())
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

export const toHex = (bytes: Uint8Array): string => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')

export function fromHex(text: string): Uint8Array {
  const clean = text.trim()
  if (!/^(?:[0-9a-f]{2})*$/i.test(clean)) throw new Error('vault: not hex')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16)
  return out
}
