import type { SealedEntry, VaultEntry, VaultFile, VaultKind } from '../types'
import { fromBase64, fromUtf8, open, randomBytes, seal, toBase64, toHex, utf8 } from './crypto'

/** The name the master key is filed under in the OS key store. */
export const SERVICE = 'claude-vault'
export const MASTER_ACCOUNT = 'master-key'
export const FORMAT = 'claude-vault/1'
/** The one variable a Bash command's secrets ride in, read and unset by the command's first line. */
export const ENV_VAR = 'CLAUDE_VAULT_ENV'

export const KINDS: readonly VaultKind[] = ['password', 'api_key', 'token', 'secret', 'email', 'username', 'text']

const MASKED_KINDS: ReadonlySet<VaultKind> = new Set(['password', 'api_key', 'token', 'secret'])

export const isMasked = (kind: VaultKind): boolean => MASKED_KINDS.has(kind)

export const NAME_PATTERN = '^[A-Z][A-Z0-9_]{1,63}$'
const NAME_RE = new RegExp(NAME_PATTERN)

/** Variables the shell and its programs rely on: a secret must never shadow them. */
const RESERVED = new Set([
  'PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'PWD', 'OLDPWD', 'TMPDIR', 'TERM', 'LANG', 'LC_ALL',
  'EDITOR', 'VISUAL', 'IFS', 'PS1', 'PS2', 'SHLVL', 'HOSTNAME', 'DISPLAY', 'SSH_AUTH_SOCK', 'NODE_OPTIONS',
])

/** Why a name cannot be used, or undefined when it can. */
export function nameProblem(name: unknown): string | undefined {
  if (typeof name !== 'string' || !NAME_RE.test(name)) {
    return 'name must be an environment variable name in capitals, like MODAL_TOKEN_ID (2-64 of A-Z, 0-9, _)'
  }
  if (RESERVED.has(name) || name.startsWith('CLAUDE') || name.startsWith('BASH_')) {
    return `${name} is a variable the shell or Claude Code relies on; pick another name`
  }
  return undefined
}

export const isKind = (kind: unknown): kind is VaultKind =>
  typeof kind === 'string' && (KINDS as readonly string[]).includes(kind)

// ---------------------------------------------------------------------------
// Paths

/** A path with forward slashes and no trailing one: what every platform's file calls and Git Bash take. */
export const normalizePath = (path: string): string => path.replace(/\\/g, '/').replace(/\/+$/, '')

/** Whether `path` (as a tool was handed it) lies in the vault folder. `~` is the home folder. */
export function isInVault(path: string, vaultDir: string, home: string): boolean {
  if (vaultDir === '') return false
  const spelled = normalizePath(path.startsWith('~') ? home + path.slice(1) : path)
  const dir = normalizePath(vaultDir)
  const fold = (text: string) => text.toLowerCase()
  return fold(spelled) === fold(dir) || fold(spelled).startsWith(`${fold(dir)}/`)
}

// ---------------------------------------------------------------------------
// The vault file

const aadFor = (name: string): Uint8Array => utf8(`${FORMAT}:${name}`)

export function sealEntry(key: Uint8Array, entry: VaultEntry, value: string): SealedEntry {
  const nonce = randomBytes(12)
  return { ...entry, nonce: toBase64(nonce), box: toBase64(seal(key, nonce, utf8(value), aadFor(entry.name))) }
}

/** The value of a sealed entry; throws when the key is wrong or the entry was altered (renamed included). */
export const openEntry = (key: Uint8Array, entry: SealedEntry): string =>
  fromUtf8(open(key, fromBase64(entry.nonce), fromBase64(entry.box), aadFor(entry.name)))

export const describe = ({ name, label, kind, service, savedAt }: VaultEntry): VaultEntry => ({ name, label, kind, service, savedAt })

/** The vault file read back, or undefined when the text is not one. */
export function parseVault(text: string): VaultFile | undefined {
  try {
    const data = JSON.parse(text) as Partial<VaultFile>
    if (data.format !== FORMAT || !Array.isArray(data.entries) || typeof data.keyStore !== 'string') return undefined
    return data as VaultFile
  } catch {
    return undefined
  }
}

export const README = [
  'Claude vault',
  '',
  'vault.json holds the secrets Claude asked for through the vault\'s secure field.',
  'Every value in it is encrypted (ChaCha20-Poly1305). The key is not in this folder:',
  'it is in the macOS Keychain, the Linux Secret Service or Windows DPAPI',
  '(only where none of them exists does it fall back to master.key here, readable by you alone).',
  '',
  'Claude uses a secret as $NAME in its shell and never sees the value.',
  'Do not share, sync or commit this folder. To remove a secret, type /vault remove NAME.',
  '',
].join('\n')

// ---------------------------------------------------------------------------
// Old storage (vault 0.1: one Keychain item per secret)

/** A value as `security find-generic-password -w` printed it in vault 0.1, decoded. */
export function decodeStored(stdout: string, encoding: 'raw' | 'base64'): string {
  const printed = stdout.endsWith('\n') ? stdout.slice(0, -1) : stdout
  return encoding === 'base64' ? fromUtf8(fromBase64(printed)) : printed
}

const quote = (text: string): string => `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`

/** A line for `security -i` on stdin, so a value never sits on a command line where `ps` could read it. */
export const keychainAddLine = (account: string, label: string, value: string): string =>
  `add-generic-password -U -s ${SERVICE} -a ${account} -l ${quote(label)} -w ${quote(value)}\n`

// ---------------------------------------------------------------------------
// Shell

const REFERENCE = /\$\{#?([A-Za-z_][A-Za-z0-9_]*)|\$([A-Za-z_][A-Za-z0-9_]*)/g

/** The vault names a shell command refers to as $NAME or ${NAME}. */
export function referencedNames(command: string, names: readonly string[]): string[] {
  if (names.length === 0) return []
  const found = new Set<string>()
  for (const match of command.matchAll(REFERENCE)) {
    const name = match[1] ?? match[2]
    if (name !== undefined && names.includes(name)) found.add(name)
  }
  return [...found]
}

const singleQuoted = (value: string): string => `'${value.replace(/'/g, `'\\''`)}'`

/** What CLAUDE_VAULT_ENV holds: one export per secret, quoted for sh, bash and zsh alike. */
export const exportScript = (secrets: readonly Secret[]): string =>
  secrets.map(({ name, value }) => `export ${name}=${singleQuoted(value)}`).join('\n')

/**
 * The command a Bash call runs. With secrets, its first line evaluates the
 * exports and drops the variable that carried them; while another call's
 * secrets are in the environment, a call that uses none drops them unread.
 */
export function shellCommand(command: string, usesSecrets: boolean, isCarrying: boolean): string {
  if (usesSecrets) return `eval "$${ENV_VAR}"; unset ${ENV_VAR}\n${command}`
  if (isCarrying) return `unset ${ENV_VAR}\n${command}`
  return command
}

/** Whether the model's own command reaches for the vault: its folder, its carrier variable, or the master key. */
export function touchesVault(command: string, vaultDir: string): boolean {
  const spelled = command.replace(/\\/g, '/')
  if (spelled.includes('.claude/vault') || (vaultDir !== '' && spelled.includes(normalizePath(vaultDir)))) return true
  if (spelled.includes(ENV_VAR) || /ProtectedData/i.test(spelled)) return true
  return /\b(security|secret-tool)\b/.test(spelled) && spelled.includes(SERVICE)
}

// ---------------------------------------------------------------------------
// Where a command sends its secrets

// A host is letters, digits, dots and hyphens: whatever follows (`;`, `)`, a
// quote) ends it, so `$U;` in a shell line does not read as another site.
const URL_HOST = /\b(?:https?|wss?):\/\/(?:[^\s/'"`<>@]*@)?([A-Za-z0-9.-]+)/gi

/** The hosts of the URLs a command names, lower-cased, each once. */
export function hostsIn(command: string): string[] {
  const found = new Set<string>()
  for (const match of command.matchAll(URL_HOST)) if (match[1]) found.add(match[1].toLowerCase().replace(/\.$/, ''))
  return [...found]
}

/** The domain a secret was saved for (`modal.com`), or '' when its service names none. */
export function serviceDomain(service: string): string {
  const host = service.trim().toLowerCase().replace(/^[a-z]+:\/\//, '').split(/[/?#:\s]/)[0] ?? ''
  const bare = host.replace(/^www\./, '')
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(bare) ? bare : ''
}

/** Whether a host is the secret's own site or one under it (`api.modal.com` for `modal.com`). */
export function isOwnHost(host: string, service: string): boolean {
  const domain = serviceDomain(service)
  return domain !== '' && (host === domain || host.endsWith(`.${domain}`))
}

/** Each secret a command uses paired with each URL host in it that is not that secret's own site. */
export function strangeSends(command: string, used: readonly VaultEntry[]): Array<{ name: string; host: string; service: string }> {
  const hosts = hostsIn(command)
  return used.flatMap(entry => hosts.filter(host => !isOwnHost(host, entry.service)).map(host => ({ name: entry.name, host, service: entry.service })))
}

// ---------------------------------------------------------------------------
// Redaction

export type Secret = { readonly name: string; readonly value: string }

/** Values shorter than this are not redacted: they would match ordinary text. */
export const MIN_REDACT = 6

/** A long value is also caught in pieces this long, so a part of it (`${KEY:0:20}`) does not get through. */
export const WINDOW = 12
const WINDOWED_FROM = 16

/**
 * The whole spellings a value turns up in: as is, JSON-escaped, URL-encoded,
 * shell-quoted, hex, and base64 (with and without a newline).
 */
export function spellings(value: string): string[] {
  if (value.length < MIN_REDACT) return []
  const out = new Set([value, JSON.stringify(value).slice(1, -1), encodeURIComponent(value), value.replace(/'/g, `'\\''`)])
  for (const raw of [value, `${value}\n`]) {
    const bytes = utf8(raw)
    const base64 = toBase64(bytes)
    out.add(base64)
    out.add(base64.replace(/=+$/, ''))
    out.add(toHex(bytes))
  }
  return [...out].filter(spelling => spelling.length >= MIN_REDACT)
}

/**
 * Whether a run looks like part of a key rather than ordinary text: it has a
 * digit, mixed case, or a symbol. A value that holds words (a whole
 * `modal token set --token-id …` line) would otherwise cover those words
 * wherever they appear.
 */
const isDistinctive = (piece: string): boolean =>
  !/^\s|\s$/.test(piece) && (/\d/.test(piece) || (/[A-Z]/.test(piece) && /[a-z]/.test(piece)) || /[^A-Za-z0-9\s._-]/.test(piece))

/** Every distinctive run of WINDOW characters of a long value: a part of it found in any output is covered too. */
export const windowsOf = (value: string): string[] =>
  value.length < WINDOWED_FROM
    ? []
    : Array.from({ length: value.length - WINDOW + 1 }, (_, i) => value.slice(i, i + WINDOW)).filter(isDistinctive)

export type Redactor = {
  readonly isEmpty: boolean
  /** The text with every secret replaced by `[vault:NAME]`. */
  text: (text: string) => string
  /** The value with every string in it redacted; the same reference when nothing changed. */
  deep: <T>(value: T) => T
}

export function makeRedactor(secrets: readonly Secret[]): Redactor {
  const pairs = secrets
    .flatMap(({ name, value }) => spellings(value).map(spelling => [spelling, `[vault:${name}]`] as const))
    .sort((a, b) => b[0].length - a[0].length)
  const pieces = new Map<string, string>()
  for (const { name, value } of secrets) for (const piece of windowsOf(value)) pieces.set(piece, `[vault:${name}]`)

  /** Covers every run of the text that a piece of a secret matches, overlapping runs merged, so no part is left. */
  const covered = (input: string): string => {
    const runs: Array<[number, number, string]> = []
    for (let i = 0; i + WINDOW <= input.length; i++) {
      const mark = pieces.get(input.slice(i, i + WINDOW))
      if (mark === undefined) continue
      const last = runs[runs.length - 1]
      if (last !== undefined && i <= last[1]) last[1] = i + WINDOW
      else runs.push([i, i + WINDOW, mark])
    }
    if (runs.length === 0) return input
    let out = ''
    let at = 0
    for (const [start, end, mark] of runs) {
      out += input.slice(at, start) + mark
      at = end
    }
    return out + input.slice(at)
  }

  const text = (input: string): string => {
    let out = input
    for (const [spelling, mark] of pairs) if (out.includes(spelling)) out = out.split(spelling).join(mark)
    return pieces.size === 0 ? out : covered(out)
  }

  const deep = <T>(value: T): T => {
    if (typeof value === 'string') return text(value) as T
    if (Array.isArray(value)) {
      let changed = false
      const next = value.map(item => {
        const red = deep(item)
        if (red !== item) changed = true
        return red
      })
      return (changed ? next : value) as T
    }
    if (value !== null && typeof value === 'object') {
      let changed = false
      const next: Record<string, unknown> = {}
      for (const [key, item] of Object.entries(value)) {
        const red = deep(item)
        if (red !== item) changed = true
        next[key] = red
      }
      return (changed ? next : value) as T
    }
    return value
  }

  return { isEmpty: pairs.length === 0 && pieces.size === 0, text, deep }
}

// ---------------------------------------------------------------------------
// What the model reads

export function guide(entries: readonly VaultEntry[], problem: string): string {
  const saved = entries.length === 0
    ? 'Nothing is saved yet.'
    : `Saved: ${entries.map(entry => `${entry.name} (${entry.label}${entry.service ? `, ${entry.service}` : ''})`).join('; ')}.`
  return [
    '# Secrets vault',
    'Never ask the person to type or paste a password, API key, token, or a login (email, username) into the chat.',
    'Call mcp__vault__request_secret instead: it shows them a secure field above their prompt, the value is encrypted into their vault, and you never see it.',
    'Then use it in Bash as "$NAME" (double-quoted). The vault puts it into that command\'s shell and replaces it with [vault:NAME] in every output you read.',
    'Pass it straight to the program that needs it (`curl -H "Authorization: Bearer $API_KEY"`, `printf \'KEY=%s\\n\' "$API_KEY" > .env`); never echo or print it, and never write it to a file you then read.',
    'The vault folder and its key are off limits to your tools. If the person pastes a secret into the chat anyway, do not repeat it; offer to save it with request_secret.',
    'Give every secret its service (the site it belongs to, e.g. modal.com): a command that sends a secret to any other site waits for the person to allow it.',
    saved,
    ...(problem ? [`The vault cannot be opened right now: ${problem}`] : []),
  ].join('\n')
}

