import { atom, read, update } from 'claude-code'
import type { EngineInterface, ProcessRunInit, ProcessRunResult, Register } from 'claude-code'

import type { KeyStore, VaultAsk, VaultEntry, VaultFile, VaultRequest } from '../types'
import { fromHex, randomBytes, toHex } from './crypto'
import {
  FORMAT, KINDS, MASTER_ACCOUNT, NAME_PATTERN, README, SERVICE, decodeStored, describe, exportScript, guide, isInVault, isKind,
  isMasked, keychainAddLine, makeRedactor, nameProblem, normalizePath, openEntry, parseVault, referencedNames, sealEntry,
  shellCommand, strangeSends, touchesVault,
} from './lib'
import type { Redactor, Secret } from './lib'

const pending = atom({ plugin: 'vault', key: 'pending' } as const, null)
const asking = atom({ plugin: 'vault', key: 'asking' } as const, null)
const ring = atom({ plugin: 'vault', key: 'ring' } as const, null)

const REQUEST = 'mcp__vault__request_secret'
const LIST = 'mcp__vault__list_secrets'
const PREVIEW = 'mcp__vault__preview_field'
const WAIT_MS = 10 * 60 * 1000
const FILE_TOOLS = new Set(['Read', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'Grep', 'Glob', 'LS'])

type Os = 'macos' | 'linux' | 'windows'

// What this session holds of the vault. The values live here alone, in this
// module's memory: never in $.state, $.store, a log, or anything the model or
// another plugin reads. A reload starts it over and session.start loads again.
let os: Os = 'linux'
let home = ''
let vaultDir = ''
let vaultRealDir = ''
let masterKey: Uint8Array | undefined
let keyStore: KeyStore | undefined
let entries: VaultEntry[] = []
let secrets: Secret[] = []
let redactor: Redactor = makeRedactor([])
let loadedAt = -1
let problem = ''
/** The secrets each running Bash call asked for, by tool_use_id. */
const carrying = new Map<string, string[]>()
/** `NAME@host` pairs the person allowed for the rest of this session. */
const allowed = new Set<string>()
/** What a paste brought for an open field, by request id: never drawn, never in $.state. */
const held = new Map<string, string>()
const PASTE_MAX = 8192

const vaultFile = () => `${vaultDir}/vault.json`

function hold(nextEntries: VaultEntry[], nextSecrets: Secret[]) {
  entries = nextEntries
  secrets = nextSecrets
  redactor = makeRedactor(nextSecrets)
}

async function run($: EngineInterface, argv: readonly string[], init?: ProcessRunInit): Promise<ProcessRunResult | undefined> {
  try {
    return await $.process.run(argv, init)
  } catch {
    return undefined
  }
}

async function locate($: EngineInterface) {
  os = (await $.env.get('OS')) === 'Windows_NT' ? 'windows' : (await run($, ['uname', '-s']))?.stdout.trim() === 'Darwin' ? 'macos' : 'linux'
  home = normalizePath((await $.env.get('HOME')) ?? (await $.env.get('USERPROFILE')) ?? '')
  const config = await $.env.get('CLAUDE_CONFIG_DIR')
  vaultDir = `${normalizePath(config ?? `${home}/.claude`)}/vault`
  vaultRealDir = (await $.fs.stat(vaultDir, { resolve: true }).catch(() => undefined))?.realPath ?? vaultDir
}

async function restrict($: EngineInterface, path: string, mode: '600' | '700') {
  if (os !== 'windows') await run($, ['chmod', mode, path])
}

async function ensureVaultDir($: EngineInterface) {
  if (!(await $.fs.exists(`${vaultDir}/README.txt`))) await $.fs.write(`${vaultDir}/README.txt`, README)
  await restrict($, vaultDir, '700')
  vaultRealDir = (await $.fs.stat(vaultDir, { resolve: true }).catch(() => undefined))?.realPath ?? vaultDir
}

// ---------------------------------------------------------------------------
// The master key: kept by the OS, so the vault file alone opens nothing.

const powershell = (script: string) => ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script] as const
const DPAPI_PROTECT =
  "Add-Type -AssemblyName System.Security; $h=[Console]::In.ReadToEnd().Trim(); " +
  "[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::ASCII.GetBytes($h),$null,'CurrentUser'))"
const DPAPI_UNPROTECT =
  "Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); " +
  "[Text.Encoding]::ASCII.GetString([Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser'))"

async function readMasterKey($: EngineInterface, store: KeyStore): Promise<Uint8Array | undefined> {
  let hex: string | undefined
  if (store === 'macos-keychain') {
    const found = await run($, ['/usr/bin/security', 'find-generic-password', '-s', SERVICE, '-a', MASTER_ACCOUNT, '-w'])
    hex = found?.exitCode === 0 ? found.stdout : undefined
  } else if (store === 'secret-service') {
    const found = await run($, ['secret-tool', 'lookup', 'service', SERVICE, 'account', MASTER_ACCOUNT])
    hex = found?.exitCode === 0 ? found.stdout : undefined
  } else if (store === 'windows-dpapi') {
    const sealed = await $.fs.read(`${vaultDir}/master.key.dpapi`).catch(() => undefined)
    const opened = sealed === undefined ? undefined : await run($, powershell(DPAPI_UNPROTECT), { stdin: sealed })
    hex = opened?.exitCode === 0 ? opened.stdout : undefined
  } else {
    hex = await $.fs.read(`${vaultDir}/master.key`).catch(() => undefined)
  }
  try {
    const key = hex === undefined ? undefined : fromHex(hex)
    return key?.length === 32 ? key : undefined
  } catch {
    return undefined
  }
}

/** Makes the key and files it with the strongest store this machine has; reads it back before trusting it. */
async function createMasterKey($: EngineInterface): Promise<{ key: Uint8Array; store: KeyStore }> {
  const key = randomBytes(32)
  const hex = toHex(key)
  await ensureVaultDir($)
  const tries: KeyStore[] = os === 'macos' ? ['macos-keychain', 'file'] : os === 'windows' ? ['windows-dpapi', 'file'] : ['secret-service', 'file']
  for (const store of tries) {
    if (store === 'macos-keychain') {
      await run($, ['/usr/bin/security', '-i'], { stdin: keychainAddLine(MASTER_ACCOUNT, 'Claude vault master key', hex), timeoutMs: 15_000 })
    } else if (store === 'secret-service') {
      await run($, ['secret-tool', 'store', '--label=Claude vault master key', 'service', SERVICE, 'account', MASTER_ACCOUNT], { stdin: hex, timeoutMs: 15_000 })
    } else if (store === 'windows-dpapi') {
      const sealed = await run($, powershell(DPAPI_PROTECT), { stdin: hex, timeoutMs: 30_000 })
      if (sealed?.exitCode === 0 && sealed.stdout.trim() !== '') await $.fs.write(`${vaultDir}/master.key.dpapi`, sealed.stdout.trim())
    } else {
      await $.fs.write(`${vaultDir}/master.key`, hex)
      await restrict($, `${vaultDir}/master.key`, '600')
    }
    const back = await readMasterKey($, store)
    if (back !== undefined && toHex(back) === hex) return { key, store }
  }
  throw new Error('no place to keep the vault key')
}

// ---------------------------------------------------------------------------
// The vault file

async function readVault($: EngineInterface): Promise<{ file: VaultFile; mtime: number } | undefined> {
  const stat = await $.fs.stat(vaultFile()).catch(() => undefined)
  if (stat === undefined) return undefined
  const file = parseVault(await $.fs.read(vaultFile()))
  return file === undefined ? undefined : { file, mtime: stat.mtimeMs }
}

async function loadVault($: EngineInterface) {
  const found = await readVault($)
  problem = ''
  if (found === undefined) {
    loadedAt = 0
    hold([], [])
    return
  }
  loadedAt = found.mtime
  keyStore = found.file.keyStore
  masterKey = masterKey ?? (await readMasterKey($, found.file.keyStore))
  const described = found.file.entries.map(describe)
  if (masterKey === undefined) {
    problem = `its key is missing from the ${found.file.keyStore}`
    hold(described, [])
    return
  }
  const opened: Secret[] = []
  for (const entry of found.file.entries) {
    try {
      opened.push({ name: entry.name, value: openEntry(masterKey, entry) })
    } catch {
      problem = `${entry.name} does not open with the vault key`
    }
  }
  hold(described, opened)
}

/** Loads again when another session changed the vault since this one read it (or none was loaded yet). */
async function refresh($: EngineInterface) {
  if (vaultDir === '') await locate($)
  const stat = await $.fs.stat(vaultFile()).catch(() => undefined)
  if ((stat?.mtimeMs ?? 0) !== loadedAt) await loadVault($)
}

async function writeVault($: EngineInterface, file: VaultFile) {
  await ensureVaultDir($)
  const before = await $.fs.read(vaultFile()).catch(() => undefined)
  if (before !== undefined) {
    await $.fs.write(`${vaultDir}/vault.json.bak`, before)
    await restrict($, `${vaultDir}/vault.json.bak`, '600')
  }
  await $.fs.write(vaultFile(), `${JSON.stringify(file, null, 2)}\n`)
  await restrict($, vaultFile(), '600')
  await loadVault($)
}

async function storeSecret($: EngineInterface, entry: VaultEntry, value: string) {
  await refresh($)
  if (masterKey === undefined) {
    if (entries.length > 0) throw new Error(problem || 'the vault key is missing')
    const made = await createMasterKey($)
    masterKey = made.key
    keyStore = made.store
  }
  const current = (await readVault($))?.file
  const file: VaultFile = {
    format: FORMAT,
    keyStore: current?.keyStore ?? keyStore ?? 'file',
    entries: [...(current?.entries ?? []).filter(one => one.name !== entry.name), sealEntry(masterKey, entry, value)],
  }
  await writeVault($, file)
}

async function removeSecret($: EngineInterface, name: string) {
  const current = (await readVault($))?.file
  if (current !== undefined) await writeVault($, { ...current, entries: current.entries.filter(one => one.name !== name) })
}

/** Vault 0.1 kept each secret as its own Keychain item: move them into the vault file once. */
async function migrate($: EngineInterface) {
  const old = await $.store.get('index')
  if (!Array.isArray(old) || old.length === 0 || os !== 'macos') return
  for (const item of old as Array<VaultEntry & { encoding?: 'raw' | 'base64' }>) {
    const found = await run($, ['/usr/bin/security', 'find-generic-password', '-s', SERVICE, '-a', item.name, '-w'])
    if (found?.exitCode !== 0) continue
    await storeSecret($, describe(item), decodeStored(found.stdout, item.encoding ?? 'raw'))
    await run($, ['/usr/bin/security', 'delete-generic-password', '-s', SERVICE, '-a', item.name])
  }
  await $.store.delete('index')
}

// ---------------------------------------------------------------------------
// The field

async function finish($: EngineInterface, id: string, outcome: string) {
  await $.fs.write(`${vaultDir}/.wait/${id}`, outcome)
}

async function waitFor($: EngineInterface, id: string): Promise<string> {
  const marker = `${vaultDir}/.wait/${id}`
  const argv = os === 'windows'
    ? powershell(
        `$p='${marker.replace(/'/g, "''")}'; while(-not (Test-Path -LiteralPath $p) -or (Get-Item -LiteralPath $p).Length -eq 0){Start-Sleep -Milliseconds 250}; Get-Content -Raw -LiteralPath $p`,
      )
    : (['/bin/sh', '-c', 'while [ ! -s "$1" ]; do sleep 0.25; done; cat "$1"; rm -f "$1"', 'vault-wait', marker] as const)
  const waited = await $.process.run(argv, { timeoutMs: WAIT_MS })
  return waited.stdout.trim()
}

async function fail($: EngineInterface, request: VaultRequest, error: string) {
  await update($, pending, now => (now?.id === request.id ? { ...now, error } : now))
}

async function save($: EngineInterface, request: VaultRequest, value: string) {
  if (value.length === 0) return fail($, request, 'The field is empty.')
  if (request.id.startsWith('preview-')) {
    await update($, pending, () => null)
    $.ui.toast('Preview only: nothing was saved.')
    return
  }
  try {
    const savedAt = new Date(await $.clock.now()).toISOString()
    await storeSecret($, { name: request.name, label: request.label, kind: request.kind, service: request.service, savedAt }, value)
  } catch (error) {
    return fail($, request, `Could not save it: ${error instanceof Error ? error.message : 'unknown error'}.`)
  }
  await finish($, request.id, 'saved')
}

async function cancel($: EngineInterface, request: VaultRequest) {
  if (request.id.startsWith('preview-')) {
    await update($, pending, () => null)
    return
  }
  await finish($, request.id, 'cancelled')
}

/** Puts the secrets of every running Bash call into CLAUDE_VAULT_ENV, or takes it away when none needs it. */
async function carry($: EngineInterface) {
  const names = new Set([...carrying.values()].flat())
  const script = exportScript(secrets.filter(secret => names.has(secret.name)))
  await $.env.set('CLAUDE_VAULT_ENV', names.size > 0 ? script : undefined)
}

async function readClipboard($: EngineInterface): Promise<string | undefined> {
  const readers: ReadonlyArray<readonly string[]> =
    os === 'macos'
      ? [['pbpaste']]
      : os === 'windows'
        ? [['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', 'Get-Clipboard -Raw']]
        : [['wl-paste', '--no-newline'], ['xclip', '-selection', 'clipboard', '-o'], ['xsel', '--clipboard', '--output']]
  for (const argv of readers) {
    const read = await run($, argv, { timeoutMs: 5_000 })
    if (read?.exitCode === 0) return read.stdout
  }
  return undefined
}

/** Reads the clipboard into the open field: the value stays here, only its length goes to the drawing. */
async function pasteInto($: EngineInterface, request: VaultRequest) {
  const text = await readClipboard($)
  if (text === undefined) return fail($, request, 'Could not read the clipboard. Type it instead.')
  const value = text.trim()
  if (value === '') return fail($, request, 'The clipboard is empty. Copy the value first.')
  if (/[\r\n]/.test(value)) return fail($, request, 'The clipboard holds several lines. Copy just the value.')
  if (value.length > PASTE_MAX) return fail($, request, 'The clipboard holds too much text. Copy just the value.')
  held.set(request.id, value)
  await update($, pending, now => (now?.id === request.id ? { ...now, pasted: Array.from(value).length, error: '' } : now))
}

async function unpaste($: EngineInterface, request: VaultRequest) {
  held.delete(request.id)
  await update($, pending, now => (now?.id === request.id ? { ...now, pasted: 0 } : now))
}

/**
 * A command that would send secrets to sites they were not saved for waits for
 * the person: the guard against a page or a file that talks Claude into
 * mailing a key away. Answers whether it may run.
 */
async function mayRun($: EngineInterface, id: string, command: string, used: readonly VaultEntry[], signal: AbortSignal): Promise<boolean> {
  const pairs = strangeSends(command, used).filter(pair => !allowed.has(`${pair.name}@${pair.host}`))
  if (pairs.length === 0) return true
  if ((await read($, asking)) !== null) return false
  const ask: VaultAsk = { id: `send-${id}`, command: command.length > 400 ? `${command.slice(0, 400)}…` : command, pairs }
  const onAbort = () => void finish($, ask.id, 'deny')
  await ensureVaultDir($)
  await update($, asking, () => ask)
  $.ui.status('vault: waiting for you to allow a send')
  signal.addEventListener('abort', onAbort, { once: true })
  let answer = 'deny'
  try {
    answer = await waitFor($, ask.id)
  } catch {
    answer = 'deny'
  } finally {
    signal.removeEventListener('abort', onAbort)
    await update($, asking, now => (now?.id === ask.id ? null : now))
    $.ui.status(undefined)
  }
  if (answer === 'session') for (const pair of pairs) allowed.add(`${pair.name}@${pair.host}`)
  return answer === 'once' || answer === 'session'
}

async function answerAsk($: EngineInterface, ask: VaultAsk, answer: 'once' | 'session' | 'deny') {
  await finish($, ask.id, answer)
}

async function isVaultPath($: EngineInterface, path: unknown): Promise<boolean> {
  if (typeof path !== 'string' || path === '') return false
  if (isInVault(path, vaultDir, home)) return true
  const real = (await $.fs.stat(path, { resolve: true }).catch(() => undefined))?.realPath
  return real !== undefined && isInVault(real, vaultRealDir, home)
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.tool.register({
      name: 'request_secret',
      description:
        'Ask the person for a password, API key, token or login (email, username) through a secure field drawn above their prompt, ' +
        'instead of asking them to paste it into the chat. The value is encrypted into their vault and you never see it. ' +
        'Waits until they save or cancel (10 minutes at most). Then use it in Bash as "$NAME": the vault puts it into that ' +
        'command\'s shell and redacts it from every output. Never echo or print it.',
      inputSchema: {
        type: 'object',
        properties: {
          name: { type: 'string', pattern: NAME_PATTERN, description: 'The environment variable it becomes, e.g. MODAL_TOKEN_ID.' },
          label: { type: 'string', description: 'What the person is asked for, in their language, e.g. "Modal token ID".' },
          why: { type: 'string', description: 'One sentence: what you need it for.' },
          kind: { type: 'string', enum: [...KINDS], description: 'password, api_key, token and secret are typed masked; email, username and text in the clear.' },
          service: { type: 'string', description: 'The site or service it belongs to, e.g. modal.com.' },
          replace: { type: 'boolean', description: 'Ask again even though a secret of this name is saved.' },
        },
        required: ['name', 'label', 'kind'],
      },
      isDeferred: false,
    })
    await $.tool.register({
      name: 'list_secrets',
      description: 'Lists the secrets saved in the vault: names, what each is, the service, when saved. Never the values.',
      inputSchema: { type: 'object', properties: {} },
      isDeferred: false,
    })
    if ($.plugin.root.includes('/dev-mods/')) {
      await $.tool.register({
        name: 'preview_field',
        description: 'Development only: shows the secure field with sample text and returns at once, so its look can be checked. Saves nothing.',
        inputSchema: { type: 'object', properties: { kind: { type: 'string', enum: [...KINDS] } } },
      })
    }
    await $.command.register({
      name: 'vault',
      description: 'Shows the Claude vault (where it is, what it holds), or removes a secret: /vault remove NAME',
      argumentHint: '[remove NAME]',
    })
    await locate($)
    if (os !== 'windows') await run($, ['rm', '-rf', `${vaultDir}/.wait`])
    await loadVault($)
    await migrate($)
    return next(e)
  })

  on('prompt.compose', async ($, e, next) => {
    const composed = await next(e)
    return { sections: [...composed.sections, { id: 'vault:guide', scope: 'session', text: guide(entries, problem) }] }
  })

  // Every tool: keep the model's tools out of the vault, carry the secrets a
  // Bash command names into its shell, and redact every secret from what comes
  // back, before the model or the transcript has it.
  on('tool.call', async ($, e, next) => {
    await refresh($)
    let ran
    if (e.tool === 'Bash') {
      if (touchesVault(e.command, vaultDir)) {
        return { deny: 'The vault folder and its key are off limits. Use a saved secret as "$NAME" in the command instead.' }
      }
      const used = referencedNames(e.command, secrets.map(secret => secret.name))
      const id = e.tool_use_id ?? crypto.randomUUID()
      const usedEntries = entries.filter(entry => used.includes(entry.name))
      if (used.length > 0 && !(await mayRun($, id, e.command, usedEntries, next.signal))) {
        const sites = strangeSends(e.command, usedEntries).map(pair => `${pair.name} to ${pair.host}`).join(', ')
        return { deny: `The person did not allow sending ${sites}. Do not try another way; ask them what they want.` }
      }
      if (used.length > 0) {
        carrying.set(id, used)
        await carry($)
      }
      try {
        ran = await next({ ...e, command: shellCommand(e.command, used.length > 0, carrying.size > 0) })
      } finally {
        if (carrying.delete(id)) await carry($)
      }
    } else {
      if (FILE_TOOLS.has(String(e.tool))) {
        const input = e as unknown as Record<string, unknown>
        for (const field of ['file_path', 'path', 'notebook_path', 'pattern']) {
          if (await isVaultPath($, input[field])) return { deny: 'The vault folder is off limits.' }
        }
      }
      ran = await next(e)
    }
    if (redactor.isEmpty) return ran
    if (ran.deny !== undefined) {
      const deny = redactor.text(ran.deny)
      return deny === ran.deny ? ran : { deny }
    }
    if (ran.isError) {
      const text = redactor.text(ran.text ?? '')
      return text === (ran.text ?? '') && redactor.deep(ran.result) === ran.result ? ran : { deny: text || 'The tool failed.' }
    }
    const result = redactor.deep(ran.result)
    if (result === ran.result) return ran
    return ran.context === undefined ? { result } : { result, context: ran.context }
  }).catch(($, e, next) =>
    // Open before the call (the guard is a second line), closed after it: an
    // output the vault could not redact is never handed on.
    next.called ? { deny: 'The vault could not redact what this call returned.' } : next(e),
  )

  // Rows the conversation keeps (a prompt the person pasted a saved secret
  // into, a hook's context): the same redaction, as a last net.
  on('session.append', ($, e, next) => {
    if (redactor.isEmpty) return next(e)
    const content = redactor.deep(e.message.content)
    return content === e.message.content ? next(e) : next({ ...e, message: { ...e.message, content } })
  })

  on('tool.call', { tool: REQUEST }, async ($, e, next) => {
    const input = e as unknown as Record<string, unknown>
    const name = input.name
    const issue = nameProblem(name)
    if (issue !== undefined || typeof name !== 'string') return { deny: issue ?? 'name is missing' }
    if (!isKind(input.kind)) return { deny: `kind must be one of ${KINDS.join(', ')}` }
    if (typeof input.label !== 'string' || input.label.trim() === '') return { deny: 'label is missing' }
    if (input.replace !== true && entries.some(entry => entry.name === name)) {
      return { result: `${name} is already in the vault. Use it in Bash as "$${name}". To ask for a new value, call again with replace: true.` }
    }
    if ((await read($, pending)) !== null) return { deny: 'Another secure field is open. Wait for the person to answer it first.' }

    const request: VaultRequest = {
      id: e.tool_use_id ?? `request-${crypto.randomUUID()}`,
      name,
      label: input.label.trim(),
      why: typeof input.why === 'string' ? input.why.trim() : '',
      kind: input.kind,
      service: typeof input.service === 'string' ? input.service.trim() : '',
      isPlain: false,
      error: '',
      pasted: 0,
    }
    const onAbort = () => {
      const reason = next.signal.reason instanceof Error ? next.signal.reason.message : String(next.signal.reason)
      $.ui.log(`vault: the request for ${request.name} was interrupted (${reason})`)
      void finish($, request.id, 'interrupted')
    }
    await ensureVaultDir($)
    await update($, pending, () => request)
    $.ui.status(`vault: waiting for ${request.label}`)
    next.signal.addEventListener('abort', onAbort, { once: true })

    let outcome = 'timeout'
    try {
      outcome = await waitFor($, request.id)
    } catch {
      outcome = 'timeout'
    } finally {
      next.signal.removeEventListener('abort', onAbort)
      held.delete(request.id)
      await update($, pending, now => (now?.id === request.id ? null : now))
      await update($, ring, () => null)
      $.ui.status(undefined)
    }

    if (outcome === 'saved') {
      return {
        result:
          `Saved "${request.label}" in the vault as ${name}. Use it in Bash as "$${name}"; it is put into the shell at run time ` +
          'and redacted from every output. You will never see the value.',
      }
    }
    if (outcome === 'cancelled') {
      return { result: `The person cancelled; ${name} was not saved. Ask how they want to go on, and do not ask for it in the chat.` }
    }
    if (outcome === 'interrupted') return { result: `The request was interrupted before the person answered; ${name} was not saved.` }
    return { result: `No answer within 10 minutes, so the field was closed and ${name} was not saved.` }
  })

  on('tool.call', { tool: PREVIEW }, async ($, e) => {
    const input = e as unknown as Record<string, unknown>
    const kind = isKind(input.kind) ? input.kind : 'api_key'
    await update($, pending, () => ({
      id: `preview-${crypto.randomUUID()}`,
      name: 'MODAL_TOKEN_ID',
      label: 'Modal token ID',
      why: 'To deploy openshorts to Modal from this session.',
      kind,
      service: 'modal.com',
      isPlain: false,
      error: '',
      pasted: 0,
    }))
    return { result: 'The preview field is up. Cancel or Save closes it; nothing is saved.' }
  })

  on('tool.call', { tool: LIST }, async () => {
    if (entries.length === 0) return { result: 'The vault is empty.' }
    return {
      result: entries
        .map(entry => `${entry.name}: ${entry.label} (${entry.kind}${entry.service ? `, ${entry.service}` : ''}), saved ${entry.savedAt.slice(0, 10)}`)
        .join('\n'),
    }
  })

  on('command.run', { command: 'vault' }, async ($, e) => {
    await refresh($)
    const [verb, name] = e.args.trim().split(/\s+/)
    if (verb === 'remove') {
      if (!name || !entries.some(entry => entry.name === name)) return { text: `No secret named ${name ?? '(none)'} in the vault.` }
      await removeSecret($, name)
      return { text: `Removed ${name} from the vault.` }
    }
    const where = `${vaultFile()}${keyStore ? `, key in the ${keyStore}` : ''}`
    if (entries.length === 0) return { text: `The vault is empty (${where}). Claude asks for a secret with a secure field when it needs one.` }
    return {
      text: [
        `Vault: ${where}`,
        ...(problem ? [`Problem: ${problem}`] : []),
        ...entries.map(entry => `  ${entry.name}  ${entry.label}${entry.service ? `  ·  ${entry.service}` : ''}`),
        '',
        'Remove one: /vault remove NAME',
      ].join('\n'),
    }
  })

  on('ui.message', async ($, e, next) => {
    const data = e.data as { type?: unknown; value?: unknown } | null
    const request = await read($, pending)
    if (request === null || e.element !== request.id) return next(e)
    if (data?.type === 'submit' && typeof data.value === 'string') {
      const pastedValue = (data as { usePasted?: unknown }).usePasted === true ? held.get(request.id) : undefined
      await save($, request, pastedValue ?? data.value)
    }
    if (data?.type === 'paste') await pasteInto($, request)
    if (data?.type === 'unpaste') await unpaste($, request)
    if (data?.type === 'cancel') await cancel($, request)
    if (data?.type === 'focus') await update($, ring, () => request.id)
    return next(e)
  })

  // The band's focus ring moving (Tab, arrows, a click on a button) takes the
  // field's focused look away, or gives it back.
  on('ui.focus', { component: 'AbovePrompt' }, async ($, e, next) => {
    await update($, ring, () => e.element ?? null)
    return next(e)
  })

  // Drawn like Claude Code's own permission dialog: a rounded box in the
  // permission colour, a bold title, the details indented, then the field.
  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (e.props.hasSurvey) return next(e)
    const ask = await read($, asking)
    if (ask !== null) {
      const { Box, Text, Button, Code } = $.ui.resolve(e)
      return (
        <Box flexDirection="column" borderStyle="round" borderColor="warning" paddingX={1}>
          <Text bold color="warning">⚠ Send a secret to another site?</Text>
          <Box flexDirection="column" paddingLeft={2} paddingTop={1} paddingBottom={1}>
            {ask.pairs.map(pair => (
              <Box key={`${pair.name}@${pair.host}`} gap={1}>
                <Text bold>${pair.name}</Text>
                <Text>→ {pair.host}</Text>
                <Text dimColor>{pair.service ? `(saved for ${pair.service})` : '(saved with no site)'}</Text>
              </Box>
            ))}
            <Box paddingTop={1}>
              <Code source={ask.command} language="bash" />
            </Box>
          </Box>
          <Box gap={1}>
            <Button key="once" label="Allow once" variant="primary" onPress={() => void answerAsk($, ask, 'once')} />
            <Button key="session" label="Allow for this session" onPress={() => void answerAsk($, ask, 'session')} />
            <Button key="deny" label="Deny" onPress={() => void answerAsk($, ask, 'deny')} />
          </Box>
          <Text dimColor>Allow only if you asked for this.</Text>
        </Box>
      )
    }
    const request = await read($, pending)
    if (request === null) return next(e)

    const masked = isMasked(request.kind)
    const placeholder = masked ? 'Paste (⌘V) or type it…' : request.kind === 'email' ? 'name@example.com' : 'Type it…'
    const isFocused = (await read($, ring)) === request.id
    const { Box, Text } = $.ui.resolve(e)
    const header = (
      <Box flexDirection="column" paddingBottom={1}>
        <Box gap={1}>
          <Text bold color="permission">🔒 {request.label}</Text>
          {request.service !== '' && <Text dimColor>{request.service}</Text>}
        </Box>
        {request.why !== '' && <Text dimColor>{request.why}</Text>}
      </Box>
    )
    const note = <Text dimColor>Encrypted on this computer · Claude never sees it</Text>

    if (e.surface === 'mobile') {
      return (
        <Box flexDirection="column" borderStyle="round" borderColor="permission" paddingX={1}>
          {header}
          <Text dimColor>Open this session on your computer to fill it in.</Text>
        </Box>
      )
    }

    if (e.surface !== 'vscode') {
      const { Client } = $.ui.resolve(e)
      return (
        <Box flexDirection="column" borderStyle="round" borderColor="permission" paddingX={1}>
          {header}
          <Client key={request.id} module="./field.tsx" props={{ masked, placeholder, isFocused, error: request.error, pasted: request.pasted }} />
          {request.error !== '' && <Text color="error">{request.error}</Text>}
          {note}
        </Box>
      )
    }

    const { Input, Button } = $.ui.resolve(e)
    return (
      <Box flexDirection="column" borderStyle="round" borderColor="permission" paddingX={1}>
        {header}
        <Input key={`plain-${request.id}`} label=">" placeholder={placeholder} submitLabel="save" autoFocus onSubmit={value => void save($, request, value)} />
        <Box gap={1}>
          <Button key="cancel" label="Cancel" onPress={() => void cancel($, request)} />
          {note}
        </Box>
        {request.error !== '' && <Text color="error">{request.error}</Text>}
      </Box>
    )
  })
}
