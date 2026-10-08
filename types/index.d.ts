export type VaultKind = 'password' | 'api_key' | 'token' | 'secret' | 'email' | 'username' | 'text'

/** A field Claude asked for and the person has not answered yet. Never holds a value. */
export type VaultRequest = {
  /** The tool_use_id of the request_secret call. */
  id: string
  name: string
  label: string
  why: string
  kind: VaultKind
  service: string
  /** The person switched to the plain (visible) field. */
  isPlain: boolean
  /** The last error to show under the field, if saving failed. */
  error: string
}

/** What the vault file says of a secret besides its value. */
export type VaultEntry = {
  name: string
  label: string
  kind: VaultKind
  service: string
  savedAt: string
}

/** An entry as the vault file keeps it: its value sealed with ChaCha20-Poly1305 under the master key. */
export type SealedEntry = VaultEntry & {
  /** 12 random bytes, base64. */
  nonce: string
  /** The ciphertext and its 16-byte tag, base64; the aad is the format and the name. */
  box: string
}

/** Where the master key is kept, so the vault file alone opens nothing. */
export type KeyStore = 'macos-keychain' | 'secret-service' | 'windows-dpapi' | 'file'

/** The one vault file, `<claude config dir>/vault/vault.json`. */
export type VaultFile = {
  format: 'claude-vault/1'
  keyStore: KeyStore
  entries: SealedEntry[]
}

/** A Bash command that would send saved secrets to a site they were not saved for, waiting for the person. */
export type VaultAsk = {
  /** `send-` and the tool_use_id of the Bash call. */
  id: string
  /** The command as the model wrote it: names, never values. */
  command: string
  /** Each secret and the site it would go to. */
  pairs: Array<{ name: string; host: string; service: string }>
}

declare module 'claude-code' {
  interface PluginState {
    /** `ring`: the key of the element in the band that holds the keyboard, as the vault last saw it. */
    vault: { pending: VaultRequest | null; asking: VaultAsk | null; ring: string | null }
  }
}
