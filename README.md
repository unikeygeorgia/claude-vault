# vault

A Claude Code plugin that asks for passwords, API keys, tokens and logins
through a secure field instead of the chat, keeps them encrypted in one vault
file, and lets Claude use them in its shell without ever seeing them.

## How it works

1. Claude needs a secret and calls `request_secret` (name, label, why, site).
   A field opens above your prompt. Click it, paste or type, press Enter.
   Masked kinds (password, API key, token) show dots; Show reveals them.
2. The value is sealed with ChaCha20-Poly1305 into `~/.claude/vault/vault.json`
   (or `$CLAUDE_CONFIG_DIR/vault`). The key is not in that folder: it is kept by
   the OS (macOS Keychain, Linux Secret Service, Windows DPAPI). Only where none
   exists does it fall back to `master.key` in the folder, readable by you alone.
3. Claude writes `"$MODAL_TOKEN"` in a Bash command. The plugin hands the value
   to that command's shell through the environment, and the command's first
   line drops the carrier variable. Nothing is written to disk on the way.
4. Every tool result and every row the conversation keeps is redacted before
   Claude or the transcript has it: the value, its base64, hex, URL, JSON and
   shell spellings, and any 12-character run of a long value, become
   `[vault:NAME]`.

## What it guards against

| Risk | Guard |
| --- | --- |
| Claude reads a secret | It never gets one: values reach the shell only, and outputs are redacted |
| A secret ends up in the transcript | Redaction runs before rows are stored |
| Claude's tools open the vault | Bash, Read, Grep, Glob, Edit and Write are refused inside the vault folder, symlinks resolved; the carrier variable and the OS key are off limits |
| A page or file talks Claude into sending a key away | A command that sends a secret to a site other than the one it was saved for waits for you: Allow once, Allow for this session, or Deny |
| The vault file leaks (backup, sync) | It is encrypted, its key is held by the OS, and an altered or renamed entry does not open |
| Other plugins see what you type | The masked field is a surface module: keys stay on the drawing side and reach this plugin alone |

What it cannot do: stop a program you run from misusing a secret it was given,
or redaction catch a value deliberately scrambled past recognition. Allow a
send only when you asked for it.

## Commands

- `/vault`: where the vault is, which key store holds its key, what it holds
- `/vault remove NAME`: removes one secret

## Install

On any computer, at a Claude Code terminal prompt (the repository is private,
so git there must be signed in to GitHub):

```
/plugin install vault --marketplace unikeygeorgia/claude-vault
```

or from a shell:

```bash
claude plugin marketplace add unikeygeorgia/claude-vault
claude plugin install vault@claude-vault
```

Each computer keeps its own vault: secrets are never in this repository and
never leave the machine they were typed on.

On the computer that develops it, the marketplace is this folder instead
(`claude plugin marketplace add ~/Projects/claude-vault`), so an edit here
reaches a session after `/reload-plugins`.

## Develop

```bash
claude plugin validate .
claude plugin test .
```

`hooks/crypto.ts` is checked against RFC 8439's test vector and against
Node's own ChaCha20-Poly1305.
