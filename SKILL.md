---
name: secret
description: Store and use credentials without pasting them into chat. Use the macOS Keychain or Windows DPAPI with a masked GUI input prompt, then inject credentials into a process environment without printing them. Applies when the user wants to store a key or a command needs a credential.
---

# secret — agent-safe credential handling

## Windows

On Windows use the repository's `windows/secret.ps1` (keep `SecretStore.psm1`
beside it); the Bash entry point is for macOS. Run `set <name>` to open the
masked dialog for the user. DPAPI stores encrypted files under LOCALAPPDATA,
scoped to the current Windows user. Do not change execution policy to run it.

```powershell
& '<repo>\windows\secret.ps1' set example-key
$previous = $env:SOME_ENV
try {
    $env:SOME_ENV = & '<repo>\windows\secret.ps1' get example-key
    if (-not $?) { throw 'Secret lookup failed' }
    # Run the intended command; never print its environment.
} finally {
    $env:SOME_ENV = $previous
}
```

Never call `get` on its own, print the captured value, pass it in command-line
arguments, or use transcription/debug tracing while retrieving it. `list`
reveals names only. There is no Windows per-read prompt; same-user programs can
decrypt the store. Inspect a command's logging behavior before injecting secrets;
prefix filtering is not a guarantee against leakage. The remaining Keychain
instructions apply only to macOS.

Backed by `secret` (macOS Keychain). The whole point: the human types the value
into a GUI box, it lives only in the Keychain, and **the plaintext never enters
the chat transcript or a plaintext file** — provided you follow the ironclad
rules below. This tool keeps secrets out of the *conversation*; it does NOT make
them un-leakable at the OS level (`ps`, env vars, a wrapped command that echoes
its own args, etc.). Your discipline is the security boundary — the `get`
command will happily print plaintext if you misuse it.

## When you need a credential that isn't stored yet

Do NOT ask the user to paste it in chat (that leaks it into history). Instead
**you** trigger the GUI prompt for them:

```
secret set <name>
```

This pops a native hidden-answer dialog. The user types the value and clicks
Save; it goes straight into the Keychain. Your Bash output only shows
`stored '<name>' ...` — you never see the value. Then tell the user it's stored.

## When you need to USE a stored secret

Inject it, never print it:

```
SOME_ENV="$(secret get <name>)" the-command-that-needs-it
```

- Pipe through `grep -v` of the secret's likely prefix if the wrapped command
  might echo it (e.g. `| grep -v 'postgresql://'`).
- The first `get` may pop a Keychain authorization dialog — click **Always Allow**.

## Ironclad rules

- NEVER `Read`, `cat`, `echo`, or otherwise surface the plaintext value.
- NEVER ask the user to paste a secret into the chat — trigger `secret set` instead.
- `secret list` shows only names (safe to run); use it to see what's available.

## Commands

| Command | What it does |
|---|---|
| `secret set <name>` | GUI prompt → store in Keychain (you trigger, user types) |
| `secret get <name>` | print value to stdout — only for `$(...)` injection |
| `secret list` | list stored names only (never values) |
| `secret rm <name>` | delete a secret |
