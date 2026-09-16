# secret — a tiny secret manager for AI coding agents

A ~70-line Bash wrapper around the **macOS Keychain** that keeps your
credentials out of the **LLM transcript** when an AI agent (Claude Code, Cursor,
etc.) needs to use them.

The problem it solves: when an agent needs an API key or DB password, the naive
flow is "paste it in the chat" — which writes the plaintext into the
conversation history and the model's context, where it persists. `secret` closes
*that specific hole*: you type the value into a GUI box (never the chat), and the
agent references it as `$(secret get <name>)` — a command string that contains no
plaintext, so the transcript stays clean.

**It is not a general "the plaintext never leaks" guarantee.** See
[Threat model](#threat-model--limitations) below for exactly what it does and
does not protect against.

## How it works

- **You** type the value into a native macOS GUI box (hidden answer). It goes
  straight into the login Keychain — never the chat, never a plaintext file.
- **The agent** injects it at run time with `$(secret get <name>)`. The command
  string holds no plaintext, so it's safe to appear in the transcript. The agent
  is also instructed never to print, `cat`, or echo the resolved value.

```
secret set <name>   # pop a hidden GUI prompt, store the value in Keychain
secret get <name>   # print value to stdout — for $(secret get <name>) injection
secret list         # list stored NAMES only (values never shown)
secret rm <name>    # delete a secret
```

## Install

```sh
git clone https://github.com/Fino-wind/agent-secret.git
install -m 755 agent-secret/secret /usr/local/bin/secret   # or anywhere on PATH
```

## Use with Claude Code

### Windows (PowerShell 5.1 / 7)

Clone the repository and keep both files in `windows/` together. No third-party
packages or system execution-policy changes are required. From PowerShell:

```powershell
& .\windows\secret.ps1 set supabase-key
& .\windows\secret.ps1 list
```

`set` opens a masked Windows Forms dialog. Cancel or an empty value leaves any
existing value unchanged. Values are encrypted using Windows DPAPI CurrentUser
in `%LOCALAPPDATA%\agent-secret`; the directory grants only the current user
access. Secret names are visible filenames, case-insensitive on Windows, and
limited to 1-128 ASCII letters, digits, underscores, dots and hyphens.

Capture `get` directly into the environment, check success, and restore it after
the child command finishes. Never run `get` alone in an agent transcript:

```powershell
$previous = $env:SOME_ENV
try {
    $env:SOME_ENV = & .\windows\secret.ps1 get supabase-key
    if (-not $?) { throw 'Secret lookup failed' }
    # Run the application here; it must not log its environment.
} finally {
    $env:SOME_ENV = $previous
}
```

Use `rm <name>` to delete a value. Run `windows/test.ps1` to exercise storage
with disposable dummy values. GUI Save/Cancel should also be checked manually
on an interactive Windows desktop. If organizational policy blocks scripts,
use your administrator's approved signing/execution process; do not disable it.

DPAPI data is tied to the Windows user/profile, not portable backups. There is
no per-read authorization dialog: programs running as that user can decrypt it.
The GUI text and decrypted values necessarily exist in process memory; this
does not protect against malware, administrators, logging by child programs,
PowerShell transcription/debug tracing, or an agent printing `get` output.
Do not supply a `-Key` to the storage commands or store real keys in this repo.

Drop `SKILL.md` into a skill directory (e.g. `~/.claude/skills/secret/SKILL.md`)
so the agent knows when and how to reach for it. The skill teaches the agent to
trigger `secret set` instead of asking you to paste credentials in chat, and to
inject stored secrets with `$(secret get <name>)` without surfacing the value.

## Example

```sh
# store once (GUI box, value never shown):
secret set openai-key

# use it without leaking it:
OPENAI_API_KEY="$(secret get openai-key)" python my_script.py
```

## Threat model & limitations

Be honest about what this does. It is a **narrow** tool with one job.

**What it protects against**
- ✅ The credential entering the **LLM transcript / model context**. You never
  paste it in chat; the `$(secret get <name>)` command string contains no
  plaintext. This is the whole point.
- ✅ The credential sitting in a **plaintext file** (`.env`, config) on disk.
- ✅ The credential landing in **shell history** (the history line is the
  command substitution, not the value).

**What it does NOT protect against**
- ❌ **An agent that runs `secret get <name>` on its own** (to "see" the value)
  prints the plaintext straight to stdout — and into its context/logs. The only
  guard is the instruction in `SKILL.md`; the tool cannot enforce it. `get`
  exists to emit plaintext, by design.
- ❌ **A wrapped command that echoes its own env/args.** If `the-command` prints
  `$SOME_ENV`, the value lands in stdout. Mitigate by piping through
  `grep -v '<prefix>'`, but that's fragile.
- ❌ **Process inspection.** A value injected via env var is visible to
  same-user processes via `ps eww` / `ps -E`. Passing it as a CLI arg
  (`--key=$(secret get x)`) is worse — it shows up in `ps aux` for everyone.
  Prefer env-var injection, never argv.
- ❌ **Keychain "Always Allow".** After you grant it once, *any* program running
  as your user can read that item via `security` with no further prompt. That's
  the convenience/security trade-off; if you want a prompt every time, don't
  click Always Allow.
- ❌ **Memory disclosure** (swap, core dumps). Generic to any process holding a
  plaintext secret in memory; not specific to this tool.

In short: this keeps secrets out of the **conversation**, not out of the
**operating system**. For OS-level secret hygiene use a real secrets manager and
least-privilege scoping.

## Notes

- The Bash entry point is **macOS only** (`security` and `osascript`).
  Windows has a separate PowerShell entry point, documented above.
- Secrets are stored under the Keychain service prefix `agent.secret.<name>`,
  scoped to your user account.
- The first `secret get` may pop a Keychain authorization dialog; click
  **Always Allow** to let the wrapping command read it non-interactively
  (see the trade-off in [Threat model](#threat-model--limitations)).

## License

MIT
