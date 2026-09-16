# code-map — architecture, invariants, and where each guarantee actually lives

> Read this before touching `secret`, anything under `windows/`, or `SKILL.md`.
> It exists because this repo has no test suite on one of its two platforms
> and a security-critical regex duplicated by hand across two files — the
> kind of thing that's easy to break without anything telling you.

## 1. What this repo is

A ~70-line command-line tool, implemented twice, once per OS, with no shared
code between the two implementations:

| Platform | Entry point | Backing store | Total |
|---|---|---|---|
| macOS | `secret` (Bash) | macOS Keychain (`security`, `osascript`) | 73 lines |
| Windows | `windows/secret.ps1` + `windows/SecretStore.psm1` | Windows DPAPI, `CurrentUser` scope | 71 + 62 = 133 lines |

Both expose the same four verbs: `set <name>`, `get <name>`, `list`,
`rm <name>`. `windows/test.ps1` (47 lines) is an automated test harness for
the Windows storage module only — there is no equivalent for the macOS
script (see `docs/roadmap.md`).

The point of the tool, on either platform, is narrow: keep a credential's
plaintext out of an AI agent's chat transcript. It is not a general secrets
manager and does not claim to protect against OS-level disclosure (process
inspection, a wrapped command that echoes its own env, Keychain "Always
Allow", DPAPI's lack of a per-read prompt). README.md's "Threat model &
limitations" section is the authoritative statement of what is and isn't
covered — this file is about *how the code delivers what it does deliver*,
not a second copy of the threat model.

## 2. Repo layout

```
LICENSE                    MIT
README.md                  user-facing usage + threat model (source of truth for claims)
SKILL.md                   agent-facing trigger + ironclad-rules doc
secret                     macOS entry point (Bash, Keychain-backed)
windows/
  secret.ps1               Windows entry point: CLI parsing, GUI dialog, output
  SecretStore.psm1         Windows storage module: DPAPI encrypt/decrypt, ACLs, atomic write
  test.ps1                 automated test harness for SecretStore.psm1 (LOCALAPPDATA sandboxed)
docs/
  code-map.md               this file
  roadmap.md                known gaps and platform asymmetries
scripts/
  ci/check_docs.py         doc-drift guard, see § 6 below
```

## 3. macOS implementation (`secret`)

Single Bash script, `set -euo pipefail`, no dependencies beyond `security`
and `osascript` (both are part of the OS). Four subcommands live in a
`case "$cmd" in ... esac` block (lines 35-73):

- **`set <name>`** (lines 36-49) — pops a hidden-answer `osascript` dialog
  titled "Agent Secret Manager". Cancel → prints `cancelled`, exits 1,
  nothing is written. Empty value → prints `empty value — nothing stored`,
  exits 1. On success: `security add-generic-password -U -a "$USER"
  -s "${SERVICE_PREFIX}.${name}" -w "$value"` (the `-U` flag makes this an
  upsert — Apple's own docs describe it as "equivalent to first deleting the
  item and then re-adding it"), then the name is appended to the index file
  and the file is re-sorted and de-duplicated.
- **`get <name>`** (lines 50-53) — `security find-generic-password ... -w`,
  straight to stdout. This is the one command whose entire job is to emit
  plaintext; nothing here filters or wraps it. It does **not** consult the
  index file at all — it queries the Keychain directly.
- **`list`** (lines 54-56) — prints the index file's contents, or
  `(no secrets stored yet)` if it's empty/missing. This is the one command
  that reads the index instead of the Keychain.
- **`rm <name>`** (lines 57-65) — deletes from the Keychain (failure is
  swallowed with `|| true` — a delete of a name that was never stored is not
  treated as an error) and removes the name from the index file via
  `grep -vxF`.

### Naming

`SERVICE_PREFIX="agent.secret"` (line 16). Every Keychain item this tool
touches is namespaced under `agent.secret.<name>`, scoped to `-a "$USER"`.
`require_name()` (lines 25-30) rejects any name containing a character
outside `[a-zA-Z0-9_.-]`, but — unlike the Windows side — **imposes no
maximum length**. See `docs/roadmap.md` for why that's an asymmetry worth
knowing about, not (currently) a bug.

### The index file is not the source of truth for `get`

`INDEX_FILE="$INDEX_DIR/names"` (default `~/.config/agent-secret/names`) is
a plain sorted, de-duplicated list of names, maintained by `set` and `rm`.
It exists purely so `list` has something fast and Keychain-prompt-free to
read — enumerating "every Keychain item under this service prefix" isn't a
single clean `security` invocation the way it is on Windows (§ 4). Because
`get` bypasses the index and reads the Keychain directly, the two can
diverge: if the index file is deleted, edited by hand, or a `set` is
interrupted between the `security add-generic-password` call and the index
rewrite, `list` will lie about what's actually retrievable — `get` will
still work for anything really in the Keychain, `list` won't show it.

## 4. Windows implementation (`windows/`)

Two files with a deliberate split: `secret.ps1` is the CLI shell (argument
parsing, the GUI dialog, decrypted-value output, top-level error handling);
`SecretStore.psm1` is the storage module (path resolution, DPAPI
encrypt/decrypt, filesystem hardening). `secret.ps1` imports the module with
`Import-Module (Join-Path $PSScriptRoot 'SecretStore.psm1') -Force` — the
two files must be kept together, which is why README.md says so explicitly.

`Export-ModuleMember` exposes exactly four functions from the module:
`Save-AgentSecret`, `Read-AgentSecret`, `Get-AgentSecretNames`,
`Remove-AgentSecret` — one per verb, plus `Get-SecretPath` as an internal
helper that is *not* exported (callers only ever get a stored/loaded
`SecureString`, never a raw path they could hand elsewhere).

### Storage layout

One file per secret: `%LOCALAPPDATA%\agent-secret\secret.<name>.dpapi`. The
name is a literal, unencrypted filename component (only the *value* inside
the file is DPAPI-encrypted — see § 5, "names are never protected, only
values"). `Get-AgentSecretNames` derives `list`'s output by scanning that
directory for `secret.*.dpapi` and stripping the fixed prefix/suffix
(`SecretStore.psm1` line 53-54) — there is no separate index file, so unlike
the macOS side, `list` cannot drift from what's actually on disk: the
directory listing *is* the source of truth for both `list` and `get`.

## 5. 🔒 Invariants

These are load-bearing. Each one was checked against the actual PowerShell
source (not the prose describing it) while this file was written. If you
change the corresponding code, update this list in the same commit — that's
exactly the kind of drift `scripts/ci/check_docs.py` cannot see, because it
checks documented *claims* against code, not architectural properties like
"is this write atomic."

1. **Name validation is a length-bounded allowlist regex, applied in two
   places.** `Get-SecretPath` (`SecretStore.psm1:5`) and the CLI's own
   pre-check (`secret.ps1:10`) both run
   `$Name -cnotmatch '\A[a-zA-Z0-9_.-]{1,128}\z'` — case-sensitive, anchored
   `\A`/`\z` (not `^`/`$`, which in .NET regex can match at embedded
   newlines), 1-128 characters. **This is the same literal string
   hand-duplicated in two files, not a shared constant** — nothing in the
   language enforces they stay identical. `check_docs.py`'s
   `regex-consistency` check exists specifically because of this.

2. **The `secret.` prefix and `.dpapi` suffix exist to defeat Windows
   reserved device names.** The code comment says it outright: "Prefix
   avoids Windows reserved device names and trailing-dot ambiguity." A name
   of `CON`, `NUL`, `AUX`, `PRN`, `COM1`, etc. would collide with a reserved
   DOS device name if it ever became a bare filename or leading path
   component; wrapping it as `secret.CON.dpapi` means the reserved word
   never appears in the position where Win32 special-cases it.

3. **DPAPI here means `CurrentUser` scope with no per-read prompt — the
   single biggest security-model gap versus macOS.** `Save-AgentSecret`
   calls `ConvertFrom-SecureString -SecureString $Value` with no `-Key`
   argument (`SecretStore.psm1:31`, and the code comment says so directly:
   "On Windows, no `-Key` means DPAPI CurrentUser, not portable
   encryption"). That's the correct choice — a hardcoded `-Key` would be a
   worse secret than what it protects — but the consequence is: **any
   process running as the same Windows user can decrypt any stored value
   with no additional authorization step, ever.** macOS Keychain items can
   at least *start* with a per-application access-control prompt (before
   the user clicks "Always Allow", which is a documented,
   user-in-the-loop trade-off — see README's threat model). DPAPI never
   offers that first prompt at all. README documents this ("There is no
   per-read authorization dialog") but it is worth stating here as an
   architectural fact, not just a prose warning: **this is not a bug to
   fix, it's the ceiling of what DPAPI CurrentUser can do**, and any future
   Windows hardening pass that wants a real per-read gate would need a
   different primitive entirely (e.g. Windows Hello / CNG key with a
   stronger policy), not a tweak to this code.

4. **NTFS ACLs are hardened on every write, not just on first creation.**
   `Save-AgentSecret` (`SecretStore.psm1:18-27`) calls
   `SetAccessRuleProtection($true, $false)` (disable inheritance, don't
   preserve inherited rules), removes every existing ACE on the directory,
   and adds exactly one: `FullControl` for the current user's SID. This
   runs on *every* `set`, not once at directory-creation time, so even if
   something else (an installer, a misconfigured backup tool, a restored
   ACL from elsewhere) loosens the directory permissions between runs, the
   next `set` re-tightens them. There's a version split for how the ACL
   gets applied — `[IO.FileSystemAclExtensions]::SetAccessControl` on
   PowerShell 7+, `$directoryInfo.SetAccessControl($acl)` on 5.1 — because
   the extension method only exists in newer .NET.

5. **Symlink/reparse-point attack on the storage directory is checked and
   rejected before any write.** `SecretStore.psm1:15-17`: if
   `(Get-Item -LiteralPath $directory).Attributes` has the `ReparsePoint`
   flag set, `Save-AgentSecret` throws `'Secret directory must not be a
   link.'` before creating or touching anything. This blocks the class of
   attack where `%LOCALAPPDATA%\agent-secret` has been replaced with a
   junction/symlink pointing somewhere the attacker controls, which would
   otherwise cause the hardened ACL and the encrypted file to land in the
   wrong place while looking like they succeeded.

6. **Writes are atomic: temp file + rename, not write-in-place.**
   `Save-AgentSecret:28-41` writes the encrypted blob to a `.tmp` file with
   a random GUID name in the same directory, then:
   - if the target doesn't exist yet: `[IO.File]::Move($temporary, $path)`
   - if it does (an overwrite): `[IO.File]::Replace($temporary, $path,
     $backup)`, which is itself atomic and leaves a `.bak` that's deleted
     in a `finally` immediately after.
   Either way, a crash mid-write can never leave `secret.<name>.dpapi`
   half-written or missing — readers always see either the old value or the
   new one, never a torn file. The temp file is also cleaned up in a
   `finally` if anything above throws.

7. **`get` actively zeroes the decrypted value's unmanaged memory copy after
   printing it.** `secret.ps1:51-60` marshals the `SecureString` to a BSTR
   with `SecureStringToBSTR`, prints it with `PtrToStringBSTR`, then in a
   `finally` calls `ZeroFreeBSTR($pointer)` — which overwrites the
   unmanaged memory with zeros *before* freeing it, not just freeing it.
   `$value.Dispose()` is also called on the `SecureString` itself. This
   doesn't make the value un-recoverable in general (it's on stdout, in the
   caller's process, potentially in a debugger, in the .NET string pool
   momentarily during `Write-Output` — none of that is defended here) but
   it does close the specific, narrow window of "this value sits in
   unmanaged memory after we're done with it and before GC gets around to
   it," which is exactly the kind of thing that shows up in a crash dump or
   memory-scraping tool if left alone.

8. **`list`'s source of truth is a directory scan of `secret.*.dpapi`
   filenames, not a maintained index.** `Get-AgentSecretNames`
   (`SecretStore.psm1:50-56`) globs the storage directory and derives each
   name by stripping the fixed 7-char prefix (`secret.`) and 6-char suffix
   (`.dpapi`) from each filename. There is nothing to keep in sync — the
   filesystem *is* the index. Compare § 3's macOS index-file mechanism,
   which is a separate artifact that `get` doesn't consult and that can
   fall out of sync with the Keychain.

9. **Top-level error handling on Windows deliberately swallows exception
   detail.** `secret.ps1:67-71` wraps the entire command dispatch in a
   `try`/`catch` that prints one fixed, generic message to stderr on any
   failure — "Secret operation failed. Check the command, name, local
   permissions and Windows user profile..." — and the code comment states
   the reasoning directly: "Do not print exceptions that might include
   input or decrypted material." The macOS script has no equivalent
   filter: `security`'s and `osascript`'s own error text goes to stderr
   unmodified when either fails. In practice `security`/`osascript` error
   strings are generic OS messages, not secret material, so this isn't a
   live leak — but it's a real, intentional difference in error-message
   hygiene between the two implementations, and worth knowing before
   assuming stderr output means the same thing on both platforms.

10. **Names are never protected — only values are.** On macOS the name is
    the plaintext Keychain *service string suffix* (`agent.secret.<name>`,
    findable with `security dump-keychain` by anyone who can read the login
    keychain's metadata, without ever decrypting a value) and it's also
    sitting in plaintext in `~/.config/agent-secret/names`. On Windows the
    name is a plaintext *filename* under `%LOCALAPPDATA%\agent-secret\`.
    Both implementations agree on this shape even though nothing forced
    them to: **an attacker who can list Keychain items or read a directory
    listing — without decrypting anything — learns which secrets exist and
    what they're called, on either platform.** README's threat model
    doesn't currently call this out explicitly (it's implied by "Secret
    names are visible filenames" in the Windows section, but there's no
    equivalent sentence for macOS). Worth a README addition at some point;
    not urgent, since name secrecy was never a design goal here.

## 6. `scripts/ci/check_docs.py` — what it guards and why

Full rationale is in the script's own module docstring (read it — this
section is a pointer, not a duplicate). In one line: it checks that
(a) every backtick-quoted repo path in the docs resolves, (b) the two
platforms' `set|get|list|rm` command surfaces are identical to each other
and each is mentioned in both README.md and SKILL.md, (c) the
name-validation regex is byte-identical between `secret.ps1` and
`SecretStore.psm1` and its bound matches what README states, (d) the
Keychain service prefix hardcoded in `secret` matches what README claims,
and (e) SKILL.md's `description:` still names both platforms. Run it with
`python3 scripts/ci/check_docs.py`; run `--self-test` to see it reject
synthetic bad input for all five checks at once.

It does **not** execute either PowerShell script (no `pwsh` in the sandbox
this was authored in, and it shouldn't shell out to something that pops a
GUI dialog and writes real DPAPI state as a docs check regardless). It also
does not check prose quality or re-litigate whether a threat-model trade-off
is still the right call — see `docs/roadmap.md` for what's deliberately left
to a human.

## 7. Provenance

```
02f8fc2  2026-06-11  secret — agent-safe credential handling via macOS Keychain
                     (LICENSE, README.md, SKILL.md, secret — macOS only)
9cc8b03  2026-06-11  docs: correct over-promise, add honest threat model
                     (README/SKILL reframed from "never leaks" to "kept out
                     of the transcript"; added the Threat model section)
c6f653a  2026-09-16  Add Windows DPAPI secret storage and masked input (#1)
                     (windows/secret.ps1, windows/SecretStore.psm1,
                     windows/test.ps1; README/SKILL extended with a Windows
                     section each)
```

PR: https://github.com/Fino-wind/agent-secret/pull/1
