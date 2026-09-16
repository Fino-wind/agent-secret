# roadmap — real gaps between the two platforms, found by actually comparing them

> Nothing here is invented to fill space. Each item below was found by diffing
> the macOS (`secret`) and Windows (`windows/`) command interfaces and
> behavior line-by-line — see `docs/code-map.md` for how each side works.
> Where a difference is intentional and fine as-is, it's listed under
> "Confirmed symmetric" or "Not going to change," not left as an implied TODO.

## Real asymmetries

### 1. macOS has no automated tests; Windows does — and CI runs neither

`windows/test.ps1` exercises `SecretStore.psm1` against a temp directory
(redirects `$env:LOCALAPPDATA` to a throwaway GUID-named folder, restores it
in `finally`) and asserts: encrypted-on-disk (plaintext never appears in the
`.dpapi` file), a Unicode round-trip (CJK + `$`/backtick/quote/space in one
value), overwrite, `list` count, four invalid-name rejections
(`../escape`, empty, `a/b`, `x:y`), empty-value rejection, corrupted-file
rejection, and deletion. That's real, meaningful coverage of the storage
module's security-relevant behavior.

**`secret` (Bash/Keychain) has no test at all.** This isn't obviously "just
add one" the way it was for Windows: Windows could redirect `$LOCALAPPDATA`
to a temp directory and get a fully isolated store for free, because DPAPI
storage is just files under a path the test controls. macOS Keychain has no
equivalent single-env-var isolation — a test would need to
`security create-keychain` a throwaway keychain, add it to (and later remove
it from) the process's keychain search list, run against *that*, and clean
up even if a step fails midway (leaving stray keychains around on failure is
its own hazard). That's real setup complexity that Windows' testability
happened to sidestep, not laziness — worth knowing before assuming "just
port test.ps1's approach" is a small change.

**And even the test that does exist has no CI wiring.** There is no
`.github/workflows/` in this repo, so `windows/test.ps1` only runs when a
human remembers to run it by hand on a Windows machine. It could regress
silently for a long time.

### 2. No maximum name length on macOS

Windows enforces a hard `1-128` character bound on secret names, checked in
two places (`secret.ps1` and `SecretStore.psm1` — see code-map's
`regex-consistency` invariant). `require_name()` in the Bash script (`secret`
lines 25-30) only rejects disallowed *characters* — there is no length check
at all. In practice the macOS Keychain itself has its own internal limits on
attribute lengths, so this probably doesn't produce a usable exploit, but the
*tool* doesn't enforce the same bound its own README documents for the
Windows side, and there's no test on the macOS side that would catch it if
someone tried.

### 3. `list` with zero secrets stored behaves differently

macOS: prints `(no secrets stored yet)` (`secret` line 55).
Windows: `Get-AgentSecretNames` returns nothing when the storage directory
doesn't exist yet or is empty, so `windows/secret.ps1 list` with zero
secrets produces blank output — no message at all. Minor UX inconsistency,
not a security issue; listed here because it's the kind of thing that looks
like a bug report ("list printed nothing, is it broken?") to someone who
hasn't read the source.

### 4. README doesn't state the "names are visible, only values are
protected" fact for macOS

Documented explicitly for Windows: "Secret names are visible filenames...".
The macOS equivalent is true (the name is a plaintext suffix on the Keychain
service string, and sits in plaintext in `~/.config/agent-secret/names`) but
isn't spelled out anywhere in README's Threat model section. See code-map
§5 invariant 10 for the detail. Worth a one-sentence addition to README at
some point; not urgent since name secrecy was never a design goal of this
tool.

## Confirmed symmetric — checked, no action needed

These were verified by reading both implementations, in case a future
session wonders the same thing and starts re-deriving the answer:

- **Command surface**: both platforms implement exactly `set`, `get`,
  `list`, `rm` — nothing on one side that's missing from the other
  (`scripts/ci/check_docs.py`'s `command-parity` check enforces this stays
  true going forward).
- **Overwrite semantics**: `set` on an existing name replaces the value on
  both platforms (macOS: `security add-generic-password -U`; Windows:
  `[IO.File]::Replace` for existing files) — confirmed by
  `windows/test.ps1`'s "Overwrite failed" assertion and by reading the `-U`
  flag's documented behavior on macOS. Not independently executed against a
  live `pwsh` here (none available in this sandbox); reasoning is from the
  documented semantics of each call, not a live run.
- **Cancel / empty-value handling**: on both platforms, cancelling the GUI
  dialog or submitting an empty value leaves any existing stored value
  untouched and exits non-zero. On macOS this falls out of the script simply
  never reaching the `security add-generic-password` call. On Windows,
  `Save-AgentSecret`'s empty-value guard (`SecretStore.psm1:12`) runs before
  any file I/O, so the same holds. README's claim "Cancel or an empty value
  leaves any existing value unchanged" is accurate for Windows as written,
  and true-but-unstated for macOS.
- **Deleting a name that was never stored**: idempotent "success" on both
  platforms. macOS: `security delete-generic-password ... || true`
  explicitly swallows the not-found case. Windows: `[IO.File]::Delete`
  is documented .NET behavior to no-op silently when the target doesn't
  exist (not independently executed here, same caveat as above). Neither
  `rm` errors on a name that isn't there — intentional and consistent.

## Not going to change (documented trade-off, not a gap)

- **Windows DPAPI has no per-read authorization prompt; macOS Keychain can
  have one (until "Always Allow" is clicked).** This is the single largest
  real security-model difference between the two platforms and it is
  already correctly documented in README's Windows section and restated in
  `code-map.md` §5 invariant 3. It's a ceiling of the DPAPI `CurrentUser`
  primitive, not something this codebase can fix without switching to a
  fundamentally different Windows API.
- **Error-message hygiene**: Windows sanitizes every exception into one
  fixed generic message; macOS lets `security`/`osascript`'s own stderr
  through unfiltered. See code-map §5 invariant 9. Worth being aware of,
  not urgent to "fix" macOS to match — the native error strings on macOS
  aren't secret material in practice, just less polished.
