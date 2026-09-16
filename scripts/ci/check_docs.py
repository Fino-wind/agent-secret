#!/usr/bin/env python3
r"""Guard agent-secret's docs against the two failure modes a two-implementation
security tool actually has: a claim in the docs that stops being true, and the
two platforms' command surfaces silently drifting apart.

Why this exists
----------------
This repo ships two independent implementations of the same tool: a ~70-line
Bash script backed by the macOS Keychain, and three PowerShell files backed by
Windows DPAPI. They share no code. Nothing forces them to stay in sync, and
nothing forces README.md / SKILL.md to keep describing what the scripts
actually do. Two concrete risks follow directly from that:

  1. The two platforms' command surfaces (`set|get|list|rm`) could drift —
     someone adds a subcommand to one script and not the other, or to a
     script and not the docs, and nobody notices because there's no shared
     source of truth to diff against.
  2. The name-validation regex `\A[a-zA-Z0-9_.-]{1,128}\z` is hand-duplicated
     verbatim in windows/secret.ps1 AND windows/SecretStore.psm1 (see
     docs/code-map.md "duplicated, not shared" for why). If one copy is
     edited and the other isn't, the tool silently enforces two different
     security boundaries depending on which code path runs — the kind of bug
     that doesn't throw, doesn't fail a test, and just quietly stops being
     what the README promises.

What this deliberately does NOT do
------------------------------------
It does not execute windows/secret.ps1 or windows/test.ps1 (no `pwsh` on this
host, and even where one exists, shelling out to a script that pops a GUI
dialog and writes to a real DPAPI store is not what a docs guard should do).
It does not check prose quality, whether a security tradeoff is still the
right one, or run in CI on a schedule of its own — for a repo this size, a
guard that only fires on `git commit`/CI is enough; a guard that also polls
for staleness would be scaffolding nobody asked for. See docs/roadmap.md for
the (separate, real) gap that nothing runs windows/test.ps1 automatically.

What it checks (all credential-free, sub-second, no network)
----------------------------------------------------------------
1. dead-paths      — every backtick-quoted repo path in README.md / SKILL.md
                      / docs/*.md resolves to a real file on disk (checked
                      prefixes: windows/, docs/, scripts/, plus a small
                      bare-filename whitelist for top-level files).
2. command-parity  — the subcommands implemented by `secret` (bash case block)
                      and by windows/secret.ps1 (switch block) are the SAME
                      set, and every command in that set is mentioned inside
                      a code span (backtick or fence) in both README.md and
                      SKILL.md.
3. regex-consistency — the name-validation regex literal is byte-identical
                      in windows/secret.ps1 and windows/SecretStore.psm1, and
                      its {min,max} bound is restated correctly in README.md
                      ("1-128 ASCII letters...").
4. service-prefix  — the Keychain service prefix hardcoded in `secret`
                      (SERVICE_PREFIX="agent.secret") matches what README.md
                      documents ("agent.secret.<name>").
5. skill-platforms — SKILL.md's frontmatter `description:` still names both
                      platforms (macOS/Keychain AND Windows/DPAPI), since
                      that description is literally what the agent uses to
                      decide whether this skill applies on either OS.

Run `--self-test` to prove none of these five checks is vacuous: it feeds
each one synthetic input that is known to violate the rule and asserts every
check fires. See self_test() at the bottom.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# windows/... and docs/... path mentions are checked by prefix; a handful of
# top-level files get referenced bare (no directory) in prose, so they're
# listed explicitly and mapped to their real repo-relative path.
PATH_PREFIXES = ("windows/", "docs/", "scripts/")
BARE_FILE_MAP = {
    "README.md": "README.md",
    "SKILL.md": "SKILL.md",
    "LICENSE": "LICENSE",
    "secret": "secret",
    "SecretStore.psm1": "windows/SecretStore.psm1",
}

DOC_FILES = ("README.md", "SKILL.md", "docs/code-map.md", "docs/roadmap.md")


class Findings:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str]] = []

    def add(self, check: str, detail: str) -> None:
        self.rows.append((check, detail))

    def __len__(self) -> int:
        return len(self.rows)

    def __bool__(self) -> bool:
        return bool(self.rows)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


# ---------------------------------------------------------------- 1. dead paths

def check_dead_paths(text: str, repo: Path, f: Findings) -> None:
    prefix_alt = "|".join(re.escape(p) for p in PATH_PREFIXES)
    bare_alt = "|".join(re.escape(b) for b in BARE_FILE_MAP)
    pattern = rf"`((?:{prefix_alt})[\w./-]+|{bare_alt})`"
    for quoted in sorted(set(re.findall(pattern, text))):
        if quoted.endswith("/"):
            continue  # directory mention (e.g. `windows/`), not a file
        real = BARE_FILE_MAP.get(quoted, quoted)
        if not (repo / real).exists():
            f.add("dead-paths", f"`{quoted}` (resolved: {real}) does not exist on disk")


# ---------------------------------------------------------- 2. command parity

def extract_bash_commands(text: str) -> set[str]:
    """Subcommand labels in `secret`'s `case "$cmd" in ... esac` block, minus
    the help/error fallback labels — i.e. the real subcommands it implements."""
    m = re.search(r'case "\$cmd" in\n(.*?)\nesac', text, re.S)
    if not m:
        return set()
    labels: set[str] = set()
    for line in m.group(1).splitlines():
        line = line.strip()
        if ")" not in line:
            continue
        head = line.split(")", 1)[0]
        for alt in head.split("|"):
            alt = alt.strip().strip('"').strip("'")
            if re.fullmatch(r"[a-z]+", alt):
                labels.add(alt)
    return labels - {"help"}


def extract_ps1_commands(text: str) -> set[str]:
    """Subcommand labels in windows/secret.ps1's `switch ($Command) { ... }`
    block — every `'word' {` at the top level of the switch is a real case;
    the help/default arms use `{ $_ -in @(...) }` / `default` and never match
    this pattern, so no exclusion list is needed (verified against the file:
    only set/get/list/rm match `'[a-z]+'\\s*\\{` anywhere in the script)."""
    return set(re.findall(r"'([a-z]+)'\s*\{", text))


def code_spans(text: str) -> str:
    """Every fenced code block and every backtick span, concatenated. Command
    names get checked for presence in here, not in raw prose — README uses
    the bare word "secret" in ordinary sentences ("secret manager", "secret
    hygiene", "a real secrets manager") that would otherwise pollute a naive
    whole-word search with false "documented" hits for unrelated words, and
    false confidence that a genuinely undocumented command was mentioned."""
    fences = re.findall(r"```[a-zA-Z]*\n(.*?)```", text, re.S)
    backticks = re.findall(r"`([^`\n]+)`", text)
    return "\n".join(fences) + "\n" + "\n".join(backticks)


def check_command_parity(bash_text: str, ps1_text: str, readme_text: str,
                          skill_text: str, f: Findings) -> None:
    bash_cmds = extract_bash_commands(bash_text)
    ps1_cmds = extract_ps1_commands(ps1_text)

    if not bash_cmds:
        f.add("command-parity", "could not find any subcommand in secret's "
              "case block — the `case \"$cmd\" in ... esac` structure this "
              "check parses may have changed; the guard itself needs fixing")
    if not ps1_cmds:
        f.add("command-parity", "could not find any subcommand in "
              "windows/secret.ps1's switch block — the `switch ($Command)` "
              "structure this check parses may have changed; the guard "
              "itself needs fixing")
    if not bash_cmds or not ps1_cmds:
        return

    only_macos = bash_cmds - ps1_cmds
    only_windows = ps1_cmds - bash_cmds
    if only_macos:
        f.add("command-parity",
              f"secret (macOS) implements {sorted(only_macos)} — "
              f"windows/secret.ps1 does not")
    if only_windows:
        f.add("command-parity",
              f"windows/secret.ps1 implements {sorted(only_windows)} — "
              f"secret (macOS) does not")

    readme_code = code_spans(readme_text)
    skill_code = code_spans(skill_text)
    for cmd in sorted(bash_cmds | ps1_cmds):
        pat = rf"\b{re.escape(cmd)}\b"
        if not re.search(pat, readme_code):
            f.add("command-parity",
                  f"`{cmd}` is implemented but not mentioned in any code "
                  f"span in README.md")
        if not re.search(pat, skill_code):
            f.add("command-parity",
                  f"`{cmd}` is implemented but not mentioned in any code "
                  f"span in SKILL.md")


# ------------------------------------------------------ 3. regex consistency

def extract_cnotmatch_regex(text: str) -> str | None:
    m = re.search(r"cnotmatch\s+'([^']+)'", text)
    return m.group(1) if m else None


def check_regex_consistency(secret_ps1_text: str, securestore_psm1_text: str,
                             readme_text: str, f: Findings) -> None:
    r1 = extract_cnotmatch_regex(secret_ps1_text)
    r2 = extract_cnotmatch_regex(securestore_psm1_text)
    if r1 is None:
        f.add("regex-consistency", "no -cnotmatch name-validation regex "
              "found in windows/secret.ps1 — the guard's own parser may be "
              "out of date")
        return
    if r2 is None:
        f.add("regex-consistency", "no -cnotmatch name-validation regex "
              "found in windows/SecretStore.psm1 — the guard's own parser "
              "may be out of date")
        return
    if r1 != r2:
        f.add("regex-consistency",
              f"windows/secret.ps1 validates names against {r1!r} but "
              f"windows/SecretStore.psm1 validates against {r2!r} — these "
              f"are hand-duplicated and must be identical (see code-map.md)")
        return  # bound-vs-README check below assumes a single agreed regex

    bound = re.search(r"\{(\d+),(\d+)\}", r1)
    if not bound:
        f.add("regex-consistency",
              f"could not parse a {{min,max}} bound out of {r1!r}")
        return
    lo, hi = bound.groups()
    if f"{lo}-{hi}" not in readme_text:
        f.add("regex-consistency",
              f"windows/secret.ps1 + SecretStore.psm1 enforce a "
              f"{lo}-{hi}-character name bound, but README.md does not "
              f"state '{lo}-{hi}' anywhere")


# -------------------------------------------------------- 4. service prefix

def check_service_prefix(bash_text: str, readme_text: str, f: Findings) -> None:
    m = re.search(r'SERVICE_PREFIX="([^"]+)"', bash_text)
    if not m:
        f.add("service-prefix", "no SERVICE_PREFIX=\"...\" assignment found "
              "in secret — the guard's own parser may be out of date")
        return
    prefix = m.group(1)
    if f"{prefix}.<name>" not in readme_text:
        f.add("service-prefix",
              f"secret stores items under Keychain service "
              f"'{prefix}.<name>', but README.md does not document that "
              f"exact prefix (looked for '{prefix}.<name>')")


# ------------------------------------------------------- 5. skill platforms

def check_skill_platforms(skill_text: str, f: Findings) -> None:
    m = re.search(r"^description:\s*(.+)$", skill_text, re.MULTILINE)
    if not m:
        f.add("skill-platforms", "SKILL.md has no `description:` line in "
              "its frontmatter — that's the string the agent triggers on")
        return
    desc = m.group(1)
    has_macos = bool(re.search(r"macOS|Keychain", desc, re.IGNORECASE))
    has_windows = bool(re.search(r"Windows|DPAPI", desc, re.IGNORECASE))
    if not has_macos:
        f.add("skill-platforms",
              "SKILL.md description no longer mentions macOS/Keychain — an "
              "agent on macOS may no longer trigger this skill")
    if not has_windows:
        f.add("skill-platforms",
              "SKILL.md description no longer mentions Windows/DPAPI — an "
              "agent on Windows may no longer trigger this skill")


# --------------------------------------------------------------------- run

def run(repo: Path) -> Findings:
    f = Findings()

    corpus = "\n".join(read(repo / rel) for rel in DOC_FILES)
    check_dead_paths(corpus, repo, f)

    bash_text = read(repo / "secret")
    ps1_text = read(repo / "windows" / "secret.ps1")
    psm1_text = read(repo / "windows" / "SecretStore.psm1")
    readme_text = read(repo / "README.md")
    skill_text = read(repo / "SKILL.md")

    check_command_parity(bash_text, ps1_text, readme_text, skill_text, f)
    check_regex_consistency(ps1_text, psm1_text, readme_text, f)
    check_service_prefix(bash_text, readme_text, f)
    check_skill_platforms(skill_text, f)
    return f


# ---------------------------------------------------------------- self-test

def self_test() -> int:
    """Feed each of the five checks input that is known to violate the rule
    it enforces, and require every one of them to produce a finding. Proves
    the checks reject bad input instead of passing vacuously — mirrors the
    approach in shop/scripts/ci/check_agents_md.py, adapted to this repo:
    every check here takes its inputs as plain strings (not module globals
    or a git ref), so self-test constructs synthetic bad text directly
    rather than replaying a historical commit."""
    f = Findings()

    # 1. dead-paths: reference two paths that don't exist.
    check_dead_paths(
        "See `windows/this-file-does-not-exist.ps1` and "
        "`docs/this-doc-was-never-written.md` for details.",
        REPO, f,
    )

    # 2. command-parity: bash has {set,get,list,rm}; windows additionally
    #    implements an undocumented 'rotate' — both the cross-platform diff
    #    and the missing-from-docs check should fire on it.
    synthetic_bash = (
        'case "$cmd" in\n'
        "  set)\n    ;;\n"
        "  get)\n    ;;\n"
        "  list)\n    ;;\n"
        "  rm)\n    ;;\n"
        '  ""|-h|--help|help)\n    ;;\n'
        "  *)\n    ;;\n"
        "esac"
    )
    synthetic_ps1 = (
        "switch ($Command) {\n"
        "    'set' { }\n"
        "    'get' { }\n"
        "    'list' { }\n"
        "    'rm' { }\n"
        "    'rotate' { }\n"
        "    default { }\n"
        "}"
    )
    synthetic_readme = "```\nsecret set <name>\nsecret get <name>\n"\
                        "secret list\nsecret rm <name>\n```"
    synthetic_skill = "| `secret set <name>` | ... |\n"\
                       "| `secret get <name>` | ... |\n"\
                       "| `secret list` | ... |\n"\
                       "| `secret rm <name>` | ... |"
    check_command_parity(synthetic_bash, synthetic_ps1, synthetic_readme,
                          synthetic_skill, f)

    # 3. regex-consistency: the two PowerShell files disagree with each other,
    #    AND (separately) the bound they agree on isn't restated in README.
    check_regex_consistency(
        r"cnotmatch '\A[a-zA-Z0-9_.-]{1,128}\z'",
        r"cnotmatch '\A[a-zA-Z0-9_.-]{1,64}\z'",
        "no bound mentioned here",
        f,
    )

    # 4. service-prefix: code and doc disagree on the Keychain prefix.
    check_service_prefix(
        'SERVICE_PREFIX="totally.different"',
        "stored under the Keychain service prefix `agent.secret.<name>`",
        f,
    )

    # 5. skill-platforms: description drops Windows entirely.
    check_skill_platforms(
        "---\nname: secret\ndescription: Store and use credentials on "
        "macOS via the Keychain without pasting them into chat.\n---\n",
        f,
    )

    print(f"{len(f)} findings:")
    for check, detail in f.rows:
        print(f"  [{check}] {detail}")

    expected_checks = {"dead-paths", "command-parity", "regex-consistency",
                        "service-prefix", "skill-platforms"}
    fired_checks = {check for check, _ in f.rows}
    missing = expected_checks - fired_checks
    if missing:
        print(f"\nFAIL  these checks did not fire on known-bad input: "
              f"{sorted(missing)} — they may be vacuous.", file=sys.stderr)
        return 1
    print("\nPASS  known-bad input was rejected by every check.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true",
                     help="Run every check against synthetic known-bad "
                          "input and require each one to fire. Proves the "
                          "checks detect real drift instead of passing "
                          "vacuously.")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    f = run(REPO)
    if not f:
        print("PASS  README.md / SKILL.md / docs: dead paths resolve, "
              "macOS and Windows command surfaces match and are both "
              "documented, the name-validation regex agrees between "
              "secret.ps1 and SecretStore.psm1 and matches README's stated "
              "bound, the Keychain service prefix matches README, and "
              "SKILL.md's description still names both platforms.")
        return 0

    print(f"FAIL  {len(f)} finding(s)\n")
    current = None
    for check, detail in f.rows:
        if check != current:
            print(f"[{check}]")
            current = check
        print(f"  {detail}")
    print("\nEach of these is a claim (or a cross-platform guarantee) that "
          "used to be true and silently stopped being true.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
