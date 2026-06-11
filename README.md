# secret — a tiny secret manager for AI coding agents

A ~70-line Bash wrapper around the **macOS Keychain** that lets an AI agent
(Claude Code, Cursor, etc.) *use* your credentials without ever *seeing* them.

The problem: when an agent needs an API key or DB password, the naive flow is
"paste it in the chat" — which leaks the plaintext into conversation history,
logs, and the model's context. `secret` closes that hole.

## How it works

- **You** type the value into a native macOS GUI box (hidden answer). It goes
  straight into the login Keychain. It never touches the chat or a plaintext file.
- **The agent** injects it at run time with `$(secret get <name>)` and is
  instructed never to print, `cat`, or echo the plaintext.

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

## Notes

- **macOS only** — relies on `security` (Keychain) and `osascript` (GUI dialog).
- Secrets are stored under the Keychain service prefix `agent.secret.<name>`,
  scoped to your user account.
- The first `secret get` may pop a Keychain authorization dialog; click
  **Always Allow** to let the wrapping command read it non-interactively.

## License

MIT
