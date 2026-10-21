# AGENTS.md — guardian alert triage runbook

> When the user says "cek issues, ada IOC tercreate" / "guardian alert" / anything about guardian findings — follow this runbook exactly.

## What guardian is (30 seconds)

An hourly sweep (`.github/workflows/guardian-sweep.yml`) over **personal non-fork repos + The-Aetheris org**, executed from this repo with a **read-only** fine-grained PAT (`GUARD_PAT`). Findings open an issue here and the run exits 1. It is triggered by the native cron and by an external Cloudflare Worker dispatcher (see README). A **"Manually run"** entry in Actions history = the Worker fallback fired = native cron missed a slot.

## Issue anatomy

Title: `IOC detected - sweep <UTC timestamp>`. Body lines, one per finding:

```
R-<8hex>@<branch> :: <path> (<reason>)
```

`R-<8hex>` is a salted hash masking the repo name. Resolve locally — the salt never leaves the user's machine:

```bash
grep R-xxxxxx ~/.guardian-map.txt        # → athallarizky/<repo>
```

If the map is missing/stale, regenerate with `guardian-map.sh` (agent-playbooks `guardian-protection`) using the same salt as the `GUARD_SALT` secret.

## Triage steps

1. **List & read:** `gh issue list -R athallarizky/guardian` → `gh issue view <n> -R athallarizky/guardian`
2. **Resolve every R-code** against `~/.guardian-map.txt`
3. **Classify each line:**

   | Reason in alert | Meaning | Action |
   |---|---|---|
   | `SCAN-ERROR (...)` | API fetch failed — rate limit or deleted repo. **Not malware by itself.** | Check repo exists; check later runs clean; if transient → comment + close |
   | `.vscode on remote - policy` | Any `.vscode/**` file on any branch (presence-based policy) | Verify, then purge (below) |
   | font/api.js/tasks/settings/rider/gitignore reasons | Campaign IOC — treat as real | Verify with scanner, then clean (below) |

4. **Verify before acting** — never trust the alert blindly, and never judge by file presence alone (content markers arbitrate, except the `.vscode` policy):
   ```bash
   printf 'athallarizky/<repo> <branch>\n' > /tmp/t.txt
   bash ~/development/personal/agent-playbooks/gh-incident-response/scripts/scan-ioc.sh /tmp/t.txt
   ```
   `ERR` lines mean *verdict withheld* (rate limit) — rerun later, never assume clean.

5. **Clean (confirmed findings):**
   - Campaign files → `scripts/clean-markers-local.sh` (local **signed** commits; rider configs get stripped in place, payloads deleted)
   - `.vscode` → `scripts/purge-vscode.sh`
   - Repos under the `malware-guard` ruleset: cleanup pushes are fast-forward + signed, so they pass. Any **ref surgery** (force-update / branch delete) is blocked — set `enforcement=disabled` on the repo's ruleset first (`PUT /repos/{repo}/rulesets/{id} -f enforcement=disabled`), operate, then reactivate.

6. **Re-verify:** scan → `0 BAD`; then confirm the next sweep is green (or force one: `gh workflow run guardian-sweep.yml -R athallarizky/guardian`)

7. **Close the issue** with a resolution comment: what each R-code resolved to, what was found, what was done, final verdict. The issue list is the incident log — keep it self-explanatory.

## Hard rules

- **Never open repo paths in an IDE, never run repo code** — the payload's entire design is auto-execution on open
- The sweep PAT is read-only by design — guardian can never modify the watched repos; cleanup always happens from the user's authenticated `gh` context
- Never print secrets, tokens, or the salt; never paste tokens into chats
- Never ask for or accept the GUARD_SALT value in conversation — it flows password-manager → salt file → script, never through an agent (see "Setup on a new machine")
- Cleanup commits must be signed (local git already signs) and fast-forward — no history rewrites unless the incident playbook calls for it
- If dispatches fail on the Worker (`npx wrangler tail` in `guardian-dispatcher/`), suspect this workflow was disabled or the repo tampered with — that is itself a security signal

## Quick reference

- Cleanup playbook: `~/development/personal/agent-playbooks/gh-incident-response/SKILL.md`
- Protection playbook (rulesets, guardian ops): `~/development/personal/agent-playbooks/guardian-protection/SKILL.md`
- R-code map: `~/.guardian-map.txt`
- Dispatcher: `~/development/personal/guardian-dispatcher/` (logs: `npx wrangler tail`)
- Repo scope watched: `user/repos` non-fork + `ORGS` env in the workflow (currently The-Aetheris only)

## Setup on a new machine

Two artifacts make triage work — only ONE of them travels:

- `~/.guardian-salt` — the real secret. Installed once **by the user, in their own terminal** (never by an agent, never pasted into any chat):
  ```bash
  printf '%s' "<salt from password manager>" > ~/.guardian-salt && chmod 600 ~/.guardian-salt
  ```
- `~/.guardian-map.txt` — derived, deterministic, **never synced** (a synced map goes stale as new repos appear). Regenerate whenever:
  ```bash
  bash ~/development/personal/agent-playbooks/guardian-protection/scripts/guardian-map.sh
  ```

**Agents never need the salt value.** You only need the file to exist. If `guardian-map.sh` reports the salt file missing, ask the user to install it from their password manager — do not accept the salt in conversation. The flow is password-manager → salt file → script; an agent is never a stop on that route.
