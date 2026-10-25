<img width="1536" height="1024" alt="guardian" src="https://github.com/user-attachments/assets/b0315014-07b9-40bc-899d-c72958b249f6" />

# Guardian

> A central, read-only IOC sweep that scans **every repository** (personal + orgs, every branch) on a 30-minute cadence — **from outside those repos**, so no write-token on any victim repo can disable it. Findings raise an issue here and a Telegram alert with real repo names.

## The threat class

Guardian detects a supply-chain campaign that plants **dormant execution hooks and disguised payloads** via git history rewrites (lookalike commits — original messages/dates/authors, different trees). The artifact set:

| Artifact | Role |
|---|---|
| `.vscode/tasks.json` (`"runOn": "folderOpen"`) | Execution vector — fires the moment the folder opens in an IDE |
| `.vscode/settings.json` (`task.allowAutomaticTasks: true`) | Kills the confirmation prompt |
| Fake fonts in `public/fonts/` (`fa-*.orc/.woff/.woff2`, 4–30KB text) | Obfuscated JS disguised as assets; stage-2 fetched from C2 (EtherHiding-style) |
| `public/fonts/README.md` ("Blockchain Explorer") | Camouflage for the planted dir |
| `api.js` | XOR-hex decoder droplet |
| `.env` with base64 value that decodes to a URL | Stage-2 C2 config |
| Riders appended to `*.config.*` / `*.conf.*` / rc-files | Executes on dev/build |
| `atob(process.env.AUTH_API_KEY)` IIFE in any source file | Fetch-C2-then-eval loader |
| `config.bat` / `temp_*_push.bat` | Self-propagation helpers |
| `.gitignore` line `config.bat` / `*.bat` | Campaign fingerprint |
| `package.json` `postinstall: curl … \| sh` | npm lifecycle dropper |

Two properties make this class hard for naive scanners:
1. **Camouflage is content-benign** — the planted FontAwesome family is *real font binaries*; the `.vscode` trio (`extensions/launch/spellright`) is inert JSON. Content arbitration alone lets them pass. Hence the strict *presence* policies below.
2. **Containers rotate** — the payload moved `.woff` → `.woff2` → `.orc` (29KB, over naive size gates) → next whatever. Detection must be name-agnostic and extension-agnostic where possible.

## Architecture

```
guardian-sweep.yml (this repo, public = free Actions minutes)
  • cron ×4/hour (:02 :17 :32 :47 — redundant slots; GitHub drops scheduled
    runs under load) + workflow_dispatch
  • lists repos via fine-grained read-only PAT, scans every branch
  • findings → GitHub issue (repo names masked as R-<8hex> = sha256(name+salt))
              → Telegram (private group, real repo names)
  • issue dedup: comments on an open IOC issue <90 min old instead of spamming

malware-guard.yml (per-repo, private repos where rulesets are unavailable)
  • on push: scans tree; verdict != clean → force-reverts the branch to the
    pre-push SHA using the ephemeral GITHUB_TOKEN (nothing stealable)
  • AUTO-REVERT GOTCHA: the scan step exits 1 on detection; the revert step's
    `if:` MUST include always() or GitHub skips it when the scan goes red

rulesets (public repos): required_signatures + non_fast_forward + deletion
cloudflare worker (dispatcher): external heartbeat — if no sweep ran for
  40 min, dispatch one manually (scheduler silence is real)
```

The structural reason this repo must exist at all: **anything stored inside a victim repo can be neutralized by the same credential that infected it.** Branch protection, workflows, revert scripts — all editable in-repo. The watcher lives outside the blast radius, and its PAT is read-only.

## Detection logic reference

Two stages. Stage 1 decides *which files deserve a content fetch* (the tree API returns path+size for free — one call per branch). Stage 2 arbitrates content. **Every fetch failure is a SCAN-ERROR, never a "clean" verdict** (a throttled run once reported 134 infected refs as clean by failing silently).

### Stage 1 — candidate selection

| Rule | Catches | Rationale |
|---|---|---|
| any `.vscode/*` → **immediate finding** | IDE hooks + benign-looking trio | Presence policy — content-benign camouflage survives arbitration |
| any `public/fonts/*` → **immediate finding** | planted font dirs | Presence policy — the campaign always lands there (root or nested, e.g. `archive/public/fonts`) |
| executable surfaces: `api.js`, `.env`, `config.bat`, `.gitignore`, `*.config.*`, rc-files, `package.json`, `scripts/*`, entry-points `(index\|main\|app\|server\|cli).{ts,js,mjs}` | riders, droppers, loaders | If a path can't execute, its content can't hurt you — don't fetch it |
| name `fa-(brand\|brands\|solid\|regular)-N.*` — **any size** | payload fonts | a 29KB `.orc` sailed over a 10KB size gate once; size is not trusted |
| inside `fonts/`: non-font extension → candidate at any size; font extension → only <10KB | container rotation | attacker swaps extensions; legit font formats (`woff2 ttf otf eot svg ttc`) above 10KB are real binaries (`.ttc` = macOS collections, easily 77MB) |
| fonts outside `fonts/` → only <10KB | stray payloads | tiny standalone fonts are almost never legitimate |

### Stage 2 — content markers (checked in order)

**Whole-tree first, before any path logic:**

```
atob(process.env.AUTH_API_KEY)     → okshanaby loader (fetch-C2-then-eval)
```

This string cannot legitimately appear in any file at any path — zero false
positives, so it bypasses path filtering entirely.

**Per-class markers — deliberately two-condition (single conditions false-positive):**

| Marker | Logic | Why tight |
|---|---|---|
| api.js droplet | `/.{1,2}/g` **AND** `TextDecoder` | XOR-hex decoder signature; plain `require(` is legitimate CommonJS |
| .env dropper | a quoted base64 value that **decodes to `http(s)://`** | JWTs and passwords are also base64 — only a decoded URL is C2 config |
| config.bat / temp_*_push.bat | filename alone | never legitimate |
| .gitignore fingerprint | bare `config.bat` / `*.bat` line | campaign marker; normal projects don't ignore .bat |
| config rider (classic) | `function (spin\|peel\|splitLane)(` **AND** (`(global, require)` OR `var z =`) | obfuscator's function names + its CJS shim |
| config rider (ESM) | `createRequire(import.meta.url)` **AND** `var module = { exports: {} }` | how an ESM rider emulates CommonJS |
| config rider (Nx/OmniStealer) | `global['_V'\|'_H'\|'_R'\|'e'] = …` | corporate-stealer marker set |
| config rider (obfuscator vars) | `function sfL(` / `_$af<hex4+>` / `fromCharCode(127)` | generator artifacts, incl. the DEL character |
| config rider (padding) | `' {40,}var '` | payloads are always appended after giant whitespace runs — a structural tell |
| npm lifecycle | `postinstall` containing `curl\|wget … \| sh` / `node -e` / `eval(` | download-and-execute on install |
| camouflage README | `fonts/README.md` containing `Blockchain Explorer` | fixed campaign text |
| fake font | font file content matching `\(function` / `Function(` / `require(` / `eval(` / `child_process` | real fonts are binaries; JS inside an asset is a payload |

### The three-tier principle

1. **Presence policies** for what can never be legitimate (`.vscode` on remote, `public/fonts` dirs) — no arbitration, no bypass.
2. **Two-condition markers** for what resembles legitimate content (configs, `.env`, fonts) — both conditions must match.
3. **Whole-tree strings** for what is impossible in any legitimate file (`AUTH_API_KEY`) — scan everywhere, path-blind.

## Hardening notes (learned the hard way)

- **A scan step that exits 1 on detection skips later steps** unless they carry `if: always()` — the auto-revert silently never ran until this was fixed.
- **gh prints API error bodies to STDOUT** — an "empty output" check lets 403/404 JSON pass as data. Test exit codes, and validate SHAs (40-char hex) before using them.
- **Rate-limited ≠ clean.** Withhold the verdict on any failed fetch; re-run later.
- **The defense system's own credentials are attack surface.** During remediation, rotate the watchers' tokens too — a Contents:Write token held by defense tooling is a push-capable master key if leaked. Give them short expiry and minimal scope; prefer ephemeral tokens (`GITHUB_TOKEN`) for revert actions.
- **Paths can contain spaces** (`"TP Mod 3/…"`, macOS `file.js 09-21-22-090.js` duplicates) — percent-encode for the contents API and parse tree listings positionally (size = last field), not by naive word-splitting.
- **A drift-restoring re-push daemon is cheap to run** (identical cached SHAs, constant <150s latency) and cheap to kill — revoke credentials one at a time and measure; the round that stops the behavior names the vector.

## Setup

Secrets (Settings → Secrets → Actions):

```
GUARD_PAT      fine-grained PAT, Contents:Read-only, all repositories
GUARD_SALT     random hex — enables R-code masking (resolve locally with
               guardian-map.sh, same salt)
TG_BOT_TOKEN / TG_CHAT_ID / TG_THREAD_ID   Telegram alerts (optional)
```

`workflow_dispatch` with `test_notify: true` sends a channel test.
The `ORGS` env var in the workflow lists orgs to include beyond personal repos.

Companion tooling (scan/clean/purge scripts, per-repo guard workflow,
ruleset automation): [`agent-playbooks/guardian-protection`](https://github.com/athallarizky/agent-playbooks/tree/main/guardian-protection).
