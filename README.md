<img width="1536" height="1024" alt="guardian" src="https://github.com/user-attachments/assets/b0335014-07b9-40bc-899d-c72958b249f6" />

# Guardian

> Central watchdog that sweeps **every repo I own** (personal, non-fork + [The-Aetheris](https://github.com/The-Aetheris)) every hour for the malware campaign that hit this account — **from outside those repos**, so a stolen write-token on any victim repo cannot disable it.

## The problem

On 2026-10-19 an actor with stolen credentials rewrote histories across ~90 of my repos with **lookalike commits** (original messages/dates, different SHAs) injecting malware:

- `.vscode/tasks.json` — hidden task, `"runOn": "folderOpen"`, executing `node ./public/fonts/fa-brand-400.woff` — a fake font that is actually obfuscated JS (EtherHiding-style C2)
- Fake fonts (<10KB text files), `api.js` droplets, dropper `.env`, stage-2 `config.bat`, campaign `.gitignore` fingerprints, riders appended to build configs (postcss/tailwind/eslint)

Defense-in-depth against this class of attack has a structural problem: **anything stored inside a victim repo can be neutralized with the same stolen token that infected it**. Branch protection, workflows, even this repo's own workflow — all editable by whoever holds the credential. So the watcher must live *outside* the blast radius.

A second problem surfaced on 2026-10-20: **GitHub's Actions scheduler silently drops the hourly cron** (2 fires in ~36 h, 0 in the last 5 h, while `workflow_dispatch` works 100% — suspected account abuse-flag from the incident). A scheduled-only watchdog would be dead without anyone noticing.

## The design

```
┌─ Cloudflare Worker (guardian-dispatcher) — OUTSIDE GitHub, different auth domain
│    cron */20 min → is the last sweep stale (>45 min)? → workflow_dispatch
│
└─ GitHub Actions (this repo)
     guardian-sweep.yml — scans every branch of every watched repo with a
       read-only fine-grained PAT (GUARD_PAT): it can never modify my repos
     keepalive.yml — weekly commit so the schedule never hits the 60-day
       repo-inactivity auto-disable
```

- **Trigger redundancy:** if GitHub lifts the scheduler suppression, the native cron and the Worker coexist — the Worker's staleness gate makes them idempotent (no double sweeps).
- **Alert-only by design:** findings open an issue here (watch this repo for email notifications). The sweep PAT is read-only — the guardian itself can never be turned into a weapon.

## What it detects

Same layered marker set as the [`gh-incident-response`](https://github.com/athallarizky/agent-playbooks) playbook — size-aware and name-agnostic (payload names rotate):

- **Campaign IOCs** — fake fonts (any font <10KB, arbitrated by content), obfuscated `api.js`, `.vscode` auto-run tasks & weaponized settings, fonts-dir README camouflage, `.env` dropper URLs, `config.bat`, injected `.gitignore` lines, build-config riders, npm lifecycle droppers
- **Policy: no `.vscode` on remote** — presence-based, any file under any `.vscode/` directory on any branch is a finding (the campaign proved `.vscode` is the attack vector; legit files belong in local gitignore)
- **SCAN-ERROR** — a failed API fetch (rate limit, deleted repo) is reported as a finding, never silently skipped: a watchdog that skips what it cannot read is blind

Repo names in alerts are masked as `R-<hash>` (salted); resolve locally via `~/.guardian-map.txt`.

## Setup (one manual step each)

1. Fine-grained PAT — **Contents: Read-only + Metadata: Read-only**, all repositories → `gh secret set GUARD_PAT -R athallarizky/guardian` (never paste tokens into chats)
2. Any random salt → `gh secret set GUARD_SALT -R athallarizky/guardian`, and regenerate the local map with the same salt (`scripts/guardian-map.sh`)
3. Dispatcher Worker: see `guardian-dispatcher` (local) — `wrangler login`, PAT (Actions: Write, this repo only) as secret, `wrangler deploy`

## Self-protection

- **Ruleset `malware-guard`** (branch): block deletion + force-push. Deliberately **no required-signatures** — the keepalive commits via the Contents API, which is unsigned by design (REST commits get no GitHub signature); a signature rule would kill the keepalive and re-open the 60-day auto-disable.
- **The dispatcher is the real tamper alarm**: if someone disables this workflow or the repo, dispatches start failing on the Worker (`npx wrangler tail`) — visible outside GitHub, where the attacker's token has no reach.

## Limitations (known, accepted)

- **Forks are not swept** (by design — upstream mirror noise); verified manually after the incident
- **Only The-Aetheris org is watched** — other orgs were swept & cleaned 2026-10-20; add them to `ORGS` in the workflow if that ever changes
- **Detection, not prevention** — server-side path blocking (`file_path_restriction`) requires paid org push rules; the compensating control is response speed (≤ ~1 h)
