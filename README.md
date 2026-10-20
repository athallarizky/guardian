<img width="1536" height="1024" alt="Wallpaper patung bersayap hitam-putih di tengah dengan latar hitam" src="https://github.com/user-attachments/assets/49af6273-56e5-43eb-922d-55cd8d61438a" />

# Guardian

Central watchdog: an hourly GitHub Actions sweep across **all** repos (personal + configured orgs) hunting for the malware campaign IOCs — from OUTSIDE those repos, so a stolen write-token on any victim repo cannot disable it.

## What it detects
Hidden `.vscode` auto-run tasks, weaponized settings, fake fonts (JS inside font files), obfuscated `api.js` droplets, `.env` files whose base64 values decode to dropper URLs, stage-2 `config.bat`, and the campaign `.gitignore` fingerprint. Same marker set as the `gh-incident-response` playbook.

## Alerting
Findings open an issue here (watch this repo for email notifications). The sweep PAT is **read-only** — the guardian can never modify your repos.

## Setup (one manual step)
1. Create a fine-grained PAT: **Contents: Read-only** + **Metadata: Read-only**, all repositories, short expiry.
2. Add it as a secret — run from your machine (do NOT paste tokens into chats):
   `gh secret set GUARD_PAT -R athallarizky/guardian`
3. Run manually once: Actions → guardian-sweep → Run workflow.
