# WebMask — Setup Guide

Complete instructions to install and run WebMask locally.

## Requirements

| Requirement | Version |
|-------------|---------|
| Node.js | 18 or newer |
| npm | 9+ (bundled with Node) |
| OS | macOS, Linux, or Windows |

Optional: [Playwright Chromium](https://playwright.dev/) (installed automatically by setup scripts) for login-flow scans.

## Quick start

### macOS (recommended)

1. Clone the repository and open the folder in Finder.
2. Double-click **`Install WebMask.command`** — installs server, client, and Playwright.
3. Double-click **`Start WebMask.command`** — starts the app and opens **http://localhost:5173** in your browser.
4. Press **Ctrl+C** in the Start window when you are done.

If macOS blocks the scripts: right-click → **Open** → confirm.

### Windows

1. Clone the repository.
2. Double-click **`Install WebMask.bat`**.
3. Double-click **`Start WebMask.bat`**.

### Terminal

```bash
git clone https://github.com/mamyan2001-gif/webmask.git
cd webmask

npm run setup       # first time only
npm run start:app   # start API + UI, open browser
```

## Manual development mode

Use two terminals if you prefer separate logs:

```bash
npm run install:all

# Terminal 1 — API on http://localhost:4000
npm run dev:server

# Terminal 2 — UI on http://localhost:5173
npm run dev:client
```

Open **http://localhost:5173**. The Vite dev server proxies `/api` to port 4000.

## Production build

```bash
npm run install:all
npm run build          # builds client to client/dist/
npm start              # serves UI + API from port 4000
```

Then open **http://localhost:4000**.

## First launch

1. The app checks that dependencies are installed (first-run screen).
2. Click **New target** on the dashboard.
3. Enter a URL you are **authorized to scan**.
4. Choose a scan profile (**Quick**, **Standard**, or **Deep**) and run a scan.
5. Review findings on the **Findings** tab.

## Scan profiles

| Profile | Use case |
|---------|----------|
| **Quick** | Fast passive checks on the homepage (~30s) |
| **Standard** | Balanced spider + active probes |
| **Deep** | Maximum coverage — spider, templates, injection probes, subdomains |

Advanced options (hidden for Quick): auth headers, login flow (Playwright), seed URLs, scope rules, multi-role scans, OAST callbacks, OpenAPI fuzzing.

## Data & privacy

All data stays on your machine:

| Path | Contents |
|------|----------|
| `server/data/sites.json` | Targets and scan metadata (created on first use) |
| `server/data/scanner-settings.json` | Webhook URL, OAST settings |
| `server/data/schedules.json` | Scheduled scan jobs |
| `server/data/triage.json` | Finding triage state |
| `reports/{targetId}/{scanId}/` | Full scan reports (JSON) |

These paths are **gitignored** — they are never pushed to GitHub.

## Troubleshooting

### “Could not load dashboard — is the API running on port 4000?”

Start the API: `npm run dev:server` or use `Start WebMask.command`.

### Port already in use

Stop other processes on ports **4000** and **5173**, or close a previous WebMask window.

```bash
# macOS
lsof -i :4000
lsof -i :5173
```

### Playwright / login flow fails

Re-run setup or install Chromium manually:

```bash
cd server && npx playwright install chromium
```

### Scan blocked (SSRF safety)

WebMask refuses to scan localhost, private IPs, and `.local` hosts. This is intentional.

## Legal

**Only scan websites you own or have explicit written permission to test.** Unauthorized scanning may be illegal in your jurisdiction.

See also [README](../README.md) and [Development](DEV.md).
