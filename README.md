# WebMask

![Node](https://img.shields.io/badge/Node-18+-339933)
![React](https://img.shields.io/badge/React-19-61DAFB)
![License](https://img.shields.io/badge/License-MIT-green)

**Website vulnerability scanner** — 43+ check modules, multi-page spidering, Nuclei-style templates, OpenAPI fuzzing, and active injection probes from a React admin panel.

> **Legal:** Only scan websites you own or have explicit written permission to test.

## Features

- **43+ security checks** — TLS, headers, CORS, cookies, paths, Nikto-class wordlists, API/GraphQL, DNS, XSS reflection, WebDAV, CRLF, recon, CVE hints, and more
- **Scan profiles** — Quick (passive), Standard, and Deep (spider + active probes)
- **Live scan logs** — streaming NDJSON progress with per-module timing
- **Finding triage** — mark findings open, confirmed, false positive, or accepted risk
- **Scan compare** — diff two scans to spot regressions
- **Authenticated scanning** — cookies, Bearer/API keys, Playwright login flows, multi-role comparison
- **OpenAPI import** — fuzz REST endpoints from a spec
- **OAST callbacks** — blind SSRF / out-of-band detection via callback URL
- **Export** — HTML and CSV report downloads
- **SSRF protection** — blocks private/internal targets before any outbound request
- **No database** — JSON files + scan reports on disk

## Quick start

| Platform | Steps |
|----------|--------|
| **macOS** | Double-click `Install WebMask.command`, then `Start WebMask.command` |
| **Windows** | Double-click `Install WebMask.bat`, then `Start WebMask.bat` |
| **Terminal** | `npm run setup` then `npm run start:app` |

Browser opens at **http://localhost:5173**.

Full instructions: **[docs/SETUP.md](docs/SETUP.md)**

```bash
git clone https://github.com/YOUR_USERNAME/webmask.git
cd webmask
npm run setup
npm run start:app
```

## Usage

1. **Dashboard** — create a target, view stats and recent activity
2. **Scan** — enter URL, pick a profile, optionally configure auth / scope / OpenAPI, run scan
3. **Findings** — review severities, evidence, remediation, triage state, and export

## Documentation

| Doc | Description |
|-----|-------------|
| [docs/SETUP.md](docs/SETUP.md) | Installation, profiles, troubleshooting |
| [docs/DEV.md](docs/DEV.md) | Development and adding scan checks |
| [docs/GITHUB.md](docs/GITHUB.md) | Push to GitHub, CI, repo checklist |

## API (selected)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/dashboard` | Stats and onboarding |
| GET | `/api/checks` | List scan modules |
| GET | `/api/profiles` | Scan profile definitions |
| GET/POST | `/api/sites` | List / create targets |
| POST | `/api/sites/:id/scan` | Run scan (NDJSON stream with `stream: true`) |
| GET | `/api/sites/:id/scans/:scanId` | Full report |
| GET | `/api/sites/:id/scans/diff` | Compare two scans |
| GET/PATCH | `/api/sites/:id/scans/:scanId/triage` | Finding triage |
| POST | `/api/sites/:id/auth/test` | Test Playwright login profile |
| POST | `/api/sites/:id/openapi` | Save OpenAPI spec |
| GET/PATCH | `/api/settings` | Webhooks, OAST URL |
| GET/POST/DELETE | `/api/schedules` | Scheduled scans |

## Project layout

```
webmask/
├── client/              React admin UI (Vite)
├── server/              Express API + job runner
├── scanner/             Scan engine
│   ├── checks/          Security check modules
│   ├── crawler/         BFS spider + Playwright spider
│   ├── engine/          Template runner
│   ├── nuclei/          Bundled YAML templates
│   ├── openapi/         OpenAPI import + fuzzer
│   └── wordlists/       Path databases
├── scripts/             install.sh, start.sh
├── docs/                Setup, dev, GitHub guides
├── reports/             Scan output (gitignored)
├── Install WebMask.*    One-click installers
└── Start WebMask.*      One-click launchers
```

## Development

```bash
npm run install:all
npm run dev:server   # :4000
npm run dev:client   # :5173
```

## Production

```bash
npm run build
npm start            # serves built UI + API on :4000
```

## License

[MIT](LICENSE)
