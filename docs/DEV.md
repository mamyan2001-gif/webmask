# Development

See [SETUP.md](SETUP.md) for installation. This guide covers extending the scanner.

## Running locally

```bash
npm run setup       # first time
npm run start:app   # one command + browser

# or two terminals:
npm run dev:server  # port 4000
npm run dev:client  # port 5173, proxies /api
```

## Adding a scan check

1. Create `scanner/checks/mycheck.js` exporting an async function that returns an array of findings
2. Register it in `scanner/run.js` inside the scan orchestrator
3. Add the module to `CHECK_MODULES` in `scanner/run.js`

Each finding should include:

```js
{
  id: "unique-id",
  severity: "critical" | "high" | "medium" | "low" | "info",
  category: "ssl",
  title: "Short title",
  description: "What was found",
  evidence: "Raw evidence string",
  remediation: "How to fix",
}
```

## Data files

| File | Purpose |
|------|---------|
| `server/data/sites.json` | Targets and scan metadata (gitignored; copy from `sites.example.json`) |
| `server/data/scanner-settings.json` | Webhooks, OAST URL (gitignored) |
| `server/data/schedules.json` | Cron jobs (gitignored) |
| `server/data/triage.json` | Finding triage (gitignored) |
| `reports/{targetId}/{scanId}/report.json` | Full findings (gitignored) |

## SSRF safety

`scanner/utils/url.js` blocks localhost, private IPs, and `.local` hosts before any outbound request.

## CI

GitHub Actions runs `npm run install:all`, builds the client, and syntax-checks the server on push/PR. See `.github/workflows/ci.yml`.

## Publishing

See [GITHUB.md](GITHUB.md) for push checklist and repository setup.
