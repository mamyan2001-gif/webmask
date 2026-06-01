# Publishing to GitHub

Step-by-step guide to push WebMask to a new GitHub repository.

## Before you push

Confirm nothing sensitive will be committed:

```bash
cd webmask   # or your local folder name

# Should show no sites.json, reports, .tools, node_modules, or .env
git status

# After first commit, double-check tracked files:
git ls-files | grep -E 'sites\.json|reports/|\.tools|\.env|node_modules'
# (should return nothing)
```

**Never commit:**

- `server/data/sites.json` — your scan targets
- `reports/**` — scan results
- `server/data/scanner-settings.json` — may contain Slack webhooks
- `.env` / API keys
- `node_modules/`, `.tools/`, `client/dist/`

These are listed in `.gitignore`.

## 1. Initialize git (first time only)

```bash
cd webmask
git init
git branch -M main
```

## 2. Stage and commit

```bash
git add .
git status   # review the list carefully
git commit -m "$(cat <<'EOF'
Initial release of WebMask vulnerability scanner.

Includes React admin UI, Express API, 43+ scan modules, setup scripts,
and documentation for local installation.
EOF
)"
```

## 3. Create the GitHub repository

**Option A — GitHub website**

1. Go to [github.com/new](https://github.com/new).
2. Repository name: `webmask` (or your choice).
3. Description: *Website vulnerability scanner with React UI and 43+ security checks.*
4. Choose **Public** or **Private**.
5. Do **not** add README, .gitignore, or license (this repo already has them).
6. Click **Create repository**.

**Option B — GitHub CLI**

```bash
gh repo create webmask --public --source=. --remote=origin --push
```

Skip steps 4–5 below if you used `--push`.

## 4. Connect remote and push

Replace `YOUR_USERNAME` with your GitHub username:

```bash
git remote add origin https://github.com/YOUR_USERNAME/webmask.git
git push -u origin main
```

SSH remote:

```bash
git remote add origin git@github.com:YOUR_USERNAME/webmask.git
git push -u origin main
```

## 5. Verify on GitHub

- README renders with badges and quick-start instructions.
- **Actions** tab shows the CI workflow (install + client build).
- Clone URL works: `git clone https://github.com/mamyan2001-gif/webmask.git`

## Repository settings (recommended)

| Setting | Recommendation |
|---------|----------------|
| **About** | Add topics: `security`, `vulnerability-scanner`, `react`, `nodejs`, `owasp` |
| **Branch protection** | Require CI on `main` before merge |
| **Security** | Enable Dependabot alerts (Settings → Security) |

## Updating after changes

```bash
git add .
git commit -m "Describe your change"
git push
```

## CI

`.github/workflows/ci.yml` runs on every push and PR:

- `npm run install:all`
- `npm run build --prefix client`
- Syntax check on the server entry file

Fix any CI failures before merging to `main`.

## License

This project is [MIT licensed](../LICENSE). Keep the copyright line when forked.
