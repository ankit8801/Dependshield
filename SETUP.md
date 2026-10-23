# DependShield — Setup & Deployment Guide

> **Setting up on a new PC?** Check out the dedicated [CLONE_AND_SETUP.md](CLONE_AND_SETUP.md) for quick-start cloning instructions.

## Architecture

```
Browser → Nginx (port 80) → /api/* → Backend (port 3000) → PostgreSQL (port 5432)
                          → /      → Static SPA
```

| Service    | Technology            | Default Port |
|------------|-----------------------|--------------|
| `db`       | PostgreSQL 15 Alpine  | 5432         |
| `backend`  | Node.js 20 + Express  | 3000         |
| `frontend` | Nginx 1.27 + Vite SPA | 80           |

---

## Prerequisites

| Requirement         | Minimum Version | Notes |
|---------------------|-----------------|-------|
| Docker Desktop      | 4.x             | **Must be launched and running** prior to starting containers |
| Docker Compose v2   | 2.0 (bundled)   | Bundled with modern Docker Desktop (`docker compose`) |
| (Local dev) Node.js | 20.x            | Required only for running outside Docker |
| (Local dev) npm     | 10.x            | Required only for running outside Docker |

---

## Quick Start (Docker Compose)

### 1. Ensure Docker Desktop is running

Launch **Docker Desktop** from your operating system's applications menu and verify that the Docker engine status is active/green.

### 2. Open the project root directory

```bash
cd DependShield-Workspace/dependshield
```

### 3. Configure the environment

For local Docker testing, copy the pre-configured `.env.docker.example` template:

**macOS / Linux / Git Bash:**
```bash
cp .env.docker.example .env
```

**Windows PowerShell:**
```powershell
Copy-Item .env.docker.example .env
```

> **For Production:** Copy `backend/.env.example` to `.env` and configure strong random secrets for `POSTGRES_PASSWORD` and `JWT_SECRET`.
> Generate a secure 64-character JWT secret with:
> ```bash
> node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
> ```

### 4. Build and start all services

```bash
docker compose up -d --build
```

This builds and launches the three multi-container services:
1. `db`: PostgreSQL 15 database on port `5432`
2. `backend`: Node.js 20 Express API on port `3000`
3. `frontend`: Nginx 1.27 serving the compiled Vite React SPA on port `80`

### 5. Apply database migrations

**Always use `prisma migrate deploy` — never `db push`:**

```bash
docker compose exec backend npx prisma migrate deploy
```

> - **Initial Run:** Applies all Prisma migrations, creating the database schema, tables, indexes, and relations.
> - **Subsequent Runs:** Idempotently checks and applies any new pending migrations.

### 6. Verify container health & endpoints

Check running containers:
```bash
docker compose ps
```

Expected output:
```text
NAME                     STATUS              PORTS
dependshield-db-1        running (healthy)   0.0.0.0:5432->5432/tcp
dependshield-backend-1   running (healthy)   0.0.0.0:3000->3000/tcp
dependshield-frontend-1  running             0.0.0.0:80->80/tcp
```

Verify backend health:
```bash
# Direct backend check
curl http://localhost:3000/api/v1/health

# Via Nginx reverse-proxy
curl http://localhost/api/v1/health
```

Expected response:
```json
{"status":"ok","database":"connected","timestamp":"..."}
```

### 7. Access and use the application

Open your browser:
* **Web Application (Frontend UI):** [http://localhost](http://localhost) (or `http://localhost:80`)
* **API Endpoints:** `http://localhost/api/v1` (proxied by Nginx) or `http://localhost:3000/api/v1` (direct)

**Initial workflow:**
1. Navigate to [http://localhost/register](http://localhost/register) and create an account.
2. Log in at [http://localhost/login](http://localhost/login).
3. On the Dashboard, click **+ New Project** to create a project.
4. Link a GitHub repository or click **Upload ZIP** on the project page to run an automated dependency security scan.

---

## Common Commands

### Stop all containers

```bash
docker compose down
```

### Stop and remove volumes (WARNING: deletes database data)

```bash
docker compose down -v
```

### Restart a single service

```bash
docker compose restart backend
```

### View logs

```bash
# All services
docker compose logs -f

# Single service
docker compose logs -f backend
docker compose logs -f frontend
docker compose logs -f db
```

### Rebuild images after code changes

```bash
docker compose up -d --build
```

### Open a shell in the backend container

```bash
docker compose exec backend sh
```

---

## Database

### Run migrations (production)

```bash
docker compose exec backend npx prisma migrate deploy
```

### Check migration status

```bash
docker compose exec backend npx prisma migrate status
```

### Inspect the database

```bash
docker compose exec db psql -U dependshield -d dependshield_db
```

---

## Environment Variables Reference

All variables are configured in `.env` (in the project root for Docker, or `backend/.env` for local dev).

| Variable           | Required | Default           | Description                                      |
|--------------------|----------|-------------------|--------------------------------------------------|
| `NODE_ENV`         | Yes      | `production`      | Node environment. Use `production` in Docker.    |
| `POSTGRES_USER`    | Yes      | `dependshield`    | PostgreSQL username                              |
| `POSTGRES_PASSWORD`| **Yes**  | *(none)*          | PostgreSQL password. **Must be set.**            |
| `POSTGRES_DB`      | Yes      | `dependshield_db` | PostgreSQL database name                         |
| `DB_PORT`          | No       | `5432`            | Host port for the DB container                   |
| `BACKEND_PORT`     | No       | `3000`            | Host port for the backend API                    |
| `DATABASE_URL`     | Yes      | *(auto-built)*    | Full Prisma connection string                    |
| `JWT_SECRET`       | **Yes**  | *(none)*          | JWT signing secret. **Must be ≥ 32 chars.**      |
| `CORS_ORIGIN`      | Yes      | `http://localhost`| Allowed CORS origin (browser-facing URL)         |
| `FRONTEND_PORT`    | No       | `80`              | Host port for the Nginx frontend                 |
| `VITE_API_URL`     | No       | `http://localhost:3000/api/v1` | Backend API URL for the browser    |
| `GITHUB_TOKEN`     | No       | *(empty)*         | GitHub PAT for cloning private repos             |
| `NVD_API_KEY`      | No       | *(empty)*         | NVD API key for higher rate limits               |

---

## Development (without Docker)

### Backend

```bash
cd backend
cp .env.example .env
# Edit .env: set DATABASE_URL to your local PostgreSQL instance
npm install
npx prisma migrate deploy    # or: prisma migrate dev
node server.js               # or: npm start
```

### Frontend

```bash
cd frontend
npm install
npm run dev   # Vite dev server on http://localhost:5173
```

To create a production build manually:
```bash
npm run build
```

The Vite dev server uses `VITE_API_URL` from the environment or falls back to `http://localhost:3000/api/v1`.

### Running Tests

```bash
cd backend
# Requires a running PostgreSQL instance (see .env)
npm run test -- --runInBand
```

Tests run against the database configured in `backend/.env`. They clean up after themselves.

---

## Production Deployment Notes

### Secrets

- **Never commit** `.env`, `.env.production`, or any file with real credentials.
- Use a secrets manager or your CI/CD platform's secret injection.
- Rotate `JWT_SECRET` if it is ever exposed — all sessions will be invalidated.

### CORS

- Set `CORS_ORIGIN` to the exact URL your users access the frontend on.
- E.g. `CORS_ORIGIN=https://dependshield.yourdomain.com`

### HTTPS

- The provided Docker setup is HTTP-only.
- For production HTTPS, add an nginx reverse proxy or load balancer (e.g., Traefik, Caddy, AWS ALB) in front of the frontend container.

### Database Migrations

- **Never** use `prisma db push` in production — it bypasses migration history.
- Always run `npx prisma migrate deploy` after deploying a new backend version.

### Container Security

- Backend runs as the built-in `node` user (uid 1000) — not root.
- Frontend runs as the built-in `nginx` user — not root.
- Images use Alpine Linux to minimize attack surface.
- No development tooling (nodemon, jest, etc.) is installed in production images.

---

## Troubleshooting

### Backend cannot connect to the database

```bash
docker compose logs db
docker compose exec backend npx prisma migrate status
```

Check that `POSTGRES_PASSWORD` in `.env` matches `POSTGRES_PASSWORD` used by the `db` service.

### "Cannot connect to the Docker daemon" error on compose up

Ensure that **Docker Desktop** is running on your machine. On Windows or macOS, Docker commands will fail if the desktop application has not finished starting.

### "POSTGRES_PASSWORD is required" error on compose up

You must provide `POSTGRES_PASSWORD` in `.env`. For local testing, copy `.env.docker.example`:
```bash
# macOS / Linux / Git Bash:
cp .env.docker.example .env

# Windows PowerShell:
Copy-Item .env.docker.example .env
```

### CORS policy blocked error in browser console

If you see an error indicating that `Access-Control-Allow-Origin` does not match `http://localhost`:
* Ensure `CORS_ORIGIN` in `.env` includes `http://localhost:80,http://localhost`.
* Rebuild and restart the backend container: `docker compose up -d --build backend`.

### Frontend shows blank page or outdated bundle

1. Perform a hard browser reload to bypass local cache:
   * **Windows / Linux:** `Ctrl + Shift + R` or `Ctrl + F5`
   * **macOS:** `Cmd + Shift + R`
2. Check that the frontend build completed: `docker compose logs frontend`
3. Verify Nginx is serving assets: `curl http://localhost`
4. Inspect browser DevTools console (F12) for JavaScript runtime errors.

### Health endpoint returns `database: disconnected`

The backend cannot reach PostgreSQL. Check:
```bash
docker compose ps db              # should be "healthy"
docker compose logs backend       # look for connection errors
```

### Old data after a rebuild

Docker volumes persist data across `docker compose down` (without `-v`). To reset:
```bash
docker compose down -v   # removes pgdata volume — ALL DATA DELETED
docker compose up -d --build
docker compose exec backend npx prisma migrate deploy
```

### Port already in use

Change the host port in `.env`:
```env
BACKEND_PORT=3001
FRONTEND_PORT=8080
DB_PORT=5433
```
Then restart: `docker compose up -d`
