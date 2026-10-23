# DependShield

DependShield is a lightweight, self-hosted software supply chain security platform that analyzes Node.js repositories for vulnerable dependencies. 

## Problem

Modern software relies heavily on third-party dependencies, which often harbor vulnerabilities. Tracking these dependencies, mapping them to known vulnerabilities (like CVEs from the National Vulnerability Database), and calculating the overall security risk is a complex and tedious process. Organizations need an internal, secure, and reproducible way to monitor their application dependencies.

## Key Features

### Implemented
- **Automated Scanning**: Supports scanning GitHub repositories and ZIP archives.
- **Dependency Extraction**: Accurately extracts direct and transitive dependencies from `package.json` and `package-lock.json` (npm v1, v2, v3) without executing arbitrary code.
- **SBOM Generation**: Generates CycloneDX 1.5 JSON Software Bill of Materials.
- **Vulnerability Matching**: Matches identified dependencies against a local mirror of the National Vulnerability Database (NVD).
- **Risk Scoring**: Calculates an aggregate Risk Index based on vulnerability severity (CVSS scores) and context.
- **Dashboard & Visualization**: A modern React-based frontend providing a high-level summary of project security posture.
- **Security Reports**: Generates comprehensive security reports downloadable in JSON, HTML, and Markdown.
- **Authentication**: JWT-based authentication using HttpOnly cookies with a Bearer token fallback for API integration.
- **Docker Deployment**: Fully containerized environment for reproducible setup using Docker Compose.
- **Automated CI/CD**: GitHub Actions workflow for linting, testing, and verifying database migrations against a clean environment.

### Limitations
- **Ecosystem Support**: Currently limited to Node.js/npm.
- **Matching Accuracy**: Uses fuzzy product name matching against NVD; does not fully resolve all ecosystem nuances (CPE matching limitations).
- **Dependency Graph**: Dependencies are stored as a flat list. Deep parent-child relationship tracking is not supported in the UI yet.

### Future Scope
- Support for Python, Java, and Go ecosystems.
- Advanced CPE-based vulnerability matching.
- Real-time GitHub Webhook integration.
- Automated PR generation for vulnerable dependencies.

## Architecture Overview

DependShield is structured as a client-server web application:
- **Frontend**: A Single Page Application (SPA) built with React and Vite.
- **Backend**: A RESTful API built with Node.js, Express, and Prisma ORM.
- **Database**: PostgreSQL 15 for persisting projects, dependencies, SBOMs, and vulnerability definitions.
- **Nginx**: Serves the frontend assets and acts as a reverse proxy in production.

For detailed architecture diagrams and service responsibilities, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Technology Stack

- **Frontend**: React 18, Vite, Tailwind CSS, Lucide React (Icons), Recharts
- **Backend**: Node.js 20, Express.js, Prisma ORM, Jest (Testing), Winston (Logging)
- **Database**: PostgreSQL 15
- **Infrastructure**: Docker, Docker Compose, GitHub Actions

## Setup & Deployment

### Quick Start (Docker Deployment — Recommended)
Ensure **Docker Desktop is running**, then:
1. Copy `.env.docker.example` to `.env`:
   - macOS / Linux / Git Bash: `cp .env.docker.example .env`
   - Windows PowerShell: `Copy-Item .env.docker.example .env`
2. Build and launch services:
   ```bash
   docker compose up -d --build
   ```
3. Apply database migrations:
   ```bash
   docker compose exec backend npx prisma migrate deploy
   ```
4. Access the application in your browser at **[http://localhost](http://localhost)** (Frontend SPA).
   - API Health check: `http://localhost/api/v1/health` or `http://localhost:3000/api/v1/health`

### Local Development Setup (without Docker)
1. Ensure a local PostgreSQL 15 instance is running.
2. Copy `backend/.env.example` to `backend/.env` and update `DATABASE_URL`.
3. Install dependencies:
   ```bash
   npm install --prefix backend && npm install --prefix frontend
   ```
4. In `backend/`, apply migrations: `npx prisma migrate deploy`.
5. Start backend: `npm start --prefix backend` (port `3000`).
6. Start frontend: `npm run dev --prefix frontend` (port `5173`).
7. Open **http://localhost:5173** in your browser.

For complete environment variable references, architecture details, and troubleshooting, see [SETUP.md](SETUP.md).
If you are cloning this project onto a new PC, follow the step-by-step instructions in [CLONE_AND_SETUP.md](CLONE_AND_SETUP.md).

## Project Status

1. **Phase 1-19: MVP Implementation** — Completed
2. **Phase 20: Documentation** — Current
3. **Phase 21: Final Integration / Release** — Remaining

## Testing & CI/CD

- **Testing**: Backend features a robust test suite using Jest. Run `npm test -- --runInBand` from the `backend/` directory.
- **CI/CD**: The repository includes a GitHub Actions workflow (`.github/workflows/ci.yml`) that provisions an isolated PostgreSQL database, deploys Prisma migrations, runs backend tests, and verifies the frontend build. 

## References and Licensing

DependShield draws architectural inspiration from [OWASP Dependency-Track](https://github.com/DependencyTrack/dependency-track), adopting concepts like SBOM ingestion and portfolio-level risk analysis. DependShield is an independent project and is not an official Dependency-Track product. Where applicable, software components and concepts reflect Apache-2.0 licensing principles. See [docs/REFERENCE_DECISIONS.md](docs/REFERENCE_DECISIONS.md) for more details.
