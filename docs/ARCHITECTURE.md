# DependShield Architecture

## System Components

DependShield is composed of a modular monolith architecture, with a clear separation between the frontend SPA, backend API, and background asynchronous processing routines.

### 1. Frontend (React SPA)
- **Framework**: React.js with Vite
- **Routing**: React Router
- **Styling**: Tailwind CSS
- **Communication**: REST API via Axios. The frontend uses a polling mechanism to retrieve the status of long-running scans.

### 2. Backend API (Node.js / Express)
- **Role**: Serves frontend requests, manages authentication, processes project CRUD operations, handles file uploads, and initiates background scanning tasks.
- **Authentication**: JWT-based authentication. Tokens are transported using `HttpOnly, SameSite=Lax` cookies for the web client (preventing direct XSS theft) with a fallback to `Authorization: Bearer` headers for external API clients.
- **Validation**: Strict input validation using Zod schemas (`validators/`).

### 3. Background Services (Node.js Asynchronous Execution)
- **Role**: Rather than separate OS processes, background tasks run asynchronously within the Node.js event loop, allowing the API to respond immediately while heavy tasks execute.
- **NVD Sync (`nvdService.js`)**: Downloads and parses JSON CVE data from the NVD API, extracting CVSS scores, vulnerable software version ranges, and populating the local PostgreSQL database.
- **Scan Pipeline (`scanService.js`)**: Executes the security scan lifecycle. 

### 4. Database (PostgreSQL & Prisma)
- **Role**: The single source of truth for users, projects, scan history, SBOMs, and the local NVD vulnerability cache.
- **ORM**: Prisma provides type-safe schema definitions and automated migrations.

---

## Scan Pipeline Workflow

1. **User Request**: The user submits a GitHub repository URL or uploads a ZIP file.
2. **API Layer**: `scanController.js` creates a Scan record in the DB with status `QUEUED` and immediately returns the Scan ID to the client.
3. **Background Execution**: `scanService.processScan()` is invoked without `await`, starting the pipeline:
   - **Ingestion**: `githubService.js` or `zipUtils.js` downloads/extracts the source code to a temporary directory. -> Status: `INGESTING`.
   - **Extraction**: `extractionService.js` parses `package.json` and `package-lock.json` to extract direct and transitive dependencies. -> Status: `EXTRACTING`.
   - **SBOM Generation**: `sbomService.js` translates the extracted dependencies into a CycloneDX 1.5 JSON SBOM and stores it. -> Status: `SBOM_GENERATING`.
   - **Vulnerability Matching**: `vulnerabilityService.js` maps dependencies (by package name/ecosystem) against the local NVD cache to find known CVEs. -> Status: `VULNERABILITY_ANALYSIS`.
   - **Risk Scoring**: `riskService.js` calculates a comprehensive risk index based on the matches. -> Status: `MATCHING`.
   - **Cleanup**: The temporary code is deleted. -> Status: `COMPLETED`.
   - *If any step throws an error, the scan safely catches it, deletes temp files, and updates the status to `FAILED` with the error message.*

---

## Source Tree Structure

```text
dependshield/
│
├── frontend/                 # React frontend application
│   ├── src/
│   │   ├── components/       # Reusable UI components
│   │   ├── context/          # React Context (Auth)
│   │   ├── pages/            # Page-level components
│   │   ├── services/         # API abstraction (axios config)
│   │   ├── styles/           # Tailwind and global CSS
│   │   └── utils/
│   └── package.json
│
├── backend/                  # Express API
│   ├── src/
│   │   ├── config/           # Database and logger configuration
│   │   ├── controllers/      # Route handlers
│   │   ├── middlewares/      # Auth, Error handling
│   │   ├── routes/           # Express route definitions
│   │   ├── services/         # Core business logic (Extraction, SBOM, NVD, Risk)
│   │   ├── utils/            # ZIP extraction, file system helpers
│   │   └── validators/       # Zod schemas for input validation
│   ├── tests/                # Jest integration test suites
│   ├── package.json
│   └── app.js                # Express app configuration
│
├── docs/                     # Project documentation
├── DEPENDSHIELD_MASTER_PLAN.md
├── docker-compose.yml        # Multi-container orchestration
└── README.md
```
