# DependShield Master Plan

## 1. Project Overview
DependShield is a web-based software dependency and security analysis platform designed to help developers identify vulnerabilities in their open-source dependencies. By providing a GitHub repository URL or a ZIP archive, developers can quickly generate a Software Bill of Materials (SBOM) and receive a comprehensive security report.

## 2. Problem Statement
Modern software applications heavily rely on open-source dependencies. Tracking these dependencies and ensuring they are free of known vulnerabilities (CVEs) is a complex, time-consuming task. Developers lack a simple, unified tool to ingest a repository, map dependencies, and instantly highlight security risks with remediation advice.

## 3. Objectives
- Automatically ingest and parse project manifests (e.g., `package.json`).
- Generate a standardized CycloneDX SBOM.
- Cross-reference components against a local cache of vulnerability databases (NVD).
- Provide a clear, actionable dashboard with risk scores and remediation steps.

## 4. Scope
The platform will handle authentication, project management, repository ingestion, dependency parsing, SBOM generation, vulnerability matching, and reporting.

## 5. Users
- **Developers / Software Engineers**: Checking their projects for vulnerable libraries.
- **Security Analysts / Auditors**: Reviewing project security postures and tracking historical scan results.

## 6. Functional Requirements
- Secure user registration and login.
- Project creation and management.
- Source ingestion via ZIP upload and public GitHub URL.
- Parsing of Node.js (`package.json`, `package-lock.json`) dependencies.
- CycloneDX SBOM generation.
- Background synchronization of NVD vulnerabilities to a local cache.
- Vulnerability scanning against the local NVD database.
- Dashboard visualization of risk, severity, and scan history.
- Real-time scan progress/status tracking.
- Downloadable security reports.

## 7. Non-functional Requirements
- **Security**: Mitigate path traversal on ZIP uploads, protect credentials (JWT).
- **Maintainability**: Modular backend and frontend structure.
- **Performance**: Asynchronous/efficient parsing, background NVD syncing, and scanning against local DB.
- **Usability**: Clean, responsive, intuitive UI.

## 8. Main Features
- Project Dashboard
- Dependency Extraction & Normalization (PURL)
- Asynchronous Vulnerability Intelligence Syncing (NVD to PostgreSQL)
- Component-to-Vulnerability Matching (using local DB)
- Actionable Remediation Guidance

## 9. MVP Scope
- **Ecosystem**: Node.js / npm ONLY. (No Python, Maven, Go, Rust, etc., until Node.js pipeline works perfectly).
- **Authentication**: JWT-based email/password.
- **Ingestion**: ZIP upload and public GitHub URLs.
- **SBOM**: CycloneDX JSON generation.
- **Vulnerability Data**: NVD CVE matching from a local PostgreSQL cache.
- **Output**: Web dashboard and downloadable report.

## 10. Future Enhancements
- Support for Python, Java (Maven/Gradle), Go, and Rust.
- GitHub webhooks for automated PR scanning.
- Integration with OSV and GitHub Advisory databases.
- Dependency graph visualization.

## 11. System Architecture
- **Frontend**: React SPA communicating via REST API.
- **Backend**: Node.js / Express API serving frontend requests and orchestrating scans.
- **Background Worker**: Handles NVD synchronization to PostgreSQL and async scan processing.
- **Database**: PostgreSQL storing users, projects, dependencies, vulnerabilities, and SBOMs.

## 12. Component Architecture
- **Frontend**: `react-router`, `axios`, component library (Tailwind/Bootstrap), Recharts for graphs.
- **Backend**: `express` routing, `multer` (file upload), `jsonwebtoken`, ORM (e.g. Prisma/Sequelize), Scanner Engine.

## 13. Data Flow
`User -> Frontend -> API -> Creates Scan Record -> Background Scanner -> Ingest -> Parse -> SBOM -> Match vs Local DB -> Updates Scan Record -> Frontend Polls/WebSockets for Status`

## 14. Scan Pipeline & States
The scan pipeline has explicit states to track progress. The API and Frontend will expose and consume these states:
1. `QUEUED`: Scan is submitted and waiting for a worker.
2. `INGESTING`: Downloading ZIP or cloning GitHub repository.
3. `ANALYZING`: Detecting project types and manifests.
4. `EXTRACTING`: Parsing `package.json` and `package-lock.json`.
5. `SBOM_GENERATING`: Formatting dependencies into CycloneDX SBOM.
6. `VULNERABILITY_ANALYSIS`: Querying local vulnerability cache for dependencies.
7. `MATCHING`: Confirming CVE matches based on version ranges and ecosystem.
8. `COMPLETED`: Scan finished successfully, results ready.
9. `FAILED`: Scan failed due to error.
10. `CANCELLED`: Scan was cancelled by user or system.

## 15. SBOM Pipeline
Takes the normalized list of dependencies (with PURLs), metadata about the project, formats them into a valid CycloneDX v1.4+ JSON document, and stores it in the database.

## 16. Vulnerability Pipeline
An asynchronous background worker regularly pulls the latest CVE data from the NVD API, parses CVSS scores, vulnerable CPE configurations, descriptions, and updates the local PostgreSQL vulnerability cache. Scans ONLY query this local cache, never the NVD API directly.

## 17. Risk Scoring Strategy
The risk scoring model is designed to be transparent, explainable, and reflective of actual impact:
**Formula**: `Total Risk Index = Σ (Base_Severity_Weight * Dependency_Context_Weight)`

**Base Severity Weight**:
- Critical (CVSS 9.0 - 10.0): 10 points
- High (CVSS 7.0 - 8.9): 5 points
- Medium (CVSS 4.0 - 6.9): 3 points
- Low (CVSS 0.1 - 3.9): 1 point

**Dependency Context Weight**:
- Direct Dependency: Multiplier of 1.5
- Transitive Dependency: Multiplier of 1.0
- Known Exploit Available (Future enhancement if data available): Multiplier of 2.0

*Example: A High severity vulnerability (5 pts) in a direct dependency (1.5) contributes 7.5 to the Risk Index.*

## 18. Database Architecture
Relational database (PostgreSQL) optimized for querying dependencies and vulnerabilities efficiently. Shared responsibility among all team members.

## 19. Database Schema (Proposed)
- See `docs/DATABASE.md` for complete schema design.

## 20. API Architecture
RESTful API with `/api/v1/...` namespace. Secured with Bearer tokens (JWT). Includes endpoints for polling scan progress.
- See `docs/API.md` for complete API design.

## 21. API Endpoint Specification (Example)
- `GET /api/v1/scans/:id/status` (Poll for QUEUED, INGESTING, MATCHING, COMPLETED states)

## 22. Frontend Architecture
- `/src/pages`: Login, Dashboard, Project details, Scan results.
- `/src/components`: Tables, charts, navigation, progress bars for scan status.
- `/src/services`: API abstraction layer.

## 23. Backend Architecture
- `/src/routes`: Express endpoints.
- `/src/controllers`: Request/Response handling.
- `/src/services`: Business logic.
- `/src/workers`: NVD synchronization and background scanning engine.

## 24. Scanner Architecture
- `ingestion`: Handles ZIP extraction safely and GitHub API/git clone.
- `manifest-detector`: Finds package files.
- `dependency-parser`: Extracts packages.
- `sbom`: Formats to CycloneDX.
- `matcher`: Queries local DB for CVEs matching the PURL/CPE.

## 25. External Services
- NVD API (National Vulnerability Database) - accessed only by background sync worker.
- GitHub API (for fetching public repositories).

## 26. Security Architecture
- Passwords hashed with bcrypt.
- JWT for session management.
- Parameterized queries to prevent SQL Injection.
- ZIP uploads processed in isolated temp directories with size and path validation.

## 27. Threat Model Overview
- **Path Traversal (Zip Slip)**: Mitigated by validating extracted file paths.
- **Denial of Service (Zip Bomb)**: Mitigated by max file size and extraction limits.
- **SSRF**: Mitigated by strictly validating and restricting accepted GitHub URLs.

## 28. Error Handling
Global error middleware in Express. User-friendly error messages on the frontend. Failed scans marked explicitly with `FAILED` state and failure reason in the database.

## 29. Logging
Winston/Morgan for backend API logs. Structured logging for the scanner pipeline and NVD sync worker.

## 30. Testing Strategy
- **Unit Tests**: Parsers, normalization, CVSS calculation, Risk score logic.
- **Integration Tests**: API endpoints, DB queries.
- **Security Tests**: Malicious ZIP uploads.

## 31. Deployment Architecture
- **Frontend**: Static hosting (e.g., Vercel, Netlify).
- **Backend / Workers**: Node environment (e.g., Render, Railway).
- **Database**: Managed PostgreSQL.

## 32. Docker Architecture
- `Dockerfile` for Backend (API + Workers).
- `Dockerfile` for Frontend (Nginx).
- `docker-compose.yml` for local development (Postgres + Backend + Frontend).

## 33. CI/CD Possibilities
GitHub Actions to run linting, unit tests, and build Docker images on push to main.

## 34. Team Division
- **Member 1 (Dependency Scanner + SBOM)**: Repository/ZIP ingestion, manifest detection, dependency extraction, normalization, and CycloneDX generation.
- **Member 2 (Vulnerability + Risk Engine)**: NVD API background integration, local vulnerability database cache, CVE matching, CVSS parsing, severity, and risk scoring.
- **Member 3 (Frontend + Platform)**: React UI, Auth, Dashboard, API routes, scan state integration, and deployment.
- **Shared**: Database architecture, Git workflow, Testing, Documentation.

## 35. Development Phases
- **Phase 0**: Reference analysis (Completed).
- **Phase 1**: Architecture + project scaffolding (Completed).
- **Phase 2**: PostgreSQL schema + backend foundation ✅ **LIVE VERIFIED** (2026-09-27).
  - Container `postgres:15-alpine` started via `docker compose up db -d`.
  - Schema applied via `npx prisma db push` — synced in 179ms (Prisma 5.22.0).
  - **8 tables**: `users`, `projects`, `scans`, `sboms`, `dependencies`, `vulnerabilities`, `vulnerable_software`, `scan_vulnerability_matches`.
  - **2 enums**: `ScanStatus` (10 states), `Severity` (5 levels).
  - **Tests**: 3/3 suites, 8/8 tests PASS (`app.test.js`, `health.test.js`, `db.test.js`).
  - **Health endpoint**: `GET /api/v1/health` → `HTTP 200 {"status":"ok","database":"connected"}`.
- **Phase 3**: Authentication ✅ **VERIFIED** (2026-09-27).
  - Implemented bcrypt hashing and JWT token generation.
  - Used HttpOnly cookies as the primary token transport for XSS mitigation (alongside SameSite protections).
  - Created `register`, `login`, `logout`, and `me` endpoints with Zod validation.
  - Implemented React frontend auth flow (Login, Register, Dashboard, ProtectedRoute).
  - **Tests**: 13/13 Auth scenarios PASS (live DB integration).
- **Phase 4**: Project creation ✅ **VERIFIED** (2026-09-27).
  - Extracted `Repository` into a separate model.
  - Implemented secure project CRUD and Repository management endpoints.
  - Added Zod validations (limiting to GitHub URLs).
  - Added frontend React views: Dashboard (List + Create), Project Details (Edit Repo, Delete).
  - Enforced ownership authorization on all operations.
- **Phase 5**: ZIP/GitHub ingestion.
- **Phase 6**: Node.js dependency extraction (MVP restriction).
- **Phase 7**: Dependency normalization.
- **Phase 8**: CycloneDX SBOM generation.
- **Phase 9**: NVD background synchronization to local cache.
- **Phase 10**: Vulnerability matching (local cache only).
- **Phase 11**: Severity/CVSS handling.
- **Phase 12**: Risk engine & metrics.
- **Phase 13**: Scan persistence/history & Pipeline State tracking.
- **Phase 14**: Dashboard & Scan Progress UI.
- **Phase 15**: Dependency/vulnerability details.
- **Phase 16**: Security reports.
- **Phase 17**: Security hardening.
- **Phase 18**: Testing.
- **Phase 19**: Dockerization.
- **Phase 20**: Deployment preparation.
- **Phase 21**: Optional additional ecosystems/features (Do not start until Node.js MVP is complete).

## 36. Milestones
- **M1**: Working Platform (Auth, Projects, UI scaffolding, Schema).
- **M2**: Functional Scanner (ZIP to CycloneDX SBOM).
- **M3**: Vulnerability Engine (NVD Cache Sync & DB Match).
- **M4**: Integration & Reporting (Full Pipeline with status tracking).

## 37. Definition of Done for every phase
- Code implemented and reviewed.
- Unit/Integration tests pass.
- Edge cases handled.
- Documentation updated.
- Successfully verified via manual checkpoint testing.

## 38. Risks
- Initial syncing of the NVD database may take a long time; requires robust retry and backoff mechanisms.
- False positives in matching generic package names to CVEs.

## 39. Limitations
- MVP restricted to Node.js/npm.
- Requires reliable internet access for vulnerability syncing to the background worker.

## 40. License Considerations
DependShield will be open-source or academic-licensed. It uses concepts from Apache 2.0 licensed Dependency-Track, requiring proper attribution if applicable.

## 41. Documentation Requirements
Maintain current architecture, database schemas, and API definitions in the `/docs` folder. Update SETUP.md with local run instructions.
