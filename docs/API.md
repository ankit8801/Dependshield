# API Specification

All routes are prefixed with `/api/v1`. Authentication primarily uses an `HttpOnly` cookie (`ds_token`) for the web client. As a fallback for external API clients, a Bearer token in the `Authorization` header is also supported for protected routes.

## Authentication

### `POST /api/v1/auth/register`
- **Body**: `{ "email": "user@example.com", "password": "SecurePassword1" }`
- **Response (201)**: `{ "message": "Registration successful", "data": { "user": { "id": "...", "email": "..." }, "token": "jwt_string" } }`
- **Side Effect**: Sets `ds_token` as HttpOnly cookie.

### `POST /api/v1/auth/login`
- **Body**: `{ "email": "user@example.com", "password": "SecurePassword1" }`
- **Response (200)**: `{ "message": "Login successful", "data": { "user": { "id": "...", "email": "..." }, "token": "jwt_string" } }`
- **Side Effect**: Sets `ds_token` as HttpOnly cookie.

### `POST /api/v1/auth/logout`
- **Response (200)**: `{ "message": "Logged out successfully" }`
- **Side Effect**: Clears `ds_token` cookie.

### `GET /api/v1/auth/me`
- **Headers**: (Requires HttpOnly cookie `ds_token` or `Authorization: Bearer <token>`)
- **Response (200)**: `{ "data": { "user": { "id": "...", "email": "..." } } }`

---

## Projects

### `GET /api/v1/projects`
- **Response (200)**: `{ "data": [ { "id": "...", "name": "...", "description": "...", "createdAt": "...", "repository": { ... } } ] }`

### `POST /api/v1/projects`
- **Body**: `{ "name": "My Node App", "description": "Backend API" }`
- **Response (201)**: `{ "data": { "id": "...", "name": "..." } }`

### `GET /api/v1/projects/:id`
- **Response (200)**: `{ "data": { "id": "...", "name": "...", "repository": { ... } } }`

### `PATCH /api/v1/projects/:id`
- **Body**: `{ "name": "Updated Name" }`
- **Response (200)**: `{ "data": { "id": "...", "name": "..." } }`

### `DELETE /api/v1/projects/:id`
- **Response (200)**: `{ "message": "Project deleted successfully" }`

---

## Repositories (Sources)

### `POST /api/v1/projects/:id/repository`
- **Body**: `{ "url": "https://github.com/owner/repo" }`
- **Response (200)**: `{ "data": { "id": "...", "type": "GITHUB", "url": "..." } }`

### `DELETE /api/v1/projects/:id/repository`
- **Response (200)**: `{ "message": "Repository deleted successfully" }`

---

## Scans, Extraction & SBOM (Phases 5–7)

All scan routes require authentication (cookie or Bearer token).

### `POST /api/v1/projects/:projectId/scans`
- **Description**: Triggers a GitHub repository scan using the project's linked repository.
- **Response (201)**: `{ "data": { "id": "...", "status": "QUEUED", "projectId": "..." } }`
- **Behavior**: Asynchronously clones/downloads the repository from the project's linked GitHub URL, then runs dependency extraction.

### `POST /api/v1/projects/:projectId/scans/upload`
- **Description**: Accepts a ZIP archive upload and starts a scan.
- **Body**: `multipart/form-data` with field `file` (.zip, max 50 MB).
- **Response (201)**: `{ "data": { "id": "...", "status": "QUEUED", "projectId": "..." } }`
- **Behavior**: Extracts the ZIP securely (Zip Slip / Zip Bomb protected), then runs dependency extraction.

### `GET /api/v1/projects/:projectId/scans`
- **Description**: Returns the list of historical scans for a project, sorted by newest first (`createdAt: 'desc'`), including aggregated metrics.
- **Response (200)**:
  ```json
  {
    "data": [
      {
        "id": "uuid",
        "projectId": "uuid",
        "status": "COMPLETED",
        "errorMessage": null,
        "riskScore": 15.0,
        "totalRiskIndex": 15.0,
        "createdAt": "2026-09-30T12:00:00.000Z",
        "completedAt": "2026-09-30T12:00:08.000Z",
        "source": "GITHUB",
        "dependencyCount": 24,
        "vulnerabilityCount": 3,
        "sbomComponentCount": 24
      }
    ]
  }
  ```
- **Authorization**: User must own the project. Returns 404 for other users' projects.

### `GET /api/v1/projects/:projectId/scans/:scanId`
- **Description**: Returns detailed lifecycle and summary metrics for an individual scan.
- **Response (200)**: `{ "data": { "id": "...", "status": "...", "source": "...", "dependencyCount": 24, "vulnerabilityCount": 3, "totalRiskIndex": 15.0, "sbomComponentCount": 24, ... } }`
- **Authorization**: User must own the project. Returns 404 for other users' scans.

### `GET /api/v1/projects/:projectId/scans/:scanId/dependencies`
- **Description**: Returns the extracted dependency list for a completed scan.
- **Response (200)**: `{ "data": [ { "id": "...", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2", "isDirect": true, "ecosystem": "npm" }, ... ] }`
- **Authorization**: User must own the project. Returns 404 for other users' scans.

### `GET /api/v1/projects/:projectId/scans/:scanId/sbom`
- **Description**: Returns the generated CycloneDX 1.5 JSON SBOM for a scan.
- **Query Params**: `?download=true` triggers a file download attachment instead of inline JSON.
- **Response (200)**: CycloneDX JSON object.
- **Authorization**: User must own the project. Returns 404 if SBOM is not yet generated.

### `GET /api/v1/projects/:projectId/scans/:scanId/vulnerabilities`
- **Description**: Returns all vulnerability matches found for the scan.
- **Response (200)**: `{ "data": [ { "id": "...", "dependency": { ... }, "vulnerability": { ... } } ] }`
- **Authorization**: User must own the project. Returns 404 for other users' scans.

### `GET /api/v1/projects/:projectId/scans/:scanId/risk`
- **Description**: Returns risk summary and severity counts.
- **Response (200)**: `{ "data": { "totalRiskScore": 15.0, "counts": { "CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNASSIGNED": 0 } } }`
- **Authorization**: User must own the project.

### `GET /api/v1/projects/:projectId/scans/:scanId/dashboard`
- **Description**: Aggregated payload for the scan security dashboard (scan status, dependencies, SBOM components, vulnerability breakdown, risk scores, findings).
- **Response (200)**: `{ "data": { "scan": { ... }, "summary": { ... }, "findings": [ ... ] } }`
- **Authorization**: User must own the project.

### `GET /api/v1/projects/:projectId/scans/:scanId/report`
- **Description**: Generates a consolidated security report for a scan, with project info, dependencies, SBOM metadata, vulnerability counts, transparent risk scores, and detailed findings.
- **Query Params**:
  - `format`: `json` (default), `html`, or `markdown` (or `md`).
  - `download`: `true` sets `Content-Disposition: attachment` to trigger a file download.
- **Response**:
  - `json`: `{ "data": { "reportMetadata": { ... }, "project": { ... }, "scan": { ... }, "dependencySummary": { ... }, "vulnerabilitySummary": { ... }, "riskSummary": { ... }, "sbom": { ... }, "findings": [ ... ] } }`
  - `html`: Standalone HTML security report with executive summary, tables, and styling (`Content-Type: text/html; charset=utf-8`).
  - `markdown`: Clean GitHub-flavored Markdown formatted report (`Content-Type: text/markdown; charset=utf-8`).
- **Authorization**: User must own the project. Returns 404 for unauthorized access.

### `GET /api/v1/projects/:projectId/scans/:scanId/report/export`
- **Description**: Direct export download alias for the report. Equivalent to calling `/report?download=true`.
- **Query Params**: `format` (`json`, `html`, `markdown`).

---

## Scan Pipeline States

| Status                   | Description                                          |
|--------------------------|------------------------------------------------------|
| `QUEUED`                 | Scan created, waiting to start                      |
| `INGESTING`              | Downloading/extracting repository                   |
| `EXTRACTING`             | Parsing manifests and extracting dependencies       |
| `SBOM_GENERATING`        | Generating CycloneDX 1.5 SBOM                       |
| `VULNERABILITY_ANALYSIS` | Matching dependencies against local NVD cache       |
| `COMPLETED`              | All stages (including Phase 9 Risk) finished        |
| `FAILED`                 | An error occurred; see `errorMessage`               |
| `CANCELLED`              | Scan was cancelled                                  |

---

## Dependency Extraction (Phase 6 — Node.js/npm MVP)

- Supports `package.json` and `package-lock.json` (lockfileVersion 1, 2, and 3).
- Direct dependencies: packages listed in `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies` of `package.json`.
- Transitive dependencies: all additional packages resolved in `package-lock.json` that are not in the above sections.
- Repository code is **never executed** — no `npm install`, no script execution, no `require()`.
- Malformed JSON causes controlled scan failure (status `FAILED`) rather than a server crash.
- Scoped packages (e.g. `@types/node`) are fully supported and correctly encoded in PURLs.

---

## Dependency & SBOM Visualization (Phase 13)

No new backend API endpoints were introduced in Phase 13. The visualization layer is served entirely by the existing endpoints listed above.

### Endpoints consumed by the visualization

| Endpoint | Provides |
|---|---|
| `GET /projects/:id/scans/:sid/dependencies` | Full package list with `isDirect`, `name`, `version`, `purl`, `ecosystem` |
| `GET /projects/:id/scans/:sid/sbom` | CycloneDX 1.5 JSON with `metadata.timestamp`, `specVersion`, `components`, `properties` |
| `GET /projects/:id/scans/:sid/dashboard` | Per-finding data including `packageName` to compute vulnerability counts per package |

### Dependency Graph Limitation

Phase 6 stores a **flat dependency list**. Parent-child edges between transitive packages (e.g., `A → B → C`) are determined by npm's resolver at install time but are **not persisted** to the database as individual edges.

Consequently:
- A true node-edge dependency graph **cannot** be rendered without re-parsing the lockfile.
- Re-parsing the lockfile in the browser is outside the current scope.
- The UI renders a **component-oriented visualization** (filterable table + stats bar) that accurately reflects all resolved packages from the database.
- If edge-level relationships are required in future phases, the extraction service would need to persist `parentId` references during Phase 6 ingestion.

### SBOM Data Accuracy

- `specVersion` is read from the stored SBOM's `cycloneDxContent.specVersion` — it always reflects the actual generated version (`1.5`).
- `metadata.timestamp` reflects the actual time the SBOM was generated during the scan pipeline.
- Each SBOM component includes `dependshield:isDirect` and `dependshield:ecosystem` as CycloneDX properties.

### Authorization

All visualization endpoints use the same ownership-based authorization as all other scan endpoints:
- Unauthenticated → **401**
- Another user's project → **404**

---

## API Validation (Phase 17)

### UUID Parameter Validation

All route parameters that accept UUIDs (`:id`, `:projectId`, `:scanId`) are validated before the request reaches the controller or database. Malformed values return a structured `400` immediately:

```json
{
  "error": {
    "message": "Validation Error",
    "details": [{ "code": "invalid_string", "message": "Invalid ID format", "path": ["params", "id"] }]
  }
}
```

This prevents Prisma from receiving malformed input and avoids accidental `500` responses for invalid IDs.

### Report Format Query Validation

`GET /api/v1/projects/:projectId/scans/:scanId/report`

| Query param | Allowed values | Default |
|-------------|---------------|---------|
| `format` | `json`, `html`, `markdown`, `md` | `json` |
| `download` | `true`, `false` | (absent) |

An unknown `format` value returns `400 Validation Error` before the controller is invoked.

### Controller / Service Separation (Phase 17)

- **`getScanDashboardData`** was moved from an inline controller implementation to `scanService.js`. The controller delegates entirely to the service.
- **`getScanVulnerabilities`** was similarly moved to `scanService.js`. Both `getScanVulnerabilities` and `getScanRiskSummary` controllers now share a single service call.
- **`scanController.js`** no longer instantiates `PrismaClient` directly — all database access goes through service functions.

### Dashboard 404 Handling

The `GET .../dashboard` endpoint now returns `404` (not `500`) when the scanId does not belong to the requested project. Previously the service threw an error with `err.status = 404` which was not caught in the controller's error handler.

---

## Vulnerabilities

### `GET /api/v1/vulnerabilities/:id`
- **Description**: Fetch CVE details and vulnerable software ranges.
- **Response (200)**: `{ "data": { "id": "...", "cveId": "...", "description": "..." } }`

### `POST /api/v1/vulnerabilities/sync`
- **Description**: Manually trigger an NVD sync in the background. Note: this endpoint does not enforce RBAC in the MVP, but does require standard authentication.
- **Response (202)**: `{ "message": "NVD sync started in background" }`

### `GET /api/v1/vulnerabilities/sync/status`
- **Description**: Get the last sync timestamp.
- **Response (200)**: `{ "data": { "id": "NVD", "lastSyncDate": "2026-10-06T12:00:00Z" } }`
