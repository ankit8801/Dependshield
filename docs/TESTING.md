# Testing Strategy

This document outlines the testing strategy for DependShield. 
Tests are primarily written using **Jest** and **Supertest** for integration tests, allowing API tests against a live PostgreSQL database.

## Running Tests

Ensure your test environment is running correctly:

1. **Start the Database**: The backend tests require the PostgreSQL container to be running.
   ```bash
   docker compose up db -d
   ```
2. **Apply Migrations** (if needed):
   ```bash
   npm run db:push
   ```
3. **Run the Test Suite**:
   ```bash
   npm test
   ```

## Test Suites

### Authentication (`backend/tests/auth.test.js`)
- Validates the `/api/v1/auth/register` route, ensuring duplicate emails are rejected and password hashing is utilized.
- Tests validation requirements enforced by Zod.
- Tests the `/api/v1/auth/login` route, including correct and incorrect credentials to ensure no username enumeration.
- Validates `HttpOnly` cookie generation.
- Tests the protected `/api/v1/auth/me` endpoint with missing, invalid, and expired tokens.
- Tests the `/api/v1/auth/logout` endpoint.

### Application Integrity (`backend/tests/app.test.js`)
- Tests global 404 handler.
- Asserts that middleware like CORS and Helmet are active.

### Health Check (`backend/tests/health.test.js`)
- Verifies that the `/api/v1/health` endpoint correctly connects to PostgreSQL.

### Database Connection (`backend/tests/db.test.js`)
- Direct integration tests for the Prisma client connecting to PostgreSQL.

### Vulnerability Intelligence (`backend/tests/vulnerabilities.test.js`)
- Tests NVD sync mechanism, local cache storage, and CPE version range matching.

### Risk Scoring (`backend/tests/risk.test.js`)
- Validates transparent deterministic risk scoring formula: Severity Weight × Dependency Context Weight (Direct: 1.5, Transitive: 1.0).

### Security Reports and Export (`backend/tests/report.test.js`)
- Validates comprehensive security report generation across JSON, HTML, and Markdown formats.
- Asserts metadata correctness: project details, scan status, dependency totals, vulnerability breakdown, risk formula, and actual CycloneDX 1.5 SBOM metadata.
- Validates edge states: zero findings, incomplete scan status, failed scan error messages, and project ownership access control.
- Tests report download endpoint (`Content-Disposition` attachments) and data consistency with the security dashboard.

### Scan History and Tracking (`backend/tests/history.test.js`)
- Validates project scan history listing with accurate aggregated metrics (dependencies, vulnerabilities, Total Risk Index, SBOM component count, source).
- Verifies reverse chronological ordering (newest first).
- Validates lifecycle states (`COMPLETED`, `FAILED`, `INGESTING`/in-progress) and prevents presentation of failed scans as successful.
- Tests strict project ownership and cross-project scan isolation.
- Asserts seamless navigation from historical scans to security dashboards, reports, dependency lists, and SBOMs.

### Dependency & SBOM Visualization (`backend/tests/visualization.test.js`)
- Validates that existing `/dependencies` and `/sbom` endpoints supply all data required for Phase 13 visualization — no new backend routes were added.
- Tests empty dependency list for a scan with no extracted packages.
- Verifies all required visualization fields are present: `id`, `name`, `version`, `purl`, `isDirect`, `ecosystem`.
- Confirms that direct vs transitive counts are derivable from the `isDirect` field (2 direct / 3 transitive in a 5-package fixture).
- Validates deterministic alphabetical ordering of the dependency list.
- Tests SBOM metadata accuracy: `bomFormat`, `specVersion: 1.5`, `metadata.timestamp`, tool attribution, and `dependshield:isDirect` property on components.
- Verifies 404 is returned when SBOM has not yet been generated for a scan.
- Confirms correct `Content-Disposition: attachment` header for SBOM download mode.
- Tests unauthenticated requests to `/dependencies` and `/sbom` return **401**.
- Tests cross-user authorization: user2 cannot access user1's dependencies or SBOM (returns **404**).
- Verifies historical completed scans remain accessible for visualization (older timestamps preserved).
- Confirms that per-package vulnerability counts can be derived from the dashboard endpoint's findings array.
