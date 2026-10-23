# Database Schema

DependShield uses PostgreSQL, configured and managed via Prisma ORM.

## ERD (Entity Relationship Diagram) Overview

The core domains modeled in the database are:
1. **User and Project Management** (`User`, `Project`, `Repository`)
2. **Scan Lifecycle and Results** (`Scan`, `Sbom`, `Dependency`)
3. **Vulnerability Intelligence** (`Vulnerability`, `VulnerableSoftware`, `SyncState`)
4. **Security Findings** (`ScanVulnerabilityMatch`)

---

## Core Models

### `User`
Stores authenticated users.
- `id` (UUID): Primary key.
- `email` (String): Unique email address.
- `passwordHash` (String): Bcrypt hashed password.
- **Relations**: Has many `Project`s.

### `Project`
A grouping mechanism for repositories and scans.
- `id` (UUID): Primary key.
- `userId` (UUID): Foreign key to the owner.
- `name`, `description` (String): Metadata.
- **Relations**: Belongs to one `User`. Has one `Repository`. Has many `Scan`s.

### `Repository`
Defines the source code location for a project.
- `id` (UUID): Primary key.
- `projectId` (UUID): Foreign key to the project.
- `type` (SourceType Enum): `GITHUB` or `ZIP`.
- `url` (String): The GitHub clone URL.
- **Relations**: Belongs to one `Project`.

### `Scan`
Represents a single execution of the security pipeline.
- `id` (UUID): Primary key.
- `projectId` (UUID): Foreign key to the project.
- `status` (ScanStatus Enum): The current pipeline phase (e.g. `QUEUED`, `EXTRACTING`, `COMPLETED`, `FAILED`).
- `errorMessage` (String): Populated if the scan fails.
- `riskScore` (Float): Overall risk index calculation.
- **Relations**: Belongs to one `Project`. Has one `Sbom`. Has many `Dependency` records.

### `Sbom`
Stores the generated CycloneDX Software Bill of Materials.
- `id` (UUID): Primary key.
- `scanId` (UUID): Foreign key to the scan.
- `cycloneDxContent` (JSON): The full CycloneDX 1.5 JSON payload.

### `Dependency`
A specific software package extracted during a scan.
- `id` (UUID): Primary key.
- `scanId` (UUID): Foreign key to the scan.
- `name` (String): Package name.
- `version` (String): Resolved package version.
- `purl` (String): Package URL (e.g., `pkg:npm/express@4.18.2`).
- `isDirect` (Boolean): Indicates whether it's a direct or transitive dependency.
- `ecosystem` (String): e.g., `npm`.
- **Relations**: Has many `ScanVulnerabilityMatch`es.

### `Vulnerability`
The local cache of National Vulnerability Database (NVD) CVE records.
- `id` (UUID): Primary key.
- `cveId` (String): Unique NVD CVE identifier (e.g., `CVE-2023-1234`).
- `description` (String): CVE details.
- `severity` (Severity Enum): Qualitative severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `cvssScore` (Decimal): Numerical CVSS score.
- `cvssVector`, `cvssVersion`: CVSS metadata.
- **Relations**: Has many `VulnerableSoftware` constraints.

### `VulnerableSoftware`
Specifies the affected software and vulnerable version ranges for a CVE.
- `vulnerabilityId` (UUID): Foreign key to the CVE.
- `vendor`, `product` (String): CPE vendor and product name.
- `versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding` (String): Semantic version bounds determining if a specific dependency version is vulnerable.

### `ScanVulnerabilityMatch`
The junction table linking a discovered `Dependency` to a known `Vulnerability`.
- `dependencyId` (UUID): Foreign key to the extracted dependency.
- `vulnerabilityId` (UUID): Foreign key to the CVE.
- `riskScore` (Float): The computed risk score for this specific finding based on severity and context weight.

### `SyncState`
Tracks the last successful synchronization with external vulnerability sources (NVD).
- `id` (String): E.g., `NVD`.
- `lastSyncDate` (DateTime): The timestamp of the last successful data fetch.

## Migrations

Prisma handles all schema changes. The migration history is stored in `backend/prisma/migrations`. 
**Note:** In production, migrations should strictly be applied using `npx prisma migrate deploy`. Local development instances that bypass migration history using `prisma db push` must be reset before running standard deployments.
