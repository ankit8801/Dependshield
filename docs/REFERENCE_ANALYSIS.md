# Dependency-Track Reference Analysis

## 1. Architecture Overview
Dependency-Track is a mature, enterprise-grade Software Bill of Materials (SBOM) and vulnerability analysis platform. It operates on an API-first architecture, separating the backend (Java/Jakarta EE) from the frontend (Vue.js). The architecture has evolved, particularly in v5 (Hyades), towards greater decoupling of services (e.g., separating vulnerability data ingestion, vulnerability analysis, and the core API server).

## 2. Backend Architecture
The backend is a multi-module Java application:
- **Core Technologies**: Java 21+, JAX-RS (Jersey), OpenAPI, JDBI/JDO (DataNucleus transitioning to JDBI), PostgreSQL, embedded Jetty.
- **Modules**: Includes `apiserver`, `vuln-analysis`, `vuln-data-source`, `package-metadata`, `notification`, etc.
- **Design Philosophy**: Throughput over latency, strong consistency by default, and interruptible long-running tasks.

## 3. Frontend Architecture
The frontend is a Single Page Application (SPA):
- **Core Technologies**: Vue 2.7, CoreUI, Bootstrap-Vue, Chart.js.
- **Build System**: Vue CLI / Webpack.
- **Features**: Dashboards, component and vulnerability details, policy management, and reporting.

## 4. Important Modules
- `apiserver`: The core REST API and persistence layer.
- `vuln-data-source`: Responsible for syncing vulnerability intelligence from external sources (NVD, OSV, GitHub Advisories).
- `vuln-analysis`: The engine that matches components to known vulnerabilities using internal databases or external scanner integrations (Trivy, Snyk, OSS Index).

## 5. Relevant Data Models
- **Project**: Represents a software project/application being analyzed.
- **Component**: A specific dependency or library with attributes like PURL (Package URL), CPE (Common Platform Enumeration), version, and group.
- **Vulnerability**: A known security flaw (e.g., CVE-XXXX-XXXX) containing descriptions, CVSS scores, and severities.
- **VulnerableSoftware**: Represents the affected versions/ranges of a component.
- **Finding/Analysis**: The linkage between a component and a vulnerability, along with audit/triage states.

## 6. Relevant APIs
The API is completely RESTful.
- Authentication endpoints (Login, tokens).
- Project management (CRUD for projects).
- BOM upload (ingesting CycloneDX XML/JSON).
- Vulnerability and finding retrieval.
- Metrics and dashboard endpoints.

## 7. SBOM Processing Approach
Dependency-Track heavily relies on the **CycloneDX** standard. The system ingests CycloneDX SBOMs, parses the components, and merges or updates the project's dependency graph in the database, retaining metadata like PURLs and CPEs.

## 8. Dependency/Component Analysis Approach
Components are identified primarily using **Package URL (PURL)** and **CPE**. PURL provides a reliable, ecosystem-aware identifier (e.g., `pkg:npm/lodash@4.17.20`). The system normalizes incoming components and compares them against known vulnerability datasets.

## 9. Vulnerability Analysis Approach
Analysis is decoupled. The system maintains an internal vulnerability database synced from upstream sources. When a project is analyzed, its components' PURLs/CPEs are matched against the vulnerable software ranges in the internal DB. It also supports delegating analysis to third-party services.

## 10. Vulnerability Intelligence Sources
- **NVD (National Vulnerability Database)**: The primary source for CVEs.
- **OSV (Open Source Vulnerability)**: Important for ecosystem-specific (e.g., npm, PyPI) advisories.
- **GitHub Advisory Database**.
- **JVN (Japan Vulnerability Notes)**.

## 11. Security/Risk Concepts
- **Severity**: Critical, High, Medium, Low, Unassigned.
- **CVSS v2/v3/v4**: Base, Temporal, and Environmental scores.
- **Risk Score**: Calculated based on the highest severity vulnerabilities and their impact on the project portfolio.

## 12. Dashboard Concepts
- High-level portfolio metrics (total projects, vulnerable projects).
- Vulnerability trends over time.
- Breakdown of vulnerabilities by severity.
- Risk metrics and policy violations.

## 13. Reporting Concepts
Generates actionable reports detailing project risks, affected components, audit states, and remediation guidance (e.g., safe versions to upgrade to).

## 14. Authentication/Security Concepts
- OIDC (OpenID Connect), LDAP, and local authentication (JWT).
- API Keys for CI/CD integrations and automated uploads.
- Fine-grained permission model (e.g., `BOM_UPLOAD`, `VULNERABILITY_ANALYSIS`).

## 15. Features Relevant to DependShield
- CycloneDX SBOM generation and ingestion.
- Component normalization and PURL usage.
- NVD integration for vulnerability data.
- CVSS scoring and severity mapping.
- Component-to-Vulnerability matching logic.
- Basic dashboard and reporting capabilities.

## 16. Features NOT Required by DependShield
- Enterprise SSO / LDAP.
- Policy engines and complex organizational workflows.
- VEX (Vulnerability Exploitability eXchange) and advanced audit trails.
- Kafka integration and highly distributed microservices (for the MVP).
- Third-party scanner integrations (Trivy, Checkmarx, Snyk).

## 17. Potentially Reusable Concepts
- Using PURL as the primary identifier for accurate matching.
- Decoupling vulnerability syncing from project scanning.
- ER diagram concepts (Projects -> Components -> Vulnerabilities).

## 18. Potentially Reusable Code
Because DependShield will be built using Node.js/React rather than Java/Vue, **no code will be directly reused**.

## 19. Code That Should NOT Be Reused
- All Java backend code.
- All Vue.js frontend code.
- Complex DataNucleus/JDO entity mapping logic.

## 20. Technical Lessons Learned
- Simple package name matching is insufficient; PURLs and ecosystem awareness are critical to avoid false positives.
- Vulnerability datasets (like NVD) are huge. Syncing and querying must be optimized.
- Separation of concerns: Manifest parsing, SBOM generation, and Vulnerability matching should be distinct pipeline steps.

## 21. Recommended DependShield Architecture
- **Frontend**: React, React Router, TailwindCSS/Bootstrap (Single Page Application).
- **Backend**: Node.js, Express.js (REST API).
- **Scanner**: Node.js worker/module for parsing `package.json`, extracting dependencies, and generating CycloneDX.
- **Database**: PostgreSQL with Prisma or Sequelize ORM.

## 22. Major Risks and Challenges
- **False Positives in Matching**: Accurately mapping npm packages to NVD CVEs.
- **NVD API Rate Limits**: Syncing NVD data efficiently without being blocked.
- **Archive Extraction Risks**: Securely unzipping user uploads without path traversal vulnerabilities (Zip Slip).
- **Transitive Dependencies**: Accurately building the dependency tree from `package-lock.json`.

## 23. Licensing/Reuse Considerations
Dependency-Track is licensed under the Apache License 2.0. While we will not copy code, we will adopt architectural concepts. We must ensure any libraries we use in our Node.js/React stack have permissive licenses (MIT, Apache 2.0).
