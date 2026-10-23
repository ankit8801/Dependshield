# Reference Decisions

## What We Learned from Dependency-Track
1. **Accurate Identification**: Identifying dependencies by package name alone leads to massive false positives. We must use Package URL (PURL) to distinguish between ecosystems (e.g., `pkg:npm/lodash` vs `pkg:pypi/lodash`).
2. **Decoupled Architecture & Asynchronous Syncing**: Vulnerability syncing must be decoupled from the actual scanning process. Dependency-Track uses an internal vulnerability database synced from upstream sources. Scans match against this local database rather than querying external APIs during a scan.
3. **Standardization**: CycloneDX is an excellent, standardized format for representing Software Bill of Materials (SBOM) and should be the central artifact passed between ingestion and analysis.

## What We Decided to Reimplement
- **Asynchronous Vulnerability Synchronization**: We will implement a background worker to sync NVD vulnerability intelligence into a local PostgreSQL cache. Our scan pipeline will exclusively query this local cache to ensure high performance and avoid NVD rate limits.
- **CycloneDX SBOM Representation**: We will generate and utilize CycloneDX internally as the standard format for representing project dependencies.
- **PURL Normalization**: We will implement logic to convert `package.json` dependencies into valid PURLs.
- **CVSS Risk Scoring Principles**: We will adopt the CVSS base score paradigm to classify severities (Critical, High, Medium, Low), but we will use our own transparent formula to aggregate a Project Risk Index (weighing direct vs. transitive dependencies).
- **Explicit Scan States**: Like Dependency-Track, we will track the state of analysis (`QUEUED`, `ANALYZING`, etc.) to provide real-time feedback to the user.

## What We Decided NOT to Implement
- **Enterprise Features**: LDAP/OIDC authentication, granular role-based access control (RBAC), and multi-tenancy.
- **Advanced Ecosystems**: We will strictly restrict the MVP to Node.js/npm environments only. Maven, Python, Go, etc., are excluded for now.
- **Policy Engine**: We will not implement custom compliance policies or VEX (Vulnerability Exploitability eXchange) workflows.
- **Complex Microservices Architecture**: Dependency-Track v5 uses a distributed architecture with Kafka. We will use a modular monolithic Node.js application (with a background worker for NVD syncing and scan processing) for simplicity and ease of deployment.
- **Third-Party Scanners**: We will not integrate with external analysis services like Snyk, Trivy, or OSS Index for the MVP.

## Reused Code
**None.** 
The reference project is written in Java and Vue 2. DependShield is being developed in Node.js and React. Therefore, no source code was or will be copied.

## License Information
Dependency-Track is distributed under the **Apache License 2.0**. Our conceptual reuse of their architecture falls well within acceptable use. Our own implementation will also utilize open-source friendly dependencies.

## Key Differences Between Dependency-Track and DependShield
| Feature | Dependency-Track | DependShield |
| :--- | :--- | :--- |
| **Tech Stack** | Java, JAX-RS, Vue.js | Node.js, Express, React |
| **Complexity** | Enterprise-grade, distributed | Student project, modular monolith + worker |
| **Ecosystems** | Dozens of ecosystems | Strictly Node.js (npm) MVP |
| **Vulnerability Sources** | NVD, OSV, GitHub, JVN, VulnDB | NVD Local Cache (Initial focus) |
| **Risk Model** | High watermark / Portfolio Metrics | Custom transparent formula (Base Score × Dependency Context Weight) |
| **Ingestion** | Accepts pre-built SBOMs | Parses source (`package.json`) & generates SBOM |
