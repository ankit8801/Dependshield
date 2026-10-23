# Threat Model and Security Profile

DependShield is a security product, making its own security posture critically important. This document outlines the threat model, protections implemented in the MVP, and residual risks.

## Implemented Protections

### 1. Authentication & Session Management
- **JWT (JSON Web Tokens)**: Used for stateless session management.
- **HttpOnly, SameSite=Strict Cookies**: By default, the web interface stores JWTs in a secure cookie that is inaccessible to client-side JavaScript. This protects the *stored* token from typical Cross-Site Scripting (XSS) theft. However, because the token is also returned in the JSON body during login/registration (to support API clients), an active XSS attack could still theoretically intercept the token at the time of login.
- **Bearer Token Fallback**: External clients can bypass cookies and supply tokens via the `Authorization: Bearer` header.
- **Password Security**: Passwords are mathematically hashed using `bcrypt` before storage.

### 2. Authorization (Data Ownership)
- **Tenant Isolation**: Projects, Repositories, Scans, and Reports are strictly bound to the `userId` of the creator.
- **Access Control**: Every data retrieval endpoint (e.g., fetching a dashboard or viewing a scan report) verifies that the authenticated user actually owns the parent project. Requests for unowned data return a sanitized `404 Not Found` rather than a `403 Forbidden` to prevent object enumeration.

### 3. Input Validation
- **Zod Schemas**: The backend utilizes Zod schemas to rigorously validate the shape, type, and bounds of incoming HTTP requests.
- **GitHub URL Constraints**: When adding a GitHub repository, the URL is verified via Regex to guarantee it matches a standard `https://github.com/owner/repo` pattern. This mitigates Server-Side Request Forgery (SSRF) against internal network resources.

### 4. Malicious File Processing
- **ZIP Upload Limits**: ZIP uploads are strictly limited via `multer` to 50 MB to prevent Denial of Service (DoS) via disk exhaustion.
- **Zip Slip Prevention**: The `zipUtils.js` extraction logic explicitly validates that all extracted file paths resolve safely *within* the intended target directory. Any path traversing out (e.g., `../../etc/passwd`) throws an error and halts extraction.
- **Extraction Limits**: A maximum file count limit (10,000 files) is enforced to prevent Zip Bomb attacks (e.g., a tiny ZIP containing millions of files).
- **Execution Prevention**: The backend *never* executes `npm install`, pre/post-install scripts, or `require()` on uploaded code. It purely parses JSON AST representations of dependency manifests.

### 5. Output Encoding (Report Generation)
- **HTML Escaping**: When exporting reports in HTML format, untrusted inputs (like package names and vulnerability descriptions) are safely escaped to prevent stored XSS attacks if a user opens the report in a browser.

## Limitations and Residual Risks

### Vulnerability Matching Accuracy
DependShield currently performs basic string matching against the NVD database (Package Name -> CPE Product). It does not deeply evaluate complex CPE matching constraints or ecosystem-specific aliasing. This leads to **false positives** (flagging safe packages) and **false negatives** (missing vulnerable packages).

### Outdated Vulnerability Data
The system relies on a periodic sync task to download CVEs from NVD. If the NVD API is unreachable or rate-limited, the local database will grow stale, missing newly disclosed Zero-Day vulnerabilities.

### Missing Dependency Edges
Transitive dependencies are extracted, but the parent-child node graph is not fully materialized. As a result, calculating precise exploitability reachability (e.g., determining which direct dependency pulled in the vulnerable transitive dependency) must be performed manually by inspecting `package-lock.json`.

### Single-Tenant Assumptions
The current implementation isolates data by `userId`, but lacks robust Organization or Role-Based Access Control (RBAC). It is designed as a single-user or small-team self-hosted solution. Deploying this multi-tenant in a public cloud environment without architectural changes is not recommended.
