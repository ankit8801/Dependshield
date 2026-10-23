You are the lead software architect, senior full-stack engineer, and cybersecurity engineer for my final-year Computer Science Engineering major project.

============================================================
PROJECT INFORMATION
============================================================

Project Name:
DependShield

Project Title:
DependShield: Software Dependency and Security Analysis Platform

Team Size:
3 members

Project Domain:
Cyber Security

Primary Objective:
Develop a web-based software dependency and security analysis platform that allows developers to submit a software project through a GitHub repository URL or ZIP upload, identify its dependencies, generate an SBOM, detect known vulnerabilities, classify their severity, prioritize risks, monitor scan history, and generate security reports.

The project must be a real, working application.

Do not create fake CVE data, fake scan results, fake dependency counts, or hard-coded security results.

============================================================
REFERENCE REPOSITORIES
============================================================

The workspace contains TWO official Dependency-Track repositories.

REFERENCE REPOSITORY 1 — BACKEND / API:

Path:
reference/dependency-track/

Official GitHub:
https://github.com/DependencyTrack/dependency-track

REFERENCE REPOSITORY 2 — FRONTEND:

Path:
reference/frontend/

Official GitHub:
https://github.com/DependencyTrack/frontend

Both repositories are OPEN-SOURCE reference implementations.

They exist in this workspace ONLY for:

- architecture study
- implementation research
- understanding design decisions
- understanding SBOM processing
- understanding vulnerability analysis
- understanding database models
- understanding REST APIs
- understanding frontend architecture
- identifying useful concepts
- identifying potentially reusable code

============================================================
CRITICAL REFERENCE REPOSITORY RULE
============================================================

Treat BOTH of these directories as READ-ONLY:

reference/dependency-track/
reference/frontend/

DO NOT modify them.

DO NOT:
- edit files inside them
- delete files
- rename files
- move files
- add DependShield code inside them
- initialize DependShield inside them
- overwrite their configuration
- change package files
- change Maven files
- change frontend files
- change database configuration
- commit DependShield changes to their Git repositories
- use them as the actual DependShield source tree

DependShield must be developed separately.

ALL DependShield implementation must stay inside:

dependshield/

The expected workspace structure is:

DependShield-Workspace/
│
├── reference/
│   ├── dependency-track/
│   └── frontend/
│
└── dependshield/

The reference repositories must remain untouched.

============================================================
LICENSE AND CODE REUSE
============================================================

The Dependency-Track repositories are open source.

Before reusing ANY code from the reference repositories:

1. Inspect the applicable license.
2. Inspect file-level copyright/license headers where present.
3. Determine whether the code can legally and technically be reused.
4. Preserve required copyright notices and license requirements.
5. Document reused or adapted code.
6. Prefer reimplementing concepts rather than copying large portions of the reference project.

Do NOT copy the entire Dependency-Track backend or frontend.

Do NOT simply rename Dependency-Track and call it DependShield.

DependShield must be an independently structured project.

Use Dependency-Track primarily as a reference for how a mature software dependency security platform works.

Create:

dependshield/docs/REFERENCE_DECISIONS.md

Record significant decisions such as:

- what we learned from Dependency-Track
- what we decided to reimplement
- what we decided not to implement
- what code, if any, was reused
- why it was reused
- applicable license information
- differences between Dependency-Track and DependShield

============================================================
PROJECT PHILOSOPHY
============================================================

DependShield is NOT intended to reproduce every feature of Dependency-Track.

Dependency-Track is a large, enterprise-grade project.

Our project is a final-year CSE project developed by 3 students.

Therefore:

Prefer:
- smaller architecture
- understandable code
- maintainability
- real functionality
- clear modules
- testability
- clean UI
- realistic scope

Avoid:
- unnecessary enterprise features
- excessive microservices
- unnecessary technologies
- unnecessary infrastructure
- implementing features just because Dependency-Track has them

The goal is:

UNDERSTAND
    ↓
DESIGN
    ↓
REIMPLEMENT
    ↓
TEST
    ↓
DOCUMENT

Not:

COPY
    ↓
RENAME
    ↓
SUBMIT

============================================================
FIRST TASK — DO NOT BUILD YET
============================================================

Your FIRST task is ONLY to study the reference repositories and design DependShield.

Do NOT start implementing the application yet.

Do NOT create the final frontend/backend architecture yet until you have inspected the reference implementation.

Do NOT run the application.

Do NOT run database initialization for DependShield.

Do NOT start Docker for DependShield.

Do NOT run npm start.

Do NOT run npm run dev.

Do NOT run Maven builds for the reference project unless absolutely necessary for understanding something.

Do NOT make changes to either reference repository.

============================================================
PHASE 0 — REFERENCE ANALYSIS
============================================================

Study:

reference/dependency-track/

and:

reference/frontend/

Inspect the repositories enough to understand:

1. Overall Dependency-Track architecture.
2. Backend architecture.
3. Frontend architecture.
4. API-first design.
5. Authentication and authorization concepts.
6. Project/version concepts.
7. Component/dependency data models.
8. SBOM processing.
9. CycloneDX handling.
10. Vulnerability analysis.
11. Vulnerability data sources.
12. Vulnerability-to-component matching.
13. Severity handling.
14. CVSS handling.
15. EPSS or other prioritization concepts where relevant.
16. Database design and important entities.
17. REST API organization.
18. Scan/analysis workflow.
19. Dashboard concepts.
20. Reporting concepts.
21. Notification concepts.
22. Audit/activity concepts.
23. Relevant security mechanisms.
24. Relevant frontend components.
25. Relevant charts/tables/views.
26. Error handling.
27. Logging.
28. Background processing if relevant.
29. What makes the reference project enterprise-scale.
30. What is unnecessary for a student implementation.

Do NOT blindly inspect every file if it is irrelevant.

Follow the architecture and identify the most useful modules first.

============================================================
CREATE REFERENCE_ANALYSIS.MD
============================================================

Create:

dependshield/docs/REFERENCE_ANALYSIS.md

It must contain:

1. Dependency-Track architecture overview.
2. Backend architecture.
3. Frontend architecture.
4. Important modules/directories.
5. Relevant data models.
6. Relevant APIs.
7. SBOM processing approach.
8. Dependency/component analysis approach.
9. Vulnerability analysis approach.
10. Vulnerability intelligence sources.
11. Security/risk concepts.
12. Dashboard concepts.
13. Reporting concepts.
14. Authentication/security concepts.
15. Features relevant to DependShield.
16. Features NOT required by DependShield.
17. Potentially reusable concepts.
18. Potentially reusable code.
19. Code that should NOT be reused.
20. Technical lessons learned.
21. Recommended DependShield architecture.
22. Major risks and challenges.
23. Licensing/reuse considerations.

============================================================
PHASE 1 — MASTER PLAN
============================================================

Create:

dependshield/DEPENDSHIELD_MASTER_PLAN.md

This file is the SINGLE SOURCE OF TRUTH for the project.

It must contain the complete plan for developing DependShield.

Include:

1. Project overview
2. Problem statement
3. Objectives
4. Scope
5. Users
6. Functional requirements
7. Non-functional requirements
8. Main features
9. MVP scope
10. Future enhancements
11. System architecture
12. Component architecture
13. Data flow
14. Scan pipeline
15. SBOM pipeline
16. Vulnerability pipeline
17. Risk scoring strategy
18. Database architecture
19. Database schema
20. API architecture
21. API endpoint specification
22. Frontend architecture
23. Backend architecture
24. Scanner architecture
25. External services
26. Security architecture
27. Threat model overview
28. Error handling
29. Logging
30. Testing strategy
31. Deployment architecture
32. Docker architecture
33. CI/CD possibilities
34. Team division
35. Development phases
36. Milestones
37. Definition of Done for every phase
38. Risks
39. Limitations
40. License considerations
41. Documentation requirements

============================================================
DEPENDSHIELD CORE USER WORKFLOW
============================================================

The main workflow should be:

User
  ↓
Create/Login to account
  ↓
Create project
  ↓
Choose input method
  ├── GitHub Repository URL
  └── ZIP Upload
  ↓
Repository/Project Ingestion
  ↓
Detect package ecosystem
  ↓
Dependency Manifest Detection
  ↓
Dependency Extraction
  ↓
Dependency Normalization
  ↓
SBOM Generation
  ↓
Component Identification
  ↓
Vulnerability Lookup
  ↓
Vulnerability Matching
  ↓
Severity / CVSS
  ↓
Risk Prioritization
  ↓
Store Scan Results
  ↓
Security Dashboard
  ↓
Vulnerability Details
  ↓
Remediation Guidance
  ↓
Security Report

============================================================
MVP SCOPE
============================================================

The first complete working version MUST support:

1. Registration.
2. Login.
3. Secure authentication.
4. Project creation.
5. ZIP upload.
6. GitHub repository URL input.
7. Node.js/npm project scanning.
8. Detection of package.json.
9. Detection of package-lock.json where applicable.
10. Dependency extraction.
11. Direct dependency identification where possible.
12. Transitive dependency identification where practical.
13. Dependency normalization.
14. CycloneDX SBOM generation.
15. Vulnerability lookup.
16. CVE identification.
17. CVSS where available.
18. Severity classification.
19. Vulnerability-to-dependency mapping.
20. Risk summary.
21. Vulnerability table.
22. Dependency table.
23. Scan history.
24. Dashboard.
25. Security report generation.
26. Basic remediation guidance.

============================================================
IMPORTANT SCOPE DECISION
============================================================

START WITH NODE.JS / NPM ONLY.

Do NOT immediately attempt:

- Python
- Maven
- Gradle
- Go
- Rust
- PHP
- Ruby
- NuGet
- Cargo
- etc.

The FIRST objective is to make this pipeline fully functional:

Node.js Project
    ↓
package.json / package-lock.json
    ↓
Dependencies
    ↓
CycloneDX SBOM
    ↓
Vulnerability Intelligence
    ↓
CVE Matching
    ↓
Severity
    ↓
Risk
    ↓
Dashboard
    ↓
Report

ONLY after that works correctly should you evaluate adding other ecosystems.

============================================================
DEPENDENCY EXTRACTION
============================================================

Design a reliable dependency extraction system.

It should:

- detect supported manifest files
- parse package.json
- parse package-lock.json
- distinguish direct dependencies where possible
- identify transitive dependencies
- capture package name
- capture version
- capture dependency relationship
- normalize identifiers
- handle missing/invalid files safely
- reject malformed inputs safely

Do NOT assume package names alone are enough for vulnerability matching.

Consider package:
- ecosystem
- namespace
- name
- version
- package URL / purl where appropriate
- CPE where appropriate

Document the component identification strategy.

============================================================
SBOM
============================================================

Use CycloneDX as the primary SBOM format unless the reference analysis demonstrates a better project-specific reason.

The system should generate a valid SBOM.

At minimum the SBOM should represent:

- project information
- components
- versions
- dependency relationships
- identifiers
- metadata where appropriate

Store the generated SBOM securely.

Allow the user to view/download the SBOM.

Do not merely generate a fake JSON file.

Validate the generated SBOM where practical.

============================================================
VULNERABILITY INTELLIGENCE
============================================================

Use real vulnerability data.

Initial primary source:

NVD / NIST

Use the NVD API where appropriate.

Architect the code so additional vulnerability sources can later be added, such as:

- OSV
- GitHub Advisory Database
- other legitimate vulnerability sources

Do NOT hard-code vulnerability results.

Store enough information to trace every security finding back to its source.

For each vulnerability where available, capture:

- CVE ID
- vulnerability identifier
- affected package/component
- affected version
- severity
- CVSS score/version
- description
- references
- published date
- modified date
- remediation information where reliable

============================================================
VULNERABILITY MATCHING
============================================================

This is one of the most important parts of the project.

Do not perform simplistic:

package name == CVE

matching.

Design a proper component-to-vulnerability matching approach using available package identifiers, versions, ecosystem data, and vulnerability applicability information.

Clearly document:

- how components are normalized
- how versions are compared
- how vulnerable version ranges are interpreted
- how false matches are reduced
- how missing metadata is handled

If exact vulnerability matching cannot be guaranteed, clearly represent uncertainty rather than pretending the result is definitive.

============================================================
RISK SCORING
============================================================

Create a transparent and explainable risk model.

Do NOT invent a meaningless arbitrary score.

Potential inputs can include:

- severity
- CVSS
- direct dependency
- transitive dependency
- exploitability information where available
- affected component importance
- number of vulnerable dependencies

The exact formula must be defined and documented.

The UI must explain WHY a result is classified as:

Critical
High
Medium
Low

If your implementation uses a project-level risk score, explain how it is calculated.

============================================================
DASHBOARD
============================================================

Create a professional security-focused dashboard.

Do NOT copy Dependency-Track's UI directly.

Create an original DependShield interface.

The dashboard should show:

Total projects
Total dependencies
Vulnerable dependencies
Total vulnerabilities
Critical
High
Medium
Low

Also include:

- severity distribution
- recent scans
- project risk
- top vulnerable dependencies
- vulnerability trends where enough history exists

============================================================
SCAN RESULT PAGE
============================================================

A scan should produce a detailed result page.

Example:

Project:
MyNodeApp

Scan:
#12

Dependencies:
143

Vulnerable:
27

Critical:
2

High:
7

Medium:
13

Low:
5

Then show vulnerability records with:

Package
Version
CVE
Severity
CVSS
Direct/Transitive
Description
Recommended action

============================================================
DEPENDENCY DETAILS
============================================================

For every dependency, show where possible:

Package name
Version
Ecosystem
Direct/Transitive
purl
Vulnerability count
Highest severity
Known fixes
Scan history

============================================================
VULNERABILITY DETAILS
============================================================

A vulnerability details page should show:

CVE ID
Package
Affected versions
Current version
Severity
CVSS
Description
References
Published date
Modified date
Remediation guidance

The source of the vulnerability must be visible.

============================================================
REMEDIATION
============================================================

Do NOT automatically modify repositories in the MVP.

Instead provide useful remediation guidance.

For example:

Current version:
4.17.20

Affected:
CVE-XXXX-XXXX

Recommended:
4.17.21 or later

Command:
npm install package@version

Only provide a recommended version if the data source supports the recommendation reliably.

============================================================
SECURITY REPORT
============================================================

Generate a downloadable security report.

The report should include:

Project information
Scan date
Scan ID
Total dependencies
Vulnerability summary
Severity distribution
Detailed vulnerabilities
CVE identifiers
CVSS
Affected versions
Remediation guidance
SBOM information

The report should look professional.

============================================================
SCAN HISTORY
============================================================

Store previous scan results.

Show:

Scan date
Project
Dependency count
Vulnerability count
Critical/High/Medium/Low
Risk status

Allow comparison between scans where practical.

Example:

Scan #8
Critical: 4

Scan #9
Critical: 2

The UI should make changes visible.

============================================================
GITHUB SUPPORT
============================================================

Allow the user to provide a GitHub repository URL.

Perform strict validation.

Do not accept arbitrary URLs blindly.

Consider:

- allowed GitHub domain
- repository format validation
- public/private repository requirements
- authentication if private repositories are later supported
- rate limits
- repository download security

For the MVP, PUBLIC GitHub repositories are preferred.

============================================================
ZIP UPLOAD SECURITY
============================================================

Treat uploaded project archives as untrusted.

Implement appropriate protections against:

- path traversal
- malicious file paths
- oversized files
- huge archives
- zip bombs where practical
- executable files where unnecessary
- arbitrary filesystem writes
- malicious nested archives where practical

Set:

- maximum upload size
- extraction limits
- safe temporary directory
- filename/path sanitization
- cleanup of temporary files

Never extract user-controlled archive paths directly onto arbitrary filesystem locations.

============================================================
AUTHENTICATION
============================================================

Implement secure authentication.

Suggested:

- JWT
- password hashing
- secure authentication middleware
- authorization checks

Do not store plain-text passwords.

Do not put secrets directly into source code.

Use environment variables.

============================================================
DATABASE
============================================================

Use PostgreSQL unless the reference analysis demonstrates a strong reason otherwise.

Design a clean relational schema.

Potential entities include:

users
projects
project_scans
repositories
components
component_versions
sboms
vulnerabilities
component_vulnerabilities
scan_results
remediations
audit_logs

These are examples, not mandatory final table names.

Before implementation, reason through:

- normalization
- relationships
- indexing
- foreign keys
- uniqueness
- scan versioning
- historical data
- query performance

Generate:

docs/DATABASE.md

containing:

- ER/data model explanation
- table descriptions
- relationships
- indexes
- important constraints

============================================================
REST API
============================================================

Use a clean RESTful API.

Possible examples:

POST /api/auth/register
POST /api/auth/login

POST /api/projects
GET /api/projects

POST /api/projects/:id/scans
GET /api/projects/:id/scans

GET /api/scans/:id
GET /api/scans/:id/dependencies
GET /api/scans/:id/vulnerabilities
GET /api/scans/:id/sbom
GET /api/scans/:id/report

These are examples only.

Design the final API based on the architecture.

Create:

docs/API.md

including:

- endpoints
- HTTP methods
- request bodies
- response structures
- authentication
- validation
- error responses

============================================================
FRONTEND
============================================================

Use:

React
JavaScript
HTML5
CSS3

The frontend should contain at least:

Login
Register
Dashboard
Projects
Create Project
New Scan
Scan Progress
Scan Result
Dependencies
Vulnerabilities
Vulnerability Details
SBOM
Scan History
Security Report

Keep the UI original.

Do NOT clone the Dependency-Track frontend visually.

Study its UX concepts where useful, but create a separate design system.

============================================================
BACKEND
============================================================

Suggested stack:

Node.js
Express.js
REST APIs
PostgreSQL

Structure the backend logically.

Possible layers:

Routes
Controllers
Services
Repositories/Data Access
Validation
Authentication
Scanner
SBOM
Vulnerability
Risk
Reports
Utilities

Do not create excessive abstractions without reason.

============================================================
SCANNER ENGINE
============================================================

Separate scanning logic from the API layer where practical.

Suggested conceptual modules:

scanner/
    ingestion
    manifest-detector
    dependency-parser
    normalizer
    sbom
    vulnerability
    risk

The API should trigger the scanning process rather than contain all scanner logic.

============================================================
EXTERNAL SERVICES
============================================================

Potential external services:

GitHub API
NVD API

Potential future:

OSV
GitHub Advisory Database

External APIs must have:

- timeout handling
- retry handling where appropriate
- rate-limit awareness
- graceful failure
- error logging
- clear user-facing status

Do not let an unavailable external API crash the entire platform.

============================================================
LOGGING
============================================================

Implement meaningful application logging.

Log:

- scan start
- scan end
- failures
- API failures
- parser errors
- vulnerability service errors
- important security events

Do NOT log:

- passwords
- JWT secrets
- API secrets
- unnecessary sensitive information

============================================================
ERROR HANDLING
============================================================

All major services must handle errors properly.

Examples:

Invalid ZIP
Invalid GitHub URL
Invalid repository
Malformed package.json
Missing package-lock.json
No dependencies
NVD unavailable
Rate limit
Database failure
SBOM generation failure
Vulnerability lookup failure

Show useful messages to the user.

Do not expose stack traces in production UI.

============================================================
NON-FUNCTIONAL REQUIREMENTS
============================================================

The application should be:

- secure
- maintainable
- modular
- responsive
- testable
- understandable
- reasonably performant
- fault tolerant
- documented

============================================================
TESTING
============================================================

Create a testing strategy covering:

Unit tests
Integration tests
API tests
Scanner tests
Dependency parser tests
SBOM tests
Vulnerability matching tests
Risk scoring tests
Authentication tests
Upload security tests

Create:

docs/TESTING.md

Include:

- what is tested
- test tools
- important test cases
- how to run tests
- expected behavior

============================================================
THREAT MODEL
============================================================

Create:

docs/THREAT_MODEL.md

Consider threats such as:

- malicious ZIP uploads
- path traversal
- zip bombs
- malicious GitHub URLs
- SSRF possibilities
- unauthorized project access
- JWT misuse
- credential attacks
- API abuse
- vulnerable dependency processing
- database injection
- secrets exposure

Provide mitigations.

============================================================
DEPLOYMENT
============================================================

The final project should be deployable.

Suggested architecture:

Frontend:
Vercel or equivalent

Backend:
Render / Railway / equivalent

Database:
PostgreSQL

Containerization:
Docker

Do not make deployment dependent on unnecessary enterprise infrastructure.

============================================================
TEAM DIVISION
============================================================

Structure the work for 3 members.

MEMBER 1:
Dependency Scanner + SBOM

Responsibilities:
- repository/ZIP ingestion
- manifest detection
- dependency extraction
- dependency normalization
- dependency relationships
- CycloneDX SBOM generation

MEMBER 2:
Vulnerability + Risk Engine

Responsibilities:
- NVD integration
- vulnerability matching
- CVE processing
- CVSS
- severity
- risk scoring
- remediation data

MEMBER 3:
Frontend + Platform

Responsibilities:
- React UI
- authentication UI
- dashboards
- scan pages
- vulnerability pages
- dependency pages
- reports
- API integration

Shared responsibilities:

- API contracts
- PostgreSQL schema
- Git workflow
- testing
- documentation
- deployment

============================================================
GIT STRUCTURE
============================================================

DependShield must have its OWN Git repository.

Do NOT use the Dependency-Track Git repositories for DependShield development.

Initialize Git only inside:

dependshield/

The reference repositories must remain independent.

Do not commit changes to:

reference/dependency-track/
reference/frontend/

============================================================
PROJECT TREE
============================================================

Before implementation, propose a project structure similar in concept to:

dependshield/
│
├── frontend/
│
├── backend/
│
├── scanner/
│
├── docs/
│
├── tests/
│
├── .env.example
├── DEPENDSHIELD_MASTER_PLAN.md
├── README.md
└── ...

Do NOT blindly use this exact tree.

Design the actual tree after analyzing the reference repositories.

============================================================
DOCUMENTATION REQUIREMENTS
============================================================

Create/update these files as development progresses:

DEPENDSHIELD_MASTER_PLAN.md

docs/
    REFERENCE_ANALYSIS.md
    REFERENCE_DECISIONS.md
    ARCHITECTURE.md
    DATABASE.md
    API.md
    THREAT_MODEL.md
    TESTING.md
    SETUP.md

README.md

Documentation must reflect the actual implementation.

Never document a feature as complete if it does not work.

============================================================
DEVELOPMENT ORDER
============================================================

Build in this order.

PHASE 0:
Reference analysis

PHASE 1:
Architecture + project scaffolding

PHASE 2:
PostgreSQL schema + backend foundation

PHASE 3:
Authentication

PHASE 4:
Project creation

PHASE 5:
ZIP/GitHub ingestion

PHASE 6:
Node.js dependency extraction

PHASE 7:
Dependency normalization

PHASE 8:
CycloneDX SBOM generation

PHASE 9:
NVD integration

PHASE 10:
Vulnerability matching

PHASE 11:
Severity/CVSS handling

PHASE 12:
Risk engine

PHASE 13:
Scan persistence/history

PHASE 14:
Dashboard

PHASE 15:
Dependency/vulnerability details

PHASE 16:
Security reports

PHASE 17:
Security hardening

PHASE 18:
Testing

PHASE 19:
Dockerization

PHASE 20:
Deployment preparation

PHASE 21:
Optional additional ecosystems/features

============================================================
DEFINITION OF DONE
============================================================

Every phase must have an explicit Definition of Done.

Example:

Phase 6 is complete only when:

- package.json can be parsed
- dependencies are extracted
- malformed files are handled
- dependency tests pass
- extracted dependency data is persisted or passed to the next pipeline
- documentation is updated

Do not mark a phase complete just because code exists.

============================================================
CHECKPOINT RULE
============================================================

After every major phase:

1. Run relevant tests.
2. Check for errors.
3. Summarize files created/changed.
4. Summarize what works.
5. Summarize what does not work.
6. Update documentation.
7. Update DEPENDSHIELD_MASTER_PLAN.md.
8. Report remaining risks.
9. STOP before a risky architectural change.

Do not silently continue through major architectural decisions.

============================================================
NO AUTOMATIC STARTUP
============================================================

This is extremely important.

Do NOT automatically start DependShield.

Do NOT automatically execute:

npm start
npm run dev
npm run build
docker compose up
docker-compose up
any equivalent startup command

unless I explicitly ask you to run the application.

At the end of development, create:

docs/SETUP.md

This must contain exact instructions for:

1. Prerequisites
2. Node.js version
3. PostgreSQL setup
4. Database creation
5. Environment variables
6. GitHub API configuration if required
7. NVD API configuration if required
8. Dependency installation
9. Database migration/setup
10. Backend startup
11. Frontend startup
12. Scanner execution if separate
13. Running tests
14. Docker setup
15. Deployment
16. Troubleshooting

At the end, give me the commands to execute manually.

Then STOP.

Only after I explicitly tell you to start the project may you run startup commands.

============================================================
IMPORTANT REAL-DATA RULE
============================================================

Do not fake functionality.

The following must use real data whenever implemented:

- dependencies
- SBOM
- CVEs
- CVSS
- vulnerability counts
- scan results
- job/project metadata
- repository contents

If an API is unavailable:
- report it
- handle it gracefully
- do not invent the missing data

If a vulnerability cannot confidently be matched:
- mark it uncertain/unresolved
- explain why
- do not present it as confirmed

============================================================
IMPORTANT DESIGN PRINCIPLE
============================================================

DependShield should be inspired by the architecture and capabilities of Dependency-Track but should NOT attempt to become a full replacement for Dependency-Track.

Our value is:

A simpler, understandable, developer-oriented security platform that demonstrates the complete software supply-chain security workflow.

Core value proposition:

"Submit a project → discover dependencies → generate SBOM → identify vulnerabilities → prioritize risks → understand remediation → monitor results."

============================================================
FUTURE ENHANCEMENTS
============================================================

Future features may include:

- Python support
- Maven support
- Gradle support
- Go support
- Rust support
- OSV integration
- GitHub Advisory integration
- EPSS
- license analysis
- dependency graph visualization
- GitHub webhooks
- scheduled rescanning
- CI/CD integration
- pull-request security checks
- notifications
- organization/team support
- policy engine

These are FUTURE features unless explicitly added to the MVP.

============================================================
FIRST ACTION — STOP AFTER ANALYSIS
============================================================

DO NOT BUILD THE APPLICATION AFTER THIS PROMPT.

FIRST:

1. Inspect reference/dependency-track/
2. Inspect reference/frontend/
3. Create docs/REFERENCE_ANALYSIS.md
4. Create docs/REFERENCE_DECISIONS.md
5. Create DEPENDSHIELD_MASTER_PLAN.md
6. Propose the final DependShield architecture
7. Propose the final database schema
8. Propose the REST API structure
9. Propose the frontend structure
10. Propose the scanner structure
11. Propose the project directory tree
12. Propose the 3-member responsibility split
13. Propose the development phases
14. Identify major technical risks
15. Identify what should be reused, reimplemented, or excluded from Dependency-Track

Then STOP.

DO NOT START CODING.

DO NOT START THE DATABASE.

DO NOT START DOCKER.

DO NOT START THE FRONTEND.

DO NOT START THE BACKEND.

WAIT FOR MY APPROVAL.

============================================================
FINAL INSTRUCTION
============================================================

Your immediate task is RESEARCH, ANALYSIS, ARCHITECTURE, AND PLANNING ONLY.

The reference repositories are:

reference/dependency-track/
reference/frontend/

The actual project is:

dependshield/

Keep these completely separate.

Analyze first.
Plan second.
Wait for approval.
Only then begin implementation phase-by-phase.