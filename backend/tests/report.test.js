const request = require('supertest');
const { PrismaClient } = require('@prisma/client');
const app = require('../src/app');
const jwt = require('jsonwebtoken');

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_not_for_production';

describe('Phase 11 - Security Reports and Export', () => {
  let user1, token1, user2, token2, project1, scan1;

  beforeAll(async () => {
    await prisma.scanVulnerabilityMatch.deleteMany({});
    await prisma.vulnerableSoftware.deleteMany({});
    await prisma.vulnerability.deleteMany({});
    await prisma.dependency.deleteMany({});
    await prisma.sbom.deleteMany({});
    await prisma.scan.deleteMany({});
    await prisma.repository.deleteMany({});
    await prisma.project.deleteMany({});
    await prisma.user.deleteMany({});

    user1 = await prisma.user.create({
      data: { email: 'report-owner@test.com', passwordHash: 'hash1' }
    });
    token1 = jwt.sign({ sub: user1.id }, JWT_SECRET, { expiresIn: '1h' });

    user2 = await prisma.user.create({
      data: { email: 'report-other@test.com', passwordHash: 'hash2' }
    });
    token2 = jwt.sign({ sub: user2.id }, JWT_SECRET, { expiresIn: '1h' });

    project1 = await prisma.project.create({
      data: {
        name: 'Report Test Project',
        description: 'Test Project for Security Reports',
        userId: user1.id
      }
    });

    await prisma.repository.create({
      data: {
        projectId: project1.id,
        type: 'GITHUB',
        url: 'https://github.com/test-org/test-repo'
      }
    });
  });

  beforeEach(async () => {
    await prisma.scanVulnerabilityMatch.deleteMany({});
    await prisma.vulnerableSoftware.deleteMany({});
    await prisma.vulnerability.deleteMany({});
    await prisma.dependency.deleteMany({});
    await prisma.sbom.deleteMany({});
    await prisma.scan.deleteMany({});

    scan1 = await prisma.scan.create({
      data: {
        projectId: project1.id,
        status: 'COMPLETED',
        riskScore: 17.5,
        completedAt: new Date()
      }
    });
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  test('1. Generates complete JSON security report with accurate project, dependency, vulnerability, risk, and SBOM metadata', async () => {
    // 1 Direct dep with Critical vuln (10 * 1.5 = 15)
    const dep1 = await prisma.dependency.create({
      data: {
        scanId: scan1.id,
        name: 'express',
        version: '4.17.1',
        purl: 'pkg:npm/express@4.17.1',
        isDirect: true,
        ecosystem: 'npm'
      }
    });

    // 1 Transitive dep with Low vuln (1 * 1.0 = 1)
    const dep2 = await prisma.dependency.create({
      data: {
        scanId: scan1.id,
        name: 'lodash',
        version: '4.17.15',
        purl: 'pkg:npm/lodash@4.17.15',
        isDirect: false,
        ecosystem: 'npm'
      }
    });

    // 1 Clean direct dep (no vuln)
    await prisma.dependency.create({
      data: {
        scanId: scan1.id,
        name: 'uuid',
        version: '9.0.0',
        purl: 'pkg:npm/uuid@9.0.0',
        isDirect: true,
        ecosystem: 'npm'
      }
    });

    const vuln1 = await prisma.vulnerability.create({
      data: {
        cveId: 'CVE-2022-25883',
        description: 'Prototype pollution in express',
        severity: 'CRITICAL',
        cvssScore: 9.8,
        cvssVersion: '3.1',
        source: 'NVD'
      }
    });

    await prisma.vulnerableSoftware.create({
      data: {
        vulnerabilityId: vuln1.id,
        vendor: 'expressjs',
        product: 'express',
        versionEndExcluding: '4.18.0'
      }
    });

    const vuln2 = await prisma.vulnerability.create({
      data: {
        cveId: 'CVE-2020-8203',
        description: 'Low severity issue in lodash',
        severity: 'LOW',
        cvssScore: 3.5,
        cvssVersion: '3.1',
        source: 'NVD'
      }
    });

    await prisma.scanVulnerabilityMatch.create({
      data: {
        dependencyId: dep1.id,
        vulnerabilityId: vuln1.id,
        severityWeight: 10,
        contextWeight: 1.5,
        riskScore: 15.0
      }
    });

    await prisma.scanVulnerabilityMatch.create({
      data: {
        dependencyId: dep2.id,
        vulnerabilityId: vuln2.id,
        severityWeight: 1,
        contextWeight: 1.0,
        riskScore: 1.0
      }
    });

    // SBOM record with CycloneDX 1.5
    await prisma.sbom.create({
      data: {
        scanId: scan1.id,
        cycloneDxContent: {
          bomFormat: 'CycloneDX',
          specVersion: '1.5',
          serialNumber: 'urn:uuid:test-sbom-serial-1234',
          version: 1,
          metadata: {
            timestamp: '2026-09-30T12:00:00.000Z',
            tools: [{ name: 'DependShield Scanner', version: '0.1.0' }]
          },
          components: [
            { name: 'express', version: '4.17.1', purl: 'pkg:npm/express@4.17.1' },
            { name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15' },
            { name: 'uuid', version: '9.0.0', purl: 'pkg:npm/uuid@9.0.0' }
          ]
        }
      }
    });

    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan1.id}/report`)
      .set('Cookie', [`ds_token=${token1}`]);

    expect(res.status).toBe(200);
    const report = res.body.data;

    // 1. Project Information
    expect(report.project.id).toBe(project1.id);
    expect(report.project.name).toBe('Report Test Project');
    expect(report.project.repository.type).toBe('GITHUB');
    expect(report.project.repository.url).toBe('https://github.com/test-org/test-repo');

    // Scan info
    expect(report.scan.id).toBe(scan1.id);
    expect(report.scan.status).toBe('COMPLETED');
    expect(report.scan.isIncomplete).toBe(false);

    // 2. Dependency Summary
    expect(report.dependencySummary.totalDependencies).toBe(3);
    expect(report.dependencySummary.directDependencies).toBe(2);
    expect(report.dependencySummary.transitiveDependencies).toBe(1);
    expect(report.dependencySummary.sbomComponentCount).toBe(3);

    // 3. Vulnerability Summary
    expect(report.vulnerabilitySummary.totalFindings).toBe(2);
    expect(report.vulnerabilitySummary.severityCounts.CRITICAL).toBe(1);
    expect(report.vulnerabilitySummary.severityCounts.LOW).toBe(1);
    expect(report.vulnerabilitySummary.severityCounts.HIGH).toBe(0);

    // 4. Risk Summary
    expect(report.riskSummary.totalRiskIndex).toBe(17.5);
    expect(report.riskSummary.formula.formula).toBe('Risk Score = Severity Weight × Context Weight');

    // 5. Findings details
    expect(report.findings.length).toBe(2);
    const criticalFinding = report.findings.find((f) => f.cveId === 'CVE-2022-25883');
    expect(criticalFinding).toBeDefined();
    expect(criticalFinding.packageName).toBe('express');
    expect(criticalFinding.isDirect).toBe(true);
    expect(criticalFinding.severity).toBe('CRITICAL');
    expect(criticalFinding.cvssScore).toBe(9.8);
    expect(criticalFinding.riskScore).toBe(15.0);
    expect(criticalFinding.affectedSoftware.length).toBe(1);
    expect(criticalFinding.affectedSoftware[0].product).toBe('express');

    // 6. SBOM Information (actual generated metadata, not hard-coded 1.4)
    expect(report.sbom.isAvailable).toBe(true);
    expect(report.sbom.bomFormat).toBe('CycloneDX');
    expect(report.sbom.specVersion).toBe('1.5');
    expect(report.sbom.serialNumber).toBe('urn:uuid:test-sbom-serial-1234');
    expect(report.sbom.componentCount).toBe(3);

    // Disclaimer
    expect(report.reportMetadata.disclaimer).toContain('Zero findings indicates no known vulnerabilities');
  });

  test('2. Handles scan with zero vulnerabilities accurately without declaring false security guarantee', async () => {
    await prisma.dependency.create({
      data: {
        scanId: scan1.id,
        name: 'clean-dep',
        version: '1.0.0',
        purl: 'pkg:npm/clean-dep@1.0.0',
        isDirect: true
      }
    });

    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan1.id}/report`)
      .set('Cookie', [`ds_token=${token1}`]);

    expect(res.status).toBe(200);
    const report = res.body.data;
    expect(report.vulnerabilitySummary.totalFindings).toBe(0);
    expect(report.findings).toEqual([]);
    expect(report.reportMetadata.disclaimer).toContain('Zero findings indicates no known vulnerabilities were detected');
  });

  test('3. Indicates incomplete state when scan is still in progress', async () => {
    const runningScan = await prisma.scan.create({
      data: {
        projectId: project1.id,
        status: 'INGESTING'
      }
    });

    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${runningScan.id}/report`)
      .set('Cookie', [`ds_token=${token1}`]);

    expect(res.status).toBe(200);
    const report = res.body.data;
    expect(report.scan.status).toBe('INGESTING');
    expect(report.scan.isIncomplete).toBe(true);
    expect(report.reportMetadata.scanNotice).toContain('is in state \'INGESTING\'');
  });

  test('4. Indicates failed state and error message for failed scan', async () => {
    const failedScan = await prisma.scan.create({
      data: {
        projectId: project1.id,
        status: 'FAILED',
        errorMessage: 'Invalid package.json manifest'
      }
    });

    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${failedScan.id}/report`)
      .set('Cookie', [`ds_token=${token1}`]);

    expect(res.status).toBe(200);
    const report = res.body.data;
    expect(report.scan.status).toBe('FAILED');
    expect(report.scan.isFailed).toBe(true);
    expect(report.scan.errorMessage).toBe('Invalid package.json manifest');
    expect(report.reportMetadata.scanNotice).toContain('Scan failed: Invalid package.json manifest');
  });

  test('5. Enforces project ownership: user2 cannot access user1 report', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan1.id}/report`)
      .set('Cookie', [`ds_token=${token2}`]);

    expect(res.status).toBe(404);
    expect(res.body.error.message).toContain('Project not found');
  });

  test('6. Download endpoint sets Content-Disposition attachment for JSON, HTML, and Markdown', async () => {
    // JSON download
    const resJson = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan1.id}/report?format=json&download=true`)
      .set('Cookie', [`ds_token=${token1}`]);

    expect(resJson.status).toBe(200);
    expect(resJson.headers['content-disposition']).toMatch(/attachment; filename="dependshield-report-.*\.json"/);
    expect(resJson.headers['content-type']).toContain('application/json');

    // HTML download
    const resHtml = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan1.id}/report?format=html&download=true`)
      .set('Cookie', [`ds_token=${token1}`]);

    expect(resHtml.status).toBe(200);
    expect(resHtml.headers['content-disposition']).toMatch(/attachment; filename="dependshield-report-.*\.html"/);
    expect(resHtml.headers['content-type']).toContain('text/html');
    expect(resHtml.text).toContain('DependShield Security Analysis Report');

    // Markdown download
    const resMd = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan1.id}/report?format=markdown&download=true`)
      .set('Cookie', [`ds_token=${token1}`]);

    expect(resMd.status).toBe(200);
    expect(resMd.headers['content-disposition']).toMatch(/attachment; filename="dependshield-report-.*\.md"/);
    expect(resMd.headers['content-type']).toContain('text/markdown');
    expect(resMd.text).toContain('# DependShield Security Analysis Report');

    // Export route alias (/report/export)
    const resExport = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan1.id}/report/export?format=json`)
      .set('Cookie', [`ds_token=${token1}`]);

    expect(resExport.status).toBe(200);
    expect(resExport.headers['content-disposition']).toMatch(/attachment; filename="dependshield-report-.*\.json"/);
  });

  test('7. Report values are strictly consistent with Dashboard endpoint data', async () => {
    const dep = await prisma.dependency.create({
      data: {
        scanId: scan1.id,
        name: 'axios',
        version: '0.21.1',
        purl: 'pkg:npm/axios@0.21.1',
        isDirect: true
      }
    });

    const vuln = await prisma.vulnerability.create({
      data: {
        cveId: 'CVE-2021-3749',
        description: 'ReDoS in axios',
        severity: 'MEDIUM',
        cvssScore: 5.3,
        source: 'NVD'
      }
    });

    await prisma.scanVulnerabilityMatch.create({
      data: {
        dependencyId: dep.id,
        vulnerabilityId: vuln.id,
        severityWeight: 3,
        contextWeight: 1.5,
        riskScore: 4.5
      }
    });

    await prisma.scan.update({
      where: { id: scan1.id },
      data: { riskScore: 4.5 }
    });

    // Call dashboard endpoint
    const dashRes = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan1.id}/dashboard`)
      .set('Cookie', [`ds_token=${token1}`]);

    // Call report endpoint
    const reportRes = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan1.id}/report`)
      .set('Cookie', [`ds_token=${token1}`]);

    expect(dashRes.status).toBe(200);
    expect(reportRes.status).toBe(200);

    const dash = dashRes.body.data;
    const report = reportRes.body.data;

    expect(report.dependencySummary.totalDependencies).toBe(dash.summary.totalDependencies);
    expect(report.dependencySummary.directDependencies).toBe(dash.summary.directDependencies);
    expect(report.dependencySummary.transitiveDependencies).toBe(dash.summary.transitiveDependencies);
    expect(report.vulnerabilitySummary.totalFindings).toBe(dash.summary.totalFindings);
    expect(report.riskSummary.totalRiskIndex).toBe(dash.summary.totalRiskScore);
    expect(report.vulnerabilitySummary.severityCounts).toEqual(dash.summary.severityCounts);
    expect(report.findings[0].cveId).toBe(dash.findings[0].cveId);
    expect(report.findings[0].riskScore).toBe(dash.findings[0].riskScore);
  });
});
