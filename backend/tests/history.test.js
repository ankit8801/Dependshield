const request = require('supertest');
const { PrismaClient } = require('@prisma/client');
const app = require('../src/app');
const jwt = require('jsonwebtoken');

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_not_for_production';

describe('Phase 12 - Scan History and Tracking', () => {
  let user1, token1, user2, token2, project1, project2;

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
      data: { email: 'history-user1@test.com', passwordHash: 'hash1' }
    });
    token1 = jwt.sign({ sub: user1.id }, JWT_SECRET, { expiresIn: '1h' });

    user2 = await prisma.user.create({
      data: { email: 'history-user2@test.com', passwordHash: 'hash2' }
    });
    token2 = jwt.sign({ sub: user2.id }, JWT_SECRET, { expiresIn: '1h' });

    project1 = await prisma.project.create({
      data: { name: 'History Project 1', userId: user1.id }
    });

    await prisma.repository.create({
      data: { projectId: project1.id, type: 'GITHUB', url: 'https://github.com/test-org/repo-1' }
    });

    project2 = await prisma.project.create({
      data: { name: 'History Project 2', userId: user2.id }
    });
  });

  beforeEach(async () => {
    await prisma.scanVulnerabilityMatch.deleteMany({});
    await prisma.vulnerableSoftware.deleteMany({});
    await prisma.vulnerability.deleteMany({});
    await prisma.dependency.deleteMany({});
    await prisma.sbom.deleteMany({});
    await prisma.scan.deleteMany({});
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  test('1. Returns empty history array when project has no scans', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans`)
      .set('Cookie', [`ds_token=${token1}`]);

    expect(res.status).toBe(200);
    expect(res.body.data).toEqual([]);
  });

  test('2. Returns historical scans ordered by newest first with complete actual metrics', async () => {
    const dateOld = new Date(Date.now() - 60000);
    const dateNew = new Date();

    // Scan 1 (older, completed with 2 dependencies, 1 match, risk 15)
    const scanOld = await prisma.scan.create({
      data: {
        projectId: project1.id,
        status: 'COMPLETED',
        riskScore: 15.0,
        createdAt: dateOld,
        completedAt: new Date(dateOld.getTime() + 10000)
      }
    });

    const dep1 = await prisma.dependency.create({
      data: { scanId: scanOld.id, name: 'express', version: '4.17.1', purl: 'pkg:npm/express@4.17.1', isDirect: true }
    });
    await prisma.dependency.create({
      data: { scanId: scanOld.id, name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21', isDirect: false }
    });

    const vuln = await prisma.vulnerability.create({
      data: { cveId: 'CVE-HIST-1', severity: 'CRITICAL', source: 'NVD' }
    });

    await prisma.scanVulnerabilityMatch.create({
      data: { dependencyId: dep1.id, vulnerabilityId: vuln.id, riskScore: 15.0, severityWeight: 10, contextWeight: 1.5 }
    });

    await prisma.sbom.create({
      data: {
        scanId: scanOld.id,
        cycloneDxContent: {
          bomFormat: 'CycloneDX',
          specVersion: '1.5',
          components: [{ name: 'express' }, { name: 'lodash' }]
        }
      }
    });

    // Scan 2 (newer, completed with 0 dependencies, risk 0)
    const scanNew = await prisma.scan.create({
      data: {
        projectId: project1.id,
        status: 'COMPLETED',
        riskScore: 0,
        createdAt: dateNew,
        completedAt: new Date(dateNew.getTime() + 5000)
      }
    });

    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans`)
      .set('Cookie', [`ds_token=${token1}`]);

    expect(res.status).toBe(200);
    const history = res.body.data;
    expect(history.length).toBe(2);

    // Ordering: newest first
    expect(history[0].id).toBe(scanNew.id);
    expect(history[1].id).toBe(scanOld.id);

    // ScanOld metrics verification
    const histOld = history[1];
    expect(histOld.source).toBe('GITHUB');
    expect(histOld.status).toBe('COMPLETED');
    expect(histOld.dependencyCount).toBe(2);
    expect(histOld.vulnerabilityCount).toBe(1);
    expect(histOld.totalRiskIndex).toBe(15.0);
    expect(histOld.sbomComponentCount).toBe(2);
    expect(histOld.completedAt).not.toBeNull();

    // ScanNew metrics verification
    const histNew = history[0];
    expect(histNew.dependencyCount).toBe(0);
    expect(histNew.vulnerabilityCount).toBe(0);
    expect(histNew.totalRiskIndex).toBe(0);
    expect(histNew.sbomComponentCount).toBeNull();
  });

  test('3. Handles non-terminal and failed scan states accurately without false metrics', async () => {
    // In-progress scan
    const runningScan = await prisma.scan.create({
      data: {
        projectId: project1.id,
        status: 'EXTRACTING',
        riskScore: null,
        completedAt: null
      }
    });

    // Failed scan
    const failedScan = await prisma.scan.create({
      data: {
        projectId: project1.id,
        status: 'FAILED',
        errorMessage: 'Invalid ZIP archive: corrupted entry',
        riskScore: null,
        completedAt: null
      }
    });

    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans`)
      .set('Cookie', [`ds_token=${token1}`]);

    expect(res.status).toBe(200);
    const history = res.body.data;
    expect(history.length).toBe(2);

    const fScan = history.find(s => s.id === failedScan.id);
    expect(fScan.status).toBe('FAILED');
    expect(fScan.errorMessage).toBe('Invalid ZIP archive: corrupted entry');
    expect(fScan.completedAt).toBeNull();
    expect(fScan.totalRiskIndex).toBeNull();
    expect(fScan.dependencyCount).toBe(0);

    const rScan = history.find(s => s.id === runningScan.id);
    expect(rScan.status).toBe('EXTRACTING');
    expect(rScan.completedAt).toBeNull();
    expect(rScan.totalRiskIndex).toBeNull();
  });

  test('4. Enforces project ownership: user2 cannot view user1 scan history', async () => {
    await prisma.scan.create({
      data: { projectId: project1.id, status: 'COMPLETED' }
    });

    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans`)
      .set('Cookie', [`ds_token=${token2}`]);

    expect(res.status).toBe(404);
    expect(res.body.error.message).toContain('Project not found');
  });

  test('5. Enforces scan ownership on single scan details endpoint', async () => {
    const scan = await prisma.scan.create({
      data: { projectId: project1.id, status: 'COMPLETED' }
    });

    // Owner can access
    const resOwner = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(resOwner.status).toBe(200);
    expect(resOwner.body.data.id).toBe(scan.id);
    expect(resOwner.body.data.source).toBe('GITHUB');

    // Unauthorized user cannot access
    const resOther = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}`)
      .set('Cookie', [`ds_token=${token2}`]);
    expect(resOther.status).toBe(404);

    // Cross-project check: scan does not belong to project2
    const resWrongProject = await request(app)
      .get(`/api/v1/projects/${project2.id}/scans/${scan.id}`)
      .set('Cookie', [`ds_token=${token2}`]);
    expect(resWrongProject.status).toBe(404);
  });

  test('6. Allows accessing dashboard, report, dependencies, and SBOM from historical scan', async () => {
    const scan = await prisma.scan.create({
      data: { projectId: project1.id, status: 'COMPLETED', riskScore: 5.0 }
    });

    await prisma.dependency.create({
      data: { scanId: scan.id, name: 'sample-lib', version: '1.0.0', purl: 'pkg:npm/sample-lib@1.0.0', isDirect: true }
    });

    await prisma.sbom.create({
      data: {
        scanId: scan.id,
        cycloneDxContent: { bomFormat: 'CycloneDX', specVersion: '1.5', components: [{ name: 'sample-lib' }] }
      }
    });

    // Dashboard access
    const dashRes = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/dashboard`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(dashRes.status).toBe(200);
    expect(dashRes.body.data.scan.id).toBe(scan.id);

    // Report access
    const reportRes = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/report`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(reportRes.status).toBe(200);
    expect(reportRes.body.data.scan.id).toBe(scan.id);

    // Dependencies access
    const depRes = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/dependencies`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(depRes.status).toBe(200);
    expect(depRes.body.data.length).toBe(1);

    // SBOM access
    const sbomRes = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/sbom`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(sbomRes.status).toBe(200);
    expect(sbomRes.body.data.bomFormat).toBe('CycloneDX');
  });
});
