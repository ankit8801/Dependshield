const request = require('supertest');
const { PrismaClient } = require('@prisma/client');
const app = require('../src/app');
const { calculateRiskForScan } = require('../src/services/riskService');
const jwt = require('jsonwebtoken');

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_not_for_production';

describe('Phase 9 Risk Prioritization', () => {
  let user, token, project, scan;

  beforeAll(async () => {
    await prisma.scanVulnerabilityMatch.deleteMany({});
    await prisma.vulnerableSoftware.deleteMany({});
    await prisma.vulnerability.deleteMany({});
    await prisma.dependency.deleteMany({});
    await prisma.scan.deleteMany({});
    await prisma.project.deleteMany({});
    await prisma.user.deleteMany({});

    user = await prisma.user.create({
      data: { email: 'risk@test.com', passwordHash: 'hash' }
    });
    token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '1h' });

    project = await prisma.project.create({
      data: { name: 'Risk Test', userId: user.id }
    });
  });

  beforeEach(async () => {
    await prisma.scanVulnerabilityMatch.deleteMany({});
    await prisma.vulnerableSoftware.deleteMany({});
    await prisma.vulnerability.deleteMany({});
    await prisma.dependency.deleteMany({});
    await prisma.scan.deleteMany({});

    scan = await prisma.scan.create({
      data: { projectId: project.id, status: 'COMPLETED' }
    });
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  test('1. Calculates risk for single Critical Direct dependency', async () => {
    const dep = await prisma.dependency.create({
      data: { scanId: scan.id, name: 'dep-a', purl: 'pkg:npm/dep-a', isDirect: true }
    });

    const vuln = await prisma.vulnerability.create({
      data: { cveId: 'CVE-1', severity: 'CRITICAL', source: 'NVD' }
    });

    await prisma.scanVulnerabilityMatch.create({
      data: { dependencyId: dep.id, vulnerabilityId: vuln.id }
    });

    const riskScore = await calculateRiskForScan(scan.id);
    // 10 (Critical) * 1.5 (Direct) = 15
    expect(riskScore).toBe(15);
  });

  test('2. Calculates risk for multiple mixed dependencies', async () => {
    // Dep 1: Transitive, High (5 * 1.0 = 5)
    const dep1 = await prisma.dependency.create({
      data: { scanId: scan.id, name: 'dep-1', purl: 'pkg:npm/dep-1', isDirect: false }
    });
    const vulnHigh = await prisma.vulnerability.create({
      data: { cveId: 'CVE-H', severity: 'HIGH', source: 'NVD' }
    });
    await prisma.scanVulnerabilityMatch.create({
      data: { dependencyId: dep1.id, vulnerabilityId: vulnHigh.id }
    });

    // Dep 2: Direct, Medium (3 * 1.5 = 4.5)
    const dep2 = await prisma.dependency.create({
      data: { scanId: scan.id, name: 'dep-2', purl: 'pkg:npm/dep-2', isDirect: true }
    });
    const vulnMed = await prisma.vulnerability.create({
      data: { cveId: 'CVE-M', severity: 'MEDIUM', source: 'NVD' }
    });
    await prisma.scanVulnerabilityMatch.create({
      data: { dependencyId: dep2.id, vulnerabilityId: vulnMed.id }
    });

    // Dep 3: Direct, Low (1 * 1.5 = 1.5)
    const dep3 = await prisma.dependency.create({
      data: { scanId: scan.id, name: 'dep-3', purl: 'pkg:npm/dep-3', isDirect: true }
    });
    const vulnLow = await prisma.vulnerability.create({
      data: { cveId: 'CVE-L', severity: 'LOW', source: 'NVD' }
    });
    await prisma.scanVulnerabilityMatch.create({
      data: { dependencyId: dep3.id, vulnerabilityId: vulnLow.id }
    });

    // Dep 4: Transitive, Unassigned (0 * 1.0 = 0)
    const dep4 = await prisma.dependency.create({
      data: { scanId: scan.id, name: 'dep-4', purl: 'pkg:npm/dep-4', isDirect: false }
    });
    const vulnUnassigned = await prisma.vulnerability.create({
      data: { cveId: 'CVE-U', severity: 'UNASSIGNED', source: 'NVD' }
    });
    await prisma.scanVulnerabilityMatch.create({
      data: { dependencyId: dep4.id, vulnerabilityId: vulnUnassigned.id }
    });

    const riskScore = await calculateRiskForScan(scan.id);
    // Total = 5 + 4.5 + 1.5 + 0 = 11
    expect(riskScore).toBe(11);
  });

  test('3. Zero matches yields zero risk', async () => {
    const riskScore = await calculateRiskForScan(scan.id);
    expect(riskScore).toBe(0);
  });

  test('4. API endpoint returns risk summary', async () => {
    // Dep 1: Direct, Critical (10 * 1.5 = 15)
    const dep = await prisma.dependency.create({
      data: { scanId: scan.id, name: 'dep-a', purl: 'pkg:npm/dep-a', isDirect: true }
    });
    const vuln = await prisma.vulnerability.create({
      data: { cveId: 'CVE-1', severity: 'CRITICAL', source: 'NVD' }
    });
    await prisma.scanVulnerabilityMatch.create({
      data: { dependencyId: dep.id, vulnerabilityId: vuln.id }
    });
    await calculateRiskForScan(scan.id);

    const res = await request(app)
      .get(`/api/v1/projects/${project.id}/scans/${scan.id}/risk`)
      .set('Cookie', [`ds_token=${token}`]);

    expect(res.status).toBe(200);
    expect(res.body.data.totalRiskScore).toBe(15);
    expect(res.body.data.counts.CRITICAL).toBe(1);
    expect(res.body.data.counts.HIGH).toBe(0);
  });

  test('5. Unmatched dependencies do not receive risk', async () => {
    await prisma.dependency.create({
      data: { scanId: scan.id, name: 'safe-dep', purl: 'pkg:npm/safe-dep', isDirect: true }
    });
    const riskScore = await calculateRiskForScan(scan.id);
    expect(riskScore).toBe(0);
  });

  test('6. Other scans do not affect current scan risk', async () => {
    const scan2 = await prisma.scan.create({
      data: { projectId: project.id, status: 'COMPLETED' }
    });

    const dep = await prisma.dependency.create({
      data: { scanId: scan2.id, name: 'dep-a', purl: 'pkg:npm/dep-a', isDirect: true }
    });

    const vuln = await prisma.vulnerability.create({
      data: { cveId: 'CVE-1', severity: 'CRITICAL', source: 'NVD' }
    });

    await prisma.scanVulnerabilityMatch.create({
      data: { dependencyId: dep.id, vulnerabilityId: vuln.id }
    });

    await calculateRiskForScan(scan2.id);

    // Scan 1 should still be 0
    const riskScore1 = await calculateRiskForScan(scan.id);
    expect(riskScore1).toBe(0);
  });
});
