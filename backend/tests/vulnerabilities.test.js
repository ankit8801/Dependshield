const request = require('supertest');
const { PrismaClient } = require('@prisma/client');
const app = require('../src/app');
const nvdService = require('../src/services/nvdService');
const vulnerabilityService = require('../src/services/vulnerabilityService');
const axios = require('axios');
const jwt = require('jsonwebtoken');

jest.mock('axios');

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_not_for_production';

describe('Vulnerability Intelligence & NVD Sync', () => {
  let user, token, project, scan;

  beforeAll(async () => {
    // Clear DB
    await prisma.scanVulnerabilityMatch.deleteMany({});
    await prisma.vulnerableSoftware.deleteMany({});
    await prisma.vulnerability.deleteMany({});
    await prisma.dependency.deleteMany({});
    await prisma.scan.deleteMany({});
    await prisma.project.deleteMany({});
    await prisma.user.deleteMany({});

    user = await prisma.user.create({
      data: { email: 'vuln@test.com', passwordHash: 'hash' }
    });
    token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '1h' });

    project = await prisma.project.create({
      data: { name: 'Vuln Test', userId: user.id }
    });

    scan = await prisma.scan.create({
      data: { projectId: project.id, status: 'COMPLETED' }
    });

    // Create a dependency
    await prisma.dependency.create({
      data: { scanId: scan.id, name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15', isDirect: true }
    });
    
    // Scoped dependency
    await prisma.dependency.create({
      data: { scanId: scan.id, name: '@types/node', version: '18.0.0', purl: 'pkg:npm/%40types/node@18.0.0', isDirect: false }
    });
  });

  afterAll(async () => {
    await prisma.scanVulnerabilityMatch.deleteMany({});
    await prisma.vulnerableSoftware.deleteMany({});
    await prisma.vulnerability.deleteMany({});
    await prisma.dependency.deleteMany({});
    await prisma.scan.deleteMany({});
    await prisma.project.deleteMany({});
    await prisma.user.deleteMany({});
    await prisma.$disconnect();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  jest.setTimeout(30000);

  test('1. NVD Sync handles successful page retrieval and incremental sync', async () => {
    const mockNvdResponse = {
      resultsPerPage: 1,
      startIndex: 0,
      totalResults: 1,
      vulnerabilities: [
        {
          cve: {
            id: 'CVE-2019-10744',
            vulnStatus: 'Analyzed',
            published: '2019-07-26T00:00:00.000Z',
            lastModified: '2020-07-26T00:00:00.000Z',
            descriptions: [{ lang: 'en', value: 'Prototype pollution in lodash.' }],
            metrics: {
              cvssMetricV31: [{
                cvssData: { baseScore: 7.3, baseSeverity: 'HIGH', version: '3.1', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L' }
              }]
            },
            configurations: [{
              nodes: [{
                cpeMatch: [{
                  vulnerable: true,
                  criteria: 'cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*',
                  versionEndExcluding: '4.17.19'
                }]
              }]
            }]
          }
        }
      ]
    };

    axios.get.mockResolvedValueOnce({ data: mockNvdResponse });

    const result = await nvdService.syncNvd();
    expect(result.success).toBe(true);
    expect(result.processedCount).toBe(1);

    // Verify DB
    const vuln = await prisma.vulnerability.findUnique({
      where: { cveId: 'CVE-2019-10744' },
      include: { affectedSoftware: true }
    });
    
    expect(vuln).toBeTruthy();
    expect(vuln.severity).toBe('HIGH');
    expect(vuln.cvssScore.toNumber()).toBe(7.3);
    expect(vuln.affectedSoftware.length).toBe(1);
    expect(vuln.affectedSoftware[0].product).toBe('lodash');
    expect(vuln.affectedSoftware[0].versionEndExcluding).toBe('4.17.19');
    
    // Verify sync state
    const state = await prisma.syncState.findUnique({ where: { id: 'NVD' } });
    expect(state).toBeTruthy();
    expect(state.lastSyncDate).toBeDefined();
  });

  test('2. NVD Sync ignores REJECTED CVEs', async () => {
    const mockRejectedResponse = {
      resultsPerPage: 1,
      startIndex: 0,
      totalResults: 1,
      vulnerabilities: [
        {
          cve: {
            id: 'CVE-2020-99999',
            vulnStatus: 'Rejected'
          }
        }
      ]
    };

    axios.get.mockResolvedValueOnce({ data: mockRejectedResponse });
    await nvdService.syncNvd();

    const vuln = await prisma.vulnerability.findUnique({ where: { cveId: 'CVE-2020-99999' } });
    expect(vuln).toBeNull();
  });

  test('3. Vulnerability matching creates matches correctly using version range', async () => {
    const matchCount = await vulnerabilityService.matchDependencies(scan.id);
    expect(matchCount).toBe(1);

    const matches = await prisma.scanVulnerabilityMatch.findMany({
      where: { dependency: { scanId: scan.id } },
      include: { vulnerability: true, dependency: true }
    });

    expect(matches.length).toBe(1);
    expect(matches[0].dependency.name).toBe('lodash');
    expect(matches[0].vulnerability.cveId).toBe('CVE-2019-10744');
  });

  test('4. Vulnerability matching prevents duplicate matches', async () => {
    const matchCount = await vulnerabilityService.matchDependencies(scan.id);
    expect(matchCount).toBe(0); // Should not create a new one
  });

  test('4b. Vulnerability matching semantic boundaries', async () => {
    // Clear out matches and software
    await prisma.scanVulnerabilityMatch.deleteMany({});
    await prisma.vulnerableSoftware.deleteMany({});
    await prisma.dependency.deleteMany({});

    // Create a generic vulnerability
    const vuln = await prisma.vulnerability.findUnique({ where: { cveId: 'CVE-2019-10744' } });

    // Set up software with all constraints: >1.0.0, >=1.5.0, <3.0.0, <=2.5.0
    // Actually let's test specific bounds
    await prisma.vulnerableSoftware.create({
      data: {
        vulnerabilityId: vuln.id,
        product: 'testpkg',
        versionStartExcluding: '1.0.0',
        versionEndExcluding: '3.0.0'
      }
    });

    await prisma.vulnerableSoftware.create({
      data: {
        vulnerabilityId: vuln.id,
        product: 'testpkg-inc',
        versionStartIncluding: '1.0.0',
        versionEndIncluding: '3.0.0'
      }
    });

    const cases = [
      { name: 'testpkg', version: '0.9.0', expectMatch: false }, // below
      { name: 'testpkg', version: '1.0.0', expectMatch: false }, // exact start boundary (excluding)
      { name: 'testpkg', version: '2.0.0', expectMatch: true },  // inside
      { name: 'testpkg', version: '3.0.0', expectMatch: false }, // exact end boundary (excluding)
      { name: 'testpkg', version: '3.1.0', expectMatch: false }, // above
      
      { name: 'testpkg-inc', version: '0.9.0', expectMatch: false }, // below
      { name: 'testpkg-inc', version: '1.0.0', expectMatch: true },  // exact start boundary (including)
      { name: 'testpkg-inc', version: '2.0.0', expectMatch: true },  // inside
      { name: 'testpkg-inc', version: '3.0.0', expectMatch: true },  // exact end boundary (including)
      { name: 'testpkg-inc', version: '3.1.0', expectMatch: false }  // above
    ];

    for (const c of cases) {
      const dep = await prisma.dependency.create({
        data: { scanId: scan.id, name: c.name, version: c.version, purl: `pkg:npm/${c.name}@${c.version}`, isDirect: true }
      });
      await vulnerabilityService.matchDependencies(scan.id);
      
      const matches = await prisma.scanVulnerabilityMatch.findMany({ where: { dependencyId: dep.id } });
      expect(matches.length > 0).toBe(c.expectMatch);
    }
  });

  test('5. API endpoint returns findings for scan', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${project.id}/scans/${scan.id}/vulnerabilities`)
      .set('Cookie', [`ds_token=${token}`]);
    
    expect(res.status).toBe(200);
    expect(res.body.data).toBeInstanceOf(Array);
    expect(res.body.data.length).toBeGreaterThan(0);
    expect(res.body.data[0].vulnerability.cveId).toBe('CVE-2019-10744');
  });
});
