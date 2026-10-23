/**
 * Phase 13 - Dependency and SBOM Visualization
 *
 * Tests the existing dependency and SBOM endpoints for all Phase 13
 * visualization scenarios. No new backend routes are added in Phase 13;
 * this suite validates that the existing APIs fully satisfy the
 * visualization layer data requirements.
 */
const request = require('supertest');
const { PrismaClient } = require('@prisma/client');
const app = require('../src/app');
const jwt = require('jsonwebtoken');

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_not_for_production';

describe('Phase 13 - Dependency and SBOM Visualization', () => {
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

    user1 = await prisma.user.create({ data: { email: 'viz-user1@test.com', passwordHash: 'hash1' } });
    token1 = jwt.sign({ sub: user1.id }, JWT_SECRET, { expiresIn: '1h' });
    user2 = await prisma.user.create({ data: { email: 'viz-user2@test.com', passwordHash: 'hash2' } });
    token2 = jwt.sign({ sub: user2.id }, JWT_SECRET, { expiresIn: '1h' });

    project1 = await prisma.project.create({ data: { name: 'Viz Project 1', userId: user1.id } });
    await prisma.repository.create({
      data: { projectId: project1.id, type: 'GITHUB', url: 'https://github.com/test-org/viz-repo' }
    });
    project2 = await prisma.project.create({ data: { name: 'Viz Project 2', userId: user2.id } });
  });

  beforeEach(async () => {
    await prisma.scanVulnerabilityMatch.deleteMany({});
    await prisma.vulnerableSoftware.deleteMany({});
    await prisma.vulnerability.deleteMany({});
    await prisma.dependency.deleteMany({});
    await prisma.sbom.deleteMany({});
    await prisma.scan.deleteMany({});
  });

  afterAll(async () => { await prisma.$disconnect(); });

  // 1. Dependency retrieval

  test('1. Returns empty dependency list for a scan with no extracted deps', async () => {
    const scan = await prisma.scan.create({ data: { projectId: project1.id, status: 'COMPLETED' } });
    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/dependencies`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBe(0);
  });

  test('2. Returns correct dependency list with complete field set for visualization', async () => {
    const scan = await prisma.scan.create({ data: { projectId: project1.id, status: 'COMPLETED' } });
    await prisma.dependency.createMany({
      data: [
        { scanId: scan.id, name: 'express',     version: '4.18.2', purl: 'pkg:npm/express@4.18.2',     isDirect: true,  ecosystem: 'npm' },
        { scanId: scan.id, name: 'lodash',      version: '4.17.21',purl: 'pkg:npm/lodash@4.17.21',     isDirect: true,  ecosystem: 'npm' },
        { scanId: scan.id, name: 'ms',          version: '2.1.3',  purl: 'pkg:npm/ms@2.1.3',           isDirect: false, ecosystem: 'npm' },
        { scanId: scan.id, name: 'depd',        version: '2.0.0',  purl: 'pkg:npm/depd@2.0.0',         isDirect: false, ecosystem: 'npm' },
        { scanId: scan.id, name: 'on-finished', version: '2.4.1',  purl: 'pkg:npm/on-finished@2.4.1',  isDirect: false, ecosystem: 'npm' },
      ]
    });
    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/dependencies`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(res.status).toBe(200);
    const deps = res.body.data;
    expect(deps.length).toBe(5);
    for (const dep of deps) {
      expect(dep).toHaveProperty('id');
      expect(dep).toHaveProperty('name');
      expect(dep).toHaveProperty('version');
      expect(dep).toHaveProperty('purl');
      expect(dep).toHaveProperty('isDirect');
      expect(dep).toHaveProperty('ecosystem');
    }
  });

  test('3. Direct vs transitive counts are derivable from isDirect field', async () => {
    const scan = await prisma.scan.create({ data: { projectId: project1.id, status: 'COMPLETED' } });
    await prisma.dependency.createMany({
      data: [
        { scanId: scan.id, name: 'react',       version: '18.0.0', purl: 'pkg:npm/react@18.0.0',       isDirect: true,  ecosystem: 'npm' },
        { scanId: scan.id, name: 'vue',         version: '3.0.0',  purl: 'pkg:npm/vue@3.0.0',          isDirect: true,  ecosystem: 'npm' },
        { scanId: scan.id, name: 'loose-envify',version: '1.4.0',  purl: 'pkg:npm/loose-envify@1.4.0', isDirect: false, ecosystem: 'npm' },
        { scanId: scan.id, name: 'js-tokens',   version: '4.0.0',  purl: 'pkg:npm/js-tokens@4.0.0',    isDirect: false, ecosystem: 'npm' },
        { scanId: scan.id, name: 'scheduler',   version: '0.23.0', purl: 'pkg:npm/scheduler@0.23.0',   isDirect: false, ecosystem: 'npm' },
      ]
    });
    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/dependencies`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(res.status).toBe(200);
    const deps = res.body.data;
    const directCount     = deps.filter(d => d.isDirect === true).length;
    const transitiveCount = deps.filter(d => d.isDirect === false).length;
    expect(directCount).toBe(2);
    expect(transitiveCount).toBe(3);
    expect(directCount + transitiveCount).toBe(5);
  });

  test('4. Dependencies returned in alphabetical order (deterministic rendering)', async () => {
    const scan = await prisma.scan.create({ data: { projectId: project1.id, status: 'COMPLETED' } });
    await prisma.dependency.createMany({
      data: [
        { scanId: scan.id, name: 'zlib',        version: '1.0.0',  purl: 'pkg:npm/zlib@1.0.0',        isDirect: false, ecosystem: 'npm' },
        { scanId: scan.id, name: 'axios',       version: '1.0.0',  purl: 'pkg:npm/axios@1.0.0',       isDirect: true,  ecosystem: 'npm' },
        { scanId: scan.id, name: 'body-parser', version: '1.20.0', purl: 'pkg:npm/body-parser@1.20.0',isDirect: true,  ecosystem: 'npm' },
      ]
    });
    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/dependencies`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(res.status).toBe(200);
    const names = res.body.data.map(d => d.name);
    expect(names).toEqual(['axios', 'body-parser', 'zlib']);
  });

  // 2. SBOM metadata retrieval

  test('5. Returns SBOM with correct CycloneDX 1.5 metadata for visualization', async () => {
    const scan = await prisma.scan.create({ data: { projectId: project1.id, status: 'COMPLETED' } });
    const sbomContent = {
      bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: 'urn:uuid:test-1234', version: 1,
      metadata: {
        timestamp: '2026-09-30T10:00:00.000Z',
        tools: [{ vendor: 'DependShield', name: 'DependShield Scanner', version: '0.1.0' }],
        component: { type: 'application', name: 'Viz Project 1', version: 'unknown' }
      },
      components: [
        {
          'bom-ref': 'dep-uuid-1', type: 'library', name: 'express', version: '4.18.2', purl: 'pkg:npm/express@4.18.2',
          properties: [{ name: 'dependshield:ecosystem', value: 'npm' }, { name: 'dependshield:isDirect', value: 'true' }]
        },
        {
          'bom-ref': 'dep-uuid-2', type: 'library', name: 'ms', version: '2.1.3', purl: 'pkg:npm/ms@2.1.3',
          properties: [{ name: 'dependshield:ecosystem', value: 'npm' }, { name: 'dependshield:isDirect', value: 'false' }]
        }
      ]
    };
    await prisma.sbom.create({ data: { scanId: scan.id, cycloneDxContent: sbomContent } });

    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/sbom`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(res.status).toBe(200);
    const sbom = res.body.data;
    expect(sbom.bomFormat).toBe('CycloneDX');
    expect(sbom.specVersion).toBe('1.5');
    expect(sbom.metadata.timestamp).toBe('2026-09-30T10:00:00.000Z');
    expect(sbom.metadata.tools[0].vendor).toBe('DependShield');
    expect(sbom.components.length).toBe(2);
    const expressComp = sbom.components.find(c => c.name === 'express');
    const isDirect = expressComp.properties.find(p => p.name === 'dependshield:isDirect');
    expect(isDirect.value).toBe('true');
  });

  test('6. SBOM not yet generated returns 404', async () => {
    const scan = await prisma.scan.create({ data: { projectId: project1.id, status: 'EXTRACTING' } });
    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/sbom`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(res.status).toBe(404);
    expect(res.body.error.message).toMatch(/SBOM not yet generated/i);
  });

  test('7. SBOM download mode sets correct Content-Disposition header', async () => {
    const scan = await prisma.scan.create({ data: { projectId: project1.id, status: 'COMPLETED' } });
    await prisma.sbom.create({
      data: {
        scanId: scan.id,
        cycloneDxContent: {
          bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: 'urn:uuid:test', version: 1,
          metadata: { timestamp: '2026-09-30T10:00:00.000Z', tools: [], component: { type: 'application', name: 'test', version: 'unknown' } },
          components: []
        }
      }
    });
    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/sbom?download=true`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(res.status).toBe(200);
    expect(res.headers['content-disposition']).toMatch(/attachment/);
    expect(res.headers['content-disposition']).toMatch(/\.cdx\.json/);
  });

  // 3. Authorization

  test('8. Unauthenticated request to dependencies endpoint returns 401', async () => {
    const scan = await prisma.scan.create({ data: { projectId: project1.id, status: 'COMPLETED' } });
    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/dependencies`);
    expect(res.status).toBe(401);
  });

  test('9. Unauthenticated request to SBOM endpoint returns 401', async () => {
    const scan = await prisma.scan.create({ data: { projectId: project1.id, status: 'COMPLETED' } });
    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/sbom`);
    expect(res.status).toBe(401);
  });

  test('10. User2 cannot access User1 dependency list', async () => {
    const scan = await prisma.scan.create({ data: { projectId: project1.id, status: 'COMPLETED' } });
    await prisma.dependency.create({
      data: { scanId: scan.id, name: 'express', version: '4.18.2', purl: 'pkg:npm/express@4.18.2', isDirect: true, ecosystem: 'npm' }
    });
    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/dependencies`)
      .set('Cookie', [`ds_token=${token2}`]);
    expect(res.status).toBe(404);
  });

  test('11. User2 cannot access User1 SBOM', async () => {
    const scan = await prisma.scan.create({ data: { projectId: project1.id, status: 'COMPLETED' } });
    await prisma.sbom.create({
      data: {
        scanId: scan.id,
        cycloneDxContent: {
          bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: 'urn:uuid:test', version: 1,
          metadata: { timestamp: '2026-09-30T10:00:00.000Z', tools: [], component: { type: 'application', name: 'test', version: 'unknown' } },
          components: []
        }
      }
    });
    const res = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/sbom`)
      .set('Cookie', [`ds_token=${token2}`]);
    expect(res.status).toBe(404);
  });

  // 4. Historical scan access

  test('12. Visualization data is accessible for historical completed scans', async () => {
    const oldDate = new Date(Date.now() - 86400000);
    const scan = await prisma.scan.create({
      data: { projectId: project1.id, status: 'COMPLETED', createdAt: oldDate, completedAt: new Date(oldDate.getTime() + 8000) }
    });
    await prisma.dependency.createMany({
      data: [
        { scanId: scan.id, name: 'express', version: '4.17.1', purl: 'pkg:npm/express@4.17.1', isDirect: true,  ecosystem: 'npm' },
        { scanId: scan.id, name: 'debug',   version: '2.6.9',  purl: 'pkg:npm/debug@2.6.9',   isDirect: false, ecosystem: 'npm' },
      ]
    });
    await prisma.sbom.create({
      data: {
        scanId: scan.id,
        cycloneDxContent: {
          bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: 'urn:uuid:hist-test', version: 1,
          metadata: { timestamp: oldDate.toISOString(), tools: [], component: { type: 'application', name: 'Viz Project 1', version: 'unknown' } },
          components: [
            { 'bom-ref': 'id1', type: 'library', name: 'express', version: '4.17.1', purl: 'pkg:npm/express@4.17.1' },
            { 'bom-ref': 'id2', type: 'library', name: 'debug',   version: '2.6.9',  purl: 'pkg:npm/debug@2.6.9'   }
          ]
        }
      }
    });
    const depRes = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/dependencies`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(depRes.status).toBe(200);
    expect(depRes.body.data.length).toBe(2);

    const sbomRes = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/sbom`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(sbomRes.status).toBe(200);
    expect(sbomRes.body.data.components.length).toBe(2);
    expect(sbomRes.body.data.metadata.timestamp).toBe(oldDate.toISOString());
  });

  // 5. Dependency-vulnerability linkage for visualization

  test('13. Dependencies with vulnerability matches identified via dashboard endpoint', async () => {
    const scan = await prisma.scan.create({ data: { projectId: project1.id, status: 'COMPLETED', riskScore: 15.0 } });
    const dep = await prisma.dependency.create({
      data: { scanId: scan.id, name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20', isDirect: true, ecosystem: 'npm' }
    });
    await prisma.dependency.create({
      data: { scanId: scan.id, name: 'debug', version: '4.3.4', purl: 'pkg:npm/debug@4.3.4', isDirect: false, ecosystem: 'npm' }
    });
    const vuln = await prisma.vulnerability.create({ data: { cveId: 'CVE-VIZ-001', severity: 'CRITICAL', source: 'NVD' } });
    await prisma.scanVulnerabilityMatch.create({
      data: { dependencyId: dep.id, vulnerabilityId: vuln.id, riskScore: 15.0, severityWeight: 10, contextWeight: 1.5 }
    });
    const dashRes = await request(app)
      .get(`/api/v1/projects/${project1.id}/scans/${scan.id}/dashboard`)
      .set('Cookie', [`ds_token=${token1}`]);
    expect(dashRes.status).toBe(200);
    const { summary, findings } = dashRes.body.data;
    expect(summary.totalDependencies).toBe(2);
    expect(summary.totalFindings).toBe(1);
    expect(findings[0].packageName).toBe('lodash');
    expect(findings[0].isDirect).toBe(true);
    expect(findings[0].cveId).toBe('CVE-VIZ-001');
  });
});
