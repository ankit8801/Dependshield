const request = require('supertest');
const app = require('../src/app');
const { PrismaClient } = require('@prisma/client');
const { generateSbom, buildNpmPurl, validateSbom, CYCLONEDX_SPEC_VERSION } = require('../src/services/sbomService');

const prisma = new PrismaClient();
let userToken, userId, projectId;

beforeAll(async () => {
  await prisma.sbom.deleteMany({});
  await prisma.dependency.deleteMany({});
  await prisma.scan.deleteMany({});
  await prisma.repository.deleteMany({});
  await prisma.project.deleteMany({});
  await prisma.user.deleteMany({});

  const res = await request(app)
    .post('/api/v1/auth/register')
    .send({ email: 'sbom@test.com', password: 'Password123' });
  userToken = res.body.data.token;
  userId = res.body.data.user.id;

  const projRes = await request(app)
    .post('/api/v1/projects')
    .set('Authorization', `Bearer ${userToken}`)
    .send({ name: 'SBOM Test Project' });
  projectId = projRes.body.data.id;
});

afterAll(async () => {
  await prisma.sbom.deleteMany({});
  await prisma.dependency.deleteMany({});
  await prisma.scan.deleteMany({});
  await prisma.repository.deleteMany({});
  await prisma.project.deleteMany({});
  await prisma.user.deleteMany({});
  await prisma.$disconnect();
});

describe('SBOM Service - buildNpmPurl', () => {
  test('1. Generates correct PURL for a regular package', () => {
    expect(buildNpmPurl('express', '4.18.2')).toBe('pkg:npm/express@4.18.2');
  });

  test('2. Generates correct PURL for a scoped package', () => {
    expect(buildNpmPurl('@types/node', '20.9.0')).toBe('pkg:npm/%40types/node@20.9.0');
  });

  test('3. Handles missing version gracefully', () => {
    expect(buildNpmPurl('lodash', null)).toBe('pkg:npm/lodash@unknown');
    expect(buildNpmPurl('lodash', undefined)).toBe('pkg:npm/lodash@unknown');
  });
});

describe('SBOM Service - validateSbom', () => {
  test('4. Accepts a valid SBOM', () => {
    const valid = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: 'urn:uuid:test',
      version: 1,
      metadata: {},
      components: [
        { 'bom-ref': '1', type: 'library', name: 'foo', version: '1.0.0', purl: 'pkg:npm/foo@1.0.0' }
      ]
    };
    expect(() => validateSbom(valid)).not.toThrow();
  });

  test('5. Rejects SBOM missing required field', () => {
    const invalid = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      // missing serialNumber, version, metadata, components
    };
    expect(() => validateSbom(invalid)).toThrow('missing required field');
  });

  test('6. Rejects SBOM with non-array components', () => {
    const invalid = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: 'x',
      version: 1,
      metadata: {},
      components: 'not-an-array'
    };
    expect(() => validateSbom(invalid)).toThrow('"components" must be an array');
  });

  test('7. Rejects component missing required fields', () => {
    const invalid = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: 'x',
      version: 1,
      metadata: {},
      components: [{ type: 'library' }] // missing name, version, bom-ref
    };
    expect(() => validateSbom(invalid)).toThrow('component missing');
  });
});

describe('SBOM Service - generateSbom', () => {
  test('8. Generates valid SBOM from dependencies', async () => {
    const scan = await prisma.scan.create({
      data: { projectId, status: 'SBOM_GENERATING' }
    });

    await prisma.dependency.createMany({
      data: [
        { scanId: scan.id, name: 'express', version: '4.18.2', purl: 'pkg:npm/express@4.18.2', isDirect: true, ecosystem: 'npm' },
        { scanId: scan.id, name: 'accepts', version: '1.3.8', purl: 'pkg:npm/accepts@1.3.8', isDirect: false, ecosystem: 'npm' },
        { scanId: scan.id, name: '@types/node', version: '20.9.0', purl: 'pkg:npm/%40types/node@20.9.0', isDirect: true, ecosystem: 'npm' },
      ]
    });

    const sbomDoc = await generateSbom(scan.id);

    // Top-level CycloneDX fields
    expect(sbomDoc.bomFormat).toBe('CycloneDX');
    expect(sbomDoc.specVersion).toBe(CYCLONEDX_SPEC_VERSION);
    expect(sbomDoc.serialNumber).toMatch(/^urn:uuid:/);
    expect(sbomDoc.version).toBe(1);
    expect(sbomDoc.metadata).toBeDefined();
    expect(sbomDoc.metadata.tools).toBeDefined();
    expect(sbomDoc.metadata.component.name).toBe('SBOM Test Project');

    // Components
    expect(sbomDoc.components).toHaveLength(3);

    const expressCmp = sbomDoc.components.find(c => c.name === 'express');
    expect(expressCmp.type).toBe('library');
    expect(expressCmp.version).toBe('4.18.2');
    expect(expressCmp.purl).toBe('pkg:npm/express@4.18.2');

    const scopedCmp = sbomDoc.components.find(c => c.name === '@types/node');
    expect(scopedCmp.purl).toBe('pkg:npm/%40types/node@20.9.0');

    // DB persistence
    const saved = await prisma.sbom.findUnique({ where: { scanId: scan.id } });
    expect(saved).not.toBeNull();
    expect(saved.cycloneDxContent.components).toHaveLength(3);
  });

  test('9. Generates valid SBOM with zero dependencies', async () => {
    const scan = await prisma.scan.create({
      data: { projectId, status: 'SBOM_GENERATING' }
    });

    const sbomDoc = await generateSbom(scan.id);
    expect(sbomDoc.components).toHaveLength(0);
    expect(sbomDoc.bomFormat).toBe('CycloneDX');
  });

  test('10. Throws for non-existent scan', async () => {
    await expect(generateSbom('00000000-0000-0000-0000-000000000000'))
      .rejects.toThrow('not found');
  });
});

describe('SBOM API', () => {
  let scanId;

  beforeAll(async () => {
    const scan = await prisma.scan.create({
      data: { projectId, status: 'COMPLETED' }
    });
    scanId = scan.id;

    await prisma.dependency.createMany({
      data: [
        { scanId, name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21', isDirect: true, ecosystem: 'npm' },
      ]
    });

    await generateSbom(scanId);
  });

  test('11. GET sbom returns valid CycloneDX JSON', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${projectId}/scans/${scanId}/sbom`)
      .set('Authorization', `Bearer ${userToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data.bomFormat).toBe('CycloneDX');
    expect(res.body.data.specVersion).toBe('1.5');
    expect(res.body.data.components.length).toBe(1);
    expect(res.body.data.components[0].name).toBe('lodash');
  });

  test('12. GET sbom with download=true returns Content-Disposition', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${projectId}/scans/${scanId}/sbom?download=true`)
      .set('Authorization', `Bearer ${userToken}`);

    expect(res.status).toBe(200);
    expect(res.headers['content-disposition']).toContain('attachment');
    expect(res.headers['content-disposition']).toContain('.cdx.json');
    expect(res.headers['content-type']).toContain('application/json');

    const body = JSON.parse(res.text);
    expect(body.bomFormat).toBe('CycloneDX');
  });

  test('13. GET sbom for scan without SBOM returns 404', async () => {
    const scan2 = await prisma.scan.create({
      data: { projectId, status: 'EXTRACTING' }
    });

    const res = await request(app)
      .get(`/api/v1/projects/${projectId}/scans/${scan2.id}/sbom`)
      .set('Authorization', `Bearer ${userToken}`);

    expect(res.status).toBe(404);
    expect(res.body.error.message).toContain('SBOM not yet generated');
  });

  test('14. GET sbom without auth returns 401', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${projectId}/scans/${scanId}/sbom`);

    expect(res.status).toBe(401);
  });

  test('15. GET sbom for another user\'s project returns 404', async () => {
    // Register a different user
    const res2 = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'sbom-other@test.com', password: 'Password123' });
    const otherToken = res2.body.data.token;

    const res = await request(app)
      .get(`/api/v1/projects/${projectId}/scans/${scanId}/sbom`)
      .set('Authorization', `Bearer ${otherToken}`);

    expect(res.status).toBe(404);
  });
});
