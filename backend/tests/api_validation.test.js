/**
 * Phase 17 – API Refinement Tests
 *
 * Tests added specifically for:
 *   1. Malformed UUID params → 400 (not 500/Prisma crash)
 *   2. Invalid report format query → 400
 *   3. Dashboard endpoint returns 404 for unknown scan (not 500)
 *   4. Report format query parameter validation
 */
const request = require('supertest');
const app = require('../src/app');
const { PrismaClient } = require('@prisma/client');

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
    .send({ email: 'phase17@test.com', password: 'Password123' });
  userToken = res.body.data.token;
  userId = res.body.data.user.id;

  const projRes = await request(app)
    .post('/api/v1/projects')
    .set('Authorization', `Bearer ${userToken}`)
    .send({ name: 'Phase17 Project' });
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

// ──────────────────────────────────────────────────────────
// UUID PARAM VALIDATION
// ──────────────────────────────────────────────────────────
describe('UUID param validation – project routes', () => {
  test('GET /projects/:id with malformed id returns 400', async () => {
    const res = await request(app)
      .get('/api/v1/projects/not-a-uuid')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });

  test('PATCH /projects/:id with malformed id returns 400', async () => {
    const res = await request(app)
      .patch('/api/v1/projects/bad-id')
      .set('Authorization', `Bearer ${userToken}`)
      .send({ name: 'Updated' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });

  test('DELETE /projects/:id with malformed id returns 400', async () => {
    const res = await request(app)
      .delete('/api/v1/projects/bad-id')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });
});

describe('UUID param validation – scan routes', () => {
  const fakeProjectId = '00000000-0000-0000-0000-000000000000';
  const fakeScanId = '11111111-1111-1111-1111-111111111111';

  test('GET /projects/:projectId/scans with malformed projectId returns 400', async () => {
    const res = await request(app)
      .get('/api/v1/projects/not-a-uuid/scans')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });

  test('GET /projects/:projectId/scans/:scanId with malformed scanId returns 400', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${fakeProjectId}/scans/bad-scan-id`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });

  test('GET /scans/:scanId/dependencies with malformed projectId returns 400', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/not-a-uuid/scans/${fakeScanId}/dependencies`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });

  test('GET /scans/:scanId/sbom with malformed scanId returns 400', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${fakeProjectId}/scans/bad/sbom`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });

  test('GET /scans/:scanId/vulnerabilities with malformed id returns 400', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/not-uuid/scans/${fakeScanId}/vulnerabilities`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });

  test('GET /scans/:scanId/risk with malformed id returns 400', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${fakeProjectId}/scans/bad/risk`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });

  test('GET /scans/:scanId/dashboard with malformed id returns 400', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/not-uuid/scans/${fakeScanId}/dashboard`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });

  test('POST /projects/:projectId/scans with malformed projectId returns 400', async () => {
    const res = await request(app)
      .post('/api/v1/projects/not-a-uuid/scans')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });
});

// ──────────────────────────────────────────────────────────
// REPORT FORMAT QUERY VALIDATION
// ──────────────────────────────────────────────────────────
describe('Report format query validation', () => {
  const fakeScanId = '11111111-1111-1111-1111-111111111111';

  test('GET /report with invalid format returns 400', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${projectId}/scans/${fakeScanId}/report?format=xml`)
      .set('Authorization', `Bearer ${userToken}`);
    // xml is not a valid format — should be 400 before hitting the controller
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });

  test('GET /report with valid format=html is processed (404 for non-existent scan)', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${projectId}/scans/${fakeScanId}/report?format=html`)
      .set('Authorization', `Bearer ${userToken}`);
    // passes format validation, then hits 404 because scan doesn't exist
    expect(res.status).toBe(404);
  });

  test('GET /report with valid format=markdown is processed (404 for non-existent scan)', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${projectId}/scans/${fakeScanId}/report?format=markdown`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(404);
  });
});

// ──────────────────────────────────────────────────────────
// DASHBOARD ENDPOINT — 404 for unknown scan
// ──────────────────────────────────────────────────────────
describe('Dashboard endpoint error handling', () => {
  const unknownScanId = '22222222-2222-2222-2222-222222222222';

  test('GET /dashboard for unknown scanId returns 404, not 500', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${projectId}/scans/${unknownScanId}/dashboard`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(404);
    expect(res.body.error.message).toBe('Scan not found');
  });

  test('GET /dashboard with wrong projectId for existing scan returns 404', async () => {
    // Create a scan under our real project
    const scanRes = await prisma.scan.create({
      data: { projectId, status: 'QUEUED' }
    });
    const otherProjectId = '33333333-3333-3333-3333-333333333333';
    const res = await request(app)
      .get(`/api/v1/projects/${otherProjectId}/scans/${scanRes.id}/dashboard`)
      .set('Authorization', `Bearer ${userToken}`);
    // Auth check: otherProject doesn't belong to this user → 404
    expect(res.status).toBe(404);
    await prisma.scan.delete({ where: { id: scanRes.id } });
  });
});

// ──────────────────────────────────────────────────────────
// AUTHENTICATION ON ALL ROUTES
// ──────────────────────────────────────────────────────────
describe('Authentication required on all scan routes', () => {
  const fakeProjectId = '00000000-0000-0000-0000-000000000000';
  const fakeScanId = '11111111-1111-1111-1111-111111111111';

  const routes = [
    { method: 'get', path: `/api/v1/projects/${fakeProjectId}/scans` },
    { method: 'get', path: `/api/v1/projects/${fakeProjectId}/scans/${fakeScanId}` },
    { method: 'get', path: `/api/v1/projects/${fakeProjectId}/scans/${fakeScanId}/dependencies` },
    { method: 'get', path: `/api/v1/projects/${fakeProjectId}/scans/${fakeScanId}/sbom` },
    { method: 'get', path: `/api/v1/projects/${fakeProjectId}/scans/${fakeScanId}/vulnerabilities` },
    { method: 'get', path: `/api/v1/projects/${fakeProjectId}/scans/${fakeScanId}/risk` },
    { method: 'get', path: `/api/v1/projects/${fakeProjectId}/scans/${fakeScanId}/dashboard` },
    { method: 'get', path: `/api/v1/projects/${fakeProjectId}/scans/${fakeScanId}/report` },
    { method: 'post', path: `/api/v1/projects/${fakeProjectId}/scans` },
  ];

  for (const { method, path } of routes) {
    test(`${method.toUpperCase()} ${path} without token → 401`, async () => {
      const res = await request(app)[method](path);
      expect(res.status).toBe(401);
    });
  }
});
