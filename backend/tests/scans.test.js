const request = require('supertest');
const app = require('../src/app');
const { PrismaClient } = require('@prisma/client');
const fs = require('fs/promises');
const path = require('path');
const os = require('os');
const AdmZip = require('adm-zip');

const prisma = new PrismaClient();
let userToken, userId, projectId;

beforeAll(async () => {
  await prisma.sbom.deleteMany({});
  await prisma.dependency.deleteMany({});
  await prisma.scan.deleteMany({});
  await prisma.repository.deleteMany({});
  await prisma.project.deleteMany({});
  await prisma.user.deleteMany({});

  const res1 = await request(app)
    .post('/api/v1/auth/register')
    .send({ email: 'scan@test.com', password: 'Password123' });
  userToken = res1.body.data.token;
  userId = res1.body.data.user.id;

  const projRes = await request(app)
    .post('/api/v1/projects')
    .set('Authorization', `Bearer ${userToken}`)
    .send({ name: 'Scan Project' });
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

describe('Ingestion & Scans API', () => {
  let validZipPath;

  beforeAll(async () => {
    // Create a valid dummy zip
    const zip = new AdmZip();
    zip.addFile('test.txt', Buffer.from('hello world'));
    zip.addFile('package.json', Buffer.from(JSON.stringify({
      dependencies: { "express": "4.18.2" }
    })));
    validZipPath = path.join(os.tmpdir(), 'valid.zip');
    zip.writeZip(validZipPath);
  });

  afterAll(async () => {
    await fs.unlink(validZipPath).catch(() => {});
  });

  test('1. Start GitHub scan without repository fails', async () => {
    const res = await request(app)
      .post(`/api/v1/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${userToken}`);
    
    expect(res.status).toBe(201);
    
    // Wait for async processing
    let scan;
    let attempts = 0;
    while (attempts < 10) {
      scan = await prisma.scan.findUnique({ where: { id: res.body.data.id }});
      if (scan.status === 'FAILED') break;
      await new Promise(r => setTimeout(r, 500));
      attempts++;
    }
    expect(scan.status).toBe('FAILED');
    expect(scan.errorMessage).toContain('No valid source');
  }, 10000);

  test('2. Upload valid ZIP starts scan and extracts', async () => {
    const res = await request(app)
      .post(`/api/v1/projects/${projectId}/scans/upload`)
      .set('Authorization', `Bearer ${userToken}`)
      .attach('file', validZipPath);

    expect(res.status).toBe(201);
    expect(res.body.data.status).toBe('QUEUED');
    
    // Wait for async processing (polling up to 15s)
    let scan;
    let attempts = 0;
    while (attempts < 30) {
      scan = await prisma.scan.findUnique({ where: { id: res.body.data.id }});
      if (scan.status === 'COMPLETED' || scan.status === 'FAILED') break;
      await new Promise(r => setTimeout(r, 500));
      attempts++;
    }
    
    // Phase 7: full pipeline runs (ingest → extract → SBOM → COMPLETED)
    if (scan.status === 'FAILED') {
      throw new Error(`Scan failed unexpectedly with message: ${scan.errorMessage}`);
    }
    expect(scan.status).toBe('COMPLETED');
  }, 20000); // increase test timeout

  test('3. Upload Zip Slip payload fails securely', async () => {
    // Create malicious zip
    const zip = new AdmZip();
    zip.addFile('evil.txt', Buffer.from('evil'));
    zip.getEntries()[0].entryName = '../../../../../../../tmp/evil.txt';
    const evilZipPath = path.join(os.tmpdir(), 'evil.zip');
    zip.writeZip(evilZipPath);

    const res = await request(app)
      .post(`/api/v1/projects/${projectId}/scans/upload`)
      .set('Authorization', `Bearer ${userToken}`)
      .attach('file', evilZipPath);

    expect(res.status).toBe(201);
    
    // Wait for async processing
    let scan;
    let attempts = 0;
    while (attempts < 10) {
      scan = await prisma.scan.findUnique({ where: { id: res.body.data.id }});
      if (scan.status === 'FAILED') break;
      await new Promise(r => setTimeout(r, 500));
      attempts++;
    }
    expect(scan.status).toBe('FAILED');
    expect(scan.errorMessage).toMatch(/Path traversal|invalid relative path/i);

    await fs.unlink(evilZipPath).catch(() => {});
  }, 10000);
  
  test('4. Start GitHub scan successfully', async () => {
    // Add repository first
    await request(app)
      .post(`/api/v1/projects/${projectId}/repository`)
      .set('Authorization', `Bearer ${userToken}`)
      .send({ url: 'https://github.com/expressjs/express' });

    const res = await request(app)
      .post(`/api/v1/projects/${projectId}/scans`)
      .set('Authorization', `Bearer ${userToken}`);
    
    expect(res.status).toBe(201);
    
    // Wait for async processing (might take a bit to download and extract)
    await new Promise(r => setTimeout(r, 3000));
    const scan = await prisma.scan.findUnique({ where: { id: res.body.data.id }});
    // Might still be in-progress depending on download speed
    expect(['ANALYZING', 'EXTRACTING', 'SBOM_GENERATING', 'COMPLETED', 'INGESTING', 'VULNERABILITY_ANALYSIS']).toContain(scan.status);
  }, 10000);

  test('5. Get scan dependencies returns 200', async () => {
    // Create a dummy scan manually with dependencies to test the endpoint
    const scan = await prisma.scan.create({
      data: {
        projectId,
        status: 'SBOM_GENERATING'
      }
    });

    await prisma.dependency.create({
      data: {
        scanId: scan.id,
        name: 'express',
        version: '4.18.2',
        purl: 'pkg:npm/express@4.18.2',
        isDirect: true,
        ecosystem: 'npm'
      }
    });

    const res = await request(app)
      .get(`/api/v1/projects/${projectId}/scans/${scan.id}/dependencies`)
      .set('Authorization', `Bearer ${userToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data.length).toBe(1);
    expect(res.body.data[0].name).toBe('express');
  });
});
