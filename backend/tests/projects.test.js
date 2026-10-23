const request = require('supertest');
const app = require('../src/app');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

let userToken;
let otherUserToken;
let userId;
let otherUserId;

beforeAll(async () => {
  // Clear tables
  await prisma.repository.deleteMany({});
  await prisma.project.deleteMany({});
  await prisma.user.deleteMany({});

  // Create users via API to get tokens properly
  const res1 = await request(app)
    .post('/api/v1/auth/register')
    .send({ email: 'proj1@test.com', password: 'Password123' });
  userToken = res1.body.data.token;
  userId = res1.body.data.user.id;

  const res2 = await request(app)
    .post('/api/v1/auth/register')
    .send({ email: 'proj2@test.com', password: 'Password123' });
  otherUserToken = res2.body.data.token;
  otherUserId = res2.body.data.user.id;
});

afterAll(async () => {
  await prisma.repository.deleteMany({});
  await prisma.project.deleteMany({});
  await prisma.user.deleteMany({});
  await prisma.$disconnect();
});

describe('Projects API', () => {
  let createdProjectId;

  test('1. Unauthenticated user cannot create project', async () => {
    const res = await request(app)
      .post('/api/v1/projects')
      .send({ name: 'Test Project' });
    expect(res.status).toBe(401);
  });

  test('2. Authenticated user creates project', async () => {
    const res = await request(app)
      .post('/api/v1/projects')
      .set('Authorization', `Bearer ${userToken}`)
      .send({ name: 'My Secure Project', description: 'Testing backend' });
    
    expect(res.status).toBe(201);
    expect(res.body.data.name).toBe('My Secure Project');
    expect(res.body.data.description).toBe('Testing backend');
    expect(res.body.data.userId).toBe(userId);
    createdProjectId = res.body.data.id;
  });

  test('3. Validation error on missing project name', async () => {
    const res = await request(app)
      .post('/api/v1/projects')
      .set('Authorization', `Bearer ${userToken}`)
      .send({});
    expect(res.status).toBe(400);
  });

  test('3a. Validation error on over-limit project name (101 chars)', async () => {
    const res = await request(app)
      .post('/api/v1/projects')
      .set('Authorization', `Bearer ${userToken}`)
      .send({ name: 'A'.repeat(101) });
    expect(res.status).toBe(400);
  });

  test('3b. Success on maximum valid project name (100 chars)', async () => {
    const res = await request(app)
      .post('/api/v1/projects')
      .set('Authorization', `Bearer ${userToken}`)
      .send({ name: 'A'.repeat(100) });
    expect(res.status).toBe(201);
  });

  test('3c. Validation error on over-limit description (501 chars)', async () => {
    const res = await request(app)
      .post('/api/v1/projects')
      .set('Authorization', `Bearer ${userToken}`)
      .send({ name: 'Proj', description: 'A'.repeat(501) });
    expect(res.status).toBe(400);
  });

  test('3d. Success on maximum description (500 chars)', async () => {
    const res = await request(app)
      .post('/api/v1/projects')
      .set('Authorization', `Bearer ${userToken}`)
      .send({ name: 'Proj2', description: 'A'.repeat(500) });
    expect(res.status).toBe(201);
  });

  test('4. User retrieves their projects', async () => {
    const res = await request(app)
      .get('/api/v1/projects')
      .set('Authorization', `Bearer ${userToken}`);
    
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.find(p => p.id === createdProjectId)).toBeDefined();
  });

  test('5. User retrieves their project by ID', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${createdProjectId}`)
      .set('Authorization', `Bearer ${userToken}`);
    
    expect(res.status).toBe(200);
    expect(res.body.data.name).toBe('My Secure Project');
  });

  test('6. User cannot retrieve another user\'s project', async () => {
    const res = await request(app)
      .get(`/api/v1/projects/${createdProjectId}`)
      .set('Authorization', `Bearer ${otherUserToken}`);
    
    expect(res.status).toBe(404);
  });

  test('6a. User cannot retrieve non-existent project', async () => {
    const res = await request(app)
      .get('/api/v1/projects/00000000-0000-0000-0000-000000000000')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(404);
  });

  test('6b. Malformed UUID for project retrieval returns 400', async () => {
    const res = await request(app)
      .get('/api/v1/projects/not-a-uuid')
      .set('Authorization', `Bearer ${userToken}`);
    expect(res.status).toBe(400);
  });

  test('7. User updates their project', async () => {
    const res = await request(app)
      .patch(`/api/v1/projects/${createdProjectId}`)
      .set('Authorization', `Bearer ${userToken}`)
      .send({ name: 'Updated Name' });
    
    expect(res.status).toBe(200);
    expect(res.body.data.name).toBe('Updated Name');
    // Description should remain unchanged in theory, depending on implementation
  });

  test('8. User cannot update another user\'s project', async () => {
    const res = await request(app)
      .patch(`/api/v1/projects/${createdProjectId}`)
      .set('Authorization', `Bearer ${otherUserToken}`)
      .send({ name: 'Hacked Name' });
    
    expect(res.status).toBe(404);
  });
  
  test('9. User creates a repository source', async () => {
    const res = await request(app)
      .post(`/api/v1/projects/${createdProjectId}/repository`)
      .set('Authorization', `Bearer ${userToken}`)
      .send({ url: 'https://github.com/user/repo' });
    
    expect(res.status).toBe(200);
    expect(res.body.data.url).toBe('https://github.com/user/repo');
    expect(res.body.data.type).toBe('GITHUB');
  });

  test('10. Invalid repository URL is rejected', async () => {
    const res = await request(app)
      .post(`/api/v1/projects/${createdProjectId}/repository`)
      .set('Authorization', `Bearer ${userToken}`)
      .send({ url: 'not-a-url' });
    
    expect(res.status).toBe(400);
  });

  test('11. Unsupported repository host is rejected', async () => {
    const res = await request(app)
      .post(`/api/v1/projects/${createdProjectId}/repository`)
      .set('Authorization', `Bearer ${userToken}`)
      .send({ url: 'https://gitlab.com/user/repo' });
    
    expect(res.status).toBe(400);
    expect(res.body.error.details[0].message).toContain('Only GitHub URLs');
  });

  test('12. User cannot manipulate another user\'s repository', async () => {
    const res = await request(app)
      .post(`/api/v1/projects/${createdProjectId}/repository`)
      .set('Authorization', `Bearer ${otherUserToken}`)
      .send({ url: 'https://github.com/other/repo' });
    
    expect(res.status).toBe(404); // returns 404 because project doesn't belong to them
  });

  test('13. User deletes/archives their project', async () => {
    const res = await request(app)
      .delete(`/api/v1/projects/${createdProjectId}`)
      .set('Authorization', `Bearer ${userToken}`);
    
    expect(res.status).toBe(200);
    
    // Verify it's gone
    const getRes = await request(app)
      .get(`/api/v1/projects/${createdProjectId}`)
      .set('Authorization', `Bearer ${userToken}`);
    expect(getRes.status).toBe(404);
  });
});
