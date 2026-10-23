const request = require('supertest');
const app = require('../src/app');
const prisma = require('../src/config/db');

describe('API Health and Database Connection', () => {
  beforeAll(async () => {
    // Attempt to connect to the database to ensure Prisma is ready
    try {
      await prisma.$connect();
    } catch (e) {
      console.warn('Could not connect to database for tests, some tests may fail');
    }
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('GET /api/v1/health - should return 200 OK and connected DB status', async () => {
    const res = await request(app).get('/api/v1/health');
    
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('status', 'ok');
    expect(res.body).toHaveProperty('database', 'connected');
    expect(res.body).toHaveProperty('timestamp');
  });

  it('GET /api/v1/unknown-route - should return 404 for non-existent routes', async () => {
    const res = await request(app).get('/api/v1/unknown-route');
    
    expect(res.statusCode).toBe(404);
    expect(res.body).toHaveProperty('error');
    expect(res.body.error.message).toBe('Resource Not Found');
  });
});
