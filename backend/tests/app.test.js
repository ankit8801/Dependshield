/**
 * Unit tests for Express app structure and error handling.
 * These tests do NOT require a live database connection.
 */
const request = require('supertest');
const app = require('../src/app');

describe('App Structure - Offline Tests (no DB required)', () => {
  it('GET /api/v1/unknown-route - should return 404 for unknown routes', async () => {
    const res = await request(app).get('/api/v1/unknown-route');
    expect(res.statusCode).toBe(404);
    expect(res.body).toHaveProperty('error');
    expect(res.body.error).toHaveProperty('message', 'Resource Not Found');
  });

  it('GET /nonexistent-path - should return 404 for unknown top-level routes', async () => {
    const res = await request(app).get('/nonexistent-path');
    expect(res.statusCode).toBe(404);
    expect(res.body).toHaveProperty('error');
  });

  it('Health endpoint exists and returns JSON', async () => {
    const res = await request(app).get('/api/v1/health');
    // Even if DB is down, response should still be JSON with a status field
    expect(res.headers['content-type']).toMatch(/json/);
    expect(res.body).toHaveProperty('status');
    expect(res.body).toHaveProperty('timestamp');
  });

  it('Health endpoint returns ok (DB up)', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});
