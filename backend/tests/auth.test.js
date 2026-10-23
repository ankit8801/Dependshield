/**
 * Phase 3 Authentication Tests
 *
 * Requires a live PostgreSQL database.
 * DB started via: docker compose up db -d
 *
 * Covers:
 *  1.  Successful registration
 *  2.  Duplicate email registration
 *  3.  Invalid registration data (missing fields, weak password)
 *  4.  Password hashing (never stored in plaintext)
 *  5.  Successful login
 *  6.  Invalid login credentials
 *  7.  JWT token validation
 *  8.  Missing token on protected route
 *  9.  Invalid/tampered token on protected route
 *  10. Expired token rejection
 *  11. GET /auth/me with valid token
 *  12. Unauthorized access to protected route
 *  13. Authorized authenticated request
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = require('../src/app');
const prisma = require('../src/config/db');

// Use a unique test email prefix to avoid collisions between runs
const testEmail = () => `test_${Date.now()}_${Math.random().toString(36).slice(2)}@example.com`;
const VALID_PASSWORD = 'TestPass1';

beforeAll(async () => {
  // Clean up any stale test users from previous incomplete runs
  await prisma.user.deleteMany({
    where: { email: { contains: 'test_' } },
  });
});

afterAll(async () => {
  // Clean up test users created during this run
  await prisma.user.deleteMany({
    where: { email: { contains: 'test_' } },
  });
  await prisma.$disconnect();
});

// ─────────────────────────────────────────────────────────────────────────────
// 1. REGISTRATION
// ─────────────────────────────────────────────────────────────────────────────

describe('POST /api/v1/auth/register', () => {
  test('1. Successful registration returns 201 with user and token', async () => {
    const email = testEmail();
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email, password: VALID_PASSWORD });

    expect(res.statusCode).toBe(201);
    expect(res.body.data.user.email).toBe(email);
    expect(res.body.data.token).toBeDefined();
    // CRITICAL: password hash must never appear in response
    expect(JSON.stringify(res.body)).not.toContain('passwordHash');
    expect(JSON.stringify(res.body)).not.toContain('password_hash');
    expect(JSON.stringify(res.body)).not.toContain(VALID_PASSWORD);
    // HttpOnly cookie must be set
    expect(res.headers['set-cookie']).toBeDefined();
    expect(res.headers['set-cookie'].some(c => c.startsWith('ds_token='))).toBe(true);
    expect(res.headers['set-cookie'].some(c => c.includes('HttpOnly'))).toBe(true);
  });

  test('2. Duplicate email returns 409 Conflict', async () => {
    const email = testEmail();
    await request(app).post('/api/v1/auth/register').send({ email, password: VALID_PASSWORD });
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email, password: VALID_PASSWORD });

    expect(res.statusCode).toBe(409);
    expect(res.body.error.message).toMatch(/already exists/i);
  });

  test('3a. Missing email returns 400 validation error', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ password: VALID_PASSWORD });

    expect(res.statusCode).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });

  test('3b. Missing password returns 400 validation error', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: testEmail() });

    expect(res.statusCode).toBe(400);
    expect(res.body.error.message).toBe('Validation Error');
  });

  test('3c. Invalid email format returns 400', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'not-an-email', password: VALID_PASSWORD });

    expect(res.statusCode).toBe(400);
  });

  test('3d. Weak password (no uppercase) returns 400', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: testEmail(), password: 'nouppercase1' });

    expect(res.statusCode).toBe(400);
  });

  test('3e. Password too short returns 400', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: testEmail(), password: 'Ab1' });

    expect(res.statusCode).toBe(400);
  });

  test('4. Password is hashed in database — never stored plaintext', async () => {
    const email = testEmail();
    await request(app).post('/api/v1/auth/register').send({ email, password: VALID_PASSWORD });

    const user = await prisma.user.findUnique({ where: { email } });
    expect(user).not.toBeNull();
    // Hash must not equal the original password
    expect(user.passwordHash).not.toBe(VALID_PASSWORD);
    // Must be a valid bcrypt hash
    expect(user.passwordHash).toMatch(/^\$2[aby]\$\d{2}\$/);
    // bcrypt.compare must still work
    const isValid = await bcrypt.compare(VALID_PASSWORD, user.passwordHash);
    expect(isValid).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. LOGIN
// ─────────────────────────────────────────────────────────────────────────────

describe('POST /api/v1/auth/login', () => {
  let registeredEmail;

  beforeAll(async () => {
    registeredEmail = testEmail();
    await request(app)
      .post('/api/v1/auth/register')
      .send({ email: registeredEmail, password: VALID_PASSWORD });
  });

  test('5. Successful login returns 200 with user and token', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: registeredEmail, password: VALID_PASSWORD });

    expect(res.statusCode).toBe(200);
    expect(res.body.data.user.email).toBe(registeredEmail);
    expect(res.body.data.token).toBeDefined();
    expect(JSON.stringify(res.body)).not.toContain('passwordHash');
    expect(res.headers['set-cookie'].some(c => c.startsWith('ds_token='))).toBe(true);
  });

  test('6a. Wrong password returns 401 (generic message)', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: registeredEmail, password: 'WrongPass9' });

    expect(res.statusCode).toBe(401);
    expect(res.body.error.message).toBe('Invalid email or password');
  });

  test('6b. Unknown email returns 401 (same generic message — no enumeration)', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'nobody@example.com', password: VALID_PASSWORD });

    expect(res.statusCode).toBe(401);
    expect(res.body.error.message).toBe('Invalid email or password');
  });

  test('7. Returned JWT contains correct subject claim', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: registeredEmail, password: VALID_PASSWORD });

    const decoded = jwt.decode(res.body.data.token);
    expect(decoded.sub).toBeDefined();
    expect(decoded.email).toBe(registeredEmail);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. AUTH ME ENDPOINT (Protected)
// ─────────────────────────────────────────────────────────────────────────────

describe('GET /api/v1/auth/me', () => {
  let validToken;
  let registeredEmail;

  beforeAll(async () => {
    registeredEmail = testEmail();
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: registeredEmail, password: VALID_PASSWORD });
    validToken = res.body.data.token;
  });

  test('11. /auth/me with valid Bearer token returns user', async () => {
    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${validToken}`);

    expect(res.statusCode).toBe(200);
    expect(res.body.data.user.email).toBe(registeredEmail);
    expect(JSON.stringify(res.body)).not.toContain('passwordHash');
  });

  test('11b. /auth/me with valid HttpOnly cookie returns user', async () => {
    // Simulate cookie by extracting from register response
    const regRes = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: testEmail(), password: VALID_PASSWORD });

    const cookie = regRes.headers['set-cookie'].find(c => c.startsWith('ds_token='));
    const cookieValue = cookie.split(';')[0]; // Extract 'ds_token=<value>'

    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Cookie', cookieValue);

    expect(res.statusCode).toBe(200);
    expect(res.body.data.user).toBeDefined();
  });

  test('8. Missing token returns 401', async () => {
    const res = await request(app).get('/api/v1/auth/me');
    expect(res.statusCode).toBe(401);
    expect(res.body.error.message).toMatch(/authentication required/i);
  });

  test('9. Invalid/tampered token returns 401', async () => {
    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', 'Bearer this.is.not.a.valid.jwt.token');

    expect(res.statusCode).toBe(401);
    expect(res.body.error.message).toMatch(/invalid/i);
  });

  test('10. Expired token returns 401 with expiry message', async () => {
    // Create a token that expired 1 second ago
    const expiredToken = jwt.sign(
      { sub: 'fake-id', email: 'fake@example.com' },
      process.env.JWT_SECRET,
      { expiresIn: -1 } // Immediately expired
    );

    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${expiredToken}`);

    expect(res.statusCode).toBe(401);
    expect(res.body.error.message).toMatch(/expired/i);
  });

  test('12. Unauthorized — wrong JWT secret results in 401', async () => {
    const foreignToken = jwt.sign(
      { sub: 'fake-id', email: 'fake@example.com' },
      'completely_wrong_secret',
      { expiresIn: '1h' }
    );

    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${foreignToken}`);

    expect(res.statusCode).toBe(401);
  });

  test('13. Authorized authenticated request succeeds', async () => {
    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${validToken}`);

    expect(res.statusCode).toBe(200);
    expect(res.body.data.user.id).toBeDefined();
    expect(res.body.data.user.email).toBe(registeredEmail);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. LOGOUT
// ─────────────────────────────────────────────────────────────────────────────

describe('POST /api/v1/auth/logout', () => {
  test('Logout clears the auth cookie and returns 200', async () => {
    const res = await request(app).post('/api/v1/auth/logout');

    expect(res.statusCode).toBe(200);
    expect(res.body.message).toMatch(/logged out/i);
    // Cookie should be cleared (empty value or expired)
    const setCookieHeader = res.headers['set-cookie'];
    if (setCookieHeader) {
      const tokenCookie = setCookieHeader.find(c => c.startsWith('ds_token='));
      if (tokenCookie) {
        // Cleared cookie has empty value or Max-Age=0
        expect(tokenCookie).toMatch(/ds_token=;|Max-Age=0/);
      }
    }
  });
});
