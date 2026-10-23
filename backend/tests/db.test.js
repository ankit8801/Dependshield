const prisma = require('../src/config/db');

describe('Database Schema Access', () => {
  beforeAll(async () => {
    try {
      await prisma.$connect();
    } catch (e) {
      console.warn('DB connection failed in setup');
    }
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('should be able to query the users table', async () => {
    // If the database is connected and schema is applied, this won't throw
    const users = await prisma.user.findMany({ take: 1 });
    expect(Array.isArray(users)).toBe(true);
  });

  it('should be able to query the projects table', async () => {
    const projects = await prisma.project.findMany({ take: 1 });
    expect(Array.isArray(projects)).toBe(true);
  });
});
