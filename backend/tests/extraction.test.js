const fs = require('fs/promises');
const path = require('path');
const os = require('os');
const { extractNodeDependencies, findProjectRoot } = require('../src/services/extractionService');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

describe('Phase 6: Dependency Extraction', () => {
  let workspaceDir;
  let scanId;
  let projectId;
  let userToken;

  beforeAll(async () => {
    // Setup a dummy scan in the database
    const user = await prisma.user.create({
      data: {
        email: 'extract@test.com',
        passwordHash: 'dummy'
      }
    });

    const project = await prisma.project.create({
      data: {
        name: 'Extraction Test',
        userId: user.id
      }
    });
    projectId = project.id;

    const scan = await prisma.scan.create({
      data: {
        projectId: project.id,
        status: 'ANALYZING'
      }
    });
    scanId = scan.id;
  });

  afterAll(async () => {
    await prisma.sbom.deleteMany({});
    await prisma.dependency.deleteMany({});
    await prisma.scan.deleteMany({});
    await prisma.project.deleteMany({});
    await prisma.user.deleteMany({});
    await prisma.$disconnect();
  });

  beforeEach(async () => {
    workspaceDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ds-extract-test-'));
    // Clear dependencies before each test
    await prisma.dependency.deleteMany({ where: { scanId } });
  });

  afterEach(async () => {
    await fs.rm(workspaceDir, { recursive: true, force: true });
  });

  test('1. Fails when no package.json is found anywhere', async () => {
    await expect(findProjectRoot(workspaceDir)).rejects.toThrow('No package.json found');
  });

  test('2. Finds package.json in root', async () => {
    await fs.writeFile(path.join(workspaceDir, 'package.json'), JSON.stringify({}));
    const root = await findProjectRoot(workspaceDir);
    expect(root).toBe(workspaceDir);
  });

  test('3. Finds package.json in single nested subdirectory', async () => {
    const subDir = path.join(workspaceDir, 'repo-main');
    await fs.mkdir(subDir);
    await fs.writeFile(path.join(subDir, 'package.json'), JSON.stringify({}));
    const root = await findProjectRoot(workspaceDir);
    expect(root).toBe(subDir);
  });

  test('4. Extracts dependencies from valid package.json (no lockfile)', async () => {
    const pkg = {
      dependencies: {
        'express': '4.18.2'
      },
      devDependencies: {
        'jest': '^29.0.0',
        '@types/node': '18.x'
      }
    };
    await fs.writeFile(path.join(workspaceDir, 'package.json'), JSON.stringify(pkg));

    const count = await extractNodeDependencies(scanId, workspaceDir);
    expect(count).toBe(3);

    const deps = await prisma.dependency.findMany({ where: { scanId } });
    expect(deps.length).toBe(3);
    
    const expressDep = deps.find(d => d.name === 'express');
    expect(expressDep.isDirect).toBe(true);
    expect(expressDep.version).toBe('4.18.2');
    expect(expressDep.purl).toBe('pkg:npm/express@4.18.2');

    const typesDep = deps.find(d => d.name === '@types/node');
    expect(typesDep.isDirect).toBe(true);
    expect(typesDep.version).toBe('18.x');
    expect(typesDep.purl).toBe('pkg:npm/%40types%2Fnode@18.x');
  });

  test('5. Extracts dependencies from lockfileVersion 2/3 (with transitive)', async () => {
    const pkg = {
      dependencies: { 'express': '^4.0.0' }
    };
    const pkgLock = {
      lockfileVersion: 3,
      packages: {
        "": {
          dependencies: { "express": "^4.0.0" }
        },
        "node_modules/express": {
          version: "4.19.2",
          dependencies: { "accepts": "~1.3.8" }
        },
        "node_modules/accepts": {
          version: "1.3.8"
        }
      }
    };

    await fs.writeFile(path.join(workspaceDir, 'package.json'), JSON.stringify(pkg));
    await fs.writeFile(path.join(workspaceDir, 'package-lock.json'), JSON.stringify(pkgLock));

    const count = await extractNodeDependencies(scanId, workspaceDir);
    expect(count).toBe(2);

    const deps = await prisma.dependency.findMany({ where: { scanId } });
    
    const expressDep = deps.find(d => d.name === 'express');
    expect(expressDep.version).toBe('4.19.2'); // from lockfile
    expect(expressDep.isDirect).toBe(true);

    const acceptsDep = deps.find(d => d.name === 'accepts');
    expect(acceptsDep.version).toBe('1.3.8');
    expect(acceptsDep.isDirect).toBe(false); // transitive
  });

  test('6. Extracts dependencies from lockfileVersion 1 (dependencies block)', async () => {
    const pkg = { dependencies: { 'lodash': '^4.17.0' } };
    const pkgLock = {
      lockfileVersion: 1,
      dependencies: {
        "lodash": {
          version: "4.17.21"
        },
        "ms": {
          version: "2.1.2"
        }
      }
    };

    await fs.writeFile(path.join(workspaceDir, 'package.json'), JSON.stringify(pkg));
    await fs.writeFile(path.join(workspaceDir, 'package-lock.json'), JSON.stringify(pkgLock));

    const count = await extractNodeDependencies(scanId, workspaceDir);
    expect(count).toBe(2);

    const deps = await prisma.dependency.findMany({ where: { scanId } });
    expect(deps.find(d => d.name === 'lodash').isDirect).toBe(true);
    expect(deps.find(d => d.name === 'ms').isDirect).toBe(false);
  });

  test('7. Fails gracefully on malformed package.json', async () => {
    await fs.writeFile(path.join(workspaceDir, 'package.json'), 'invalid json');
    await expect(extractNodeDependencies(scanId, workspaceDir))
      .rejects.toThrow('Malformed JSON in package.json');
  });

  test('8. Ignores malformed package-lock.json and extracts from package.json instead', async () => {
    const pkg = { dependencies: { 'express': '4.18.2' } };
    await fs.writeFile(path.join(workspaceDir, 'package.json'), JSON.stringify(pkg));
    await fs.writeFile(path.join(workspaceDir, 'package-lock.json'), 'invalid json');
    
    // We expect it to log a warning but still succeed using package.json
    const count = await extractNodeDependencies(scanId, workspaceDir);
    expect(count).toBe(1);
    
    const deps = await prisma.dependency.findMany({ where: { scanId } });
    expect(deps.length).toBe(1);
    expect(deps[0].name).toBe('express');
  });
});
