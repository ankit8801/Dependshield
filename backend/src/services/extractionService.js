const fs = require('fs/promises');
const path = require('path');
const { PrismaClient } = require('@prisma/client');
const logger = require('../config/logger');

const prisma = new PrismaClient();

const MAX_MANIFEST_SIZE_BYTES = 20 * 1024 * 1024; // 20MB — generous for any real lockfile

/**
 * Safely parses a JSON file.
 * Enforces a maximum file size to prevent memory exhaustion from
 * a maliciously crafted package.json or package-lock.json inside a ZIP.
 */
const safeReadJson = async (filePath) => {
  try {
    // Check file size before reading to prevent memory exhaustion
    const stat = await fs.stat(filePath);
    if (stat.size > MAX_MANIFEST_SIZE_BYTES) {
      throw new Error(`${path.basename(filePath)} exceeds maximum allowed size (20MB)`);
    }
    const content = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(content);
  } catch (error) {
    if (error.message.includes('exceeds maximum allowed size')) {
      throw error;
    }
    if (error.code === 'ENOENT') return null;
    throw new Error(`Malformed JSON in ${path.basename(filePath)}`);
  }
};

/**
 * Finds the project root by looking for package.json.
 * If not in the root, it checks if there is exactly one subdirectory and looks there.
 * This handles GitHub ZIPs which wrap everything in a repo-name-branch/ folder.
 */
const findProjectRoot = async (workspaceDir) => {
  const rootPackageJson = path.join(workspaceDir, 'package.json');
  try {
    await fs.access(rootPackageJson);
    return workspaceDir; // Found in root
  } catch {
    // Not in root, let's check if there is a single subdirectory
    const entries = await fs.readdir(workspaceDir, { withFileTypes: true });
    const subdirs = entries.filter(e => e.isDirectory());
    if (subdirs.length === 1) {
      const subDirPath = path.join(workspaceDir, subdirs[0].name);
      const subPackageJson = path.join(subDirPath, 'package.json');
      try {
        await fs.access(subPackageJson);
        return subDirPath;
      } catch {
        // Not found in sub directory
      }
    }
  }
  throw new Error('No package.json found in the repository root or top-level directory.');
};

/**
 * Extracts dependencies from package.json and package-lock.json.
 */
const extractNodeDependencies = async (scanId, workspaceDir) => {
  await prisma.scan.update({
    where: { id: scanId },
    data: { status: 'EXTRACTING' }
  });

  const projectRoot = await findProjectRoot(workspaceDir);
  
  const packageJsonPath = path.join(projectRoot, 'package.json');
  const packageLockPath = path.join(projectRoot, 'package-lock.json');

  const pkgJson = await safeReadJson(packageJsonPath);
  if (!pkgJson) throw new Error('Failed to read package.json');

  let pkgLock = null;
  try {
    pkgLock = await safeReadJson(packageLockPath);
  } catch (err) {
    logger.warn(`Failed to parse package-lock.json: ${err.message}`);
  }

  const directDeps = new Set();
  const dependencyMap = new Map(); // Key: package name, Value: Dependency object

  // 1. Identify Direct Dependencies
  const depTypes = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
  for (const type of depTypes) {
    if (pkgJson[type] && typeof pkgJson[type] === 'object') {
      for (const [name, version] of Object.entries(pkgJson[type])) {
        directDeps.add(name);
        dependencyMap.set(name, {
          scanId,
          name,
          version, // will be overwritten if in lockfile
          purl: `pkg:npm/${encodeURIComponent(name)}@${version}`,
          isDirect: true,
          ecosystem: 'npm'
        });
      }
    }
  }

  // 2. Process package-lock.json if available
  if (pkgLock) {
    const processLockDependencies = (depsObj) => {
      if (!depsObj || typeof depsObj !== 'object') return;
      for (const [key, details] of Object.entries(depsObj)) {
        // v2/v3 packages have keys like "node_modules/name" or "" (root)
        let name = key;
        if (key === '') continue; // Skip root project in v2/v3
        if (key.startsWith('node_modules/')) {
          const parts = key.split('node_modules/');
          name = parts[parts.length - 1]; // get actual package name
        }

        const version = details.version || 'unknown';
        const isDirect = directDeps.has(name);
        
        // PURL format: pkg:npm/name@version
        const purl = `pkg:npm/${encodeURIComponent(name)}@${version}`;

        dependencyMap.set(name, {
          scanId,
          name,
          version,
          purl,
          isDirect,
          ecosystem: 'npm'
        });
        
        // Recursively process v1 dependencies field
        if (details.dependencies) {
          processLockDependencies(details.dependencies);
        }
      }
    };

    if (pkgLock.packages) {
      // lockfileVersion 2 & 3
      processLockDependencies(pkgLock.packages);
    } else if (pkgLock.dependencies) {
      // lockfileVersion 1
      processLockDependencies(pkgLock.dependencies);
    }
  }

  const dependenciesToSave = Array.from(dependencyMap.values());

  if (dependenciesToSave.length > 0) {
    // Avoid duplicate dependencies in the database
    // Using createMany ignores conflicts on unique constraints, but we don't have a unique constraint on scanId+name.
    // The instructions say: "Prevent accidental duplication when the same dependency appears multiple times where the schema/design requires normalization."
    // Our Map structure already ensures unique package names per scan.
    await prisma.dependency.createMany({
      data: dependenciesToSave
    });
  }

  await prisma.scan.update({
    where: { id: scanId },
    data: { status: 'SBOM_GENERATING' }
  });

  logger.info(`Scan ${scanId} extraction complete. Found ${dependenciesToSave.length} dependencies.`);
  return dependenciesToSave.length;
};

module.exports = {
  extractNodeDependencies,
  findProjectRoot,
  safeReadJson
};
