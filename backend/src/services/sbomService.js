const { v4: uuidv4 } = require('uuid');
const { PrismaClient } = require('@prisma/client');
const logger = require('../config/logger');

const prisma = new PrismaClient();

// CycloneDX spec version we target
const CYCLONEDX_SPEC_VERSION = '1.5';
const CYCLONEDX_BOM_FORMAT = 'CycloneDX';

/**
 * Generates a well-formed CycloneDX package URL for an npm component.
 * Handles scoped packages (e.g. @types/node → pkg:npm/%40types%2Fnode@1.0.0).
 * @param {string} name
 * @param {string} version
 * @returns {string}
 */
const buildNpmPurl = (name, version) => {
  const safeVersion = (version || 'unknown').replace(/\s/g, '');
  if (name.startsWith('@') && name.includes('/')) {
    const parts = name.split('/');
    const namespace = encodeURIComponent(parts[0]);
    const pkgName = encodeURIComponent(parts.slice(1).join('/'));
    return `pkg:npm/${namespace}/${pkgName}@${safeVersion}`;
  }
  const encodedName = encodeURIComponent(name);
  return `pkg:npm/${encodedName}@${safeVersion}`;
};

/**
 * Validates that the generated SBOM meets the minimum CycloneDX requirements.
 * Throws an error with a descriptive message if validation fails.
 */
const validateSbom = (sbom) => {
  const required = ['bomFormat', 'specVersion', 'serialNumber', 'version', 'metadata', 'components'];
  for (const field of required) {
    if (sbom[field] === undefined || sbom[field] === null) {
      throw new Error(`SBOM validation failed: missing required field "${field}"`);
    }
  }

  if (!Array.isArray(sbom.components)) {
    throw new Error('SBOM validation failed: "components" must be an array');
  }

  for (const component of sbom.components) {
    if (!component.type) throw new Error(`SBOM validation failed: component missing "type"`);
    if (!component.name) throw new Error(`SBOM validation failed: component missing "name"`);
    if (!component.version) throw new Error(`SBOM validation failed: component missing "version"`);
    if (!component['bom-ref']) throw new Error(`SBOM validation failed: component missing "bom-ref"`);
    // Validate PURL format for npm components
    if (component.purl && !component.purl.startsWith('pkg:npm/')) {
      throw new Error(`SBOM validation failed: unexpected PURL format for npm component: ${component.purl}`);
    }
  }
};

/**
 * Generates a CycloneDX 1.5 SBOM from the dependencies stored for a scan,
 * validates it, persists it to the database, and updates the scan status.
 *
 * @param {string} scanId
 * @returns {object} The generated SBOM document
 */
const generateSbom = async (scanId) => {
  // 1. Load dependencies from DB (Phase 6 output)
  const dependencies = await prisma.dependency.findMany({
    where: { scanId },
    orderBy: { name: 'asc' }
  });

  // 2. Load scan + project metadata for the SBOM header
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: { project: true }
  });

  if (!scan) throw new Error(`Scan ${scanId} not found`);

  // 3. Build CycloneDX components from dependencies
  const components = dependencies.map((dep) => {
    const purl = buildNpmPurl(dep.name, dep.version);
    return {
      'bom-ref': dep.id,          // stable UUID from the dependency record
      type: 'library',
      name: dep.name || 'unknown',
      version: dep.version || 'unknown',
      purl,
      description: `npm package`,
      properties: [
        { name: 'dependshield:ecosystem', value: dep.ecosystem || 'npm' },
        { name: 'dependshield:isDirect', value: String(dep.isDirect ?? false) },
      ]
    };
  });

  // 4. Assemble the full CycloneDX document
  const sbomDocument = {
    bomFormat: CYCLONEDX_BOM_FORMAT,
    specVersion: CYCLONEDX_SPEC_VERSION,
    serialNumber: `urn:uuid:${uuidv4()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'DependShield',
          name: 'DependShield Scanner',
          version: '0.1.0'
        }
      ],
      component: {
        type: 'application',
        name: scan.project?.name || 'Unknown Project',
        version: 'unknown'
      }
    },
    components
  };

  // 5. Validate before persisting
  validateSbom(sbomDocument);

  // 6. Persist to DB (upsert: one SBOM per scan)
  await prisma.sbom.upsert({
    where: { scanId },
    update: { cycloneDxContent: sbomDocument },
    create: {
      scanId,
      cycloneDxContent: sbomDocument
    }
  });

  logger.info(`Scan ${scanId} SBOM generated. Components: ${components.length}`);
  return sbomDocument;
};

/**
 * Retrieves the persisted SBOM for a scan.
 * @param {string} scanId
 * @returns {object|null}
 */
const getSbomByScan = async (scanId) => {
  return prisma.sbom.findUnique({ where: { scanId } });
};

module.exports = {
  generateSbom,
  getSbomByScan,
  buildNpmPurl,
  validateSbom,
  CYCLONEDX_SPEC_VERSION,
  CYCLONEDX_BOM_FORMAT
};
