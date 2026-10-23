const { PrismaClient } = require('@prisma/client');
const fs = require('fs/promises');
const path = require('path');
const os = require('os');
const { extractZipSecurely } = require('../utils/zipUtils');
const { ingestGithubRepo } = require('./githubService');
const { extractNodeDependencies } = require('./extractionService');
const { generateSbom } = require('./sbomService');
const logger = require('../config/logger');

const prisma = new PrismaClient();

const createScan = async (projectId) => {
  return prisma.scan.create({
    data: {
      projectId,
      status: 'QUEUED'
    }
  });
};

const formatScanResponse = (scan) => {
  const dependencyCount = scan.dependencies ? scan.dependencies.length : 0;
  let vulnerabilityCount = 0;
  if (scan.dependencies) {
    for (const dep of scan.dependencies) {
      vulnerabilityCount += dep._count?.matches ?? 0;
    }
  }

  const sbomComponentCount = scan.sbom?.cycloneDxContent?.components?.length ?? null;
  const source = scan.project?.repository?.type || 'GITHUB';

  return {
    id: scan.id,
    projectId: scan.projectId,
    status: scan.status,
    errorMessage: scan.errorMessage,
    riskScore: scan.riskScore,
    totalRiskIndex: scan.riskScore != null ? scan.riskScore : (scan.status === 'COMPLETED' ? 0 : null),
    createdAt: scan.createdAt,
    completedAt: scan.completedAt,
    source,
    dependencyCount,
    vulnerabilityCount,
    sbomComponentCount
  };
};

const getScansByProject = async (projectId) => {
  const scans = await prisma.scan.findMany({
    where: { projectId },
    orderBy: { createdAt: 'desc' },
    include: {
      project: {
        include: {
          repository: true
        }
      },
      sbom: true,
      dependencies: {
        select: {
          _count: {
            select: {
              matches: true
            }
          }
        }
      }
    }
  });

  return scans.map(formatScanResponse);
};

const getScanById = async (scanId) => {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: {
      project: {
        include: {
          repository: true
        }
      },
      sbom: true,
      dependencies: {
        select: {
          _count: {
            select: {
              matches: true
            }
          }
        }
      }
    }
  });

  if (!scan) return null;
  return formatScanResponse(scan);
};

/**
 * Runs the ingestion pipeline (background-compatible).
 */
const runIngestion = async (scanId, projectId, zipFilePath = null) => {
  let workspaceDir = null;

  try {
    // 1. Mark as INGESTING
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'INGESTING' }
    });

    logger.info(`Scan ${scanId} started ingestion for project ${projectId}`);

    // 2. Create isolated workspace
    workspaceDir = await fs.mkdtemp(path.join(os.tmpdir(), `ds-scan-${scanId}-`));

    // 3. Get project and repository
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      include: { repository: true }
    });

    if (!project) throw new Error('Project not found');

    if (zipFilePath) {
      // It's a direct ZIP upload
      await extractZipSecurely(zipFilePath, workspaceDir);
      // Cleanup uploaded file
      await fs.unlink(zipFilePath);
    } else if (project.repository && project.repository.type === 'GITHUB' && project.repository.url) {
      // It's a GitHub repo
      await ingestGithubRepo(project.repository.url, workspaceDir);
    } else {
      throw new Error('No valid source provided for scan.');
    }

    // Phase 6 extraction
    await extractNodeDependencies(scanId, workspaceDir);

    // Phase 7 SBOM generation
    await generateSbom(scanId);

    // Phase 8 Vulnerability Analysis
    await prisma.scan.update({ where: { id: scanId }, data: { status: 'VULNERABILITY_ANALYSIS' } });
    const { matchDependencies } = require('./vulnerabilityService');
    const matchesFound = await matchDependencies(scanId);
    logger.info(`Scan ${scanId} vulnerability analysis complete. Found ${matchesFound} matches.`);

    // Phase 9 Risk Calculation
    const { calculateRiskForScan } = require('./riskService');
    await calculateRiskForScan(scanId);

    // Mark scan as COMPLETED
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'COMPLETED', completedAt: new Date() }
    });

    logger.info(`Scan ${scanId} pipeline complete.`);

  } catch (error) {
    logger.error(`Ingestion failed for scan ${scanId}: ${error.message}`);
    await prisma.scan.update({
      where: { id: scanId },
      data: { 
        status: 'FAILED',
        errorMessage: error.message
      }
    });
  } finally {
    // Cleanup: remove the isolated workspace directory
    if (workspaceDir) {
      try {
        await fs.rm(workspaceDir, { recursive: true, force: true });
      } catch (cleanupErr) {
        logger.error(`Failed to cleanup workspace ${workspaceDir}: ${cleanupErr.message}`);
      }
    }
  }
};

const getDependenciesByScan = async (scanId) => {
  return prisma.dependency.findMany({
    where: { scanId },
    orderBy: { name: 'asc' }
  });
};

const getSbomByScanId = async (scanId) => {
  const { getSbomByScan } = require('./sbomService');
  return getSbomByScan(scanId);
};

const getScanDashboardData = async (scanId, projectId) => {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: {
      sbom: true,
      dependencies: {
        include: {
          matches: {
            include: {
              vulnerability: {
                include: { affectedSoftware: true }
              }
            }
          }
        }
      }
    }
  });

  if (!scan || scan.projectId !== projectId) {
    const err = new Error('Scan not found');
    err.status = 404;
    throw err;
  }

  const totalDeps = scan.dependencies.length;
  const directDeps = scan.dependencies.filter(d => d.isDirect).length;
  const transitiveDeps = totalDeps - directDeps;
  const sbomComponents = scan.sbom ? (scan.sbom.cycloneDxContent?.components?.length ?? 0) : null;
  const findings = [];
  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNASSIGNED: 0 };

  for (const dep of scan.dependencies) {
    for (const match of dep.matches) {
      const v = match.vulnerability;
      const sev = v.severity || 'UNASSIGNED';
      severityCounts[sev] = (severityCounts[sev] || 0) + 1;
      findings.push({
        matchId: match.id,
        cveId: v.cveId,
        severity: sev,
        cvssScore: v.cvssScore,
        description: v.description,
        references: v.references,
        publishedAt: v.publishedAt,
        packageName: dep.name,
        packageVersion: dep.version,
        packagePurl: dep.purl,
        isDirect: dep.isDirect,
        severityWeight: match.severityWeight,
        contextWeight: match.contextWeight,
        riskScore: match.riskScore,
        affectedSoftware: v.affectedSoftware.map(s => ({
          vendor: s.vendor,
          product: s.product,
          versionStartIncluding: s.versionStartIncluding,
          versionStartExcluding: s.versionStartExcluding,
          versionEndIncluding: s.versionEndIncluding,
          versionEndExcluding: s.versionEndExcluding
        }))
      });
    }
  }

  return {
    scan: {
      id: scan.id,
      status: scan.status,
      createdAt: scan.createdAt,
      completedAt: scan.completedAt,
      errorMessage: scan.errorMessage,
      riskScore: scan.riskScore
    },
    summary: {
      totalDependencies: totalDeps,
      directDependencies: directDeps,
      transitiveDependencies: transitiveDeps,
      sbomComponents,
      totalFindings: findings.length,
      totalRiskScore: scan.riskScore || 0,
      severityCounts
    },
    findings
  };
};

const getScanVulnerabilities = async (scanId) => {
  return prisma.scanVulnerabilityMatch.findMany({
    where: { dependency: { scanId } },
    include: {
      dependency: true,
      vulnerability: true
    }
  });
};

module.exports = {
  createScan,
  getScansByProject,
  getScanById,
  runIngestion,
  getDependenciesByScan,
  getSbomByScanId,
  getScanDashboardData,
  getScanVulnerabilities
};

