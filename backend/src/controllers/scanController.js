const scanService = require('../services/scanService');
const projectService = require('../services/projectService');
const fs = require('fs/promises');

// Check project authorization first
const checkAuth = async (userId, projectId) => {
  const project = await projectService.getProjectById(userId, projectId);
  if (!project) throw new Error('Unauthorized or Project not found');
  return project;
};

const createScan = async (req, res, next) => {
  try {
    const { projectId } = req.params;
    await checkAuth(req.user.sub, projectId);

    const scan = await scanService.createScan(projectId);
    
    // Start ingestion asynchronously
    scanService.runIngestion(scan.id, projectId).catch(console.error);

    res.status(201).json({ data: scan });
  } catch (error) {
    if (error.message === 'Unauthorized or Project not found') {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    next(error);
  }
};

const uploadZipScan = async (req, res, next) => {
  try {
    const { projectId } = req.params;
    await checkAuth(req.user.sub, projectId);

    if (!req.file) {
      return res.status(400).json({ error: { message: 'No file uploaded' } });
    }

    const scan = await scanService.createScan(projectId);
    
    // Start ingestion asynchronously, passing the temp zip path
    scanService.runIngestion(scan.id, projectId, req.file.path).catch(console.error);

    res.status(201).json({ data: scan });
  } catch (error) {
    // If auth failed, cleanup the uploaded file
    if (req.file) {
      await fs.unlink(req.file.path).catch(() => {});
    }

    if (error.message === 'Unauthorized or Project not found') {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    next(error);
  }
};

const getScans = async (req, res, next) => {
  try {
    const { projectId } = req.params;
    await checkAuth(req.user.sub, projectId);

    const scans = await scanService.getScansByProject(projectId);
    res.status(200).json({ data: scans });
  } catch (error) {
    if (error.message === 'Unauthorized or Project not found') {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    next(error);
  }
};

const getScan = async (req, res, next) => {
  try {
    const { projectId, scanId } = req.params;
    await checkAuth(req.user.sub, projectId);

    const scan = await scanService.getScanById(scanId);
    if (!scan || scan.projectId !== projectId) {
      return res.status(404).json({ error: { message: 'Scan not found' } });
    }

    res.status(200).json({ data: scan });
  } catch (error) {
    if (error.message === 'Unauthorized or Project not found') {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    next(error);
  }
};

const getScanDependencies = async (req, res, next) => {
  try {
    const { projectId, scanId } = req.params;
    await checkAuth(req.user.sub, projectId);

    const scan = await scanService.getScanById(scanId);
    if (!scan || scan.projectId !== projectId) {
      return res.status(404).json({ error: { message: 'Scan not found' } });
    }

    const dependencies = await scanService.getDependenciesByScan(scanId);
    res.status(200).json({ data: dependencies });
  } catch (error) {
    if (error.message === 'Unauthorized or Project not found') {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    next(error);
  }
};

const getScanSbom = async (req, res, next) => {
  try {
    const { projectId, scanId } = req.params;
    await checkAuth(req.user.sub, projectId);

    const scan = await scanService.getScanById(scanId);
    if (!scan || scan.projectId !== projectId) {
      return res.status(404).json({ error: { message: 'Scan not found' } });
    }

    const sbomRecord = await scanService.getSbomByScanId(scanId);
    if (!sbomRecord) {
      return res.status(404).json({ error: { message: 'SBOM not yet generated for this scan' } });
    }

    // Support ?download=true to trigger file download
    if (req.query.download === 'true') {
      const filename = `dependshield-sbom-${scanId.split('-')[0]}.cdx.json`;
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Type', 'application/json');
      return res.status(200).send(JSON.stringify(sbomRecord.cycloneDxContent, null, 2));
    }

    res.status(200).json({ data: sbomRecord.cycloneDxContent });
  } catch (error) {
    if (error.message === 'Unauthorized or Project not found') {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    next(error);
  }
};

const getScanVulnerabilities = async (req, res, next) => {
  try {
    const { projectId, scanId } = req.params;
    await checkAuth(req.user.sub, projectId);

    const scan = await scanService.getScanById(scanId);
    if (!scan || scan.projectId !== projectId) {
      return res.status(404).json({ error: { message: 'Scan not found' } });
    }

    const matches = await scanService.getScanVulnerabilities(scanId);

    res.status(200).json({ data: matches });
  } catch (error) {
    if (error.message === 'Unauthorized or Project not found') {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    next(error);
  }
};

/**
 * GET /api/v1/projects/:projectId/scans/:scanId/dashboard
 *
 * Returns a single aggregated payload for the security dashboard:
 * scan info, dependency counts, SBOM component count, vulnerability severity
 * breakdown, per-match findings with risk scores, and total Risk Index.
 *
 * All data comes from Phase 6–9 pipeline records; nothing is inferred.
 */
const getScanDashboard = async (req, res, next) => {
  try {
    const { projectId, scanId } = req.params;
    await checkAuth(req.user.sub, projectId);

    const dashboardData = await scanService.getScanDashboardData(scanId, projectId);
    res.status(200).json({ data: dashboardData });
  } catch (error) {
    if (error.message === 'Unauthorized or Project not found') {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    if (error.message === 'Scan not found' || error.status === 404) {
      return res.status(404).json({ error: { message: 'Scan not found' } });
    }
    next(error);
  }
};

const getScanRiskSummary = async (req, res, next) => {
  try {
    const { projectId, scanId } = req.params;
    await checkAuth(req.user.sub, projectId);

    const scan = await scanService.getScanById(scanId);
    if (!scan || scan.projectId !== projectId) {
      return res.status(404).json({ error: { message: 'Scan not found' } });
    }


    const matches = await scanService.getScanVulnerabilities(scanId);

    const counts = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      UNASSIGNED: 0
    };

    for (const match of matches) {
      const severity = match.vulnerability.severity || 'UNASSIGNED';
      counts[severity] = (counts[severity] || 0) + 1;
    }

    res.status(200).json({
      data: {
        totalRiskScore: scan.riskScore || 0,
        counts
      }
    });
  } catch (error) {
    if (error.message === 'Unauthorized or Project not found') {
      return res.status(404).json({ error: { message: 'Project not found' } });
    }
    next(error);
  }
};

/**
 * GET /api/v1/projects/:projectId/scans/:scanId/report
 *
 * Generates and returns/downloads a comprehensive security report
 * in JSON, HTML, or Markdown format for a scan.
 */
const getScanReport = async (req, res, next) => {
  try {
    const { projectId, scanId } = req.params;
    await checkAuth(req.user.sub, projectId);

    const reportService = require('../services/reportService');
    const reportData = await reportService.generateReportData(scanId, projectId);

    const format = (req.query.format || 'json').toLowerCase();
    const isDownload = req.query.download === 'true';
    const shortId = scanId.split('-')[0];

    if (format === 'html') {
      const html = reportService.formatReportAsHtml(reportData);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      if (isDownload) {
        res.setHeader('Content-Disposition', `attachment; filename="dependshield-report-${shortId}.html"`);
      }
      return res.status(200).send(html);
    }

    if (format === 'markdown' || format === 'md') {
      const markdown = reportService.formatReportAsMarkdown(reportData);
      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      if (isDownload) {
        res.setHeader('Content-Disposition', `attachment; filename="dependshield-report-${shortId}.md"`);
      }
      return res.status(200).send(markdown);
    }

    // Default: JSON
    res.setHeader('Content-Type', 'application/json');
    if (isDownload) {
      res.setHeader('Content-Disposition', `attachment; filename="dependshield-report-${shortId}.json"`);
      return res.status(200).send(JSON.stringify(reportData, null, 2));
    }

    return res.status(200).json({ data: reportData });
  } catch (error) {
    if (error.message === 'Unauthorized or Project not found' || error.message === 'Scan not found' || error.status === 404) {
      return res.status(404).json({ error: { message: error.message || 'Scan not found' } });
    }
    next(error);
  }
};

module.exports = {
  createScan,
  uploadZipScan,
  getScans,
  getScan,
  getScanDependencies,
  getScanSbom,
  getScanVulnerabilities,
  getScanRiskSummary,
  getScanDashboard,
  getScanReport
};

