const express = require('express');
const router = express.Router();
const projectController = require('../controllers/projectController');
const { authenticate } = require('../middlewares/authenticate');
const validate = require('../middlewares/validate');
const { z } = require('zod');

// Reusable UUID param validator
const uuidParam = (...fields) => validate(z.object({
  params: z.object(Object.fromEntries(fields.map(f => [f, z.string().uuid('Invalid ID format')])))  
}));

// Report format query validator
const reportFormatQuery = validate(z.object({
  query: z.object({
    format: z.enum(['json', 'html', 'markdown', 'md']).optional(),
    download: z.enum(['true', 'false']).optional(),
  })
}));

// All project routes require authentication
router.use(authenticate);

// Projects CRUD
router.post('/', projectController.createProject);
router.get('/', projectController.getProjects);
router.get('/:id', uuidParam('id'), projectController.getProject);
router.patch('/:id', uuidParam('id'), projectController.updateProject);
router.delete('/:id', uuidParam('id'), projectController.deleteProject);

const multer = require('multer');

/**
 * Only accept files that declare a ZIP-family MIME type.
 * We also accept application/octet-stream since some HTTP clients
 * send it for .zip files, but in that case we additionally check
 * the original filename extension as a secondary signal.
 *
 * Note: MIME type is client-supplied and cannot be fully trusted on its own.
 * The actual archive validity is enforced by yauzl during extraction.
 */
const zipFileFilter = (req, file, cb) => {
  const allowedMimeTypes = [
    'application/zip',
    'application/x-zip',
    'application/x-zip-compressed',
    'application/x-compressed',
    'multipart/x-zip',
  ];
  const ext = (file.originalname || '').toLowerCase().split('.').pop();

  if (allowedMimeTypes.includes(file.mimetype)) {
    return cb(null, true);
  }
  // Fallback: allow application/octet-stream only if filename ends with .zip
  if (file.mimetype === 'application/octet-stream' && ext === 'zip') {
    return cb(null, true);
  }
  cb(new Error('Only .zip archives are accepted. Received: ' + file.mimetype));
};

const upload = multer({ 
  dest: 'uploads/',
  limits: { fileSize: 1024 * 1024 * 50 }, // 50MB max upload size
  fileFilter: zipFileFilter,
});
const scanController = require('../controllers/scanController');

// Repository Management
router.post('/:id/repository', uuidParam('id'), projectController.upsertRepository);
router.delete('/:id/repository', uuidParam('id'), projectController.deleteRepository);

// Scans / Ingestion
router.get('/:projectId/scans', uuidParam('projectId'), scanController.getScans);
router.get('/:projectId/scans/:scanId', uuidParam('projectId', 'scanId'), scanController.getScan);
router.get('/:projectId/scans/:scanId/dependencies', uuidParam('projectId', 'scanId'), scanController.getScanDependencies);
router.get('/:projectId/scans/:scanId/sbom', uuidParam('projectId', 'scanId'), scanController.getScanSbom);
router.get('/:projectId/scans/:scanId/vulnerabilities', uuidParam('projectId', 'scanId'), scanController.getScanVulnerabilities);
router.get('/:projectId/scans/:scanId/risk', uuidParam('projectId', 'scanId'), scanController.getScanRiskSummary);
router.get('/:projectId/scans/:scanId/dashboard', uuidParam('projectId', 'scanId'), scanController.getScanDashboard);
router.get('/:projectId/scans/:scanId/report', uuidParam('projectId', 'scanId'), reportFormatQuery, scanController.getScanReport);
router.get('/:projectId/scans/:scanId/report/export', uuidParam('projectId', 'scanId'), (req, res, next) => {
  req.query.download = 'true';
  return scanController.getScanReport(req, res, next);
});
router.post('/:projectId/scans', uuidParam('projectId'), scanController.createScan);
router.post('/:projectId/scans/upload', uuidParam('projectId'), upload.single('file'), scanController.uploadZipScan);

module.exports = router;
