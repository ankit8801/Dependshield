const express = require('express');
const router = express.Router();
const { authenticate } = require('../middlewares/authenticate');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const nvdService = require('../services/nvdService');

router.use(authenticate);

router.get('/:id', async (req, res, next) => {
  try {
    const vulnerability = await prisma.vulnerability.findUnique({
      where: { id: req.params.id },
      include: {
        affectedSoftware: true
      }
    });

    if (!vulnerability) {
      return res.status(404).json({ error: { message: 'Vulnerability not found' } });
    }

    res.status(200).json({ data: vulnerability });
  } catch (error) {
    next(error);
  }
});

// Admin-level sync trigger.
// SECURITY NOTE (MVP Limitation): This endpoint requires authentication but does NOT
// enforce an admin role because DependShield's MVP does not implement RBAC.
// Any authenticated user can trigger an NVD sync. Frequent triggers could exhaust
// NVD API rate limits and get the server IP temporarily blocked by NIST.
// For production use, restrict this endpoint to admin users or a cron-only mechanism.
router.post('/sync', async (req, res, next) => {
  try {
    const logger = require('../config/logger');
    logger.warn('NVD sync triggered by authenticated user', { userId: req.user?.sub });
    // Start sync in background
    nvdService.syncNvd().catch((err) => logger.error('NVD background sync failed', { message: err.message }));
    res.status(202).json({ message: 'NVD sync started in background' });
  } catch (error) {
    next(error);
  }
});

router.get('/sync/status', async (req, res, next) => {
  try {
    const state = await prisma.syncState.findUnique({ where: { id: 'NVD' } });
    res.status(200).json({ data: state });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
