const { PrismaClient } = require('@prisma/client');
const axios = require('axios');
const logger = require('../config/logger');

const prisma = new PrismaClient();

const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_API_KEY = process.env.NVD_API_KEY;
const MAX_RETRIES = 3;
let RATE_LIMIT_DELAY_MS = NVD_API_KEY ? 6000 : 10000;
if (process.env.NODE_ENV === 'test') {
  RATE_LIMIT_DELAY_MS = 10;
}

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const fetchWithRetry = async (url, options = {}, retries = MAX_RETRIES) => {
  for (let i = 0; i < retries; i++) {
    try {
      const config = { ...options, timeout: 30000 };
      if (NVD_API_KEY) {
        config.headers = { ...config.headers, apiKey: NVD_API_KEY };
      }
      const response = await axios.get(url, config);
      return response.data;
    } catch (error) {
      if (error.response && error.response.status === 403) {
        logger.warn(`NVD rate limit hit. Retrying in ${RATE_LIMIT_DELAY_MS}ms...`);
        await sleep(RATE_LIMIT_DELAY_MS);
      } else if (i < retries - 1) {
        logger.warn(`NVD request failed: ${error.message}. Retrying in ${RATE_LIMIT_DELAY_MS}ms...`);
        await sleep(RATE_LIMIT_DELAY_MS);
      } else {
        throw error;
      }
    }
  }
};

/**
 * Normalizes NVD CVE item to our Vulnerability model.
 */
const normalizeCve = (cveItem) => {
  const cve = cveItem.cve;
  const id = cve.id;
  const status = cve.vulnStatus;
  
  if (status === 'Rejected') {
    return null; // Skip rejected
  }

  let description = '';
  if (cve.descriptions) {
    const enDesc = cve.descriptions.find(d => d.lang === 'en' || d.lang === 'en-US');
    description = enDesc ? enDesc.value : cve.descriptions[0]?.value;
  }

  let cvssScore = null;
  let severity = 'UNASSIGNED';
  let cvssVersion = null;
  let cvssVector = null;

  if (cve.metrics) {
    // Prefer V40, then V31, then V30, then V2
    const metrics = cve.metrics.cvssMetricV40 || cve.metrics.cvssMetricV31 || cve.metrics.cvssMetricV30 || cve.metrics.cvssMetricV2;
    if (metrics && metrics.length > 0) {
      const metric = metrics[0].cvssData;
      cvssScore = metric.baseScore;
      severity = metric.baseSeverity || metrics[0].baseSeverity || 'UNASSIGNED';
      cvssVersion = metric.version;
      cvssVector = metric.vectorString;
    }
  }

  // Parse CPEs
  const vulnerableSoftware = [];
  if (cve.configurations) {
    for (const config of cve.configurations) {
      if (config.nodes) {
        for (const node of config.nodes) {
          if (node.cpeMatch) {
            for (const match of node.cpeMatch) {
              if (match.vulnerable) {
                // Parse CPE URI e.g., cpe:2.3:a:vendor:product:version:...
                const parts = match.criteria.split(':');
                if (parts.length >= 6 && parts[2] === 'a') { // 'a' is for applications
                  let exactVersion = parts[5];
                  if (exactVersion === '*' || exactVersion === '-') {
                    exactVersion = null;
                  }
                  vulnerableSoftware.push({
                    vendor: parts[3] !== '*' ? parts[3] : null,
                    product: parts[4] !== '*' ? parts[4] : null,
                    versionStartIncluding: match.versionStartIncluding || exactVersion || null,
                    versionStartExcluding: match.versionStartExcluding || null,
                    versionEndExcluding: match.versionEndExcluding || null,
                    versionEndIncluding: match.versionEndIncluding || exactVersion || null,
                  });
                }
              }
            }
          }
        }
      }
    }
  }

  return {
    cveId: id,
    description,
    severity: severity.toUpperCase(),
    cvssScore,
    cvssVersion,
    cvssVector,
    publishedAt: new Date(cve.published),
    modifiedAt: new Date(cve.lastModified),
    source: 'NVD',
    affectedSoftware: vulnerableSoftware,
  };
};

let isSyncing = false;

/**
 * Syncs vulnerabilities from NVD incrementally.
 */
const syncNvd = async () => {
  if (isSyncing) {
    logger.info('NVD sync already in progress. Skipping.');
    return { success: false, message: 'Sync already in progress' };
  }
  isSyncing = true;
  try {
    let syncState = await prisma.syncState.findUnique({ where: { id: 'NVD' } });
    
    const now = new Date();
    // NVD API recommends end date max 120 days from start date
    // If no state, we'll sync the last 7 days by default for the MVP, 
    // downloading the entire DB takes forever and is banned per instructions.
    let startDate = syncState ? new Date(syncState.lastSyncDate) : new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    
    logger.info(`Starting NVD sync from ${startDate.toISOString()}`);
    
    // NVD requires dates in specific ISO 8601 format: YYYY-MM-DDTHH:MM:SS.000Z
    // But they strictly want exactly 3 millisecond digits.
    const formatNvdDate = (d) => d.toISOString().replace(/\.\d+Z$/, '.000Z');

    let startIndex = 0;
    const resultsPerPage = 500; // max allowed by NVD is 2000, 500 is safer
    let totalResults = 1; // dummy initial value
    
    let processedCount = 0;
    
    const endDate = new Date(Math.min(startDate.getTime() + 119 * 24 * 60 * 60 * 1000, now.getTime()));

    while (startIndex < totalResults) {
      const url = `${NVD_API_URL}?lastModStartDate=${formatNvdDate(startDate)}&lastModEndDate=${formatNvdDate(endDate)}&resultsPerPage=${resultsPerPage}&startIndex=${startIndex}`;
      logger.info(`Fetching NVD page startIndex=${startIndex}...`);
      
      const data = await fetchWithRetry(url);
      totalResults = data.totalResults;
      
      const cves = data.vulnerabilities || [];
      
      for (const item of cves) {
        const normalized = normalizeCve(item);
        if (normalized) {
          const { affectedSoftware, ...vulnData } = normalized;
          
          await prisma.$transaction(async (tx) => {
            const existing = await tx.vulnerability.findUnique({ where: { cveId: vulnData.cveId } });
            
            let vulnId;
            if (existing) {
              await tx.vulnerability.update({
                where: { id: existing.id },
                data: vulnData
              });
              vulnId = existing.id;
              // Clean up old software entries
              await tx.vulnerableSoftware.deleteMany({ where: { vulnerabilityId: vulnId } });
            } else {
              const created = await tx.vulnerability.create({ data: vulnData });
              vulnId = created.id;
            }

            if (affectedSoftware.length > 0) {
              await tx.vulnerableSoftware.createMany({
                data: affectedSoftware.map(s => ({ ...s, vulnerabilityId: vulnId }))
              });
            }
          });
          processedCount++;
        }
      }
      
      startIndex += resultsPerPage;
      await sleep(RATE_LIMIT_DELAY_MS); // Pace requests
    }

    // Update sync state
    await prisma.syncState.upsert({
      where: { id: 'NVD' },
      update: { lastSyncDate: endDate },
      create: { id: 'NVD', lastSyncDate: endDate }
    });

    logger.info(`NVD sync complete. Processed ${processedCount} records.`);
    return { success: true, processedCount, endDate };
  } catch (error) {
    logger.error(`NVD sync failed: ${error.message}`);
    throw error;
  } finally {
    isSyncing = false;
  }
};

module.exports = {
  syncNvd,
  normalizeCve
};
