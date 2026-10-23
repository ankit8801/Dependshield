const { PrismaClient } = require('@prisma/client');
const logger = require('../config/logger');

const prisma = new PrismaClient();

const SEVERITY_WEIGHTS = {
  CRITICAL: 10,
  HIGH: 5,
  MEDIUM: 3,
  LOW: 1,
  UNASSIGNED: 0
};

const CONTEXT_WEIGHTS = {
  DIRECT: 1.5,
  TRANSITIVE: 1.0
};

/**
 * Calculates risk for all vulnerability matches in a scan and updates the total risk score.
 * 
 * @param {string} scanId - The ID of the scan
 */
const calculateRiskForScan = async (scanId) => {
  try {
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: {
        dependencies: {
          include: {
            matches: {
              include: {
                vulnerability: true
              }
            }
          }
        }
      }
    });

    if (!scan) {
      throw new Error('Scan not found');
    }

    let totalRiskScore = 0;

    // We process each dependency and its matches
    for (const dep of scan.dependencies) {
      const contextWeight = dep.isDirect ? CONTEXT_WEIGHTS.DIRECT : CONTEXT_WEIGHTS.TRANSITIVE;

      for (const match of dep.matches) {
        const severity = match.vulnerability.severity;
        const severityWeight = SEVERITY_WEIGHTS[severity] || 0;
        
        const riskScore = severityWeight * contextWeight;
        
        // Update the match with risk data
        await prisma.scanVulnerabilityMatch.update({
          where: { id: match.id },
          data: {
            severityWeight,
            contextWeight,
            riskScore
          }
        });

        totalRiskScore += riskScore;
      }
    }

    // Update scan total score
    await prisma.scan.update({
      where: { id: scanId },
      data: { riskScore: totalRiskScore }
    });

    logger.info(`Calculated risk for scan ${scanId}. Total Risk Index: ${totalRiskScore}`);
    
    return totalRiskScore;
  } catch (error) {
    logger.error(`Error calculating risk for scan ${scanId}: ${error.message}`);
    throw error;
  }
};

module.exports = {
  calculateRiskForScan,
  SEVERITY_WEIGHTS,
  CONTEXT_WEIGHTS
};
