const { PrismaClient } = require('@prisma/client');
const logger = require('../config/logger');

const prisma = new PrismaClient();

const RISK_FORMULA_DETAILS = {
  name: 'DependShield Risk Scoring Formula (Phase 9)',
  formula: 'Risk Score = Severity Weight × Context Weight',
  aggregateFormula: 'Total Risk Index = Sum of all finding risk scores',
  severityWeights: {
    CRITICAL: 10,
    HIGH: 5,
    MEDIUM: 3,
    LOW: 1,
    UNASSIGNED: 0
  },
  contextWeights: {
    DIRECT: 1.5,
    TRANSITIVE: 1.0
  }
};

const SECURITY_DISCLAIMER =
  'Zero findings indicates no known vulnerabilities were detected in the local vulnerability database for the analyzed dependencies. ' +
  'It does not guarantee that the software is completely secure or free from unknown/zero-day vulnerabilities.';

/**
 * Builds the comprehensive security report data for a scan.
 * Data is consolidated directly from verified Phase 6-9 pipeline records.
 *
 * @param {string} scanId
 * @param {string} projectId
 * @returns {Promise<object>} Report data object
 */
const generateReportData = async (scanId, projectId) => {
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
        orderBy: { name: 'asc' },
        include: {
          matches: {
            include: {
              vulnerability: {
                include: {
                  affectedSoftware: true
                }
              }
            }
          }
        }
      }
    }
  });

  if (!scan || scan.projectId !== projectId) {
    const error = new Error('Scan not found');
    error.status = 404;
    throw error;
  }

  const project = scan.project;
  const isIncomplete = scan.status !== 'COMPLETED';
  const isFailed = scan.status === 'FAILED';

  // Dependency calculations
  const totalDependencies = scan.dependencies.length;
  const directDependencies = scan.dependencies.filter((d) => d.isDirect).length;
  const transitiveDependencies = totalDependencies - directDependencies;

  // SBOM calculations
  let sbomInfo = null;
  if (scan.sbom && scan.sbom.cycloneDxContent) {
    const cdx = scan.sbom.cycloneDxContent;
    sbomInfo = {
      isAvailable: true,
      bomFormat: cdx.bomFormat || 'CycloneDX',
      specVersion: cdx.specVersion || 'unknown',
      serialNumber: cdx.serialNumber || null,
      sbomVersion: cdx.version || 1,
      componentCount: Array.isArray(cdx.components) ? cdx.components.length : 0,
      generatedAt: cdx.metadata?.timestamp || scan.sbom.createdAt
    };
  } else {
    sbomInfo = {
      isAvailable: false,
      bomFormat: 'CycloneDX',
      specVersion: null,
      serialNumber: null,
      sbomVersion: null,
      componentCount: 0,
      generatedAt: null,
      note: 'SBOM has not been generated for this scan.'
    };
  }

  // Vulnerability findings and severity counts
  const findings = [];
  const severityCounts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    UNASSIGNED: 0
  };

  for (const dep of scan.dependencies) {
    if (!dep.matches) continue;
    for (const match of dep.matches) {
      const v = match.vulnerability;
      const severity = v.severity || 'UNASSIGNED';
      severityCounts[severity] = (severityCounts[severity] || 0) + 1;

      findings.push({
        matchId: match.id,
        cveId: v.cveId,
        severity,
        cvssScore: v.cvssScore !== null ? Number(v.cvssScore) : null,
        cvssVersion: v.cvssVersion || null,
        cvssVector: v.cvssVector || null,
        description: v.description || 'No description provided.',
        publishedAt: v.publishedAt || null,
        references: v.references || null,
        remediationGuidance: v.remediationGuidance || null,
        // Dependency context
        packageName: dep.name,
        packageVersion: dep.version,
        packagePurl: dep.purl,
        isDirect: dep.isDirect ?? false,
        ecosystem: dep.ecosystem || 'npm',
        // Risk calculation details (Phase 9)
        severityWeight: match.severityWeight ?? (RISK_FORMULA_DETAILS.severityWeights[severity] ?? 0),
        contextWeight: match.contextWeight ?? (dep.isDirect ? 1.5 : 1.0),
        riskScore: match.riskScore ?? 0,
        // Affected version ranges
        affectedSoftware: (v.affectedSoftware || []).map((s) => ({
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

  // Sort findings by risk score desc, then CVE ID asc
  findings.sort((a, b) => (b.riskScore - a.riskScore) || a.cveId.localeCompare(b.cveId));

  // Scan state notices
  let scanNotice = null;
  if (isFailed) {
    scanNotice = `Scan failed: ${scan.errorMessage || 'An internal error occurred during analysis.'}`;
  } else if (isIncomplete) {
    scanNotice = `Notice: Scan is in state '${scan.status}'. Results are preliminary or incomplete until scan reaches COMPLETED.`;
  }

  return {
    reportMetadata: {
      generatedAt: new Date().toISOString(),
      reportVersion: '1.0',
      generator: {
        name: 'DependShield Security Engine',
        version: '0.1.0'
      },
      disclaimer: SECURITY_DISCLAIMER,
      scanNotice
    },
    project: {
      id: project.id,
      name: project.name,
      description: project.description || null,
      createdAt: project.createdAt,
      repository: project.repository
        ? {
            type: project.repository.type,
            url: project.repository.url
          }
        : null
    },
    scan: {
      id: scan.id,
      status: scan.status,
      createdAt: scan.createdAt,
      completedAt: scan.completedAt,
      errorMessage: scan.errorMessage || null,
      isIncomplete,
      isFailed
    },
    dependencySummary: {
      totalDependencies,
      directDependencies,
      transitiveDependencies,
      sbomComponentCount: sbomInfo.componentCount
    },
    vulnerabilitySummary: {
      totalFindings: findings.length,
      severityCounts
    },
    riskSummary: {
      totalRiskIndex: scan.riskScore || 0,
      formula: RISK_FORMULA_DETAILS
    },
    sbom: sbomInfo,
    findings
  };
};

/**
 * Generates a clean, standalone HTML representation of the report.
 *
 * @param {object} report
 * @returns {string} HTML string
 */
const formatReportAsHtml = (report) => {
  const { reportMetadata, project, scan, dependencySummary, vulnerabilitySummary, riskSummary, sbom, findings } = report;

  const escapeHtml = (str) => {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };

  const getSeverityColor = (sev) => {
    switch (sev) {
      case 'CRITICAL': return '#ff4d4f';
      case 'HIGH': return '#ff7a45';
      case 'MEDIUM': return '#ffa940';
      case 'LOW': return '#52c41a';
      default: return '#8c8c8c';
    }
  };

  const findingsRows = findings.length > 0
    ? findings.map((f, i) => `
      <tr style="border-bottom: 1px solid #2d3748; background: ${i % 2 === 0 ? '#1a202c' : '#171923'};">
        <td style="padding: 10px; font-weight: bold; font-family: monospace;">${escapeHtml(f.cveId)}</td>
        <td style="padding: 10px;">
          <strong>${escapeHtml(f.packageName)}</strong>
          <span style="color: #a0aec0; font-size: 0.85em;">@${escapeHtml(f.packageVersion || 'unknown')}</span>
        </td>
        <td style="padding: 10px;">
          <span style="padding: 2px 6px; border-radius: 4px; font-size: 0.8em; background: ${f.isDirect ? '#2b6cb0' : '#4a5568'}; color: #fff;">
            ${f.isDirect ? 'Direct' : 'Transitive'}
          </span>
        </td>
        <td style="padding: 10px;">
          <span style="padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em; background: ${getSeverityColor(f.severity)}22; color: ${getSeverityColor(f.severity)}; border: 1px solid ${getSeverityColor(f.severity)}44;">
            ${escapeHtml(f.severity)}
          </span>
        </td>
        <td style="padding: 10px;">${f.cvssScore !== null ? f.cvssScore : 'N/A'}</td>
        <td style="padding: 10px; font-weight: bold; color: #f6ad55;">${f.riskScore}</td>
        <td style="padding: 10px; font-size: 0.9em; max-width: 320px; line-height: 1.4;">${escapeHtml(f.description)}</td>
      </tr>
    `).join('')
    : `<tr><td colspan="7" style="padding: 20px; text-align: center; color: #a0aec0;">No vulnerability findings recorded for this scan.</td></tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DependShield Security Report - ${escapeHtml(project.name)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 24px; line-height: 1.5; }
    .container { max-width: 1100px; margin: 0 auto; }
    .header { border-bottom: 2px solid #334155; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-end; }
    .title { font-size: 24px; font-weight: 700; margin: 0; color: #38bdf8; }
    .subtitle { color: #94a3b8; font-size: 14px; margin-top: 4px; }
    .notice { background: #3b200b; border: 1px solid #d97706; color: #fef3c7; padding: 12px 16px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }
    .card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; }
    .card-title { font-size: 12px; font-weight: 600; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.05em; }
    .card-val { font-size: 28px; font-weight: 700; margin-top: 8px; color: #f8fafc; }
    .table-container { overflow-x: auto; background: #1e293b; border: 1px solid #334155; border-radius: 8px; margin-bottom: 24px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; text-align: left; }
    th { background: #0f172a; padding: 12px 10px; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; border-bottom: 2px solid #334155; }
    .section-title { font-size: 18px; font-weight: 600; margin: 24px 0 12px; color: #e2e8f0; }
    .meta-box { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; font-size: 13px; color: #cbd5e1; margin-bottom: 24px; }
    .meta-row { display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #334155; }
    .meta-row:last-child { border-bottom: none; }
    .meta-label { color: #94a3b8; font-weight: 500; }
    .disclaimer { font-size: 12px; color: #64748b; line-height: 1.6; margin-top: 32px; border-top: 1px solid #334155; padding-top: 16px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1 class="title">DependShield Security Analysis Report</h1>
        <div class="subtitle">Project: <strong>${escapeHtml(project.name)}</strong> | Generated: ${escapeHtml(reportMetadata.generatedAt)}</div>
      </div>
      <div style="text-align: right; color: #94a3b8; font-size: 13px;">
        <div>Scan ID: <code style="color: #38bdf8;">${escapeHtml(scan.id)}</code></div>
        <div>Status: <strong>${escapeHtml(scan.status)}</strong></div>
      </div>
    </div>

    ${reportMetadata.scanNotice ? `<div class="notice">⚠️ ${escapeHtml(reportMetadata.scanNotice)}</div>` : ''}

    <div class="card-grid">
      <div class="card">
        <div class="card-title">Total Risk Index</div>
        <div class="card-val" style="color: #f6ad55;">${riskSummary.totalRiskIndex}</div>
        <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Severity × Context Weight</div>
      </div>
      <div class="card">
        <div class="card-title">Total Findings</div>
        <div class="card-val" style="color: ${vulnerabilitySummary.totalFindings > 0 ? '#ff7a45' : '#52c41a'};">
          ${vulnerabilitySummary.totalFindings}
        </div>
        <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Known CVE matches</div>
      </div>
      <div class="card">
        <div class="card-title">Dependencies Analyzed</div>
        <div class="card-val">${dependencySummary.totalDependencies}</div>
        <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">${dependencySummary.directDependencies} Direct / ${dependencySummary.transitiveDependencies} Transitive</div>
      </div>
      <div class="card">
        <div class="card-title">SBOM Components</div>
        <div class="card-val">${sbom.componentCount}</div>
        <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">${escapeHtml(sbom.bomFormat)} ${escapeHtml(sbom.specVersion || 'N/A')}</div>
      </div>
    </div>

    <div class="section-title">Summary & Configuration</div>
    <div class="meta-box">
      <div class="meta-row"><span class="meta-label">Project Name:</span> <span>${escapeHtml(project.name)}</span></div>
      ${project.description ? `<div class="meta-row"><span class="meta-label">Description:</span> <span>${escapeHtml(project.description)}</span></div>` : ''}
      ${project.repository ? `<div class="meta-row"><span class="meta-label">Repository:</span> <span>${escapeHtml(project.repository.type)} - ${escapeHtml(project.repository.url || 'No URL')}</span></div>` : ''}
      <div class="meta-row"><span class="meta-label">Scan Created:</span> <span>${escapeHtml(scan.createdAt)}</span></div>
      <div class="meta-row"><span class="meta-label">Scan Completed:</span> <span>${escapeHtml(scan.completedAt || 'In progress / Failed')}</span></div>
      <div class="meta-row"><span class="meta-label">SBOM Serial Number:</span> <span>${escapeHtml(sbom.serialNumber || 'N/A')}</span></div>
      <div class="meta-row"><span class="meta-label">Vulnerability Breakdown:</span> 
        <span>
          <strong style="color: #ff4d4f;">Critical:</strong> ${vulnerabilitySummary.severityCounts.CRITICAL} &nbsp;|&nbsp;
          <strong style="color: #ff7a45;">High:</strong> ${vulnerabilitySummary.severityCounts.HIGH} &nbsp;|&nbsp;
          <strong style="color: #ffa940;">Medium:</strong> ${vulnerabilitySummary.severityCounts.MEDIUM} &nbsp;|&nbsp;
          <strong style="color: #52c41a;">Low:</strong> ${vulnerabilitySummary.severityCounts.LOW} &nbsp;|&nbsp;
          <strong style="color: #8c8c8c;">Unassigned:</strong> ${vulnerabilitySummary.severityCounts.UNASSIGNED}
        </span>
      </div>
      <div class="meta-row"><span class="meta-label">Risk Methodology:</span> <span>${escapeHtml(riskSummary.formula.formula)}. Direct = 1.5×, Transitive = 1.0×.</span></div>
    </div>

    <div class="section-title">Vulnerability Findings (${findings.length})</div>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>CVE ID</th>
            <th>Component</th>
            <th>Type</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>Risk</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          ${findingsRows}
        </tbody>
      </table>
    </div>

    <div class="disclaimer">
      <strong>Security Disclaimer:</strong> ${escapeHtml(reportMetadata.disclaimer)}<br>
      Report generated by ${escapeHtml(reportMetadata.generator.name)} v${escapeHtml(reportMetadata.generator.version)}.
    </div>
  </div>
</body>
</html>`;
};

/**
 * Formats the report as clean GitHub-flavored Markdown.
 *
 * @param {object} report
 * @returns {string} Markdown string
 */
const formatReportAsMarkdown = (report) => {
  const { reportMetadata, project, scan, dependencySummary, vulnerabilitySummary, riskSummary, sbom, findings } = report;

  const lines = [
    `# DependShield Security Analysis Report`,
    ``,
    `**Project:** ${project.name}  `,
    `**Scan ID:** \`${scan.id}\`  `,
    `**Scan Status:** ${scan.status}  `,
    `**Generated:** ${reportMetadata.generatedAt}  `,
    project.repository ? `**Repository:** ${project.repository.type} (${project.repository.url || 'No URL'})  ` : ``,
    ``
  ];

  if (reportMetadata.scanNotice) {
    lines.push(`> ⚠️ **Notice:** ${reportMetadata.scanNotice}`);
    lines.push(``);
  }

  lines.push(
    `## Executive Summary`,
    ``,
    `| Metric | Value | Details |`,
    `| :--- | :--- | :--- |`,
    `| **Total Risk Index** | **${riskSummary.totalRiskIndex}** | Calculated via ${riskSummary.formula.formula} |`,
    `| **Total Vulnerabilities** | **${vulnerabilitySummary.totalFindings}** | Known CVEs detected |`,
    `| **Total Dependencies** | **${dependencySummary.totalDependencies}** | ${dependencySummary.directDependencies} direct, ${dependencySummary.transitiveDependencies} transitive |`,
    `| **SBOM Components** | **${sbom.componentCount}** | ${sbom.bomFormat} ${sbom.specVersion || 'N/A'} |`,
    ``,
    `## Severity Breakdown`,
    ``,
    `| Severity | Count |`,
    `| :--- | :--- |`,
    `| 🔴 **Critical** | ${vulnerabilitySummary.severityCounts.CRITICAL} |`,
    `| 🟠 **High** | ${vulnerabilitySummary.severityCounts.HIGH} |`,
    `| 🟡 **Medium** | ${vulnerabilitySummary.severityCounts.MEDIUM} |`,
    `| 🟢 **Low** | ${vulnerabilitySummary.severityCounts.LOW} |`,
    `| ⚪ **Unassigned** | ${vulnerabilitySummary.severityCounts.UNASSIGNED} |`,
    ``,
    `## Risk Prioritization Methodology`,
    ``,
    `- **Formula:** \`${riskSummary.formula.formula}\``,
    `- **Severity Weights:** Critical=10, High=5, Medium=3, Low=1, Unassigned=0`,
    `- **Context Weights:** Direct=1.5, Transitive=1.0`,
    `- **Total Risk Index:** ${riskSummary.formula.aggregateFormula}`,
    ``,
    `## SBOM Metadata`,
    ``,
    `- **Format:** ${sbom.bomFormat} ${sbom.specVersion || 'N/A'}`,
    `- **Serial Number:** \`${sbom.serialNumber || 'N/A'}\``,
    `- **Component Count:** ${sbom.componentCount}`,
    `- **Generated At:** ${sbom.generatedAt || 'N/A'}`,
    ``,
    `## Vulnerability Findings (${findings.length})`,
    ``
  );

  if (findings.length === 0) {
    lines.push(`_No known vulnerability matches recorded for this scan._`, ``);
  } else {
    lines.push(
      `| CVE ID | Package | Version | Type | Severity | CVSS | Risk Score | Description |`,
      `| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |`
    );
    for (const f of findings) {
      const sanitizedDesc = (f.description || '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').slice(0, 140);
      lines.push(
        `| **${f.cveId}** | \`${f.packageName}\` | \`${f.packageVersion || 'unknown'}\` | ${f.isDirect ? 'Direct' : 'Transitive'} | **${f.severity}** | ${f.cvssScore !== null ? f.cvssScore : 'N/A'} | **${f.riskScore}** | ${sanitizedDesc}... |`
      );
    }
    lines.push(``);
  }

  lines.push(
    `---`,
    `**Security Disclaimer:** ${reportMetadata.disclaimer}  `,
    `_Report generated by ${reportMetadata.generator.name} v${reportMetadata.generator.version}._`
  );

  return lines.join('\n');
};

module.exports = {
  generateReportData,
  formatReportAsHtml,
  formatReportAsMarkdown,
  RISK_FORMULA_DETAILS,
  SECURITY_DISCLAIMER
};
