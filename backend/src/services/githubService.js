const fs = require('fs/promises');
const path = require('path');
const os = require('os');
const axios = require('axios');
const { extractZipSecurely } = require('../utils/zipUtils');

const GITHUB_API_BASE = 'https://api.github.com';

/**
 * Downloads and extracts a GitHub repository securely.
 */
const ingestGithubRepo = async (repoUrl, workspaceDir) => {
  // 1. Validate URL
  const match = repoUrl.match(/^https:\/\/github\.com\/([^\/]+)\/([^\/]+)$/);
  if (!match) {
    throw new Error('Invalid GitHub URL. Must be https://github.com/owner/repo');
  }

  const owner = match[1];
  const repoName = match[2].replace(/\.git$/, '');

  // 2. Fetch default branch via GitHub API (protect against SSRF by hardcoding the API host)
  let defaultBranch = 'main';
  try {
    const repoInfo = await axios.get(`${GITHUB_API_BASE}/repos/${owner}/${repoName}`, {
      timeout: 5000,
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        ...(process.env.GITHUB_TOKEN && { 'Authorization': `token ${process.env.GITHUB_TOKEN}` })
      }
    });
    defaultBranch = repoInfo.data.default_branch;
  } catch (error) {
    if (error.response && error.response.status === 404) {
      throw new Error('GitHub repository not found or is private.');
    }
    throw new Error('Failed to fetch repository information from GitHub.');
  }

  // 3. Download the ZIP archive
  const zipUrl = `https://github.com/${owner}/${repoName}/archive/refs/heads/${defaultBranch}.zip`;
  const zipPath = path.join(workspaceDir, 'repo.zip');

  try {
    const response = await axios({
      method: 'GET',
      url: zipUrl,
      responseType: 'stream',
      timeout: 10000,
      maxContentLength: 1024 * 1024 * 100, // 100MB max download
      headers: {
        ...(process.env.GITHUB_TOKEN && { 'Authorization': `token ${process.env.GITHUB_TOKEN}` })
      }
    });

    const writer = require('fs').createWriteStream(zipPath);
    response.data.pipe(writer);

    await new Promise((resolve, reject) => {
      writer.on('finish', resolve);
      writer.on('error', reject);
    });
  } catch (error) {
    throw new Error('Failed to download repository archive.');
  }

  // 4. Extract securely
  await extractZipSecurely(zipPath, workspaceDir);

  // 5. Cleanup the zip file
  await fs.unlink(zipPath);
};

module.exports = {
  ingestGithubRepo
};
