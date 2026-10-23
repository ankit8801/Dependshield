import axios from 'axios';

/**
 * Centralized API client for DependShield backend.
 *
 * - baseURL points to the backend (configurable via VITE_API_URL env var)
 * - withCredentials: true ensures HttpOnly cookies are sent on every request
 *   (this is what makes the cookie-based auth strategy work)
 * - 401 responses automatically trigger a redirect to /login
 */
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:3000/api/v1',
  withCredentials: true, // CRITICAL: send HttpOnly cookie with every request
  headers: {
    'Content-Type': 'application/json',
  },
});

// Response interceptor: handle 401 globally
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Clear any stale local auth state and redirect to login
      // We dispatch a custom event so AuthContext can react without circular imports
      window.dispatchEvent(new CustomEvent('auth:unauthorized'));
    }
    return Promise.reject(error);
  }
);

// ─── Auth API calls ────────────────────────────────────────────────────────

export const authApi = {
  register: (email, password) =>
    api.post('/auth/register', { email, password }),

  login: (email, password) =>
    api.post('/auth/login', { email, password }),

  logout: () =>
    api.post('/auth/logout'),

  me: () =>
    api.get('/auth/me'),
};

export const projectApi = {
  getProjects: () => api.get('/projects'),
  getProject: (id) => api.get(`/projects/${id}`),
  createProject: (data) => api.post('/projects', data),
  updateProject: (id, data) => api.patch(`/projects/${id}`, data),
  deleteProject: (id) => api.delete(`/projects/${id}`),
  
  upsertRepository: (projectId, url) => api.post(`/projects/${projectId}/repository`, { url }),
  deleteRepository: (projectId) => api.delete(`/projects/${projectId}/repository`),
};

export const scanApi = {
  getScans: (projectId) => api.get(`/projects/${projectId}/scans`),
  getScan: (projectId, scanId) => api.get(`/projects/${projectId}/scans/${scanId}`),
  getDependencies: (projectId, scanId) => api.get(`/projects/${projectId}/scans/${scanId}/dependencies`),
  getSbom: (projectId, scanId) => api.get(`/projects/${projectId}/scans/${scanId}/sbom`),
  getVulnerabilities: (projectId, scanId) => api.get(`/projects/${projectId}/scans/${scanId}/vulnerabilities`),
  getRiskSummary: (projectId, scanId) => api.get(`/projects/${projectId}/scans/${scanId}/risk`),
  getDashboard: (projectId, scanId) => api.get(`/projects/${projectId}/scans/${scanId}/dashboard`),
  getReport: (projectId, scanId, format = 'json') => api.get(`/projects/${projectId}/scans/${scanId}/report?format=${format}`),
  getReportUrl: (projectId, scanId, format = 'json', download = true) =>
    `${import.meta.env.VITE_API_URL || 'http://localhost:3000/api/v1'}/projects/${projectId}/scans/${scanId}/report?format=${format}&download=${download}`,
  createGithubScan: (projectId) => api.post(`/projects/${projectId}/scans`),
  uploadZipScan: (projectId, file) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post(`/projects/${projectId}/scans/upload`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  },
};

export const vulnerabilityApi = {
  getDetails: (id) => api.get(`/vulnerabilities/${id}`),
};

export default api;
