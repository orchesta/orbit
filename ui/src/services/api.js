// Same-origin by default: the Go server serves the UI, and vite dev proxies /api.
export const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';

// Dispatched on window whenever the API rejects the stored token.
export const UNAUTHORIZED_EVENT = 'orbit:unauthorized';

// ApiError carries the HTTP status so callers can tell "not found" from "down".
export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

function parseBody(text) {
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return null; // e.g. an HTML error page from a proxy
  }
}

// request calls the API and returns the envelope's data field.
export async function request(endpoint, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  const token = localStorage.getItem('orbit_token');
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(`${API_BASE}${endpoint}`, { ...options, headers });
  if (response.status === 204) return null;

  const body = parseBody(await response.text());
  if (!response.ok) {
    // Only the token this request was sent with was rejected; a newer one
    // (e.g. from a login while it was in flight) stays.
    if (response.status === 401 && localStorage.getItem('orbit_token') === token) {
      localStorage.removeItem('orbit_token');
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    }
    const message = body?.error || `Request failed (${response.status} ${response.statusText || 'error'})`;
    throw new ApiError(response.status, message);
  }
  if (body === null) {
    throw new ApiError(response.status, `Unexpected response (${response.status})`);
  }
  return body.data;
}

// Auth API
export const authApi = {
  status: () => request('/auth/status'),
  me: () => request('/auth/me'),
  login: (email, password) => request('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  setup: (body) => request('/auth/setup', { method: 'POST', body: JSON.stringify(body) }),
};

// Repository API
export const repositoryApi = {
  getAll: (params = {}, opts = {}) => {
    const qs = new URLSearchParams();
    if (params.page) qs.set('page', params.page);
    if (params.per_page) qs.set('per_page', params.per_page);
    if (params.provider && params.provider !== 'all') qs.set('provider', params.provider);
    if (params.q) qs.set('q', params.q);
    if (params.status) qs.set('status', params.status);
    if (params.sort) qs.set('sort', params.sort);
    const query = qs.toString();
    return request(`/repositories${query ? '?' + query : ''}`, opts);
  },
  getById: (id) => request(`/repositories/${id}`),
  create: (data) => request('/repositories', { method: 'POST', body: JSON.stringify(data) }),
  update: (id, data) => request(`/repositories/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  delete: (id) => request(`/repositories/${id}`, { method: 'DELETE' }),
  triggerScan: (id) => request(`/repositories/${id}/scan`, { method: 'POST' }),
  fetchGitHub: (tokenId) => request('/repositories/github/fetch', { method: 'POST', body: JSON.stringify({ token_id: tokenId }) }),
  fetchGitLab: (tokenId) => request('/repositories/gitlab/fetch', { method: 'POST', body: JSON.stringify({ token_id: tokenId }) }),
  fetchAzureDevOps: (tokenId) => request('/repositories/azuredevops/fetch', { method: 'POST', body: JSON.stringify({ token_id: tokenId }) }),
  // provider is optional: the server takes it from the token and rejects a mismatch.
  bulkImport: (tokenId, repositories, provider) => request('/repositories/import', { method: 'POST', body: JSON.stringify({ token_id: tokenId, ...(provider ? { provider } : {}), repositories }) }),
};

// Git host (Azure DevOps connection) API
export const gitHostApi = {
  getAll: () => request('/git-hosts'),
  create: (data) => request('/git-hosts', { method: 'POST', body: JSON.stringify(data) }),
  delete: (id) => request(`/git-hosts/${id}`, { method: 'DELETE' }),
};

// Token API
export const tokenApi = {
  getAll: () => request('/tokens'),
  create: (data) => request('/tokens', { method: 'POST', body: JSON.stringify(data) }),
  delete: (id) => request(`/tokens/${id}`, { method: 'DELETE' }),
};

// Scan API
export const scanApi = {
  getHistory: (repoId) => request(`/repositories/${repoId}/scans`),
  getById: (id) => request(`/scans/${id}`),
  getDependencies: (id) => request(`/scans/${id}/dependencies`),
  getVulnerabilities: (id) => request(`/scans/${id}/vulnerabilities`),
};

// Dashboard / Health API
export const dashboardApi = {
  health: () => request('/health'),
  stats: () => request('/dashboard/stats'),
};

// Vulnerability API
export const vulnerabilityApi = {
  list: ({ page = 1, per_page = 25, severity, kev, min_epss, sort } = {}) => {
    const qs = new URLSearchParams({ page: String(page), per_page: String(per_page) });
    if (severity) qs.set('severity', severity);
    if (kev) qs.set('kev', 'true');
    if (min_epss != null && min_epss !== '') qs.set('min_epss', String(min_epss));
    if (sort && sort !== 'severity') qs.set('sort', sort);
    return request(`/vulnerabilities?${qs}`);
  },
};
