// IMPORTANT: change this to your deployed backend URL once you host it,
// e.g. 'https://securevault-backend.onrender.com/api'
const API_BASE = 'http://localhost:8080/api';

const Api = {
  token() {
    return sessionStorage.getItem('sv_token');
  },

  setToken(token, email) {
    sessionStorage.setItem('sv_token', token);
    sessionStorage.setItem('sv_email', email);
  },

  clearSession() {
    sessionStorage.removeItem('sv_token');
    sessionStorage.removeItem('sv_email');
  },

  async request(path, { method = 'GET', body = null, auth = true } = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (auth) {
      const token = this.token();
      if (!token) {
        window.location.href = 'index.html';
        throw new Error('Not authenticated');
      }
      headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    let data = null;
    try { data = await res.json(); } catch (_) { /* no body */ }

    if (!res.ok) {
      const message = (data && data.error) || `Request failed (${res.status})`;
      throw new Error(message);
    }
    return data;
  },

  register(email, masterPassword) {
    return this.request('/auth/register', { method: 'POST', auth: false, body: { email, masterPassword } });
  },

  login(email, masterPassword) {
    return this.request('/auth/login', { method: 'POST', auth: false, body: { email, masterPassword } });
  },

  verify2fa(preAuthToken, code) {
    return this.request('/auth/2fa-verify', { method: 'POST', auth: false, body: { preAuthToken, code } });
  },

  recoverAccount(email, recoveryCode, newMasterPassword) {
    return this.request('/auth/recover', { method: 'POST', auth: false, body: { email, recoveryCode, newMasterPassword } });
  },

  setup2fa() {
    return this.request('/2fa/setup', { method: 'POST' });
  },

  enable2fa(code) {
    return this.request('/2fa/enable', { method: 'POST', body: { code } });
  },

  disable2fa(masterPassword) {
    return this.request('/2fa/disable', { method: 'POST', body: { masterPassword } });
  },

  getActivity() {
    return this.request('/audit/me');
  },

  listVaultItems() {
    return this.request('/vault');
  },

  createVaultItem(itemType, title, secretData, masterPassword) {
    return this.request('/vault', { method: 'POST', body: { itemType, title, secretData, masterPassword } });
  },

  revealVaultItem(id, masterPassword) {
    return this.request(`/vault/${id}/reveal`, { method: 'POST', body: { masterPassword } });
  },

  updateVaultItem(id, title, secretData, masterPassword) {
    return this.request(`/vault/${id}`, { method: 'PUT', body: { title, secretData, masterPassword } });
  },

  deleteVaultItem(id) {
    return this.request(`/vault/${id}`, { method: 'DELETE' });
  },

  getScorecard(masterPassword) {
    return this.request('/vault/security-scorecard', { method: 'POST', body: { masterPassword } });
  },
};
