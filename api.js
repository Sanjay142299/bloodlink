// ═══════════════════════════════════════════════════════════
//  BloodLink Frontend API — connects to Node.js backend
//  Backend must be running: cd backend && node server.js
// ═══════════════════════════════════════════════════════════

const API_BASE = 'http://127.0.0.1:5000/api';
const API_KEY = '7c3e525e1fb153a90579cd66f70d324ed04dea5203fb52313a25ff4324e4dccf';

// ── Session helpers ───────────────────────────────────────
function getToken() { return localStorage.getItem('bl_token'); }
function getRole()  { return localStorage.getItem('bl_role'); }
function getUser()  { try { return JSON.parse(localStorage.getItem('bl_user')); } catch { return null; } }
function saveSession(token, role, user) {
  localStorage.setItem('bl_token', token);
  localStorage.setItem('bl_role', role);
  localStorage.setItem('bl_user', JSON.stringify(user));
}
function clearSession() {
  ['bl_token','bl_role','bl_user'].forEach(k => localStorage.removeItem(k));
}
function isLoggedIn() { return !!getToken(); }

// ── Core fetch wrapper ────────────────────────────────────
async function apiFetch(method, path, body=null, isFormData=false) {
  const headers = {};
  const token   = getToken();
  if (token) headers['Authorization'] = 'Bearer ' + token;
  headers['X-API-Key'] = API_KEY;
  if (!isFormData && body) headers['Content-Type'] = 'application/json';

  const opts = { method, headers };
  if (body) opts.body = isFormData ? body : JSON.stringify(body);

  let res;
  try {
    res = await fetch(API_BASE + path, opts);
  } catch {
    throw new Error('Cannot connect to server. Make sure backend is running:\n  cd backend\n  node server.js');
  }

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// ── Auth ──────────────────────────────────────────────────
const Auth = {
  donorRegister:    (fd)   => apiFetch('POST', '/auth/donor/register',    fd, true),
  donorLogin:       (data) => apiFetch('POST', '/auth/donor/login',       data),
  hospitalRegister: (fd)   => apiFetch('POST', '/auth/hospital/register', fd, true),
  hospitalLogin:    (data) => apiFetch('POST', '/auth/hospital/login',    data),
  adminLogin:       (data) => apiFetch('POST', '/auth/admin/login',       data),
  sendOTP:          (data) => apiFetch('POST', '/auth/emergency/send-otp',data),
  verifyOTP:        (data) => apiFetch('POST', '/auth/emergency/verify-otp',data),
};

// ── Donor ─────────────────────────────────────────────────
const DonorAPI = {
  getProfile:       ()     => apiFetch('GET',   '/donor/profile'),
  updateProfile:    (data) => apiFetch('PUT',   '/donor/profile', data),
  updateLocation:   (data) => apiFetch('PATCH', '/donor/location', data),
  setAvailability:  (val)  => apiFetch('PATCH', '/donor/availability', { available: val }),
  getNotifications: ()     => apiFetch('GET',   '/donor/notifications'),
  getHistory:       ()     => apiFetch('GET',   '/donor/history'),
  getMapDonors:     ()     => apiFetch('GET',   '/donor/map'),
  respondRequest:   (id, resp) => apiFetch('POST', `/request/${id}/respond`, { response: resp }),
};

// ── Blood Requests ────────────────────────────────────────
const RequestAPI = {
  submit:       (data)     => apiFetch('POST', '/request', data),
  getAll:       ()         => apiFetch('GET',  '/request'),
  respond:      (id, resp) => apiFetch('POST', `/request/${id}/respond`, { response: resp }),
  matchPreview: (data)     => apiFetch('POST', '/request/match-preview', data),
};

// ── Hospital ──────────────────────────────────────────────
const HospitalAPI = {
  getProfile:    ()     => apiFetch('GET', '/hospital/profile'),
  updateProfile: (data) => apiFetch('PUT', '/hospital/profile', data),
  updateLocation:(data) => apiFetch('PATCH', '/hospital/location', data),
  getMyRequests: ()     => apiFetch('GET', '/hospital/requests'),
  getAll:        ()     => apiFetch('GET', '/hospital'),
  getNotifications: ()  => apiFetch('GET', '/hospital/notifications'),
};

// ── Admin ─────────────────────────────────────────────────
const AdminAPI = {
  getStats:       ()            => apiFetch('GET',   '/admin/stats'),
  getPending:     ()            => apiFetch('GET',   '/admin/pending'),
  verifyDonor:    (id, action)  => apiFetch('PATCH', `/admin/verify/donor/${id}`,    { action }),
  verifyHospital: (id, action)  => apiFetch('PATCH', `/admin/verify/hospital/${id}`, { action }),
  getAllDonors:    (status)      => apiFetch('GET',   `/admin/donors${status?'?status='+status:''}`),
  getAllRequests:  ()            => apiFetch('GET',   '/admin/requests'),
  getProofs:       (status)      => apiFetch('GET',   `/admin/proofs?status=${status||'pending'}`),
  getNotifications:()            => apiFetch('GET',   '/admin/notifications'),
  notifyDonors:    (reqId, ids)  => apiFetch('POST',  '/admin/notify-donors', { request_id: reqId, donor_ids: ids }),
};

// ── Toast ─────────────────────────────────────────────────
function showToast(message, type='info') {
  let c = document.getElementById('toast-container');
  if (!c) {
    c = document.createElement('div');
    c.id = 'toast-container';
    c.className = 'toast-container';
    document.body.appendChild(c);
  }
  const t = document.createElement('div');
  t.className = 'toast ' + type;
  t.innerHTML = '<span>' + message + '</span>';
  c.appendChild(t);
  setTimeout(() => { t.style.opacity='0'; t.style.transition='opacity 0.3s'; setTimeout(()=>t.remove(),300); }, 3500);
}

// ── GPS ───────────────────────────────────────────────────
function getCurrentPosition() {
  return new Promise((res, rej) =>
    navigator.geolocation
      ? navigator.geolocation.getCurrentPosition(res, rej, { enableHighAccuracy: true })
      : rej(new Error('Geolocation not supported'))
  );
}
