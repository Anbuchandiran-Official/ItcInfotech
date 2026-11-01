const state = { csrf: '', mode: 'login', resetToken: new URLSearchParams(location.search).get('reset') || '' };
const $ = selector => document.querySelector(selector);
const forms = ['#auth-form', '#mfa-form', '#forgot-form', '#reset-form'];
function notify(message, error = false) { const box = $('#notice'); box.textContent = message; box.classList.toggle('error', error); box.hidden = false; }
function clearNotice() { $('#notice').hidden = true; $('#notice').textContent = ''; $('#notice').classList.remove('error'); }
function showForm(selector) { for (const f of forms) $(f).hidden = f !== selector; $('#auth-forms').hidden = false; $('#dashboard').hidden = true; }
async function request(path, data = {}) {
  const response = await fetch(`/api${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf }, body: JSON.stringify(data), credentials: 'same-origin' });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || 'Request failed. Please try again.');
  return body;
}
async function refreshCsrf() { const response = await fetch('/api/csrf', { credentials: 'same-origin', cache: 'no-store' }); const body = await response.json(); state.csrf = body.csrfToken; }
function updateMode(mode) {
  state.mode = mode; clearNotice(); $('#panel-title').textContent = mode === 'register' ? 'Create your account' : 'Welcome back';
  $('#submit-label').textContent = mode === 'register' ? 'Create account securely' : 'Continue securely';
  $('#password-hint').textContent = mode === 'register' ? 'At least 12 characters with uppercase, lowercase and a number.' : 'Use a unique password you have not used elsewhere.';
  $('#password').autocomplete = mode === 'register' ? 'new-password' : 'current-password';
  document.querySelectorAll('.tab').forEach(tab => { const active = tab.dataset.mode === mode; tab.classList.toggle('active', active); tab.setAttribute('aria-selected', String(active)); });
  $('#auth-form').reset(); showForm('#auth-form');
}
function showDashboard(user) {
  clearNotice(); $('#auth-forms').hidden = true; $('#dashboard').hidden = false;
  $('#panel-title').textContent = 'You’re signed in'; $('#user-email').textContent = user.email;
  $('#avatar').textContent = user.email.slice(0, 1).toUpperCase();
  $('#mfa-status').textContent = user.mfaEnabled ? 'Enabled' : 'Not enabled';
  $('#mfa-setup').hidden = user.mfaEnabled; $('#mfa-disable-row').hidden = !user.mfaEnabled;
  $('#mfa-enrollment').hidden = true;
}
async function run(button, fn) {
  clearNotice(); button.disabled = true;
  try { await fn(); } catch (error) { notify(error.message, true); }
  finally { button.disabled = false; }
}
document.querySelectorAll('.tab').forEach(tab => tab.addEventListener('click', () => updateMode(tab.dataset.mode)));
$('#auth-form').addEventListener('submit', event => { event.preventDefault(); const button = event.currentTarget.querySelector('button[type=submit]'); run(button, async () => {
  const email = $('#email').value; const password = $('#password').value;
  const body = await request(state.mode === 'register' ? '/register' : '/login', { email, password });
  await refreshCsrf();
  if (body.mfaRequired) { $('#auth-form').hidden = true; $('#mfa-form').hidden = false; $('#panel-title').textContent = 'Verify it’s you'; return; }
  showDashboard(body.user);
}); });
$('#mfa-form').addEventListener('submit', event => { event.preventDefault(); const button = event.currentTarget.querySelector('button[type=submit]'); run(button, async () => { const body = await request('/login/mfa', { code: $('#mfa-code').value }); showDashboard(body.user); }); });
$('#forgot-link').addEventListener('click', () => { clearNotice(); $('#panel-title').textContent = 'Reset your password'; $('#forgot-email').value = $('#email').value; showForm('#forgot-form'); });
document.querySelectorAll('[data-back]').forEach(button => button.addEventListener('click', () => { $('#panel-title').textContent = 'Welcome back'; updateMode('login'); }));
$('#forgot-form').addEventListener('submit', event => { event.preventDefault(); const button = event.currentTarget.querySelector('button[type=submit]'); run(button, async () => { const body = await request('/forgot', { email: $('#forgot-email').value }); notify(body.message); }); });
$('#reset-form').addEventListener('submit', event => { event.preventDefault(); const button = event.currentTarget.querySelector('button[type=submit]'); run(button, async () => { const body = await request('/reset', { token: state.resetToken, password: $('#new-password').value }); history.replaceState({}, '', '/'); state.resetToken = ''; $('#panel-title').textContent = 'Welcome back'; updateMode('login'); notify(body.message); }); });
$('#logout').addEventListener('click', event => run(event.currentTarget, async () => { await request('/logout'); await refreshCsrf(); updateMode('login'); notify('You have signed out.'); }));
$('#mfa-setup').addEventListener('click', event => run(event.currentTarget, async () => { const body = await request('/mfa/setup'); $('#mfa-secret').textContent = body.secret; $('#mfa-uri').textContent = body.otpauth; $('#mfa-enrollment').hidden = false; }));
$('#mfa-enable').addEventListener('click', event => run(event.currentTarget, async () => { await request('/mfa/enable', { code: $('#enroll-code').value }); showDashboard({ email: $('#user-email').textContent, mfaEnabled: true }); notify('Authenticator MFA is enabled.'); }));
$('#mfa-disable').addEventListener('click', event => run(event.currentTarget, async () => { await request('/mfa/disable', { code: $('#disable-code').value }); showDashboard({ email: $('#user-email').textContent, mfaEnabled: false }); notify('Authenticator MFA is disabled.'); }));
(async () => {
  try {
    await refreshCsrf();
    if (state.resetToken) { $('#panel-title').textContent = 'Choose a new password'; showForm('#reset-form'); return; }
    const response = await fetch('/api/me', { credentials: 'same-origin' }); const body = await response.json();
    if (body.user) showDashboard(body.user); else updateMode('login');
  } catch { notify('The service is starting. Refresh this page in a moment.', true); }
})();
