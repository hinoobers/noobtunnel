'use strict';
/* noobtunnel control node UI. No frameworks, no external requests. */

/* ---------- tiny DOM helpers ---------- */

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  applyProps(el, props);
  appendKids(el, kids);
  return el;
}

function svg(tag, props, ...kids) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  applyProps(el, props);
  appendKids(el, kids);
  return el;
}

function applyProps(el, props) {
  if (!props) return;
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') el.setAttribute('class', value);
    else if (key === 'text') el.textContent = String(value);
    else if (key === 'html') el.innerHTML = value;
    else if (key === 'dataset') Object.assign(el.dataset, value);
    else if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2), value);
    else if (value === true) el.setAttribute(key, '');
    else el.setAttribute(key, String(value));
  }
}

function appendKids(el, kids) {
  for (const kid of kids.flat(3)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
}

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function clear(node) {
  if (node) node.replaceChildren();
  return node;
}

function icon(pathData, size = 15) {
  return svg('svg', { viewBox: '0 0 24 24', width: size, height: size, fill: 'none',
    stroke: 'currentColor', 'stroke-width': '1.9', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' },
    svg('path', { d: pathData }));
}

/* ---------- formatting ---------- */

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + ' ' + units[i];
}

function fmtRate(n) { return fmtBytes(n) + '/s'; }

function fmtDuration(seconds) {
  seconds = Math.max(0, Math.floor(Number(seconds) || 0));
  if (seconds < 60) return seconds + 's';
  if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + (seconds % 60) + 's';
  if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
  return Math.floor(seconds / 86400) + 'd ' + Math.floor((seconds % 86400) / 3600) + 'h';
}

function relTime(value) {
  if (!value) return 'never';
  const then = new Date(value).getTime();
  if (!then) return 'never';
  const diff = (Date.now() - then) / 1000;
  if (diff < 0) return 'just now';
  if (diff < 45) return Math.round(diff) + 's ago';
  if (diff < 3600) return Math.round(diff / 60) + 'm ago';
  if (diff < 86400) return Math.round(diff / 3600) + 'h ago';
  return Math.round(diff / 86400) + 'd ago';
}

function absTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  return d.toLocaleString(undefined, { hour12: false });
}

function clockTime(value) {
  const d = value ? new Date(value) : new Date();
  return d.toLocaleTimeString(undefined, { hour12: false });
}

function shortKey(key) {
  if (!key) return '—';
  return key.length > 18 ? key.slice(0, 9) + '…' + key.slice(-6) : key;
}

/* ---------- toasts & clipboard ---------- */

function toast(message, kind = 'info') {
  const node = h('div', { class: 'toast ' + kind, text: message });
  $('#toasts').append(node);
  setTimeout(() => {
    node.style.transition = 'opacity .3s, transform .3s';
    node.style.opacity = '0';
    node.style.transform = 'translateY(6px)';
    setTimeout(() => node.remove(), 320);
  }, kind === 'fail' ? 6500 : 3200);
}

async function copyText(value, label = 'Copied to clipboard') {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
    } else {
      const ta = h('textarea', { style: 'position:fixed;opacity:0' });
      ta.value = value;
      document.body.append(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    toast(label, 'ok');
  } catch (err) {
    toast('Could not copy: ' + err.message, 'fail');
  }
}

function copyButton(value, label = 'Copy') {
  return h('button', { class: 'btn btn-sm', type: 'button', 'data-no-dirty': true,
    onclick: () => copyText(value, 'Copied') }, label);
}

/* ---------- api ---------- */

async function api(path, options = {}) {
  const init = { method: options.method || 'GET', credentials: 'same-origin', headers: {} };
  if (options.raw !== undefined) {
    // Binary upload (branding). Everything else is JSON.
    init.body = options.raw;
    init.headers['Content-Type'] = options.contentType || 'application/octet-stream';
  } else if (options.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(options.body);
  }
  init.headers['X-Noobtunnel'] = '1';
  const response = await fetch(path, init);
  let payload = null;
  const text = await response.text();
  if (text) {
    try { payload = JSON.parse(text); } catch { payload = null; }
  }
  if (response.status === 401) {
    state.authenticated = false;
    state.requestPageData = null;
    render();
    throw new Error('your session expired, please sign in again');
  }
  if (!response.ok) {
    throw new Error((payload && payload.error) || ('request failed with status ' + response.status));
  }
  return payload;
}

/* ---------- state ---------- */

const state = {
  authenticated: false,
  passwordSet: false,
  meshName: 'noobtunnel',
  brandName: 'noobtunnel',
  // session holds who is signed in and what they may do.
  session: { username: '', role: '', canAdmin: false },
  data: null,
  view: 'overview',
  filter: '',
  drawer: null,
  // brandingSignature guards the branding forms so a live update cannot wipe out
  // what the admin is typing; cssStatus tracks which sheet the editor loaded.
  brandingSignature: '',
  stream: null,
  streamHealthy: false,
  lastSnapshot: 0,
  settingsSignature: '',
  users: null,
  usersAt: 0,
  resourceFilterEmail: '',
  resourceFilterData: null,
  resourceFilterRequest: 0,
  requestPageData: null,
  requestPageLoading: false,
  requestPage: 1,
  logTab: 'requests',
  settingsTab: 'mesh',
  expandedSidebarGroup: null,
  sidebarOpen: false,
  // resourceForm is null, or {id} when the publish page is open.
  resourceForm: null,
  resourceEditorKey: '',
  // The agent drawer is mounted once and updated in place: rebuilding it on
  // every live update replayed its animation and fought with the modal layer.
  drawerEl: null,
  drawerBody: null,
};

let shell = null;
const appRoot = () => $('#app');

// Views that map to a URL path, so a refresh keeps the tab you were on.
const VIEW_PATHS = ['overview', 'agents', 'resources', 'domains', 'exitnodes', 'users', 'activity', 'settings'];

function viewFromPath(pathname) {
  const route = routeFromPath(pathname);
  return route ? route.view : '';
}

// routeFromPath also recognises an open resource editor. Keeping the resource
// id in the URL means refresh, back/forward and shared links all restore the
// same editor instead of dropping the operator back on the resource list.
function routeFromPath(pathname) {
  const name = String(pathname || '').replace(/^\/+|\/+$/g, '').toLowerCase();
  const resource = name.match(/^resources\/(\d+)$/);
  if (resource) return { view: 'resources', resourceId: Number(resource[1]) };
  const subtab = name.match(/^(activity|settings)\/([a-z]+)$/);
  if (subtab) {
    const allowed = subtab[1] === 'activity'
      ? ['requests', 'statistics', 'activity', 'errors'] : ['mesh', 'users', 'smtp', 'geoip', 'branding', 'tokens'];
    if (allowed.includes(subtab[2])) return { view: subtab[1], tab: subtab[2], resourceId: null };
  }
  return VIEW_PATHS.includes(name) ? { view: name, resourceId: null } : null;
}

function applyRoute(route) {
  if (!route) return;
  state.view = route.view;
  state.expandedSidebarGroup = route.view === 'activity' || route.view === 'settings' ? route.view : null;
  if (route.view === 'activity') {
    state.logTab = route.tab || 'requests';
    const params = new URLSearchParams(window.location.search);
    const rawPage = params.get('page');
    const page = Number(rawPage);
    state.requestPage = Number.isSafeInteger(page) && page > 0 ? page : 1;
    const validSort = ['time', 'durationMs', 'host', 'path', 'client', 'country', 'resource', 'decision'];
    requestSort = {
      key: validSort.includes(params.get('sort')) ? params.get('sort') : 'time',
      direction: params.get('dir') === 'asc' ? 'asc' : 'desc',
    };
    for (const field of Object.keys(requestFilters)) {
      requestFilters[field] = new Set(params.getAll(field));
      requestSearch[field] = params.get('search_' + field) || '';
    }
    state.requestPageData = null;
  }
  if (route.view === 'settings') state.settingsTab = route.tab || 'mesh';
  state.resourceForm = route.view === 'resources' && route.resourceId !== null
    ? { id: route.resourceId }
    : null;
  state.resourceEditorKey = '';
}

// setView switches tabs and keeps the address bar in step. push=false is used
// when the URL has already changed (back/forward, or a page load).
function setView(view, push = true) {
  if (!VIEW_PATHS.includes(view)) return;
  state.view = view;
  state.expandedSidebarGroup = view === 'activity' || view === 'settings' ? view : null;
  state.resourceForm = null;
  state.resourceEditorKey = '';
  // A highlight belongs to the visit that asked for it: leaving Logs drops it.
  if (view !== 'activity') state.errorMatch = '';
  if (push && typeof window !== 'undefined' && window.history && window.history.pushState) {
    const target = view === 'activity' ? (state.logTab === 'requests' ? requestPageURL() : '/activity/' + state.logTab)
      : view === 'settings' ? '/settings/' + state.settingsTab
      : view === 'overview' ? '/' : '/' + view;
    if (window.location.pathname + window.location.search !== target) window.history.pushState({ view }, '', target);
  }
  renderShell();
  if (view === 'activity' && state.logTab === 'requests') loadRequestPage();
}

async function filterResourcesByEmail(email) {
  const value = String(email || '').trim();
  state.resourceFilterEmail = value;
  state.resourceFilterData = null;
  const request = ++state.resourceFilterRequest;
  renderShell();
  if (!value || !canAdmin()) return;
  try {
    const result = await api('/api/resources?email=' + encodeURIComponent(value));
    if (request !== state.resourceFilterRequest) return;
    state.resourceFilterData = result;
    renderShell();
  } catch (err) {
    if (request !== state.resourceFilterRequest) return;
    toast(err.message, 'fail');
  }
}

/* ---------- boot ---------- */

async function boot() {
  try {
    const session = await fetch('/api/session', { credentials: 'same-origin' }).then((r) => r.json());
    applySession(session);
  } catch (err) {
    state.authenticated = false;
  }
  if (!state.authenticated) {
    render();
    return;
  }
  const deepLink = routeFromPath(window.location.pathname);
  if (deepLink) applyRoute(deepLink);
  if (deepLink?.view === 'resources' && deepLink.resourceId !== null && canAdmin()) {
    const email = new URLSearchParams(window.location.search).get('email');
    if (email) {
      state.resourceFilterEmail = email;
      try { state.resourceFilterData = await api('/api/resources?email=' + encodeURIComponent(email)); }
      catch (err) { toast(err.message, 'fail'); }
    }
  }
  await refresh(true);
  if (state.view === 'users' && canAdmin()) loadUsers(true);
  if (state.view === 'settings' && state.settingsTab === 'users' && canAdmin()) loadSignupSettings();
  if (state.view === 'settings' && state.settingsTab === 'smtp' && canAdmin()) loadSMTP();
  startStream();
}

// applySession records who is signed in and what the UI should expose.
function applySession(session) {
  state.authenticated = !!session.authenticated;
  state.passwordSet = !!session.passwordSet;
  state.meshName = session.meshName || 'noobtunnel';
  state.brandName = session.brandName || 'noobtunnel';
  state.session = {
    username: session.username || '',
    role: session.role || '',
    canAdmin: !!session.canAdmin,
  };
}

function canAdmin() { return state.session.canAdmin; }
function canManageMesh() { return canAdmin() || state.session.role === 'regular'; }

async function refresh(showSpinner = false) {
  try {
    state.data = await api('/api/state');
    state.lastSnapshot = Date.now();
    state.authenticated = true;
  } catch (err) {
    if (state.authenticated) toast(err.message, 'fail');
  }
  render();
  if (showSpinner) setStreamLabel();
}

function startStream() {
  if (state.stream) state.stream.close();
  try {
    const stream = new EventSource('/api/events');
    state.stream = stream;
    stream.onopen = () => { state.streamHealthy = true; setStreamLabel(); };
    stream.onmessage = (event) => {
      try {
        state.data = JSON.parse(event.data);
        state.lastSnapshot = Date.now();
        state.streamHealthy = true;
        render();
      } catch (err) { /* ignore malformed frame */ }
    };
    stream.onerror = () => {
      state.streamHealthy = false;
      setStreamLabel();
    };
  } catch (err) {
    state.streamHealthy = false;
  }
}

function setStreamLabel() {
  if (!shell) return;
  const live = $('[data-live]', shell.root);
  const label = $('[data-live-label]', shell.root);
  if (!live) return;
  const stale = Date.now() - state.lastSnapshot > 20000;
  live.classList.toggle('is-stale', !state.streamHealthy || stale);
  label.textContent = state.streamHealthy && !stale ? 'live' : 'reconnecting…';
}

setInterval(() => { if (shell) setStreamLabel(); }, 5000);

// Keep the visible Requests page current without resetting the table between fetches.
setInterval(() => {
  if (state.authenticated && state.view === 'activity' && state.logTab === 'requests' &&
      document.visibilityState !== 'hidden' && state.requestPageData && !state.requestPageLoading) {
    loadRequestPage(true);
  }
}, 2000);

/* ---------- render entry point ---------- */

function render() {
  const root = appRoot();
  root.classList.remove('is-loading');
  if (!state.authenticated) {
    const path = window.location.pathname;
    if (path === '/') mountLanding();
    else if (path === '/forgot-password') mountForgotPassword();
    else if (path === '/reset-password') mountResetPassword();
    else if (path === '/verify-email') mountVerifyEmail();
    else if (path === '/signup') mountSignup();
    else mountLogin();
    applyBranding();
    return;
  }
  if (!state.data) {
    mountBoot();
    return;
  }
  const firstMount = !shell;
  if (firstMount) mountShell();
  renderShell();
  if (firstMount && state.view === 'activity' && state.logTab === 'requests') loadRequestPage();
}

function mountSignup() {
  const node = $('#tpl-signup').content.firstElementChild.cloneNode(true);
  const form = $('[data-form=signup]', node);
  fetch('/api/signup/status').then((r) => r.json()).then((status) => {
    if (!status.enabled) { const error = $('[data-error]', node); error.textContent = status.limitReached ? 'Registration limit reached. Try again later.' : 'Sign-ups are disabled right now.'; error.hidden = false; form.querySelector('button[type=submit]').disabled = true; }
  }).catch(() => {});
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const error = $('[data-error]', node); error.hidden = true;
    if (form.elements.password.value !== form.elements.confirm.value) { error.textContent = 'Passwords do not match'; error.hidden = false; return; }
    try {
      const result = await api('/api/signup', { method: 'POST', body: { username: form.elements.username.value.trim(), email: form.elements.email.value.trim(), password: form.elements.password.value } });
      const success = $('[data-success]', node); success.textContent = result.message; success.hidden = false; form.hidden = true;
    } catch (err) { error.textContent = err.message; error.hidden = false; }
  });
  clear(appRoot()).append(node);
}

function mountLanding() {
  const node = $('#tpl-home').content.firstElementChild.cloneNode(true);
  clear(appRoot()).append(node);
  fetch('/api/signup/status').then((r) => r.json()).then((status) => {
    const link = $('[data-signup-link]', node);
    if (link) link.hidden = !status.enabled;
  }).catch(() => {});
}

function mountForgotPassword() {
  const node = $('#tpl-forgot').content.firstElementChild.cloneNode(true);
  const form = $('[data-form=forgot]', node);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const error = $('[data-error]', node);
    error.hidden = true;
    try {
      const result = await api('/api/password/forgot', { method: 'POST', body: { email: form.elements.email.value.trim() } });
      const success = $('[data-success]', node);
      success.textContent = result.message;
      success.hidden = false;
    } catch (err) { error.textContent = err.message; error.hidden = false; }
  });
  clear(appRoot()).append(node);
}

function mountResetPassword() {
  const node = $('#tpl-reset').content.firstElementChild.cloneNode(true);
  const token = new URLSearchParams(window.location.search).get('token') || '';
  const form = $('[data-form=reset]', node);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const error = $('[data-error]', node);
    error.hidden = true;
    if (form.elements.password.value !== form.elements.confirm.value) {
      error.textContent = 'Passwords do not match'; error.hidden = false; return;
    }
    try {
      await api('/api/password/reset', { method: 'POST', body: { token, password: form.elements.password.value } });
      window.history.replaceState({}, '', '/login');
      const success = $('[data-success]', node);
      success.textContent = 'Password updated. You can sign in now.';
      success.hidden = false;
      form.hidden = true;
    } catch (err) { error.textContent = err.message; error.hidden = false; }
  });
  clear(appRoot()).append(node);
}

function mountVerifyEmail() {
  const node = $('#tpl-verify').content.firstElementChild.cloneNode(true);
  const token = new URLSearchParams(window.location.search).get('token') || '';
  $('[data-confirm-email]', node).addEventListener('click', async () => {
    const error = $('[data-error]', node);
    error.hidden = true;
    try {
      await api('/api/email/confirm', { method: 'POST', body: { token } });
      window.history.replaceState({}, '', '/login');
      const success = $('[data-success]', node);
      success.textContent = 'Email confirmed. You can sign in now.';
      success.hidden = false;
      $('[data-confirm-email]', node).hidden = true;
    } catch (err) { error.textContent = err.message; error.hidden = false; }
  });
  clear(appRoot()).append(node);
}

function mountBoot() {
  clear(appRoot()).append(h('div', { class: 'boot' },
    h('div', { class: 'boot-mark' }),
    h('p', { text: 'loading mesh state…' })));
}

function mountLogin() {
  // A session can expire while a modal is open: never leave it over the login form.
  closeModal();
  const node = $('#tpl-login').content.firstElementChild.cloneNode(true);
  const form = $('form', node);
  const error = $('[data-error]', node);
  const note = $('[data-login-note]', node);
  if (!state.passwordSet) {
    note.hidden = false;
    note.textContent = 'No admin password is configured yet. Restart the control node with --admin-password to set one.';
    $('button[type=submit]', node).disabled = true;
  }
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    error.hidden = true;
    const password = new FormData(form).get('password');
    const username = new FormData(form).get('username');
    try {
      const result = await api('/api/login', { method: 'POST', body: { username, password } });
      applySession({
        authenticated: true,
        passwordSet: true,
        meshName: state.meshName,
        username: result.username,
        role: result.role,
        canAdmin: result.role === 'admin',
      });
      state.authenticated = true;
      if (window.location.pathname === '/login') window.history.replaceState({}, '', '/');
      shell = null;
      await refresh(true);
      startStream();
    } catch (err) {
      error.hidden = false;
      error.textContent = err.message;
    }
  });
  clear(appRoot()).append(node);
}

function mountShell() {
  // Clone the complete shell, including its sidebar and main column.
  const fragment = $('#tpl-shell').content.cloneNode(true);
  clear(appRoot()).append(fragment);
  const node = appRoot();
  shell = {
    root: node,
    sessionUser: $('[data-session-user]', node),
    sessionRole: $('[data-session-role]', node),
    stats: $('[data-stats]', node),
    healthPanel: $('[data-health-panel]', node),
    topology: $('[data-topology]', node),
    topologySub: $('[data-topology-sub]', node),
    meshRange: $('[data-mesh-range]', node),
    agentGrid: $('[data-agent-grid]', node),
    agentsSub: $('[data-agents-sub]', node),
    usersTable: $('[data-users-table]', node),
    usersSub: $('[data-users-sub]', node),
    resourcesTable: $('[data-resources-table]', node),
    resourcesSub: $('[data-resources-sub]', node),
    resourceList: $('[data-resource-list]', node),
    resourceEditor: $('[data-resource-editor]', node),
    resourcesAdd: $('[data-resources-add]', node),
    resourcesEmailFilter: $('[data-resource-email-filter]', node),
    domainsTable: $('[data-domains-table]', node),
    domainsSub: $('[data-domains-sub]', node),
    domainList: $('[data-domain-list]', node),
    domainsAdd: $('[data-domains-add]', node),
    exitNodesTable: $('[data-exitnodes-table]', node),
    exitNodesSub: $('[data-exitnodes-sub]', node),
    exitNodesAdd: $('[data-exitnodes-add]', node),
    events: $('[data-events]', node),
    errorsTable: $('[data-errors-table]', node),
    errorsSub: $('[data-errors-sub]', node),
    requestCharts: $('[data-request-charts]', node),
    requestTable: $('[data-request-table]', node),
    requestsSub: $('[data-requests-sub]', node),
    serverInfo: $('[data-server-info]', node),
    apiTokens: $('[data-api-tokens]', node),
    settingsForm: $('form[data-form=settings]', node),
    brandingForm: $('form[data-form=branding]', node),
    brandNameForm: $('form[data-form=brand-name]', node),
    brandCSSForm: $('form[data-form=brand-css]', node),
    cssStatus: $('[data-css-status]', node),
    cssError: $('[data-css-error]', node),
    geoipForm: $('form[data-form=geoip]', node),
    geoipStatus: $('[data-geoip-status]', node),
    geoipDetail: $('[data-geoip-detail]', node),
    readonlyNote: $('[data-readonly-note]', node),
    menu: $('[data-menu]', node),
    filter: $('[data-agent-filter]', node),
  };
  installGlobalActions();
  wireShell(node);
  installTabs(node);
  renderShell();
}

function wireShell(node) {
  if (shell.resourcesEmailFilter) {
    let filterTimer;
    shell.resourcesEmailFilter.addEventListener('input', (event) => {
      clearTimeout(filterTimer);
      const value = event.target.value;
      state.resourceFilterEmail = value;
      state.resourceFilterData = null;
      ++state.resourceFilterRequest;
      filterTimer = setTimeout(() => filterResourcesByEmail(value), 350);
    });
  }
  shell.settingsForm.addEventListener('submit', saveSettings);
  const signupForm = $('form[data-form=signup-settings]', node);
  if (signupForm) signupForm.addEventListener('submit', saveSignupSettings);
  const smtpForm = $('form[data-form=smtp]', node);
  if (smtpForm) smtpForm.addEventListener('submit', saveSMTP);
  if (shell.brandingForm) shell.brandingForm.addEventListener('submit', uploadLogo);
  if (shell.brandNameForm) shell.brandNameForm.addEventListener('submit', saveBrandName);
  if (shell.brandCSSForm) shell.brandCSSForm.addEventListener('submit', saveBrandCSS);
  if (shell.geoipForm) {
    shell.geoipForm.addEventListener('submit', saveGeoIP);
    shell.geoipForm.addEventListener('change', (event) => {
      if (event.target.name === 'provider') {
        shell.geoipForm.dataset.providerSelection = event.target.value;
        renderGeoIPProvider();
      } else if (event.target.name === 'fallbackEnabled') {
        shell.geoipForm.dataset.fallbackSelection = String(event.target.checked);
      }
    });
  }
  shell.filter.addEventListener('input', () => {
    state.filter = shell.filter.value.trim().toLowerCase();
    renderShell();
  });
}

let globalActionsInstalled = false;

// installGlobalActions wires every [data-action] in the document. It has to be
// document level because modals and the agent drawer are mounted outside #app,
// so a listener on the shell would never see their buttons.
function installGlobalActions() {
  if (globalActionsInstalled) return;
  globalActionsInstalled = true;
  document.addEventListener('click', handleGlobalAction);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      if (state.sidebarOpen) { state.sidebarOpen = false; renderShell(); }
      if (dismissModalPassively()) renderShell();
    }
    if (event.key === '/' && document.activeElement === document.body) {
      event.preventDefault();
      if (shell && shell.filter) { setView('agents'); shell.filter.focus(); }
    }
  });
  window.addEventListener('popstate', async () => {
    const route = routeFromPath(window.location.pathname);
    if (route) {
      if (route.view === 'resources' && route.resourceId !== null && canAdmin()) {
        const email = new URLSearchParams(window.location.search).get('email') || '';
        if (email !== state.resourceFilterEmail) {
          state.resourceFilterEmail = email;
          state.resourceFilterData = null;
          if (email) {
            try { state.resourceFilterData = await api('/api/resources?email=' + encodeURIComponent(email)); }
            catch (err) { toast(err.message, 'fail'); }
          }
        }
      }
      applyRoute(route);
      renderShell();
      if (state.view === 'users' && canAdmin()) loadUsers(true);
      if (state.view === 'settings' && state.settingsTab === 'users' && canAdmin()) loadSignupSettings();
      if (state.view === 'activity' && state.logTab === 'requests') loadRequestPage();
    }
  });
}

function menuPop() {
  return shell ? $('.menu-pop', shell.root) : null;
}

function closeMenu() {
  const pop = menuPop();
  if (pop && !pop.hidden) pop.hidden = true;
}

async function handleGlobalAction(event) {
  const tab = event.target.closest('[data-view]');
  if (tab) {
    const view = tab.dataset.view;
    if ((view === 'activity' || view === 'settings') && state.view === view) {
      state.expandedSidebarGroup = state.expandedSidebarGroup === view ? null : view;
      renderShell();
      return;
    }
    if (view !== 'activity' && view !== 'settings') state.sidebarOpen = false;
    setView(view);
    if (state.view === 'users' && canAdmin()) loadUsers(true);
    if (state.view === 'settings' && state.settingsTab === 'smtp' && canAdmin()) loadSMTP();
    return;
  }
  const actionEl = event.target.closest('[data-action]');
  if (!actionEl) {
    if (!event.target.closest('[data-menu]')) closeMenu();
    return;
  }
  const action = actionEl.dataset.action;
  const id = actionEl.dataset.id ? Number(actionEl.dataset.id) : null;
  switch (action) {
    case 'toggle-sidebar':
      state.sidebarOpen = !state.sidebarOpen;
      renderShell();
      break;
    case 'menu':
      toggleMenu();
      break;
    case 'modal-close':
    case 'agent-close':
      closeModal();
      renderShell();
      break;
    case 'refresh':
      closeMenu();
      await refresh();
      if (state.view === 'activity' && state.logTab === 'requests') await loadRequestPage();
      toast('State refreshed', 'ok');
      break;
    case 'requests-clear-filters': clearRequestFilters(); break;
    case 'copy-fingerprint':
      closeMenu();
      await copyText(state.data.server.fingerprint, 'Certificate fingerprint copied');
      break;
    case 'logout':
      await api('/api/logout', { method: 'POST', body: {} });
      if (state.stream) state.stream.close();
      closeModal();
      state.authenticated = false; state.data = null; shell = null;
      state.requestPageData = null;
      render();
      break;
    case 'add-agent': openAddAgent(); break;
    case 'clear-errors': await clearErrors(); break;
    case 'diagnose-target': await diagnoseTarget(actionEl.dataset.resource, actionEl.dataset.target); break;
    case 'show-error': await showError(actionEl.dataset.match); break;
    case 'requests-page': setRequestPage(Number(actionEl.dataset.page)); break;
    case 'add-user': openAddUser(); break;
    case 'user-edit': openEditUser(actionEl.dataset.id); break;
    case 'user-resources': openUserResources(actionEl.dataset.id); break;
    case 'user-delete': await deleteUser(actionEl.dataset.id, actionEl.dataset.username); break;
    case 'add-resource': filterResourcesByEmail(''); openResourceEditor(null); break;
    case 'resource-edit': openResourceEditor(Number(actionEl.dataset.id)); break;
    case 'resource-cancel': closeResourceEditor(); break;
    case 'resource-toggle': await toggleResource(actionEl.dataset.id, actionEl.dataset.enabled === 'true'); break;
    case 'resource-delete': await deleteResource(actionEl.dataset.id, actionEl.dataset.name); break;
    case 'add-domain': openDomainModal(); break;
    case 'domain-edit': openDomainModal(actionEl.dataset.hostname); break;
    case 'domain-delete': await deleteDomain(actionEl.dataset.hostname); break;
    case 'domain-verify': await verifyDomain(actionEl.dataset.hostname); break;
    case 'add-exitnode': openExitNodeModal(null); break;
    case 'exitnode-edit': openExitNodeModal(actionEl.dataset.id); break;
    case 'exitnode-apply': await applyExitNode(actionEl.dataset.id); break;
    case 'exitnode-toggle':
      await toggleExitNode(actionEl.dataset.id, actionEl.dataset.name, actionEl.dataset.enabled === 'true');
      break;
    case 'exitnode-delete': await deleteExitNode(actionEl.dataset.id, actionEl.dataset.name); break;
    case 'exitnode-pool': await toggleExitNodePool(actionEl.dataset.id, actionEl.dataset.enabled === 'true'); break;
    case 'manage-dns': openDNSAutomation(); break;
    case 'domain-sync': await syncDomain(actionEl.dataset.hostname); break;
    case 'dns-provider-delete': await deleteDNSProvider(actionEl.dataset.id, actionEl.dataset.name); break;
    case 'dns-provider-toggle': await toggleDNSProvider(actionEl.dataset.id, actionEl.dataset.enabled === 'true'); break;
    case 'dns-provider-edit': openDNSProviderModal(actionEl.dataset.id); break;
    case 'dns-sync-all': await syncAllDomains(); break;
    case 'reset-logo': await resetLogo(); break;
    case 'reload-css': await loadCSSEditor(); break;
    case 'reset-css': await resetBrandCSS(); break;
    case 'geoip-clear': await clearGeoIP(); break;
    case 'topology-reset': resetTopologyLayout(); break;
    case 'health-refresh': await refreshChecks(); break;
    case 'agent-open': state.drawer = id; renderShell(); break;
    case 'agent-ping': await pingAgent(id); break;
    case 'agent-command': await sendCommand(id, actionEl.dataset.command); break;
    case 'agent-copy-install': await copyInstall(id); break;
    case 'agent-copy-config': await copyAgentConfig(id); break;
    case 'agent-edit': openEditAgent(id); break;
    case 'agent-networks': openAgentNetworks(id); break;
    case 'agent-rotate': await rotateToken(id); break;
    case 'agent-delete': await deleteAgent(id, actionEl.dataset.name); break;
    case 'change-password':
      closeMenu();
      openChangePassword();
      break;
    case 'new-api-token': await createAPIToken(); break;
    case 'delete-api-token': await deleteAPIToken(actionEl.dataset.id); break;
    default: break;
  }
}

function toggleMenu() {
  const pop = menuPop();
  if (pop) pop.hidden = !pop.hidden;
}

function renderShell() {
  if (!shell || !state.data) return;
  const { summary, settings, server } = state.data;
  shell.sessionUser.textContent = state.session.username || 'control node';
  shell.sessionRole.textContent = state.session.role
    ? state.session.role
    : server.publicEndpoint;
  shell.meshRange.textContent = summary.meshCidr + ' · hub ' + (server.hubAddress || hubAddress(settings.meshCidr));

  // Read-only accounts see the mesh but no controls that would be rejected.
  $$('[data-admin-only]', shell.root).forEach((el) => { el.hidden = !canAdmin(); });
  $$('[data-mesh-manage]', shell.root).forEach((el) => { el.hidden = !canManageMesh(); });
  if (!canAdmin() && !['overview', 'agents', 'resources', 'domains', 'exitnodes', 'activity'].includes(state.view)) state.view = 'overview';
  if (!canAdmin() && !['requests', 'errors'].includes(state.logTab)) state.logTab = 'requests';
  if (shell.readonlyNote) shell.readonlyNote.hidden = true;

  const appShell = $('[data-app-shell]', shell.root);
  if (appShell) appShell.classList.toggle('sidebar-open', state.sidebarOpen);
  const scrim = $('.sidebar-scrim', shell.root);
  if (scrim) scrim.hidden = !state.sidebarOpen;
  $$('.sidebar-link[data-view]', shell.root).forEach((tab) => {
    const active = tab.dataset.view === state.view;
    tab.classList.toggle('is-active', active);
    if (tab.classList.contains('has-children')) tab.setAttribute('aria-expanded', String(state.expandedSidebarGroup === tab.dataset.view));
  });
  $$('[data-subnav]', shell.root).forEach((nav) => { nav.hidden = nav.dataset.subnav !== state.expandedSidebarGroup; });
  $$('[data-subnav] [data-tab]', shell.root).forEach((tab) => {
    const group = tab.closest('[data-subnav]').dataset.subnav;
    tab.classList.toggle('is-active', tab.dataset.tab === (group === 'activity' ? state.logTab : state.settingsTab));
  });
  const currentView = $('[data-current-view]', shell.root);
  const activeLink = $('.sidebar-link.is-active', shell.root);
  if (currentView && activeLink) currentView.textContent = activeLink.textContent.trim();
  $$('[data-view-panel]', shell.root).forEach((panel) => {
    const active = panel.dataset.viewPanel === state.view;
    panel.classList.toggle('is-active', active);
    panel.hidden = !active;
  });
  $$('[data-view-panel="activity"] [data-tab-panel]', shell.root).forEach((panel) => { panel.hidden = panel.dataset.tabPanel !== state.logTab; });
  $$('[data-view-panel="settings"] [data-tab-panel]', shell.root).forEach((panel) => { panel.hidden = panel.dataset.tabPanel !== state.settingsTab; });

  // The server sends empty lists, but never trust that: a missing or null list
  // must not take the whole page down. Delete an agent and the next snapshot is
  // the one that used to arrive as null.
  const agents = state.data.agents || [];
  renderStats(shell.stats, summary, settings, server, agents);
  renderHealth(shell.healthPanel, state.data.health || []);
  renderTopology(shell.topology, shell.topologySub, agents, summary);
  const filtered = filterAgents(agents);
  renderAgentGrid(shell.agentGrid, filtered, summary);
  shell.agentsSub.textContent = describeAgents(summary);
  renderEvents(shell.events, state.data.events || []);
  renderErrors(shell.errorsTable, shell.errorsSub, state.data.errors || []);
  const requestLog = requestData();
  renderCharts(shell.requestCharts, requestLog.summary);
  const requestsPanel = $('[data-tab-panel="requests"]', shell.root);
  if (state.view === 'activity' && requestsPanel && !requestsPanel.hidden) {
    renderRequests(shell.requestTable, state.requestPageData);
  }
  const clearRequestFiltersButton = $('[data-requests-clear]', shell.root);
  if (clearRequestFiltersButton) clearRequestFiltersButton.hidden = !hasRequestFilters();
  renderRequestSubtitle();
  renderServerInfo(shell.serverInfo, server, settings);
  renderUsers(shell.usersTable, shell.usersSub, state.users || []);
  if (shell.resourcesEmailFilter) {
    shell.resourcesEmailFilter.hidden = !canAdmin();
    if (shell.resourcesEmailFilter.value !== state.resourceFilterEmail) shell.resourcesEmailFilter.value = state.resourceFilterEmail;
  }
  renderResources(shell.resourcesTable, shell.resourcesSub,
    state.resourceFilterEmail ? (state.resourceFilterData?.resources || []) : (state.data.resources || []));
  renderDomains(shell.domainsTable, shell.domainsSub, state.data.domains || []);
  renderExitNodes(shell.exitNodesTable, shell.exitNodesSub, state.data.exitNodes || []);
  renderResourceEditor();
  applyLogo();
  applyBranding();
  renderBranding(server);
  renderGeoIP();
  renderTokens(shell.apiTokens, state.data.apiTokens || []);
  // Only refill the settings form when the server's settings actually changed,
  // so a live update cannot wipe out whatever the admin is typing.
  const settingsSignature = JSON.stringify(settings);
  if (settingsSignature !== state.settingsSignature) {
    state.settingsSignature = settingsSignature;
    fillSettingsForm(shell.settingsForm, settings);
  }
  renderDrawer();
  if (state.filter && shell.filter.value !== state.filter) shell.filter.value = state.filter;
  setStreamLabel();
}

function filterAgents(agents) {
  if (!state.filter) return agents;
  const needle = state.filter;
  return agents.filter((agent) =>
    agent.name.toLowerCase().includes(needle) ||
    agent.address.includes(needle) ||
    (agent.publicKey || '').toLowerCase().includes(needle) ||
    (agent.hostname || '').toLowerCase().includes(needle));
}

function describeAgents(summary) {
  const parts = [summary.online + ' of ' + summary.agents + ' connected'];
  if (summary.directLinks) parts.push(summary.directLinks + ' direct link' + (summary.directLinks === 1 ? '' : 's'));
  if (summary.relayedLinks) parts.push(summary.relayedLinks + ' relayed');
  return parts.join(' · ');
}

/* ---------- modal plumbing ---------- */

let modalSession = null;
let drawerCloseTimer = null;

function shakeModal(node) {
  if (!node) return;
  node.classList.remove('modal-shake');
  // Restart the animation even when two rejected dismissals happen quickly.
  void node.offsetWidth;
  node.classList.add('modal-shake');
  setTimeout(() => node.classList.remove('modal-shake'), 360);
}

// Backdrop clicks and Escape are passive dismissal attempts. Once a form has
// been touched they refuse to discard it; an explicit close/cancel control is
// still allowed to call closeModal directly.
function dismissModalPassively() {
  if (modalSession && (modalSession.dirty || modalSession.preventPassiveDismiss)) {
    shakeModal(modalSession.node);
    return false;
  }
  closeModal();
  return true;
}

function openModal(node, { drawer = false, preventPassiveDismiss = false } = {}) {
  closeModal({ immediate: true });
  const overlay = h('div', { class: 'overlay' + (drawer ? ' drawer-overlay' : '') }, node);
  // Close on click, not mousedown: closing on mousedown removed the modal and
  // then let the same click land on whatever sat behind it (usually the button
  // that opened the dialog), which re-opened it and looked like a shake.
  overlay.addEventListener('click', (event) => {
    if (event.target !== overlay) {
      // Buttons that add/remove dynamic form rows may not emit input or change.
      const button = event.target.closest && event.target.closest('button');
      if (button && !button.hasAttribute('data-no-dirty') &&
          button.dataset.action !== 'modal-close' && button.type !== 'submit' &&
          modalSession && modalSession.node === node) {
        modalSession.dirty = true;
      }
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    dismissModalPassively();
  });
  $('#modal-root').append(overlay);
  modalSession = { node, dirty: false, preventPassiveDismiss };
  const markDirty = () => {
    if (modalSession && modalSession.node === node) modalSession.dirty = true;
  };
  node.addEventListener('input', markDirty);
  node.addEventListener('change', markDirty);
  const firstInput = $('input, textarea, select', node);
  if (firstInput && !drawer) firstInput.focus();
  return overlay;
}

function closeModal({ immediate = false } = {}) {
  const root = $('#modal-root');
  const drawerOverlay = state.drawerEl && state.drawerEl.parentElement;
  modalSession = null;
  // Clear state at once so live updates cannot reopen a dismissed drawer.
  state.drawer = null;
  state.drawerEl = null;
  state.drawerBody = null;
  if (drawerCloseTimer) { clearTimeout(drawerCloseTimer); drawerCloseTimer = null; }
  if (!immediate && root && drawerOverlay && root.firstChild === drawerOverlay) {
    drawerOverlay.classList.add('is-closing');
    const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    drawerCloseTimer = setTimeout(() => {
      if (root.firstChild === drawerOverlay) root.replaceChildren();
      drawerCloseTimer = null;
    }, reduceMotion ? 0 : 220);
    return;
  }
  if (root) root.replaceChildren();
}

// openDrawer mounts the agent drawer with its slide-in animation.
function openDrawer(agent) {
  const body = h('div', { class: 'stack' }, drawerBody(agent));
  const node = h('div', { class: 'card modal drawer' }, body);
  const overlay = h('div', { class: 'overlay drawer-overlay' }, node);
  overlay.addEventListener('click', (event) => {
    if (event.target !== overlay || overlay.classList.contains('is-closing')) return;
    event.preventDefault();
    event.stopPropagation();
    closeModal();
  });
  const root = $('#modal-root');
  if (drawerCloseTimer) { clearTimeout(drawerCloseTimer); drawerCloseTimer = null; }
  if (root) root.replaceChildren(overlay);
  state.drawerEl = node;
  state.drawerBody = body;
  return node;
}

function modal(title, subtitle, body, footer, options = {}) {
  const node = h('div', { class: 'card modal' },
    h('div', { class: 'modal-head' },
      h('div', null, h('h2', { text: title }), subtitle ? h('p', { class: 'muted', text: subtitle }) : null),
      h('button', { class: 'btn btn-icon', type: 'button', 'data-action': 'modal-close', 'aria-label': 'Close' }, '✕')),
    body,
    footer);
  openModal(node, options);
  return node;
}

function confirmModal(title, message, confirmLabel, onConfirm) {
  const node = modal(title, null,
    h('p', { class: 'muted', text: message }),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-danger', type: 'button', onclick: async () => { closeModal(); await onConfirm(); } }, confirmLabel)));
  return node;
}

document.addEventListener('DOMContentLoaded', boot);
