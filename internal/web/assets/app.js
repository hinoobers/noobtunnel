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
  return h('button', { class: 'btn btn-sm', type: 'button', onclick: () => copyText(value, 'Copied') }, label);
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
  const name = String(pathname || '').replace(/^\/+|\/+$/g, '').toLowerCase();
  return VIEW_PATHS.includes(name) ? name : '';
}

// setView switches tabs and keeps the address bar in step. push=false is used
// when the URL has already changed (back/forward, or a page load).
function setView(view, push = true) {
  if (!VIEW_PATHS.includes(view)) return;
  state.view = view;
  if (push && typeof window !== 'undefined' && window.history && window.history.pushState) {
    const target = view === 'overview' ? '/' : '/' + view;
    if (window.location.pathname !== target) window.history.pushState({ view }, '', target);
  }
  renderShell();
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
  const deepLink = viewFromPath(window.location.pathname);
  if (deepLink) state.view = deepLink;
  await refresh(true);
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

/* ---------- render entry point ---------- */

function render() {
  const root = appRoot();
  root.classList.remove('is-loading');
  if (!state.authenticated) {
    mountLogin();
    applyBranding();
    return;
  }
  if (!state.data) {
    mountBoot();
    return;
  }
  if (!shell) mountShell();
  renderShell();
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
  // The template holds several top level elements (header + main), so clone the
  // whole fragment. Cloning only the first child silently dropped the whole UI.
  // The template holds several top level elements (header + main), so clone the
  // whole fragment. Cloning only the first child silently dropped the whole UI.
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
    domainsTable: $('[data-domains-table]', node),
    domainsSub: $('[data-domains-sub]', node),
    domainList: $('[data-domain-list]', node),
    domainsAdd: $('[data-domains-add]', node),
    exitNodesTable: $('[data-exitnodes-table]', node),
    exitNodesSub: $('[data-exitnodes-sub]', node),
    exitNodesAdd: $('[data-exitnodes-add]', node),
    events: $('[data-events]', node),
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
  shell.settingsForm.addEventListener('submit', saveSettings);
  if (shell.brandingForm) shell.brandingForm.addEventListener('submit', uploadLogo);
  if (shell.brandNameForm) shell.brandNameForm.addEventListener('submit', saveBrandName);
  if (shell.brandCSSForm) shell.brandCSSForm.addEventListener('submit', saveBrandCSS);
  if (shell.geoipForm) shell.geoipForm.addEventListener('submit', saveGeoIP);
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
    if (event.key === 'Escape') { closeModal(); renderShell(); }
    if (event.key === '/' && document.activeElement === document.body) {
      event.preventDefault();
      if (shell && shell.filter) { setView('agents'); shell.filter.focus(); }
    }
  });
  window.addEventListener('popstate', () => {
    const view = viewFromPath(window.location.pathname);
    if (view) setView(view, false);
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
    setView(tab.dataset.view);
    if (state.view === 'users' && canAdmin()) loadUsers(true);
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
      toast('State refreshed', 'ok');
      break;
    case 'copy-fingerprint':
      closeMenu();
      await copyText(state.data.server.fingerprint, 'Certificate fingerprint copied');
      break;
    case 'logout':
      await api('/api/logout', { method: 'POST', body: {} });
      if (state.stream) state.stream.close();
      closeModal();
      state.authenticated = false; state.data = null; shell = null;
      render();
      break;
    case 'add-agent': openAddAgent(); break;
    case 'add-user': openAddUser(); break;
    case 'user-password': openUserPassword(actionEl.dataset.username, actionEl.dataset.id); break;
    case 'user-role': openRoleModal(actionEl.dataset.id); break;
    case 'user-toggle': await toggleUser(actionEl.dataset.id, actionEl.dataset.disabled === 'true'); break;
    case 'user-delete': await deleteUser(actionEl.dataset.id, actionEl.dataset.username); break;
    case 'add-resource': openResourceEditor(null); break;
    case 'resource-edit': openResourceEditor(Number(actionEl.dataset.id)); break;
    case 'resource-cancel': closeResourceEditor(); break;
    case 'resource-toggle': await toggleResource(actionEl.dataset.id, actionEl.dataset.enabled === 'true'); break;
    case 'resource-delete': await deleteResource(actionEl.dataset.id, actionEl.dataset.name); break;
    case 'add-domain': openDomainModal(); break;
    case 'domain-edit': openDomainModal(actionEl.dataset.hostname); break;
    case 'domain-delete': await deleteDomain(actionEl.dataset.hostname); break;
    case 'add-exitnode': openExitNodeModal(null); break;
    case 'exitnode-edit': openExitNodeModal(actionEl.dataset.id); break;
    case 'exitnode-apply': await applyExitNode(actionEl.dataset.id); break;
    case 'exitnode-toggle':
      await toggleExitNode(actionEl.dataset.id, actionEl.dataset.name, actionEl.dataset.enabled === 'true');
      break;
    case 'exitnode-delete': await deleteExitNode(actionEl.dataset.id, actionEl.dataset.name); break;
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
    case 'health-refresh': await refreshChecks(); break;
    case 'agent-open': state.drawer = id; renderShell(); break;
    case 'agent-ping': await pingAgent(id); break;
    case 'agent-command': await sendCommand(id, actionEl.dataset.command); break;
    case 'agent-copy-install': await copyInstall(id); break;
    case 'agent-copy-config': await copyAgentConfig(id); break;
    case 'agent-edit': openEditAgent(id); break;
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
    ? state.session.role + (state.session.canAdmin ? '' : ' · read only')
    : server.publicEndpoint;
  shell.meshRange.textContent = settings.meshCidr + ' · hub ' + hubAddress(settings.meshCidr);

  // Read-only accounts see the mesh but no controls that would be rejected.
  $$('[data-admin-only]', shell.root).forEach((el) => { el.hidden = !canAdmin(); });
  if (!canAdmin() && state.view === 'users') state.view = 'overview';
  if (shell.readonlyNote) shell.readonlyNote.hidden = canAdmin();

  // Only the top level navigation carries data-view; the Logs and Settings tab
  // rows own their active state and must not be cleared on every re-render.
  $$('.tab[data-view]', shell.root).forEach((tab) => tab.classList.toggle('is-active', tab.dataset.view === state.view));
  $$('[data-view-panel]', shell.root).forEach((panel) => {
    const active = panel.dataset.viewPanel === state.view;
    panel.classList.toggle('is-active', active);
    panel.hidden = !active;
  });

  renderStats(shell.stats, summary, settings, server);
  renderHealth(shell.healthPanel, state.data.health);
  renderTopology(shell.topology, shell.topologySub, state.data.agents, summary);
  const filtered = filterAgents(state.data.agents);
  renderAgentGrid(shell.agentGrid, filtered, summary);
  shell.agentsSub.textContent = describeAgents(summary);
  renderEvents(shell.events, state.data.events);
  const requestLog = requestData();
  renderCharts(shell.requestCharts, requestLog.summary);
  renderRequests(shell.requestTable, requestLog.recent);
  if (shell.requestsSub) {
    shell.requestsSub.textContent = requestLog.summary.total === 0
      ? 'Traffic through your published services'
      : requestLog.summary.total + ' requests · ' + requestLog.summary.allowed + ' allowed · ' +
        requestLog.summary.blocked + ' blocked';
  }
  renderServerInfo(shell.serverInfo, server, settings);
  renderUsers(shell.usersTable, shell.usersSub, state.users || []);
  renderResources(shell.resourcesTable, shell.resourcesSub, state.data.resources || []);
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

function openModal(node, { drawer = false } = {}) {
  closeModal();
  const overlay = h('div', { class: 'overlay' + (drawer ? ' drawer-overlay' : '') }, node);
  // Close on click, not mousedown: closing on mousedown removed the modal and
  // then let the same click land on whatever sat behind it (usually the button
  // that opened the dialog), which re-opened it and looked like a shake.
  overlay.addEventListener('click', (event) => {
    if (event.target !== overlay) return;
    event.preventDefault();
    event.stopPropagation();
    closeModal();
  });
  $('#modal-root').append(overlay);
  const firstInput = $('input, textarea, select', node);
  if (firstInput && !drawer) firstInput.focus();
  return overlay;
}

function closeModal() {
  const root = $('#modal-root');
  if (root) root.replaceChildren();
  // Also clear the drawer state, otherwise dismissing the drawer by clicking
  // outside leaves stale state that re-opens it and wipes the next modal.
  state.drawer = null;
  state.drawerEl = null;
  state.drawerBody = null;
}

// openDrawer mounts the agent drawer with its slide-in animation.
function openDrawer(agent) {
  const body = h('div', { class: 'stack' }, drawerBody(agent));
  const node = h('div', { class: 'card modal drawer' }, body);
  const overlay = h('div', { class: 'overlay drawer-overlay' }, node);
  overlay.addEventListener('mousedown', (event) => {
    if (event.target === overlay) closeModal();
  });
  const root = $('#modal-root');
  if (root) root.replaceChildren(overlay);
  state.drawerEl = node;
  state.drawerBody = body;
  return node;
}

function modal(title, subtitle, body, footer) {
  const node = h('div', { class: 'card modal' },
    h('div', { class: 'modal-head' },
      h('div', null, h('h2', { text: title }), subtitle ? h('p', { class: 'muted', text: subtitle }) : null),
      h('button', { class: 'btn btn-icon', type: 'button', 'data-action': 'modal-close', 'aria-label': 'Close' }, '✕')),
    body,
    footer);
  openModal(node);
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
