package web

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestUIRendersInAFakeDOM actually runs the UI code instead of scanning it.
//
// Reading the source catches typos in function names, but not a `const` used
// before its declaration, a missing element variable, or anything else that only
// fails when a browser executes the file. This test evaluates the scripts in a
// Node context with a minimal DOM shim and calls every render function with
// realistic data, so those errors surface here instead of in someone's browser.
//
// It skips when Node is unavailable.
func TestUIRendersInAFakeDOM(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not available, skipping the UI render check")
	}
	dir := t.TempDir()
	harness := filepath.Join(dir, "harness.mjs")
	if err := os.WriteFile(harness, []byte(renderHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", harness, "assets")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the UI threw while rendering:\n%s", out)
	}
	if strings.Contains(string(out), "Error") {
		t.Fatalf("the UI reported an error while rendering:\n%s", out)
	}
}

// renderHarness is the Node side: a tiny DOM, then every render entry point.
const renderHarness = `
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const dir = process.argv[2];

class Node {}

function fakeEl(tag = 'div') {
  const el = new Node();
  // Text children become text nodes, the way a browser does it, so the tests can
  // read what a cell or a label actually says.
  const asNode = (kid) => {
    if (kid && typeof kid === 'object') return kid;
    const textNode = new Node();
    textNode.textContent = String(kid);
    return textNode;
  };
  Object.assign(el, {
    tagName: String(tag).toUpperCase(),
    childNodes: [], dataset: {}, style: {}, files: [],
    _listeners: {},
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    hidden: false, value: '', textContent: '', innerHTML: '', checked: false,
    required: false, placeholder: '', src: '', disabled: false,
    append(...kids) { kids.flat().map(asNode).forEach((k) => { k.parentElement = el; el.childNodes.push(k); }); },
    appendChild(kid) { const node = asNode(kid); node.parentElement = el; el.childNodes.push(node); return node; },
    replaceChildren(...kids) { el.childNodes = kids.flat().map(asNode); el.childNodes.forEach((k) => { k.parentElement = el; }); },
    remove() {}, focus() {}, blur() {}, select() {}, reset() {},
    setPointerCapture() {},
    getBoundingClientRect() { return { left: 0, top: 0, width: 960, height: 470 }; },
    // Attributes are recorded: the tests check the classes the renderers set.
    attrs: {},
    setAttribute(name, value) { el.attrs[name] = String(value); if (name === 'class') el.className = String(value); },
    removeAttribute(name) { delete el.attrs[name]; },
    getAttribute(name) { return name in el.attrs ? el.attrs[name] : null; },
    addEventListener(type, fn) { (el._listeners[type] ||= []).push(fn); },
    removeEventListener() {},
    dispatchEvent(event) {
      event.target ||= el;
      event.preventDefault ||= () => {};
      event.stopPropagation ||= () => {};
      for (const fn of el._listeners[event.type] || []) fn(event);
    },
    contains() { return false; },
    scrollIntoView() {}, querySelector() { return fakeEl('div'); },
    querySelectorAll() { return []; }, closest() { return null; },
  });
  Object.defineProperty(el, 'children', { get: () => el.childNodes });
  // <select>.options is a live list of its <option> children.
  Object.defineProperty(el, 'options', { get: () => el.childNodes });
  Object.defineProperty(el, 'lastElementChild', { get: () => el.childNodes[el.childNodes.length - 1] || null });
  Object.defineProperty(el, 'firstElementChild', { get: () => el.childNodes[0] || null });
  el.firstChild = null;
  el.parentElement = null;
  return el;
}

class FakeFormData {
  constructor() { this.map = new Map(); }
  get(key) { return this.map.has(key) ? this.map.get(key) : ''; }
  set(key, value) { this.map.set(key, value); }
}

class FakeObserver { observe() {} disconnect() {} }
class FakeEventSource {
  constructor() { this.onmessage = null; this.onerror = null; this.onopen = null; }
  close() {}
}

const windowShim = {
  addEventListener() {}, removeEventListener() {},
  location: { pathname: '/', href: 'https://localhost/' },
  history: { pushState() {}, replaceState() {} },
};

const document = {
  createElement: (tag) => fakeEl(tag),
  createElementNS: (_ns, tag) => fakeEl(tag),
  querySelector: () => fakeEl('div'),
  querySelectorAll: () => [],
  addEventListener() {}, removeEventListener() {}, execCommand() {},
  createTextNode: (text) => { const textNode = new Node(); textNode.textContent = String(text); return textNode; },
  body: fakeEl('body'), cookie: '',
};

const ctx = {
  document, console, Node, setTimeout, clearTimeout,
  setInterval: () => 0, clearInterval() {}, clearTimeout() {},
  fetch: async () => ({ ok: true, status: 200, text: async () => '', json: async () => ({}) }),
  FormData: FakeFormData, MutationObserver: FakeObserver, EventSource: FakeEventSource,
  navigator: { clipboard: null }, location: windowShim.location, history: windowShim.history,
  URL, URLSearchParams, Date, JSON, Math, Object, Array, String, Number, Boolean, Promise, Error, RegExp, Map, Set,
  encodeURIComponent, decodeURIComponent, parseInt, parseFloat, isNaN, structuredClone,
  requestAnimationFrame: (fn) => fn(), queueMicrotask: (fn) => fn(),
  addEventListener() {}, removeEventListener() {},
};
ctx.window = Object.assign(windowShim, ctx);
ctx.window = ctx;
ctx.globalThis = ctx;
ctx.isSecureContext = false;
vm.createContext(ctx);

const files = ['app.js', 'views.js', 'users_api.js', 'resources_api.js', 'exitnodes_api.js', 'dns_api.js', 'branding_api.js', 'geoip_api.js', 'logs_api.js', 'diagnose_ui.js'];
for (const file of files) {
  vm.runInContext(fs.readFileSync(path.join(dir, file), 'utf8'), ctx, { filename: file });
}

// Realistic data, then call every renderer the shell uses.
vm.runInContext(` + "`" + `
const agent = {
  id: 1, name: 'homelab', address: '10.77.0.2', prefix: '10.77.0.2/32', publicKey: 'k',
  advertise: ['192.168.1.0/24'], enabled: true, online: true, endpoint: '203.0.113.9:51820',
  lastHandshake: new Date().toISOString(), lastSeen: new Date().toISOString(), latencyMs: 12,
  rxBytes: 1024, txBytes: 2048, version: '0.1.0', os: 'linux', arch: 'amd64', hostname: 'nas',
  createdAt: new Date().toISOString(), enrolledAt: new Date().toISOString(), token: 'nt_a_b',
  links: [{ peerId: 2, peerName: 'pi', direct: true, rxBytes: 1, txBytes: 2, lastHandshake: new Date().toISOString() }],
  directCount: 1, relayCount: 0,
};
const resource = {
  id: 1, name: 'web', protocol: 'https', strategy: 'round-robin', exitNodeId: 'x', exitNodeName: 'second ip',
  exitNodeAddress: '203.0.113.44', listenPort: 443, domain: 'app.example.com', public: 'https://app.example.com',
  enabled: true, listening: true, proxyProtocol: 'v2', identity: true,
  targets: [{ id: 1, agentId: 1, agentName: 'homelab', address: '10.77.0.2:8080', enabled: true, total: 3 }],
  active: 1, total: 3, rxBytes: 10, txBytes: 20, createdAt: new Date().toISOString(),
};
const domain = {
  hostname: 'example.com', pattern: '*.example.com', kind: 'wildcard',
  createdAt: new Date().toISOString(), resources: ['web'], address: '203.0.113.44',
  hint: 'managed', providerId: 'p1', providerName: 'cloudflare', synced: true, exitNodeName: 'second ip',
};
const exitNode = {
  id: 'x', name: 'second ip', kind: 'gre', address: '203.0.113.44', bindAddress: '203.0.113.44',
  enabled: true, deletable: true, status: 'ready', statusDetail: 'ok', resources: ['web'],
  setup: { local: ['ip tunnel add x'], remote: ['ip tunnel add y'], notes: 'note' },
};
const user = { id: 'u1', username: 'admin', role: 'admin', createdAt: new Date().toISOString(), enabled: true };
const check = { id: 'c', title: 'Check', status: 'warn', detail: 'detail', fix: 'do it' };
const event = { kind: 'settings', message: 'updated', time: new Date().toISOString() };

state.authenticated = true;
state.session = { username: 'admin', role: 'admin', canAdmin: true };
state.data = {
  server: { version: '0.1.0', platform: 'linux/amd64', uptimeSec: 10, listen: ':8443',
    fingerprint: 'AB:CD', publicEndpoint: '203.0.113.1:51820', backend: 'kernel', interface: 'noobtun',
    hubPublicKey: 'k', hubUp: true, knownEndpoints: 1, goVersion: 'go1.26' },
  settings: { meshName: 'noobtunnel', meshCidr: '10.77.0.0/16', mtu: 1420, wgListenPort: 51820,
    keepaliveSec: 25, directPaths: true, interface: 'noobtun', statsIntervalSec: 5 },
  agents: [agent], resources: [resource], domains: [domain], exitNodes: [exitNode],
  users: [user], health: [check], events: [event], rejected: [],
  apiTokens: [{ id: 't1', name: 'ci', role: 'admin', createdAt: new Date().toISOString() }],
  dnsProviders: [{ id: 'p1', name: 'cloudflare', kind: 'cloudflare', enabled: true, hasToken: true }],
  summary: { agents: 1, online: 1, reachable: 1, directLinks: 1, relayedLinks: 0, rxBytes: 1, txBytes: 2,
    meshCidr: '10.77.0.0/16', meshCapacity: 65533 },
  logoVersion: 'default',
};
state.users = [user];

// Resource editors are addressable pages, not transient in-memory state.
const editRoute = routeFromPath('/resources/42');
if (!editRoute || editRoute.view !== 'resources' || editRoute.resourceId !== 42) {
  throw new Error('a resource edit URL should restore its resource id');
}
applyRoute(editRoute);
if (state.view !== 'resources' || !state.resourceForm || state.resourceForm.id !== 42) {
  throw new Error('applying a resource route should reopen the editor');
}
applyRoute(routeFromPath('/resources'));
if (state.resourceForm !== null) throw new Error('the resource list URL should close the editor');

// Untouched dialogs dismiss from the backdrop; touched ones stay mounted until
// an explicit close control is used.
const cleanDialog = document.createElement('div');
const cleanOverlay = openModal(cleanDialog);
cleanOverlay.dispatchEvent({ type: 'click', target: cleanOverlay });
if (modalSession !== null) throw new Error('an untouched modal should close from its backdrop');
const dirtyDialog = document.createElement('div');
const dirtyOverlay = openModal(dirtyDialog);
dirtyDialog.dispatchEvent({ type: 'input', target: dirtyDialog });
dirtyOverlay.dispatchEvent({ type: 'click', target: dirtyOverlay });
if (!modalSession || !modalSession.dirty) throw new Error('a changed modal should reject backdrop dismissal');
closeModal();

const node = document.createElement('div');
renderStats(node, state.data.summary, state.data.settings, state.data.server);
renderHealth(node, state.data.health);
renderTopology(node, node, state.data.agents, state.data.summary);
const findTopologyNode = (parent) => {
  if (parent.className === 'node') return parent;
  for (const child of parent.childNodes || []) {
    const found = findTopologyNode(child);
    if (found) return found;
  }
  return null;
};
const movable = findTopologyNode(node);
if (!movable) throw new Error('topology has no draggable agent node');
const startingPosition = movable.getAttribute('transform');
movable.dispatchEvent({ type: 'pointerdown', button: 0, pointerId: 7, clientX: 480, clientY: 100 });
movable.dispatchEvent({ type: 'pointermove', pointerId: 7, clientX: 540, clientY: 150 });
movable.dispatchEvent({ type: 'pointerup', pointerId: 7 });
if (movable.getAttribute('transform') === startingPosition) throw new Error('dragging did not move the topology node');
renderAgentGrid(node, state.data.agents, state.data.summary);
renderEvents(node, state.data.events);

// An empty mesh, the way the control node reports it when the operator deletes
// the last (inactive) agent. The lists used to arrive as null, and the render
// that followed threw "Cannot read properties of null (reading 'reduce')",
// which left the whole page frozen.
const empty = JSON.parse(JSON.stringify(state.data));
for (const field of ['agents', 'events', 'health', 'resources', 'domains', 'exitNodes', 'apiTokens', 'rejected']) {
  empty[field] = null;
}
empty.summary = Object.assign({}, empty.summary, { agents: 0, online: 0, reachable: 0, directLinks: 0, relayedLinks: 0 });
const withAgents = state.data;
state.data = empty;
renderStats(node, empty.summary, empty.settings, empty.server);
renderHealth(node, empty.health);
renderTopology(node, node, empty.agents, empty.summary);
renderAgentGrid(node, empty.agents, empty.summary);
renderEvents(node, empty.events);
renderTokens(node, empty.apiTokens);
renderResources(node, node, empty.resources);
renderDomains(node, node, empty.domains);
renderExitNodes(node, node, empty.exitNodes);
renderCharts(node, { total: 0, allowed: 0, blocked: 0, countries: null, hosts: null });
renderRequests(node, null);
state.data = withAgents;
renderServerInfo(node, state.data.server, state.data.settings);
renderTokens(node, state.data.apiTokens);
renderUsers(node, node, state.data.users);
renderResources(node, node, state.data.resources);
renderDomains(node, node, state.data.domains);
renderExitNodes(node, node, state.data.exitNodes);
renderCharts(node, { total: 3, allowed: 2, blocked: 1, countries: [{ country: 'EE', total: 2, blocked: 1 }], hosts: [] });
const decisionPie = node.childNodes[0];
const decisionVisual = decisionPie.childNodes[1].childNodes[0];
const allowedSlice = decisionVisual.childNodes[0].childNodes[0];
if (decisionPie.getAttribute('class') !== 'chart pie-chart' ||
    allowedSlice.getAttribute('aria-label') !== 'Allowed: 2 requests') {
  throw new Error('Statistics should show a decision pie chart');
}
allowedSlice.dispatchEvent({ type: 'pointerenter' });
if (decisionVisual.childNodes[1].childNodes[0].textContent !== '2') {
  throw new Error('hovering a pie slice should show its exact request count');
}
const requestResult = { page: 1, total: 1, retained: 1, requests: [{ time: new Date().toISOString(), host: 'a.example.com', ip: '203.0.113.1', country: 'EE', allowed: true, resource: 'web' }] };
renderRequests(node, requestResult);
const stableTable = node.childNodes[0];
renderRequests(node, JSON.parse(JSON.stringify(requestResult)));
if (node.childNodes[0] !== stableTable) throw new Error('an unchanged request update replaced the table');

// The Requests table: timestamps rather than "2m ago", the resource before the
// decision, and the decision said in the row colour rather than in a pill.
const requestsNode = document.createElement('div');
renderRequests(requestsNode, { page: 1, total: 2, retained: 2, requests: [
  { time: new Date().toISOString(), host: 'a.example.com', path: '/checkip', protocol: 'https', ip: '203.0.113.1', country: 'EE', allowed: true, resource: 'web' },
  { time: new Date().toISOString(), host: 'b.example.com', ip: '203.0.113.2', country: 'RU', allowed: false, reason: 'country rule', resource: 'web' },
] });
const requestsTable = requestsNode.childNodes[0];
const headers = textsOf(requestsTable.childNodes[0]).join(',');
if (headers !== 'Timestamp,Took,Host,Path,Client,Country,Resource,Decision') {
  throw new Error('the Requests table headers are wrong: ' + headers);
}
const requestedPath = textsOf(requestsTable.childNodes[1].childNodes[0].childNodes[3]).join('');
if (requestedPath !== '/checkip') {
  throw new Error('the Requests table should show the HTTP path separately: ' + requestedPath);
}
const rowClasses = requestsTable.childNodes[1].childNodes.map((row) => row.getAttribute('class'));
if (rowClasses[0] !== 'is-allowed' || rowClasses[1] !== 'is-blocked') {
  throw new Error('each request row should carry its decision: ' + rowClasses.join(', '));
}
const decisionCells = requestsTable.childNodes[1].childNodes.map((row) => row.childNodes[7]);
const decisionText = decisionCells.map((cell) => textsOf(cell).join(''));
if (decisionText[0] !== 'allowed' || !decisionText[1].startsWith('blocked') || !decisionText[1].includes('country rule')) {
  throw new Error('a blocked decision should include its reason: ' + decisionText.join(', '));
}
if (decisionCells.some((cell) => cell.childNodes.some((kid) =>
  typeof kid.getAttribute === 'function' && (kid.getAttribute('class') || '').includes('chip')))) {
  throw new Error('the decision cell should not hold a pill any more');
}
const countryChip = requestsTable.childNodes[1].childNodes[0].childNodes[5].childNodes[0];
if (!countryChip.getAttribute('title') || countryChip.getAttribute('title') === 'EE') {
  throw new Error('a country code should reveal its country name on hover');
}

// Headers sort the request list, and country filters can include more than one
// selected value without asking the server for another page.
requestSort = { key: 'durationMs', direction: 'asc' };
const sorted = sortAndFilterRequests([
  { durationMs: 40, country: 'EE', allowed: true },
  { durationMs: 10, country: 'US', allowed: false },
]);
if (sorted[0].durationMs !== 10) throw new Error('Took should sort numerically');
requestFilters.country = new Set(['EE']);
const filtered = sortAndFilterRequests(sorted);
if (filtered.length !== 1 || filtered[0].country !== 'EE') throw new Error('country filtering did not apply');
requestFilters.country = new Set();
requestSort = { key: 'time', direction: 'desc' };
if (hasRequestFilters()) throw new Error('the default request sort should not show Clear filters');
requestSort = { key: 'durationMs', direction: 'asc' };
if (!hasRequestFilters()) throw new Error('Fastest first should show Clear filters');
state.authenticated = false;
clearRequestFilters();
if (hasRequestFilters() || requestSort.key !== 'time' || requestSort.direction !== 'desc' ||
    requestPageURL().includes('sort=')) {
  throw new Error('Clear filters should restore the default request sort');
}
state.authenticated = true;

// The chart keeps the whole label and lets the stylesheet clip it; a hostname
// used to run into its own bar.
const hostChart = trafficChart('Requests by hostname', [{ country: 'phpmyadmin', total: 4, blocked: 0 }]);
const labelSpan = hostChart.childNodes[1].childNodes[0];
if (labelSpan.textContent !== 'phpmyadmin') {
  throw new Error('the chart label was truncated in the markup: ' + labelSpan.textContent);
}
installTabs(node);
drawerBody(agent);
resourceEditorPage(null);
resourceEditorPage(resource);
const srvResource = { ...resource, protocol: 'tcp', listenPort: 25565,
  domain: 'game.example.com', srv: { service: 'minecraft', protocol: 'tcp', priority: 0, weight: 0 } };
function namedElement(root, name) {
  if (root.getAttribute?.('name') === name) return root;
  for (const child of root.childNodes || []) {
    const found = namedElement(child, name);
    if (found) return found;
  }
  return null;
}
const adminSRVForm = resourceEditorPage(srvResource);
if (!namedElement(adminSRVForm, 'srvPreset').options.some((option) => option.getAttribute('value') === 'custom')) {
  throw new Error('admin lost the custom SRV option');
}
state.session = { username: 'regular', role: 'regular', canAdmin: false };
const regularSRVForm = resourceEditorPage(srvResource);
const regularPresets = namedElement(regularSRVForm, 'srvPreset').options;
if (regularPresets.some((option) => option.getAttribute('value') === 'custom')) {
  throw new Error('regular account can choose a custom SRV service');
}
if (!regularPresets.some((option) => option.getAttribute('value') === 'minecraft' && option.getAttribute('selected') !== null)) {
  throw new Error('editing an SRV record did not select its application preset');
}
if (namedElement(regularSRVForm, 'srvPriority') || namedElement(regularSRVForm, 'srvWeight')) {
  throw new Error('SRV priority and weight are still editable');
}
if (!namedElement(regularSRVForm, 'srvService').parentElement.parentElement.hidden) {
  throw new Error('regular account can edit the preset service name');
}
const unnamedTCP = { ...srvResource, domain: '', srv: null };
const unnamedForm = resourceEditorPage(unnamedTCP);
const unnamedDomain = namedElement(unnamedForm, 'domain');
const subdomainField = namedElement(unnamedForm, 'subdomain').parentElement;
const srvField = namedElement(unnamedForm, 'createSrv').parentElement.parentElement;
if (!subdomainField.hidden || !srvField.hidden) {
  throw new Error('no-name resource still shows subdomain or SRV controls');
}
unnamedDomain.value = 'example.com';
unnamedDomain.dispatchEvent({ type: 'change' });
if (subdomainField.hidden || srvField.hidden) {
  throw new Error('selecting a wildcard domain did not restore subdomain and SRV controls');
}
unnamedDomain.value = '';
unnamedDomain.dispatchEvent({ type: 'change' });
if (!subdomainField.hidden || !srvField.hidden) {
  throw new Error('switching back to no name did not hide subdomain and SRV controls');
}
state.session = { username: 'admin', role: 'admin', canAdmin: true };
openResourceEditor(null);

// Requests: thirty per page, with a way to walk the rest. A country the API did
// not answer for is explained rather than left as a bare "unknown".
const manyRequests = [];
for (let i = 0; i < 35; i++) {
  manyRequests.push({
    time: new Date(Date.now() - i * 1000).toISOString(), host: 'app.example.com', ip: '203.0.113.' + (i + 1),
    country: i % 2 ? 'EE' : '', allowed: true, resource: 'web', durationMs: 12,
  });
}
state.requestPage = 1;
const pagedNode = document.createElement('div');
renderRequests(pagedNode, { page: 1, total: 35, retained: 35, requests: manyRequests.slice(0, 30) });
const pageRows = pagedNode.childNodes[0].childNodes[1].childNodes;
if (pageRows.length !== 30) {
  throw new Error('the requests table should show thirty rows, it shows ' + pageRows.length);
}
if (textsOf(pagedNode).join(' | ').indexOf('Showing 1-30 of 35') === -1) {
  throw new Error('the requests table needs a pager: ' + textsOf(pagedNode).join(' | '));
}
// The list is only the list: the charts moved to their own tab, and the note about
// missing countries is gone.
if (textsOf(pagedNode).join(' ').indexOf('have no country') !== -1) {
  throw new Error('the country note should not be under the requests table');
}
state.requestPage = 2;
const secondPage = document.createElement('div');
renderRequests(secondPage, { page: 2, total: 35, retained: 35, requests: manyRequests.slice(30) });
if (secondPage.childNodes[0].childNodes[1].childNodes.length !== 5) {
  throw new Error('the second page should hold the remaining five rows');
}
state.requestPage = 1;

// Resources: the dot next to the name says whether it is healthy, so there is no
// separate status column, and the diagnosis is only offered when something is
// wrong. An error is a way into Logs, Errors rather than a dead label.
const resourcesNode = document.createElement('div');
renderResources(resourcesNode, document.createElement('div'), [resource]);
const resourceHeaders = textsOf(resourcesNode.childNodes[0].childNodes[0]).join(',');
if (resourceHeaders.includes('Status')) {
  throw new Error('the resources table still has a status column: ' + resourceHeaders);
}
if (resourceHeaders !== 'Resource,Type,Targets,Public address,Traffic in/out,Actions') {
  throw new Error('the resources table headers changed unexpectedly: ' + resourceHeaders);
}
function actionIn(node, action) {
  const walk = (n) => {
    if (!n || typeof n !== 'object') return null;
    if (typeof n.getAttribute === 'function' && n.getAttribute('data-action') === action) return n;
    for (const kid of n.childNodes || []) {
      const found = walk(kid);
      if (found) return found;
    }
    return null;
  };
  return walk(node);
}
function tagIn(node, tag) {
  const walk = (n) => {
    if (!n || typeof n !== 'object') return null;
    if (n.tagName === tag) return n;
    for (const kid of n.childNodes || []) {
      const found = walk(kid);
      if (found) return found;
    }
    return null;
  };
  return walk(node);
}
if (actionIn(resourcesNode, 'diagnose-target')) {
  throw new Error('diagnose should not be offered for a target that works');
}
// A web resource is a link to open; a tcp service is an address and a port, with
// no scheme, because nothing can open "tcp://…".
const webLink = tagIn(resourcesNode, 'A');
const webHref = webLink ? String(webLink.getAttribute('href') || '') : '';
if (!webLink || webHref.indexOf('http') !== 0) {
  throw new Error('a web resource should be a link');
}
if (webLink.getAttribute('target') !== '_blank') {
  throw new Error('the link should open in a new tab');
}
const tcpResource = Object.assign({}, resource, { protocol: 'tcp', public: 'db.example.com:3306', domain: 'db.example.com' });
const tcpNode = document.createElement('div');
renderResources(tcpNode, document.createElement('div'), [tcpResource]);
if (tagIn(tcpNode, 'A')) {
  throw new Error('a tcp resource must not be a link');
}
if (!textsOf(tcpNode).some((text) => text === 'db.example.com:3306')) {
  throw new Error('the tcp address should be shown as it is: ' + textsOf(tcpNode).join(' | '));
}
const broken = JSON.parse(JSON.stringify(resource));
broken.targets[0].lastError = 'dial tcp 10.77.0.2:8080: i/o timeout';
broken.lastError = 'web is not listening';
const brokenNode = document.createElement('div');
renderResources(brokenNode, document.createElement('div'), [broken]);
if (!actionIn(brokenNode, 'diagnose-target')) {
  throw new Error('diagnose should be offered for a target that failed');
}
const errorChip = actionIn(brokenNode, 'show-error');
if (!errorChip) {
  throw new Error('an error should be a way into Logs, Errors');
}
if (errorChip.getAttribute('data-match') !== 'web') {
  throw new Error('the error chip should name its resource: ' + errorChip.getAttribute('data-match'));
}

// Errors: the entry a resource points at is highlighted, and only that one.
state.errorMatch = 'web';
const matchedNode = document.createElement('div');
renderErrors(matchedNode, document.createElement('div'), [
  { time: new Date().toISOString(), source: 'target', message: 'web: target 10.77.0.2:8080 is not reachable' },
  { time: new Date().toISOString(), source: 'dns', message: 'could not update app.example.com' },
]);
const matchedRows = matchedNode.childNodes[0].childNodes[1].childNodes;
if ((matchedRows[0].getAttribute('class') || '').indexOf('row-highlight') === -1) {
  throw new Error('the matching error should be highlighted: ' + matchedRows[0].getAttribute('class'));
}
if ((matchedRows[1].getAttribute('class') || '').indexOf('row-highlight') !== -1) {
  throw new Error('only the matching error should be highlighted');
}
state.errorMatch = '';

// Logs -> Errors: the list, with the fix, and the empty state.
renderErrors(node, node, [
  { time: new Date().toISOString(), source: 'dns', message: 'could not update app.example.com',
    detail: 'dns: Cloudflare error 1000: token is broken', hint: 'check the provider token' },
]);
renderErrors(node, node, []);
renderErrors(node, node, null);

// A wildcard domain keeps its "*.", so the Domains table shows what was added.
const wildcardDomain = Object.assign({}, domain, { hostname: 'example.com', pattern: '*.example.com', kind: 'wildcard' });
renderDomains(node, node, [wildcardDomain]);
if (!textsOf(node).some((text) => text === '*.example.com')) {
  throw new Error('the Domains table dropped the wildcard pattern');
}

// The publish preview names the hostname for a direct domain too: passing a null
// child to replaceChildren used to print the literal word "null" under it.
state.data.domains = [{ hostname: 'chat.example.com', pattern: 'chat.example.com', kind: 'direct' }];
const directEditorTexts = textsOf(resourceEditorPage(null));
if (!directEditorTexts.includes('https://chat.example.com')) {
  throw new Error('the publish preview does not name the direct domain: ' + directEditorTexts.join(' | '));
}
if (directEditorTexts.includes('null') || directEditorTexts.includes('undefined')) {
  throw new Error('the publish preview rendered a missing value: ' + directEditorTexts.join(' | '));
}

// Access rules: the comparison list follows the field, the action reads ALLOW or
// BLOCK, and the value box no longer carries a hint line underneath it.
function textsOf(root) {
  const out = [];
  const walk = (n) => {
    if (!n || typeof n !== 'object') return;
    if (typeof n.textContent === 'string' && n.textContent) out.push(n.textContent);
    (n.childNodes || []).forEach(walk);
  };
  walk(root);
  return out;
}
const hostRule = ruleRow({ field: 'host', operator: 'contains', action: 'allow', values: ['admin'] }, () => {});
const hostTexts = textsOf(hostRule);
for (const wanted of ['contains', 'starts with', 'ends with', 'matches', 'ALLOW', 'BLOCK']) {
  if (!hostTexts.includes(wanted)) throw new Error('the rule editor is missing ' + wanted);
}
if (hostTexts.some((text) => text.indexOf('The requested host') >= 0)) {
  throw new Error('the rule value box still renders a hint line');
}
const countryRule = ruleRow({ field: 'country', operator: 'is', action: 'block', values: ['EE'] }, () => {});
if (textsOf(countryRule).includes('contains')) {
  throw new Error('a country rule should only offer exact comparisons');
}

// Branding: the service name falls back to the bundled one and follows the
// session when the operator renamed it.
if (brandName() !== 'noobtunnel') throw new Error('the brand name did not fall back to noobtunnel');
state.brandName = 'acme';
if (brandName() !== 'acme') throw new Error('the brand name ignored the signed in session');
state.brandName = 'noobtunnel';
` + "`" + `, ctx, { filename: 'render.mjs' });

await vm.runInContext(` + "`" + `
(async () => {
  state.view = 'activity';
  state.logTab = 'requests';
  state.requestPage = 1;
  state.requestPageLoading = false;
  const first = { page: 1, total: 1, retained: 1,
    summary: { total: 1, allowed: 1, blocked: 0, countries: [], hosts: [] },
    requests: [{ time: '2026-09-24T12:00:00Z', host: 'a.example.com', allowed: true }] };
  state.data.server.requests = { summary: first.summary, recent: [] };
  state.requestPageData = first;
  shell = { requestTable: document.createElement('div'), requestsSub: document.createElement('p') };
  renderRequests(shell.requestTable, first);
  const oldTable = shell.requestTable.childNodes[0];
  api = async () => JSON.parse(JSON.stringify(first));
  await loadRequestPage(true);
  if (shell.requestTable.childNodes[0] !== oldTable || state.requestPageLoading) {
    throw new Error('a quiet request check should leave unchanged rows mounted');
  }
  api = async () => ({ ...first, total: 2, summary: { ...first.summary, total: 2, allowed: 2 },
    requests: [{ time: '2026-09-24T12:01:00Z', host: 'b.example.com', allowed: true }, ...first.requests] });
  await loadRequestPage(true);
  if (shell.requestTable.childNodes[0] === oldTable || shell.requestsSub.textContent.indexOf('2 requests') < 0) {
    throw new Error('a new request should appear without a loading state');
  }
})()
` + "`" + `, ctx, { filename: 'live-requests.mjs' });

await vm.runInContext(` + "`" + `
(async () => {
  const oldInterval = setInterval;
  const oldRefresh = refresh;
  const oldAPI = api;
  const current = state.data.agents[0];
  const oldEnrolled = current.enrolledAt;
  const oldOnline = current.online;
  let tick;
  let keepalives = 0;
  try {
    current.enrolledAt = null;
    current.online = false;
    setInterval = (callback) => { tick = callback; return 1; };
    refresh = async () => {};
    api = async (path) => { if (path.endsWith('/keepalive')) keepalives++; return {}; };
    showCreated(current, 'install command');
    modalSession.node.childNodes[1].isConnected = true;
    await tick();
    if (keepalives !== 1) throw new Error('the install modal did not renew its enrollment deadline');
  } finally {
    closeModal();
    setInterval = oldInterval;
    refresh = oldRefresh;
    api = oldAPI;
    current.enrolledAt = oldEnrolled;
    current.online = oldOnline;
  }
})()
` + "`" + `, ctx, { filename: 'agent-install-wait.mjs' });

console.log('every render function completed');
`
