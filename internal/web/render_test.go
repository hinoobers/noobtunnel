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
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    hidden: false, value: '', textContent: '', innerHTML: '', checked: false,
    required: false, placeholder: '', src: '', disabled: false,
    append(...kids) { kids.flat().map(asNode).forEach((k) => { k.parentElement = el; el.childNodes.push(k); }); },
    appendChild(kid) { const node = asNode(kid); node.parentElement = el; el.childNodes.push(node); return node; },
    replaceChildren(...kids) { el.childNodes = kids.flat().map(asNode); el.childNodes.forEach((k) => { k.parentElement = el; }); },
    remove() {}, focus() {}, blur() {}, select() {}, reset() {},
    // Attributes are recorded: the tests check the classes the renderers set.
    attrs: {},
    setAttribute(name, value) { el.attrs[name] = String(value); if (name === 'class') el.className = String(value); },
    removeAttribute(name) { delete el.attrs[name]; },
    getAttribute(name) { return name in el.attrs ? el.attrs[name] : null; },
    addEventListener() {}, removeEventListener() {}, contains() { return false; },
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
  URL, Date, JSON, Math, Object, Array, String, Number, Boolean, Promise, Error, RegExp, Map, Set,
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

const node = document.createElement('div');
renderStats(node, state.data.summary, state.data.settings, state.data.server);
renderHealth(node, state.data.health);
renderTopology(node, node, state.data.agents, state.data.summary);
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
renderRequests(node, [{ time: new Date().toISOString(), host: 'a.example.com', ip: '203.0.113.1', country: 'EE', allowed: true, resource: 'web' }]);

// The Requests table: timestamps rather than "2m ago", the resource before the
// decision, and the decision said in the row colour rather than in a pill.
const requestsNode = document.createElement('div');
renderRequests(requestsNode, [
  { time: new Date().toISOString(), host: 'a.example.com', ip: '203.0.113.1', country: 'EE', allowed: true, resource: 'web' },
  { time: new Date().toISOString(), host: 'b.example.com', ip: '203.0.113.2', country: 'RU', allowed: false, reason: 'country rule', resource: 'web' },
]);
const requestsTable = requestsNode.childNodes[0];
const headers = textsOf(requestsTable.childNodes[0]).join(',');
if (headers !== 'Timestamp,Host,Client,Country,Resource,Decision') {
  throw new Error('the Requests table headers are wrong: ' + headers);
}
const rowClasses = requestsTable.childNodes[1].childNodes.map((row) => row.getAttribute('class'));
if (rowClasses[0] !== 'is-allowed' || rowClasses[1] !== 'is-blocked') {
  throw new Error('each request row should carry its decision: ' + rowClasses.join(', '));
}
const decisionCells = requestsTable.childNodes[1].childNodes.map((row) => row.childNodes[5]);
const decisionText = decisionCells.map((cell) => textsOf(cell).join(''));
if (decisionText[0] !== 'allowed' || decisionText[1] !== 'blocked') {
  throw new Error('the decision should be plain text: ' + decisionText.join(', '));
}
if (decisionCells.some((cell) => cell.childNodes.some((kid) =>
  typeof kid.getAttribute === 'function' && (kid.getAttribute('class') || '').includes('chip')))) {
  throw new Error('the decision cell should not hold a pill any more');
}

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
openResourceEditor(null);

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

console.log('every render function completed');
`
