'use strict';
/* Rendering for the noobtunnel control node UI. Uses the helpers from app.js. */

/* ---------- status helpers ---------- */

function agentStatus(agent) {
  if (!agent.enabled) return { key: 'disabled', label: 'disabled', dot: 'dot-off' };
  const fresh = agent.lastHandshake && (Date.now() - new Date(agent.lastHandshake).getTime()) < 180000;
  if (agent.online && fresh) return { key: 'online', label: 'online', dot: 'dot-on' };
  if (agent.online) return { key: 'connecting', label: 'connected', dot: 'dot-warn' };
  if (fresh) return { key: 'reachable', label: 'reachable', dot: 'dot-warn' };
  return { key: 'offline', label: 'offline', dot: 'dot-off' };
}

// statusDot renders the coloured state indicator. Hovering it reveals the
// WireGuard handshake age, which is the detail behind the colour.
function statusDot(agent, extraClass = '') {
  const status = agentStatus(agent);
  const handshake = agent.lastHandshake ? relTime(agent.lastHandshake) : 'never';
  return h('span', {
    class: 'dot ' + status.dot + (extraClass ? ' ' + extraClass : ''),
    title: status.label + ' · last handshake ' + handshake,
  });
}

function hubAddress(cidr) {
  const match = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\//.exec(cidr || '');
  if (!match) return '10.77.0.1';
  const octets = match.slice(1, 5).map(Number);
  const value = ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
  const next = (value + 1) >>> 0;
  return [next >>> 24, (next >>> 16) & 255, (next >>> 8) & 255, next & 255].join('.');
}

function totalTraffic(agents) {
  return (agents || []).reduce((acc, a) => ({ rx: acc.rx + (a.rxBytes || 0), tx: acc.tx + (a.txBytes || 0) }), { rx: 0, tx: 0 });
}

/* ---------- stats ---------- */

function renderStats(node, summary, settings, server, agents) {
  clear(node);
  const traffic = totalTraffic(agents || (state.data ? state.data.agents : []));
  const cards = [
    h('div', { class: 'stat' },
      h('div', { class: 'label', text: 'Agents connected' }),
      h('div', { class: 'value' + (summary.online > 0 ? ' is-good' : '') },
        String(summary.online), h('small', { text: ' / ' + summary.agents })),
      h('div', { class: 'hint', text: summary.reachable + ' with a live WireGuard session' })),
    h('div', { class: 'stat' },
      h('div', { class: 'label', text: 'Paths' }),
      h('div', { class: 'value' }, String(summary.directLinks), h('small', { text: ' direct' })),
      h('div', { class: 'hint', text: summary.relayedLinks + ' relayed through the control node' })),
    h('div', { class: 'stat' },
      h('div', { class: 'label', text: 'Traffic' }),
      h('div', { class: 'value', style: 'font-size:1.25rem' }, fmtBytes(traffic.rx), h('small', { text: ' in' })),
      h('div', { class: 'hint', text: fmtBytes(traffic.tx) + ' out · total since each agent started' })),
  ];
  cards.forEach((card) => node.append(card));
}

/* ---------- health ---------- */

function renderHealth(node, checks) {
  const attention = (checks || []).filter((c) => c.status === 'warn' || c.status === 'fail');
  if (!attention.length) {
    node.hidden = true;
    clear(node);
    return;
  }
  node.hidden = false;
  clear(node).append(
    h('div', { class: 'panel-head' },
      h('div', null,
        h('h2', { text: attention.length + ' setup item' + (attention.length === 1 ? '' : 's') + ' need attention' }),
        h('p', { class: 'muted', text: 'These checks decide whether agents can reach each other.' })),
      h('button', { class: 'btn', 'data-action': 'health-refresh' }, 'Re-run checks')),
    h('div', { class: 'checks' }, attention.map((check) => h('div', { class: 'check' },
      h('span', { class: 'check-status ' + check.status }),
      h('div', null,
        h('div', { class: 'check-title' }, check.title),
        h('div', { class: 'check-detail', text: check.detail }),
        check.fix ? h('div', null,
          h('pre', { text: check.fix }),
          h('div', { class: 'cmd-actions' }, copyButton(check.fix, 'Copy fix'))) : null)))));
}

async function refreshChecks() {
  try {
    const result = await api('/api/checks?refresh=1');
    if (state.data) state.data.health = result.checks;
    renderShell();
    toast('Checks re-run', 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}

/* ---------- topology ---------- */

const topologyLayoutKey = 'noobtunnel.topology.layout.v1';
let topologyLayout;
let topologyDragging = false;

function loadTopologyLayout() {
  if (topologyLayout !== undefined) return topologyLayout;
  try {
    const saved = JSON.parse(window.localStorage.getItem(topologyLayoutKey));
    topologyLayout = saved && typeof saved === 'object' && !Array.isArray(saved) ? saved : {};
  } catch (_) {
    topologyLayout = {};
  }
  if (!topologyLayout.agents || typeof topologyLayout.agents !== 'object') topologyLayout.agents = {};
  return topologyLayout;
}

function saveTopologyLayout() {
  try { window.localStorage.setItem(topologyLayoutKey, JSON.stringify(topologyLayout)); } catch (_) {}
}

function resetTopologyLayout() {
  topologyLayout = undefined;
  try { window.localStorage.removeItem(topologyLayoutKey); } catch (_) {}
  renderShell();
}

function renderTopology(node, subNode, agents, summary) {
  if (topologyDragging) return;
  clear(node);
  agents = agents || [];
  if (subNode) {
    subNode.textContent = summary.agents === 0
      ? 'No agents yet'
      : summary.agents + ' agent' + (summary.agents === 1 ? '' : 's') + ' · ' +
        summary.directLinks + ' direct · ' + summary.relayedLinks + ' relayed';
  }
  if (!agents.length) {
    node.append(h('div', { class: 'topo-empty' },
      h('h3', { text: 'Your mesh is empty' }),
      h('p', { class: 'muted', text: 'Add an agent to get a one line command that installs and connects it.' }),
      h('button', { class: 'btn btn-primary', 'data-action': 'add-agent' }, 'Add your first agent')));
    return;
  }

  const width = 960, height = 470, cx = width / 2, cy = height / 2;
  const count = agents.length;
  const radiusX = Math.min(400, 200 + count * 24);
  const radiusY = Math.min(190, 120 + count * 9);
  const hub = state.data.server.hubAddress || hubAddress(state.data.settings.meshCidr);
  const layout = loadTopologyLayout();
  const clamp = (value, low, high) => Math.max(low, Math.min(high, value));
  const savedPosition = (saved, x, y) => ({
    x: saved && Number.isFinite(saved.x) ? clamp(saved.x, 60, width - 60) : x,
    y: saved && Number.isFinite(saved.y) ? clamp(saved.y, 48, height - 72) : y,
  });
  const hubPos = savedPosition(layout.hub, cx, cy);
  const positions = new Map();

  agents.forEach((agent, index) => {
    const angle = (-Math.PI / 2) + (index * 2 * Math.PI) / count;
    positions.set(agent.id, savedPosition(layout.agents[agent.id],
      cx + Math.cos(angle) * radiusX, cy + Math.sin(angle) * radiusY));
  });

  const canvas = svg('svg', { viewBox: '0 0 ' + width + ' ' + height, role: 'img',
    'aria-label': 'Mesh topology. Drag nodes to arrange them.' });
  canvas.append(svg('defs', null,
    svg('linearGradient', { id: 'linkDirect', x1: '0', y1: '0', x2: '1', y2: '1' },
      svg('stop', { offset: '0', 'stop-color': '#818cf8' }),
      svg('stop', { offset: '1', 'stop-color': '#22d3ee' })),
    svg('radialGradient', { id: 'hubFill', cx: '0.5', cy: '0.35' },
      svg('stop', { offset: '0', 'stop-color': '#8b9bff' }),
      svg('stop', { offset: '1', 'stop-color': '#4c5bd4' })),
    svg('radialGradient', { id: 'nodeFill', cx: '0.5', cy: '0.35' },
      svg('stop', { offset: '0', 'stop-color': '#3ddc97' }),
      svg('stop', { offset: '1', 'stop-color': '#178f66' })),
    svg('radialGradient', { id: 'nodeIdle', cx: '0.5', cy: '0.35' },
      svg('stop', { offset: '0', 'stop-color': '#475569' }),
      svg('stop', { offset: '1', 'stop-color': '#1e293b' }))));

  const links = svg('g', null);
  const spokes = agents.map((agent) => {
    const line = svg('line', { class: 'link hub-link' + (!agent.online ? ' idle' : '') },
      svg('title', null, agent.name + ' ↔ control node'));
    links.append(line);
    return { id: agent.id, line };
  });
  const agentById = new Map(agents.map((agent) => [agent.id, agent]));
  const pairs = new Map();
  agents.forEach((agent) => (agent.links || []).forEach((link) => {
    if (!agentById.has(link.peerId)) return;
    const ids = [agent.id, link.peerId].sort((a, b) => a - b);
    const key = ids.join('-');
    if (!pairs.has(key)) pairs.set(key, { ids, reports: [] });
    pairs.get(key).reports.push(link);
  }));
  const edges = [];
  pairs.forEach(({ ids, reports }) => {
    const from = agentById.get(ids[0]), to = agentById.get(ids[1]);
    const direct = reports.every((link) => link.direct);
    const mixed = reports.some((link) => link.direct) && !direct;
    const idle = !from.online || !to.online;
    const edge = svg(direct ? 'line' : 'path', {
      class: 'link ' + (direct ? 'direct' : 'relay') + (idle ? ' idle' : ''),
    }, svg('title', null, from.name + ' ↔ ' + to.name + ': ' +
      (direct ? 'direct agent-to-agent path' : mixed ? 'one side direct, one side via control node' : 'via control node')));
    links.append(edge);
    edges.push({ ids, direct, edge });
  });
  canvas.append(links);

  const hubNode = svg('g', { class: 'hub-node', tabindex: '0', 'aria-label': 'Control node. Drag or use arrow keys to move.' },
    svg('title', null, 'Control node ' + hub),
    svg('circle', { class: 'hub-ring', cx: 0, cy: 0, r: 42 }),
    svg('circle', { cx: 0, cy: 0, r: 28, fill: 'url(#hubFill)', stroke: 'rgba(255,255,255,.18)', 'stroke-width': '1' }),
    svg('text', { class: 'node-label', x: 0, y: 4 }, 'hub'),
    svg('text', { class: 'node-sub', x: 0, y: 58 }, hub));
  canvas.append(hubNode);

  function drawGeometry() {
    hubNode.setAttribute('transform', 'translate(' + hubPos.x + ' ' + hubPos.y + ')');
    spokes.forEach(({ id, line }) => {
      const pos = positions.get(id);
      line.setAttribute('x1', hubPos.x); line.setAttribute('y1', hubPos.y);
      line.setAttribute('x2', pos.x); line.setAttribute('y2', pos.y);
    });
    edges.forEach(({ ids, direct, edge }) => {
      const from = positions.get(ids[0]), to = positions.get(ids[1]);
      if (direct) {
        edge.setAttribute('x1', from.x); edge.setAttribute('y1', from.y);
        edge.setAttribute('x2', to.x); edge.setAttribute('y2', to.y);
      } else {
        edge.setAttribute('d', 'M' + from.x + ' ' + from.y + ' L' + hubPos.x + ' ' + hubPos.y + ' L' + to.x + ' ' + to.y);
      }
    });
  }

  function makeDraggable(group, pos, id) {
    let pointer = null, startX = 0, startY = 0, moved = false, suppressClickUntil = 0;
    const moveTo = (x, y) => {
      pos.x = clamp(x, 60, width - 60);
      pos.y = clamp(y, 48, height - 72);
      if (id === 'hub') layout.hub = { x: pos.x, y: pos.y };
      else layout.agents[id] = { x: pos.x, y: pos.y };
      if (id !== 'hub') group.setAttribute('transform', 'translate(' + pos.x + ' ' + pos.y + ')');
      drawGeometry();
    };
    const finish = (event) => {
      if (pointer !== event.pointerId) return;
      pointer = null;
      topologyDragging = false;
      group.classList.remove('dragging');
      if (moved) { saveTopologyLayout(); suppressClickUntil = Date.now() + 350; }
    };
    group.addEventListener('pointerdown', (event) => {
      if (event.button !== 0) return;
      pointer = event.pointerId;
      startX = event.clientX; startY = event.clientY; moved = false;
      topologyDragging = true;
      group.classList.add('dragging');
      group.setPointerCapture(pointer);
    });
    group.addEventListener('pointermove', (event) => {
      if (pointer !== event.pointerId) return;
      const rect = canvas.getBoundingClientRect();
      const dx = (event.clientX - startX) * width / rect.width;
      const dy = (event.clientY - startY) * height / rect.height;
      if (Math.abs(dx) + Math.abs(dy) < 3 && !moved) return;
      event.preventDefault();
      moved = true;
      moveTo(pos.x + dx, pos.y + dy);
      startX = event.clientX; startY = event.clientY;
    });
    group.addEventListener('pointerup', finish);
    group.addEventListener('pointercancel', finish);
    group.addEventListener('lostpointercapture', finish);
    group.addEventListener('keydown', (event) => {
      const steps = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] };
      if (steps[event.key]) {
        event.preventDefault();
        moveTo(pos.x + steps[event.key][0] * (event.shiftKey ? 30 : 12),
          pos.y + steps[event.key][1] * (event.shiftKey ? 30 : 12));
        saveTopologyLayout();
      } else if (id !== 'hub' && (event.key === 'Enter' || event.key === ' ')) {
        event.preventDefault(); state.drawer = id; renderShell();
      }
    });
    if (id !== 'hub') group.addEventListener('click', (event) => {
      if (Date.now() < suppressClickUntil) { event.preventDefault(); return; }
      state.drawer = id; renderShell();
    });
  }
  makeDraggable(hubNode, hubPos, 'hub');

  const nodes = svg('g', null);
  agents.forEach((agent) => {
    const pos = positions.get(agent.id);
    if (!pos) return;
    const status = agentStatus(agent);
    const group = svg('g', { class: 'node', tabindex: '0', role: 'button',
      'aria-label': agent.name + ', ' + status.label + '. Drag or use arrow keys to move; Enter opens details.' });
    group.append(svg('title', null, agent.name + ' (' + agent.address + ') — ' + status.label));
    group.append(svg('circle', {
      cx: 0, cy: 0, r: 22,
      fill: status.key === 'offline' || status.key === 'disabled' ? 'url(#nodeIdle)' : 'url(#nodeFill)',
      stroke: 'rgba(255,255,255,.16)', 'stroke-width': '1',
    }));
    group.append(svg('text', { x: 0, y: 4, 'text-anchor': 'middle', fill: 'rgba(6,12,20,.85)',
      'font-size': '11', 'font-weight': '700' }, String(agent.id)));
    group.append(svg('text', { class: 'node-label', x: 0, y: 40 }, agent.name));
    group.append(svg('text', { class: 'node-sub', x: 0, y: 55 }, agent.address));
    group.setAttribute('transform', 'translate(' + pos.x + ' ' + pos.y + ')');
    makeDraggable(group, pos, agent.id);
    nodes.append(group);
  });
  canvas.append(nodes);
  drawGeometry();
  node.append(canvas);
}

/* ---------- agent cards ---------- */

function agentChips(agent) {
  const chips = [];
  if (!agent.enabled) chips.push(h('span', { class: 'chip chip-off' }, 'disabled'));
  if (agent.directCount) chips.push(h('span', { class: 'chip chip-direct' }, agent.directCount + ' direct'));
  if (agent.relayCount) chips.push(h('span', { class: 'chip chip-relay' }, agent.relayCount + ' relayed'));
  if (!agent.enrolledAt && agent.expiresAt) chips.push(h('span', { class: 'chip chip-warn' }, enrollmentStatus(agent)));
  return chips;
}

function enrollmentStatus(agent) {
  if (agent.enrolledAt) return 'claimed';
  if (!agent.expiresAt) return 'no deadline';
  const remaining = Date.parse(agent.expiresAt) - Date.now();
  return remaining <= 0 ? 'install command expired' : 'install command expires in ' + fmtDuration(Math.ceil(remaining / 1000));
}

function renderAgentGrid(node, agents, summary) {
  clear(node);
  agents = agents || [];
  if (!agents.length) {
    node.append(h('div', { class: 'empty' },
      h('h3', { text: state.filter ? 'No agent matches that filter' : 'No agents yet' }),
      h('p', { class: 'muted', text: state.filter ? 'Try a different search term.' : 'Agents dial out to this control node, so they need no open ports.' }),
      state.filter ? null : h('button', { class: 'btn btn-primary', 'data-action': 'add-agent' }, 'Add agent')));
    return;
  }
  agents.forEach((agent) => {
    const status = agentStatus(agent);
    node.append(h('article', { class: 'agent-card' },
      h('div', { class: 'agent-card-head' },
        h('div', { class: 'agent-name' }, statusDot(agent), h('span', { text: agent.name })),
        h('span', { class: 'chip ' + statusChipClass(status), title: 'last handshake ' + relTime(agent.lastHandshake) },
          status.label)),
      h('div', { class: 'agent-addr', text: agent.prefix }),
      h('div', { class: 'row', style: 'flex-wrap:wrap;gap:6px' }, agentChips(agent)),
      h('dl', { class: 'agent-meta' },
        h('dt', null, 'Endpoint'), h('dd', { class: 'mono', title: agent.endpoint || '' }, agent.endpoint || 'behind NAT'),
        h('dt', null, 'Traffic'), h('dd', null, fmtBytes(agent.rxBytes) + ' in / ' + fmtBytes(agent.txBytes) + ' out'),
        h('dt', null, 'Latency'), h('dd', null, agent.latencyMs ? agent.latencyMs + ' ms' : '—')),
      h('div', { class: 'agent-actions' },
        h('button', { class: 'btn btn-sm btn-primary', 'data-action': 'agent-open', 'data-id': agent.id }, 'Manage'))));
  });
}

// statusChipClass maps a status to its chip colour.
function statusChipClass(status) {
  switch (status.key) {
    case 'online': return 'chip-direct';
    case 'connecting':
    case 'reachable': return 'chip-warn';
    case 'offline':
    case 'disabled': return 'chip-off';
    default: return 'chip-quiet';
  }
}

/* ---------- activity ---------- */

function renderEvents(node, events) {
  clear(node);
  if (!events || !events.length) {
    node.append(h('div', { class: 'empty' }, h('p', { class: 'muted', text: 'No activity recorded yet.' })));
    return;
  }
  events.forEach((event) => {
    node.append(h('li', null,
      h('time', { title: absTime(event.time) }, clockTime(event.time)),
      h('span', { class: 'chip chip-quiet', text: event.kind }),
      h('span', { text: event.message })));
  });
}

/* ---------- settings ---------- */

function renderServerInfo(node, server, settings) {
  clear(node);
  const rows = [
    // With --domain the control node is reachable on its own hostname, which is
    // the address to hand out; the certificate for it is managed automatically.
    server.domain ? ['Public URL', 'https://' + server.domain] : null,
    ['Control endpoint', server.publicEndpoint],
    ['Web / API listen', server.listen],
    ['WireGuard interface', server.interface + ' (udp/' + settings.wgListenPort + ')'],
    ['Hub public key', server.hubPublicKey],
    ['Certificate fingerprint', server.fingerprint],
    ['Backend', server.backend],
    ['Version', server.version + ' · ' + server.platform],
    // The build date is what tells an operator whether a running control node is
    // the build they just installed.
    server.buildDate ? ['Built', server.buildDate + (server.commit && server.commit !== 'unknown' ? ' · ' + server.commit : '')] : null,
    ['Uptime', fmtDuration(server.uptimeSec)],
  ].filter(Boolean);
  rows.forEach(([label, value]) => {
    node.append(h('dt', { text: label }));
    const copyable = ['Public URL', 'Hub public key', 'Certificate fingerprint'].includes(label);
    node.append(h('dd', null,
      h('span', { class: 'mono', text: value || '—' }),
      copyable ? h('button', { class: 'link-btn tiny', style: 'margin-left:8px', onclick: () => copyText(value, label + ' copied') }, 'copy') : null));
  });
  if (server.hubError) node.append(h('dd', { class: 'field-error' }, server.hubError));
}

function fillSettingsForm(form, settings) {
  form.meshName.value = settings.meshName;
  form.meshCidr.value = settings.meshCidr;
  form.mtu.value = settings.mtu;
  form.wgListenPort.value = settings.wgListenPort;
  form.keepaliveSec.value = settings.keepaliveSec;
  form.directPaths.checked = !!settings.directPaths;
  // Read-only accounts can look at the settings but not edit them.
  const locked = !canAdmin();
  ['meshName', 'meshCidr', 'mtu', 'wgListenPort', 'keepaliveSec', 'directPaths'].forEach((name) => {
    if (form[name]) form[name].disabled = locked;
  });
}

function renderTokens(node, tokens) {
  clear(node);
  tokens = tokens || [];
  if (!tokens.length) {
    node.append(h('li', null, h('span', { class: 'muted', text: 'No API tokens yet.' })));
    return;
  }
  tokens.forEach((token) => {
    const role = token.role || 'admin';
    node.append(h('li', null,
      h('span', null, h('strong', { text: token.name || 'unnamed token' }),
        h('span', { class: 'chip ' + (role === 'admin' ? 'chip-direct' : 'chip-relay'), style: 'margin-left:8px' }, role),
        h('span', { class: 'muted tiny', style: 'display:block' }, 'id ' + token.id + ' · created ' + absTime(token.createdAt))),
      h('button', { class: 'btn btn-sm btn-danger', 'data-action': 'delete-api-token', 'data-id': token.id }, 'Revoke')));
  });
}

/* ---------- users ---------- */

function renderUsers(node, subNode, users) {
  if (!node) return;
  users = users || [];
  clear(node);
  if (subNode) {
    const admins = users.filter((u) => u.role === 'admin' && !u.disabled).length;
    subNode.textContent = users.length === 0
      ? 'No accounts yet'
      : users.length + ' account' + (users.length === 1 ? '' : 's') + ' · ' + admins + ' admin' + (admins === 1 ? '' : 's');
  }
  if (!users.length) {
    node.append(h('div', { class: 'empty' },
      h('p', { class: 'muted', text: 'No accounts to show.' })));
    return;
  }
  const me = state.session.username;
  node.append(h('table', null,
    h('thead', null, h('tr', null,
      h('th', null, 'User'), h('th', null, 'Email'), h('th', null, 'Role'), h('th', null, 'Created'),
      h('th', null, 'Last sign in'), h('th', null, 'Actions'))),
    h('tbody', null, users.map((user) => {
      const isMe = user.username === me;
      return h('tr', null,
        h('td', null, h('div', { class: 'row' },
          h('span', { class: 'dot ' + (user.disabled ? 'dot-off' : 'dot-on') }),
          h('span', null, user.username),
          isMe ? h('span', { class: 'chip chip-quiet' }, 'you') : null,
          user.disabled ? h('span', { class: 'chip chip-off' }, 'disabled') : null)),
        h('td', { class: 'mono' }, user.email || '—'),
        h('td', null, h('span', { class: 'chip ' + (user.role === 'admin' ? 'chip-direct' : 'chip-relay') },
          user.role || 'admin')),
        h('td', { title: absTime(user.createdAt) }, relTime(user.createdAt)),
        h('td', { title: absTime(user.lastLogin) }, user.lastLogin ? relTime(user.lastLogin) : 'never'),
        h('td', null, h('div', { class: 'row', style: 'flex-wrap:wrap' },
          h('button', { class: 'btn btn-sm', 'data-action': 'user-edit', 'data-id': user.id }, 'Edit'),
          h('button', { class: 'btn btn-sm', 'data-action': 'user-resources', 'data-id': user.id, disabled: !user.email }, 'Resources'),
          isMe ? null : h('button', {
            class: 'btn btn-sm btn-danger',
            'data-action': 'user-delete',
            'data-id': user.id,
            'data-username': user.username,
          }, 'Delete'))));
    }))));
}

/* ---------- drawer ---------- */

function renderDrawer() {
  const agent = state.drawer ? agentById(state.drawer) : null;
  if (!agent) {
    // The agent was removed, or the drawer was dismissed: leave other modals
    // alone and just make sure nothing of ours is still mounted.
    if (state.drawerEl) closeModal();
    return;
  }
  if (!state.drawerEl || !state.drawerEl.isConnected) {
    openDrawer(agent);
    return;
  }
  // Update in place so the slide-in animation does not replay and the reading
  // position survives live updates.
  const node = state.drawerEl;
  const scrollTop = node.scrollTop;
  const advanced = $('details', node);
  const advancedOpen = advanced ? advanced.open : false;
  state.drawerBody.replaceChildren(drawerBody(agent));
  // Re-open the collapsed section *before* restoring the scroll offset: while it
  // is closed the content is shorter, so the browser would clamp scrollTop and
  // the reader would get yanked upwards.
  const nextAdvanced = $('details', node);
  if (nextAdvanced) nextAdvanced.open = advancedOpen;
  node.scrollTop = scrollTop;
}

function agentById(id) {
  return (state.data.agents || []).find((agent) => agent.id === Number(id)) || null;
}

function drawerBody(agent) {
  const status = agentStatus(agent);
  const body = h('div', { class: 'stack' });
  body.append(h('div', { class: 'modal-head' },
    h('div', null,
      h('div', { class: 'row' }, h('span', { class: 'dot ' + status.dot }), h('h2', { text: agent.name })),
      h('p', { class: 'muted', text: agent.prefix + ' · ' + status.label })),
    h('button', { class: 'btn btn-icon', 'data-action': 'agent-close' }, '✕')));

  const info = h('dl', { class: 'kv' });
  const rows = [
    ['Agent ID', String(agent.id)],
    ['Mesh address', agent.prefix],
    ['Public key', shortKey(agent.publicKey)],
    ['Endpoint', agent.endpoint || 'behind NAT (outbound only)'],
    ['Control latency', agent.latencyMs ? agent.latencyMs + ' ms' : '—'],
    ['Last handshake', agent.lastHandshake ? relTime(agent.lastHandshake) : 'never'],
    ['Last seen', agent.lastSeen ? relTime(agent.lastSeen) : 'never'],
    ['Enrolled', agent.enrolledAt ? absTime(agent.enrolledAt) : 'not yet'],
    ['Token created', absTime(agent.createdAt)],
    ['Enrollment command', agent.enrolledAt ? 'claimed' : (agent.expiresAt ? enrollmentStatus(agent) + ' (' + absTime(agent.expiresAt) + ')' : 'no deadline')],
    ['Version', [agent.version, agent.os, agent.arch].filter(Boolean).join(' ') || '—'],
    ['Hostname', agent.hostname || '—'],
    ['Traffic', fmtBytes(agent.rxBytes) + ' in / ' + fmtBytes(agent.txBytes) + ' out'],
    ['Shared networks', (agent.advertise || []).join(', ') || 'none'],
    ['Agent uptime', agent.uptimeSec ? fmtDuration(agent.uptimeSec) : '—'],
  ];
  rows.forEach(([label, value]) => {
    info.append(h('dt', { text: label }), h('dd', { class: label === 'Public key' ? 'mono' : '', text: value }));
  });
  body.append(h('div', { class: 'panel', style: 'box-shadow:none' }, info));

  if (agent.lastError) {
    body.append(h('div', { class: 'callout warn' }, h('strong', null, 'Agent reported'), h('span', { text: agent.lastError })));
  }

  if (agent.links && agent.links.length) {
    const links = h('div', { class: 'panel', style: 'box-shadow:none' },
      h('div', { class: 'panel-head' }, h('h2', { text: 'Paths' })));
    const table = h('table', null,
      h('thead', null, h('tr', null, h('th', null, 'Peer'), h('th', null, 'Path'), h('th', null, 'Handshake'), h('th', null, 'Traffic'))),
      h('tbody', null, agent.links.map((link) => h('tr', null,
        h('td', null, link.peerName || ('peer ' + link.peerId)),
        h('td', null, link.direct ? h('span', { class: 'chip chip-direct' }, 'direct') : h('span', { class: 'chip chip-relay' }, 'relayed')),
        h('td', { title: absTime(link.lastHandshake) }, relTime(link.lastHandshake)),
        h('td', null, fmtBytes(link.rxBytes) + ' / ' + fmtBytes(link.txBytes))))));
    links.append(table);
    body.append(links);
  }

  body.append(h('div', { class: 'agent-actions' },
    h('button', { class: 'btn btn-sm', 'data-action': 'agent-ping', 'data-id': agent.id }, 'Ping'),
    h('button', { class: 'btn btn-sm', 'data-action': 'agent-copy-config', 'data-id': agent.id }, 'Preview config'),
    canManageMesh() ? h('button', { class: 'btn btn-sm', 'data-action': 'agent-copy-install', 'data-id': agent.id }, 'Install / update') : null,
    canManageMesh() ? h('button', { class: 'btn btn-sm', 'data-action': 'agent-command', 'data-id': agent.id, 'data-command': 'reconnect' }, 'Restart tunnel') : null,
    canManageMesh() ? h('button', { class: 'btn btn-sm', 'data-action': 'agent-edit', 'data-id': agent.id }, 'Edit') : null,
    canManageMesh() ? h('button', { class: 'btn btn-sm', 'data-action': 'agent-networks', 'data-id': agent.id }, 'Networks') : null,
    canManageMesh() ? h('button', { class: 'btn btn-sm', 'data-action': 'agent-rotate', 'data-id': agent.id }, 'Rotate token') : null,
    canManageMesh() ? h('button', { class: 'btn btn-sm btn-danger', 'data-action': 'agent-delete', 'data-id': agent.id, 'data-name': agent.name }, 'Delete') : null));

  body.append(h('details', null,
    h('summary', { class: 'muted', text: 'Advanced' }),
    h('div', { class: 'stack', style: 'margin-top:10px' },
      h('div', { class: 'callout' },
        h('strong', null, 'Token'),
        h('div', { class: 'mono tiny', style: 'word-break:break-all' }, agent.token || '—'),
        h('div', { class: 'cmd-actions' }, copyButton(agent.token || '', 'Copy token'))),
      h('div', { class: 'callout' },
        h('strong', null, 'How this agent reaches others'),
        h('span', { class: 'muted', text: 'Traffic goes straight to peers when a direct path completes, otherwise through the control node. The agent only ever dials out, so it needs no inbound firewall rule.' })))));
  return body;
}

/* ---------- agent actions ---------- */

async function pingAgent(id) {
  const agent = agentById(id);
  toast('Pinging ' + (agent ? agent.name : 'agent') + '…');
  try {
    const result = await api('/api/agents/' + id + '/ping', { method: 'POST', body: {} });
    if (result.online) toast('Round trip ' + result.latencyMs + ' ms', 'ok');
    else toast(result.error || 'agent is not connected', 'fail');
  } catch (err) {
    toast(err.message, 'fail');
  }
  await refresh();
}

async function sendCommand(id, command) {
  const agent = agentById(id);
  try {
    const result = await api('/api/agents/' + id + '/command', { method: 'POST', body: { action: command } });
    if (result.ok) toast((agent ? agent.name : 'agent') + ': ' + command + ' sent', 'ok');
    else toast(result.error || 'command failed', 'fail');
  } catch (err) {
    toast(err.message, 'fail');
  }
}

async function copyInstall(id) {
  try {
    const agent = agentById(id);
    if (agent && !agent.enrolledAt && agent.expiresAt && Date.parse(agent.expiresAt) <= Date.now()) {
      throw new Error('Install command expired. Rotate the token to create a new command.');
    }
    const result = await api('/api/agents/' + id + '/install');
    const install = result.installCommand;
    const update = agent?.installMethod === 'windows' || agent?.os === 'windows' ? install : updateCommand(install);
    if (!update) throw new Error('Update command unavailable');
    modal('Install / update ' + (agent?.name || 'agent'), 'Run these on the agent machine',
      h('div', { class: 'stack' },
        h('strong', null, 'Install'),
        h('div', { class: 'cmd', text: install }),
        h('div', { class: 'cmd-actions' }, copyButton(install, 'Copy command')),
        h('strong', null, 'Update'),
        agent?.installMethod === 'docker' ? h('p', { class: 'muted', text: 'Run from the Docker compose directory.' }) : null,
        h('div', { class: 'cmd', text: update }),
        h('div', { class: 'cmd-actions' }, copyButton(update, 'Copy command'))),
      null, { preventPassiveDismiss: true });
  } catch (err) {
    toast(err.message, 'fail');
  }
}

// updateCommand turns an install command into the one that updates that machine
// later: the same script, --update instead of an enrollment. Only the binary is
// replaced, so the token, the settings and the mesh address stay as they are.
function updateCommand(command) {
  const source = String(command || '');
  const pipe = source.indexOf(' | sudo sh -s --');
  if (pipe < 0) return '';
  return source.slice(0, pipe) + ' | sudo sh -s -- --update';
}

function showInstallModal(agent, command) {
  modal('Install ' + (agent ? agent.name : 'agent'), 'Run this command on the machine joining the mesh',
    h('div', { class: 'stack' },
      h('div', { class: 'cmd', text: command }),
      h('div', { class: 'cmd-actions' }, copyButton(command, 'Copy command'))),
    null, { preventPassiveDismiss: true });
}

async function copyAgentConfig(id) {
  try {
    const result = await api('/api/agents/' + id + '/config');
    if (result.error) {
      toast(result.error, 'fail');
      return;
    }
    modal('WireGuard configuration', 'What this agent programs locally (secrets hidden)',
      h('div', { class: 'stack' },
        h('div', { class: 'cmd', text: result.config }),
        h('div', { class: 'cmd-actions' }, copyButton(result.config, 'Copy config'))),
      null, { preventPassiveDismiss: true });
  } catch (err) {
    toast(err.message, 'fail');
  }
}

function openEditAgent(id) {
  const agent = agentById(id);
  if (!agent) return;
  const form = h('form', { class: 'stack' },
    h('div', { class: 'fields' },
      h('label', { class: 'field' }, h('span', null, 'Name'),
        h('input', { name: 'name', value: agent.name, required: true })),
      h('label', { class: 'field' }, h('span', null, 'Mesh DNS (optional)'),
        h('input', { name: 'meshDns', value: agent.meshDns || '', placeholder: 'nas', maxlength: 63, pattern: '[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?', autocomplete: 'off' }),
        h('em', null, 'Use this short name from other agents in your mesh. Leave blank to remove it.')),
      h('label', { class: 'switch' },
        h('input', { type: 'checkbox', name: 'enabled', checked: agent.enabled }),
        h('span', null, h('strong', null, 'Enabled'),
          h('em', null, 'Disabling drops the agent from the mesh and revokes its session immediately.')))),
    h('div', { class: 'field-error', 'data-error': 'edit', hidden: true }),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'submit' }, 'Save changes')));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    try {
      await api('/api/agents/' + id, {
        method: 'PATCH',
        body: { name: String(data.get('name')), meshDns: String(data.get('meshDns') || '').trim(), enabled: data.get('enabled') !== null },
      });
      closeModal();
      toast('Agent updated', 'ok');
      await refresh();
    } catch (err) {
      const box = $('[data-error=edit]', form);
      box.hidden = false;
      box.textContent = err.message;
    }
  });
  modal('Edit ' + agent.name, null, form);
}

function openAgentNetworks(id) {
  const agent = agentById(id);
  if (!agent) return;
  const content = h('div', { class: 'stack' });
  modal('Networks for ' + agent.name, 'Choose which networks other agents can reach through this machine', content);
  showAgentNetworkSetup(agent, content);

  // Status reports update automatically. Add newly detected interfaces without
  // losing the checkboxes or manual address the operator is editing.
  const signature = (current) => JSON.stringify([
    current.networks || [], current.advertise || [],
    (state.data.agents || []).filter((other) => other.id !== id)
      .map((other) => [other.id, other.advertise || []]),
  ]);
  let shown = agent;
  let lastSignature = signature(agent);
  let checking = false;
  const timer = setInterval(async () => {
    if (!content.isConnected) { clearInterval(timer); return; }
    if (checking) return;
    checking = true;
    try {
      await refresh();
      if (!content.isConnected) { clearInterval(timer); return; }
      const current = agentById(id);
      if (!current) { clearInterval(timer); return; }
      const nextSignature = signature(current);
      if (nextSignature !== lastSignature) {
        const form = $('form', content);
        const draft = form ? {
          selectedRoutes: new FormData(form).getAll('network').map(String),
          manual: form.elements.manual.value,
          advertiseAll: form.elements.advertiseAll.checked,
        } : null;
        if (draft) {
          (current.advertise || []).forEach((prefix) => {
            if (!(shown.advertise || []).includes(prefix) && !draft.selectedRoutes.includes(prefix))
              draft.selectedRoutes.push(prefix);
          });
        }
        showAgentNetworkSetup(current, content, draft);
        shown = current;
        lastSignature = nextSignature;
      }
    } catch (err) {
      // A later status report will retry; keep the current draft visible.
    } finally { checking = false; }
  }, 2500);
}

async function rotateToken(id) {
  const agent = agentById(id);
  confirmModal('Rotate token', 'Rotating the token disconnects ' + (agent ? agent.name : 'this agent') +
    ' and issues a new install command. The machine keeps its mesh address and identity.', 'Rotate token', async () => {
    try {
      const result = await api('/api/agents/' + id + '/rotate', { method: 'POST', body: {} });
      await refresh();
      showInstallModal(result.agent, result.installCommand);
      toast('Token rotated', 'ok');
    } catch (err) {
      toast(err.message, 'fail');
    }
  });
}

async function deleteAgent(id, name) {
  try {
    const removal = await api('/api/agents/' + id + '/uninstall');
    const command = removal.command;
    const instruction = removal.method === 'windows' ? 'Run in Command Prompt on the agent machine.' :
      'Run on the agent machine. The installer finds its local service or Docker compose directory.';
    const dialog = modal('Delete ' + (name || 'agent'), 'Remove the agent from its machine and the control node',
      h('div', { class: 'stack' },
        h('p', { class: 'muted', text: instruction + ' The command contacts the control node first, then removes the local installation and identity.' }),
        h('div', { class: 'cmd', text: command }),
        h('div', { class: 'cmd-actions' }, copyButton(command, 'Copy command')),
        h('p', { class: 'muted', text: 'If the machine is lost or cannot reach the control node, remove only its control node record. The local installation will remain until removed on that machine.' })),
      h('div', { class: 'modal-foot' },
        h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
        h('button', { class: 'btn btn-danger', type: 'button', onclick: async () => {
          if (!window.confirm('Remove this agent from the control node only?')) return;
          try {
            await api('/api/agents/' + id, { method: 'DELETE' });
            closeModal();
            state.drawer = null;
            await refresh();
            toast('Agent removed from control node', 'ok');
          } catch (err) { toast(err.message, 'fail'); }
        } }, 'Remove from control node only')),
      { preventPassiveDismiss: true });
    const checkRemoved = setInterval(async () => {
      if (!dialog.isConnected) { clearInterval(checkRemoved); return; }
      try {
        const response = await fetch('/api/agents/' + id, { credentials: 'same-origin', cache: 'no-store' });
        if (response.status !== 404 || !dialog.isConnected) return;
        clearInterval(checkRemoved);
        closeModal();
        await refresh();
        toast('Agent removed', 'ok');
      } catch (_) { /* Keep the modal open while the control node is unreachable. */ }
    }, 2500);
  } catch (err) {
    toast(err.message, 'fail');
  }
}

/* ---------- add agent ---------- */

function windowsAgentIcon() {
  return svg('svg', { class: 'type-card-icon', viewBox: '0 0 24 24', 'aria-hidden': 'true' },
    svg('path', { d: 'M2 4.7 10.7 3.5v7.8H2V4.7Zm10.2-1.4L22 2v9.3h-9.8v-8ZM2 12.7h8.7v7.8L2 19.3v-6.6Zm10.2 0H22V22l-9.8-1.3v-8Z' }));
}

function dockerAgentIcon() {
  return svg('svg', { class: 'type-card-icon', viewBox: '0 0 24 24', 'aria-hidden': 'true' },
    svg('path', { d: 'M3 9h2.5v2.4H3V9Zm3.1 0h2.5v2.4H6.1V9Zm3.1 0h2.5v2.4H9.2V9Zm3.1 0h2.5v2.4h-2.5V9ZM6.1 6h2.5v2.4H6.1V6Zm3.1 0h2.5v2.4H9.2V6Zm3.1 0h2.5v2.4h-2.5V6Zm0-3h2.5v2.4h-2.5V3Zm3.1 6h2.5v2.4h-2.5V9Zm6.5 1.5c-.9-.6-2-.7-3-.3-.1-.9-.7-1.7-1.5-2.1l-.4.9c.7.5.9 1.1.7 1.8l-.2.5c-1.5 3.5-4.2 5.1-8.2 5.1H2c.6 3.8 3.5 5.6 7.4 5.6 5.1 0 8.3-2.5 9.8-7.3 1.5.2 2.6-.4 3.4-1.7l.2-.5Z' }));
}

function linuxAgentIcon() {
  return svg('svg', { class: 'type-card-icon', viewBox: '0 0 24 24', 'aria-hidden': 'true' },
    svg('ellipse', { cx: '12', cy: '12.5', rx: '6.2', ry: '9.4' }),
    svg('ellipse', { cx: '12', cy: '15', rx: '3.8', ry: '5.8', fill: 'var(--panel-2)' }),
    svg('ellipse', { cx: '10', cy: '7.7', rx: '.6', ry: '.8', fill: 'var(--panel-2)' }),
    svg('ellipse', { cx: '14', cy: '7.7', rx: '.6', ry: '.8', fill: 'var(--panel-2)' }),
    svg('path', { d: 'm10.1 9.5 1.9 1.7 1.9-1.7-1.9-.6-1.9.6ZM7.8 20.2 3 21.4l-.7 1.1h7.2l1-1.3-2.7-1Zm8.4 0 4.8 1.2.7 1.1h-7.2l-1-1.3 2.7-1Z' }));
}

function openAddAgent() {
  const method = { value: 'service' };
  const methods = cardPicker('method', [
    { value: 'service', label: 'Linux', hint: 'systemd service', icon: linuxAgentIcon },
    { value: 'windows', label: 'Windows', hint: 'paste into CMD', icon: windowsAgentIcon },
    { value: 'docker', label: 'Docker', hint: 'container', icon: dockerAgentIcon },
  ], method);
  methods.classList.add('agent-install-grid');
  const form = h('form', { class: 'stack' },
    h('div', { class: 'fields' },
      h('label', { class: 'field' }, h('span', null, 'Agent name'),
        h('input', { name: 'name', required: true, placeholder: 'homelab-nas', autocomplete: 'off' })),
      h('label', { class: 'field' }, h('span', null, 'Mesh DNS (optional)'),
        h('input', { name: 'meshDns', placeholder: 'nas', maxlength: 63, pattern: '[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?', autocomplete: 'off' }),
        h('em', null, 'Use a short name such as nas to reach this agent from your mesh. Leave blank for no name.'))),
    h('div', { class: 'stack' }, h('span', { class: 'agent-install-label' }, 'Install with'), methods),
    h('div', { class: 'field-error', 'data-error': 'add', hidden: true }),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'submit' }, 'Create install command')));

  const node = modal('Add agent', 'Create an install command. You can choose shared networks after it connects.', form);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const name = String(data.get('name') || '').trim();
    const selectedMethod = String(data.get('method') || 'service');
    if (!name) {
      const box = $('[data-error=add]', form);
      box.hidden = false;
      box.textContent = 'Give the agent a name so you can recognise it later.';
      return;
    }
    try {
      // The method decides which install command comes back: a systemd service
      // or a Docker container (--docker).
      const result = await api('/api/agents?method=' + encodeURIComponent(selectedMethod), {
        method: 'POST',
        body: { name, meshDns: String(data.get('meshDns') || '').trim() },
      });
      closeModal();
      await refresh();
      showCreated(result.agent, result.installCommand);
    } catch (err) {
      const box = $('[data-error=add]', form);
      box.hidden = false;
      box.textContent = err.message;
    }
  });
  return node;
}

function showCreated(agent, command) {
  const status = h('p', { class: 'muted', text: 'Waiting for the agent to connect…' });
  const body = h('div', { class: 'stack' },
    h('div', { class: 'cmd', text: command }),
    h('div', { class: 'cmd-actions' }, copyButton(command, 'Copy command')),
    status);
  modal('Install ' + agent.name, 'Run this command on the machine joining the mesh', body, null,
    { preventPassiveDismiss: true });

  let checking = false;
  let lastKeepalive = 0;
  const timer = setInterval(async () => {
    if (!body.isConnected) { clearInterval(timer); return; }
    if (checking) return;
    checking = true;
    try {
      await refresh();
      const current = agentById(agent.id);
      if (current && current.online && current.statsAt) {
        clearInterval(timer);
        if (body.isConnected) {
          closeModal();
          if (canManageMesh()) openAgentNetworks(agent.id);
        }
      } else if (current && !current.enrolledAt && Date.now() - lastKeepalive >= 60000) {
        await api('/api/agents/' + agent.id + '/keepalive', { method: 'POST' });
        lastKeepalive = Date.now();
      }
    } catch (err) {
      status.textContent = 'Waiting for the agent to connect… ' + err.message;
    } finally { checking = false; }
  }, 2500);
}

function routesOverlap(left, right) {
  const parse = (value) => {
    const [address, length] = String(value).split('/');
    const octets = address.split('.').map(Number);
    const bits = Number(length);
    if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255) ||
      !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
    return { address: (((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0), bits };
  };
  const a = parse(left), b = parse(right);
  if (!a || !b) return false;
  const mask = Math.min(a.bits, b.bits);
  if (mask === 0) return true;
  return (a.address >>> (32 - mask)) === (b.address >>> (32 - mask));
}

function showAgentNetworkSetup(agent, node, draft = null) {
  const selectedRoutes = draft ? draft.selectedRoutes : (agent.advertise || []);
  const candidates = [...new Map((agent.networks || []).filter((item) => item.prefix && item.interface)
    .map((item) => [item.prefix, item])).values()];
  const known = new Set(candidates.map((item) => item.prefix));
  selectedRoutes.forEach((prefix) => {
    if (!known.has(prefix)) candidates.push({ prefix, interface: 'previously configured' });
  });
  const suggested = (item) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(item.prefix) &&
    !/(docker|br-|veth)/i.test(item.interface);
  const claimedBy = (prefix) => (state.data.agents || []).find((other) => other.id !== agent.id &&
    (other.advertise || []).some((existing) => routesOverlap(prefix, existing)));
  const form = h('form', { class: 'stack' },
    h('div', { class: 'callout' },
      h('strong', null, 'Share a network with other agents?'),
      h('span', { class: 'muted', text: 'Only select a network if other agents should reach devices on it. If you only want to tunnel or publish services through this agent, you can leave everything unselected.' })),
    candidates.length ? h('div', { class: 'stack' },
      h('strong', null, 'Networks found on ' + agent.name),
      candidates.map((item) => {
        const owner = claimedBy(item.prefix);
        const description = owner ? 'Already shared by ' + owner.name + '. Remove it there first.' :
          item.interface === 'previously configured' ? 'Previously configured network' :
            'On ' + item.interface + (suggested(item) ? ' · suggested local network' :
              /(docker|br-|veth)/i.test(item.interface) ? ' · container network' : ' · check before sharing');
        return h('label', { class: 'switch' },
          h('input', { type: 'checkbox', name: 'network', value: item.prefix,
            checked: selectedRoutes.includes(item.prefix), disabled: !!owner && !selectedRoutes.includes(item.prefix) }),
          h('span', null, h('strong', null, item.prefix), h('em', null, description)));
      })) :
      h('p', { class: 'muted', text: 'No local networks were reported. You can still enter a network below if this machine can reach it.' }),
    h('label', { class: 'switch' },
      h('input', { type: 'checkbox', name: 'advertiseAll', checked: draft ? draft.advertiseAll : !!agent.advertiseAll }),
      h('span', null, h('strong', null, 'Advertise any future routes'),
        h('em', null, 'Automatically share new local networks reported by this machine when no other agent has claimed them.'))),
    h('label', { class: 'field' }, h('span', null, 'Another network this machine can reach (optional)'),
      h('input', { name: 'manual', value: draft ? draft.manual : '', placeholder: '192.168.1.0/24', autocomplete: 'off' }),
      h('em', null, 'Use a network prefix such as 192.168.1.0/24. Leave blank if you do not need one.')),
    h('div', { class: 'field-error', hidden: true }),
    h('div', { class: 'cmd-actions' },
      h('button', { class: 'btn btn-primary', type: 'submit' }, 'Done')));
  const values = () => {
    const data = new FormData(form);
    return {
      advertise: [...new Set(data.getAll('network').map(String).concat(
        String(data.get('manual') || '').split(',').map((value) => value.trim()).filter(Boolean)))].sort(),
      advertiseAll: data.get('advertiseAll') !== null,
    };
  };
  const changed = () => {
    const current = values();
    return current.advertiseAll !== !!agent.advertiseAll ||
      JSON.stringify(current.advertise) !== JSON.stringify([...(agent.advertise || [])].sort());
  };
  const action = $('button[type=submit]', form);
  const updateAction = () => { action.textContent = changed() ? 'Save and close' : 'Done'; };
  form.addEventListener('input', updateAction);
  form.addEventListener('change', updateAction);
  updateAction();
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!changed()) { closeModal(); return; }
    const { advertise, advertiseAll } = values();
    try {
      await api('/api/agents/' + agent.id, { method: 'PATCH', body: { advertise, advertiseAll } });
      toast('Networks saved', 'ok');
      closeModal();
      await refresh();
    } catch (err) {
      const box = $('.field-error', form);
      box.hidden = false;
      box.textContent = err.message;
    }
  });
  node.replaceChildren(form);
}

/* ---------- settings actions ---------- */

async function saveSettings(event) {
  event.preventDefault();
  const form = shell.settingsForm;
  const error = $('[data-settings-error]', form);
  error.hidden = true;
  const base = state.data.settings;
  const body = Object.assign({}, base, {
    meshName: form.meshName.value.trim(),
    meshCidr: form.meshCidr.value.trim(),
    mtu: Number(form.mtu.value),
    wgListenPort: Number(form.wgListenPort.value),
    keepaliveSec: Number(form.keepaliveSec.value),
    directPaths: form.directPaths.checked,
  });
  try {
    const result = await api('/api/settings', { method: 'POST', body });
    if (state.data) state.data.settings = result.settings;
    toast('Settings saved', 'ok');
    await refresh();
  } catch (err) {
    error.hidden = false;
    error.textContent = err.message;
  }
}

async function createAPIToken() {
  const form = h('form', { class: 'stack' },
    h('label', { class: 'field' }, h('span', null, 'Token name'),
      h('input', { name: 'name', placeholder: 'ci-pipeline', required: true })),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'submit' }, 'Create token')));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const name = String(data.get('name') || '');
    const role = 'admin';
    try {
      const result = await api('/api/tokens', { method: 'POST', body: { name, role } });
      closeModal();
      await refresh();
      modal('API token created', 'Copy it now, it is only shown once', h('div', { class: 'stack' },
        h('div', { class: 'cmd', text: result.token }),
        h('div', { class: 'cmd-actions' }, copyButton(result.token, 'Copy token')),
        h('p', { class: 'muted tiny' }, 'Use it as: curl -H "Authorization: Bearer TOKEN" https://' + state.data.server.publicEndpoint + '/api/state')),
        null, { preventPassiveDismiss: true });
    } catch (err) {
      toast(err.message, 'fail');
    }
  });
  modal('New API token', 'For scripts and automation', form);
}

async function deleteAPIToken(id) {
  try {
    await api('/api/tokens/' + id, { method: 'DELETE' });
    await refresh();
    toast('Token revoked', 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}
