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

function renderTopology(node, subNode, agents, summary) {
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
  const hub = hubAddress(state.data.settings.meshCidr);
  const positions = new Map();

  agents.forEach((agent, index) => {
    const angle = (-Math.PI / 2) + (index * 2 * Math.PI) / count;
    positions.set(agent.id, {
      x: cx + Math.cos(angle) * radiusX,
      y: cy + Math.sin(angle) * radiusY,
      agent,
    });
  });

  const canvas = svg('svg', { viewBox: '0 0 ' + width + ' ' + height, role: 'img', 'aria-label': 'Mesh topology' });
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

  const drawn = new Set();
  agents.forEach((agent) => {
    const from = positions.get(agent.id);
    (agent.links || []).forEach((link) => {
      if (link.peerId < agent.id) return;
      const to = positions.get(link.peerId);
      if (!to) return;
      const pairKey = agent.id + '-' + link.peerId;
      if (drawn.has(pairKey)) return;
      drawn.add(pairKey);
      const idle = !link.lastHandshake;
      if (link.direct) {
        links.append(svg('line', {
          class: 'link direct' + (idle ? ' idle' : ''),
          x1: from.x, y1: from.y, x2: to.x, y2: to.y,
        }));
      } else {
        links.append(svg('path', {
          class: 'link relay' + (idle ? ' idle' : ''),
          d: 'M' + from.x + ' ' + from.y + ' Q' + cx + ' ' + cy + ' ' + to.x + ' ' + to.y,
        }));
      }
    });
  });

  agents.forEach((agent) => {
    const pos = positions.get(agent.id);
    if (!pos) return;
    const status = agentStatus(agent);
    links.append(svg('line', {
      class: 'link ' + (status.key === 'online' || status.key === 'reachable' ? 'direct' : 'relay idle'),
      x1: cx, y1: cy, x2: pos.x, y2: pos.y,
      opacity: status.key === 'offline' || status.key === 'disabled' ? '0.35' : '1',
    }));
  });
  canvas.append(links);

  canvas.append(svg('circle', { class: 'hub-ring', cx, cy, r: 42 }));
  canvas.append(svg('circle', { cx, cy, r: 28, fill: 'url(#hubFill)', stroke: 'rgba(255,255,255,.18)', 'stroke-width': '1' }));
  canvas.append(svg('text', { class: 'node-label', x: cx, y: cy + 4 }, 'hub'));
  canvas.append(svg('text', { class: 'node-sub', x: cx, y: cy + 58 }, hub));

  const nodes = svg('g', null);
  agents.forEach((agent) => {
    const pos = positions.get(agent.id);
    if (!pos) return;
    const status = agentStatus(agent);
    const group = svg('g', { class: 'node', tabindex: '0', role: 'button',
      onclick: () => { state.drawer = agent.id; renderShell(); },
      onkeydown: (event) => { if (event.key === 'Enter') { state.drawer = agent.id; renderShell(); } } });
    group.append(svg('title', null, agent.name + ' (' + agent.address + ') — ' + status.label));
    group.append(svg('circle', {
      cx: pos.x, cy: pos.y, r: 22,
      fill: status.key === 'offline' || status.key === 'disabled' ? 'url(#nodeIdle)' : 'url(#nodeFill)',
      stroke: 'rgba(255,255,255,.16)', 'stroke-width': '1',
    }));
    group.append(svg('text', { x: pos.x, y: pos.y + 4, 'text-anchor': 'middle', fill: 'rgba(6,12,20,.85)',
      'font-size': '11', 'font-weight': '700' }, String(agent.id)));
    group.append(svg('text', { class: 'node-label', x: pos.x, y: pos.y + 40 }, agent.name));
    group.append(svg('text', { class: 'node-sub', x: pos.x, y: pos.y + 55 }, agent.address));
    nodes.append(group);
  });
  canvas.append(nodes);
  node.append(canvas);
}

/* ---------- agent cards ---------- */

function agentChips(agent) {
  const chips = [];
  if (!agent.enabled) chips.push(h('span', { class: 'chip chip-off' }, 'disabled'));
  if (agent.directCount) chips.push(h('span', { class: 'chip chip-direct' }, agent.directCount + ' direct'));
  if (agent.relayCount) chips.push(h('span', { class: 'chip chip-relay' }, agent.relayCount + ' relayed'));
  (agent.advertise || []).forEach((prefix) => chips.push(h('span', { class: 'chip chip-quiet' }, 'routes ' + prefix)));
  if (agent.expiresAt) chips.push(h('span', { class: 'chip chip-warn' }, 'token expires ' + relTime(agent.expiresAt).replace(' ago', '')));
  return chips;
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
      h('th', null, 'User'), h('th', null, 'Role'), h('th', null, 'Created'),
      h('th', null, 'Last sign in'), h('th', null, 'Actions'))),
    h('tbody', null, users.map((user) => {
      const isMe = user.username === me;
      return h('tr', null,
        h('td', null, h('div', { class: 'row' },
          h('span', { class: 'dot ' + (user.disabled ? 'dot-off' : 'dot-on') }),
          h('span', null, user.username),
          isMe ? h('span', { class: 'chip chip-quiet' }, 'you') : null,
          user.disabled ? h('span', { class: 'chip chip-off' }, 'disabled') : null)),
        h('td', null, h('span', { class: 'chip ' + (user.role === 'admin' ? 'chip-direct' : 'chip-relay') },
          user.role || 'admin')),
        h('td', { title: absTime(user.createdAt) }, relTime(user.createdAt)),
        h('td', { title: absTime(user.lastLogin) }, user.lastLogin ? relTime(user.lastLogin) : 'never'),
        h('td', null, h('div', { class: 'row', style: 'flex-wrap:wrap' },
          h('button', { class: 'btn btn-sm', 'data-action': 'user-password', 'data-id': user.id, 'data-username': user.username }, 'Password'),
          h('button', {
            class: 'btn btn-sm',
            'data-action': 'user-role',
            'data-id': user.id,
            'data-next': user.role === 'admin' ? 'viewer' : 'admin',
          }, 'Change role'),
          h('button', {
            class: 'btn btn-sm',
            'data-action': 'user-toggle',
            'data-id': user.id,
            'data-disabled': user.disabled ? 'false' : 'true',
          }, user.disabled ? 'Enable' : 'Disable'),
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
    ['Token expires', agent.expiresAt ? absTime(agent.expiresAt) : 'never'],
    ['Version', [agent.version, agent.os, agent.arch].filter(Boolean).join(' ') || '—'],
    ['Hostname', agent.hostname || '—'],
    ['Traffic', fmtBytes(agent.rxBytes) + ' in / ' + fmtBytes(agent.txBytes) + ' out'],
    ['Advertised routes', (agent.advertise || []).join(', ') || 'none'],
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
    canAdmin() ? h('button', { class: 'btn btn-sm', 'data-action': 'agent-copy-install', 'data-id': agent.id }, 'Install command') : null,
    canAdmin() ? h('button', { class: 'btn btn-sm', 'data-action': 'agent-command', 'data-id': agent.id, 'data-command': 'resync' }, 'Re-apply config') : null,
    canAdmin() ? h('button', { class: 'btn btn-sm', 'data-action': 'agent-command', 'data-id': agent.id, 'data-command': 'reconnect' }, 'Restart tunnel') : null,
    canAdmin() ? h('button', { class: 'btn btn-sm', 'data-action': 'agent-edit', 'data-id': agent.id }, 'Edit') : null,
    canAdmin() ? h('button', { class: 'btn btn-sm', 'data-action': 'agent-rotate', 'data-id': agent.id }, 'Rotate token') : null,
    canAdmin() ? h('button', { class: 'btn btn-sm btn-danger', 'data-action': 'agent-delete', 'data-id': agent.id, 'data-name': agent.name }, 'Delete') : null));

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
    const result = await api('/api/agents/' + id + '/install');
    await copyText(result.installCommand, 'Install command copied');
    showInstallModal(agentById(id), result.installCommand);
  } catch (err) {
    toast(err.message, 'fail');
  }
}

// updateCommand turns an install command into the one that updates that machine
// later: the same script, --update instead of an enrollment. Only the binary is
// replaced, so the token, the settings and the mesh address stay as they are.
function updateCommand(command) {
  const match = /https:\/\/[^\s'"]+\/install\.sh/.exec(String(command || ''));
  if (!match) return '';
  return 'curl -fsSLk ' + match[0] + ' | sudo sh -s -- --update';
}

// updateHint is the block shown under an install command.
function updateHint(command) {
  const update = updateCommand(command);
  if (!update) return null;
  return h('div', { class: 'callout' },
    h('strong', null, 'Updating that machine later'),
    h('span', { class: 'muted', text: 'Downloads the newest agent binary and restarts it there. The machine keeps its identity and address, and nothing needs to be re-enrolled.' }),
    h('div', { class: 'cmd', text: update }),
    h('div', { class: 'cmd-actions' }, copyButton(update, 'Copy update command')));
}

function showInstallModal(agent, command) {
  const steps = h('ol', { class: 'steps' },
    h('li', null, 'Run the command on the Linux machine that should join the mesh.'),
    h('li', null, 'It installs wireguard-tools, drops the agent in /usr/local/bin and starts a systemd service.'),
    h('li', null, 'The machine dials out to this control node only, so no inbound ports or port forwarding are needed.'),
    h('li', null, 'It appears here with its mesh address as soon as the tunnel is up.'));
  modal('Install ' + (agent ? agent.name : 'agent'), 'Paste this into the target machine', h('div', { class: 'stack' },
    h('div', { class: 'cmd', text: command }),
    h('div', { class: 'cmd-actions' },
      copyButton(command, 'Copy command'),
      copyButton(agent ? agent.token : '', 'Copy token only')),
    h('div', { class: 'callout' },
      h('strong', null, 'What happens on the target'),
      steps),
    updateHint(command)));
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
        h('div', { class: 'cmd-actions' }, copyButton(result.config, 'Copy config'))));
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
      h('label', { class: 'field' }, h('span', null, 'Advertised routes (comma separated CIDRs)'),
        h('input', { name: 'advertise', value: (agent.advertise || []).join(', '), placeholder: '192.168.1.0/24' })),
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
    const advertise = String(data.get('advertise') || '').split(',').map((s) => s.trim()).filter(Boolean);
    try {
      await api('/api/agents/' + id, {
        method: 'PATCH',
        body: { name: String(data.get('name')), advertise, enabled: data.get('enabled') !== null },
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
  confirmModal('Delete agent', 'This removes ' + (name || 'the agent') + ' from the mesh and revokes its token. ' +
    'The machine keeps running but can no longer connect.', 'Delete agent', async () => {
    try {
      await api('/api/agents/' + id, { method: 'DELETE' });
      state.drawer = null;
      await refresh();
      toast('Agent deleted', 'ok');
    } catch (err) {
      toast(err.message, 'fail');
    }
  });
}

/* ---------- add agent ---------- */

function openAddAgent() {
  const form = h('form', { class: 'stack' },
    h('div', { class: 'fields' },
      h('label', { class: 'field' }, h('span', null, 'Agent name'),
        h('input', { name: 'name', required: true, placeholder: 'homelab-nas', autocomplete: 'off' })),
      h('label', { class: 'switch' },
        h('input', { type: 'checkbox', name: 'advertiseAll' }),
        h('span', null, h('strong', null, 'Advertise everything'),
          h('em', null, 'Route every network this machine can reach, instead of naming them below.'))),
      h('label', { class: 'field', 'data-advertise-field': '' },
        h('span', null, 'Advertise extra networks (optional, comma separated)'),
        h('input', { name: 'advertise', placeholder: '192.168.1.0/24, 10.10.0.0/16', autocomplete: 'off' })),
      h('label', { class: 'field' }, h('span', null, 'Enrollment link expires after'),
        h('select', { name: 'ttlHours' },
          h('option', { value: '0' }, 'never'),
          h('option', { value: '1' }, '1 hour'),
          h('option', { value: '24' }, '24 hours'),
          h('option', { value: '168' }, '7 days'))),
      h('label', { class: 'field' }, h('span', null, 'Install with'),
        h('select', { name: 'method' },
          h('option', { value: 'service' }, 'a systemd service (recommended)'),
          h('option', { value: 'docker' }, 'a Docker container')))),
    h('div', { class: 'callout' },
      h('strong', null, 'How agents connect'),
      h('span', { class: 'muted', text: 'Agents dial out to this control node, so they need no open ports. ' +
        'They reach each other directly when their NAT allows it and through the control node otherwise. ' +
        'With Docker, run the command on the machine that should host the agent, in the directory the compose files should live in.' })),
    h('div', { class: 'field-error', 'data-error': 'add', hidden: true }),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'submit' }, 'Create install command')));

  const node = modal('Add agent', 'Generates a single command that installs and connects a new machine', form);
  // "Advertise everything" replaces the explicit list.
  const allBox = $('input[name=advertiseAll]', form);
  const advertiseField = $('[data-advertise-field]', form);
  const syncAdvertise = () => {
    advertiseField.hidden = allBox.checked;
    const input = $('input[name=advertise]', form);
    if (allBox.checked) input.value = '';
  };
  allBox.addEventListener('change', syncAdvertise);
  syncAdvertise();
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const advertise = String(data.get('advertise') || '').split(',').map((s) => s.trim()).filter(Boolean);
    const name = String(data.get('name') || '').trim();
    const method = String(data.get('method') || 'service');
    if (!name) {
      const box = $('[data-error=add]', form);
      box.hidden = false;
      box.textContent = 'Give the agent a name so you can recognise it later.';
      return;
    }
    try {
      // The method decides which install command comes back: a systemd service
      // or a Docker container (--docker).
      const result = await api('/api/agents?method=' + encodeURIComponent(method), {
        method: 'POST',
        body: {
          name,
          advertise,
          advertiseAll: data.get('advertiseAll') !== null,
          ttlHours: Number(data.get('ttlHours') || 0),
        },
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
  const docker = String(command || '').includes('--docker');
  const body = h('div', { class: 'stack' },
    h('div', { class: 'callout ok' },
      h('strong', null, agent.name + ' is ready to enroll'),
      h('span', { class: 'muted', text: 'Mesh address ' + agent.prefix + '. The command below only works while the token is valid.' +
        (docker ? ' It writes a Dockerfile, a docker-compose.yml and a .env, then starts the container.' : '') })),
    h('div', { class: 'cmd', text: command }),
    h('div', { class: 'cmd-actions' },
      copyButton(command, 'Copy command'),
      copyButton(agent.token, 'Copy token')),
    h('div', { class: 'callout' },
      h('strong', null, 'On the target machine'),
      h('ol', { class: 'steps' },
        h('li', null, 'Paste the command into a terminal (root or sudo).'),
        h('li', null, 'The installer verifies the control node certificate fingerprint before trusting it.'),
        h('li', null, 'Watch it appear here as ' + agent.prefix + ' within a few seconds.'))),
    updateHint(command),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn btn-primary', 'data-action': 'modal-close' }, 'Done')));
  modal('Install ' + agent.name, 'Copy and run this on the new machine', body);
  copyText(command, 'Install command copied');
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
    h('label', { class: 'field' }, h('span', null, 'Role'),
      h('select', { name: 'role' },
        h('option', { value: 'viewer' }, 'Viewer — read only'),
        h('option', { value: 'admin' }, 'Admin — full control'))),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'submit' }, 'Create token')));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const name = String(data.get('name') || '');
    const role = String(data.get('role') || 'viewer');
    try {
      const result = await api('/api/tokens', { method: 'POST', body: { name, role } });
      closeModal();
      await refresh();
      modal('API token created', 'Copy it now, it is only shown once', h('div', { class: 'stack' },
        h('div', { class: 'cmd', text: result.token }),
        h('div', { class: 'cmd-actions' }, copyButton(result.token, 'Copy token')),
        h('p', { class: 'muted tiny' }, 'Use it as: curl -H "Authorization: Bearer TOKEN" https://' + state.data.server.publicEndpoint + '/api/state')));
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
