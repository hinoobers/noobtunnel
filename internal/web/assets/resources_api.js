'use strict';
/* Resources (published services) and Domains for the control node UI. */

const PROTOCOL_INFO = {
  http: { label: 'HTTP', hint: 'Reverse proxy on the control node, routed by domain (Host header).' },
  https: { label: 'HTTPS', hint: 'The control node terminates TLS with a certificate for the domain and proxies to your service. Always port 443.' },
  tcp: { label: 'TCP', hint: 'Raw TCP forward: SSH, RDP, databases, game servers.' },
  udp: { label: 'UDP', hint: 'Datagram forward with per-client sessions: DNS, QUIC, game servers.' },
};

const STRATEGY_INFO = {
  'round-robin': { label: 'Round robin', hint: 'Spread new connections evenly over the targets.' },
  failover: { label: 'Failover', hint: 'Always use the first target and fall back when it cannot be reached.' },
};

const PROXY_PROTOCOL_INFO = {
  '': { label: 'Off', hint: 'The service sees the control node as its client. HTTP still receives X-Forwarded-For.' },
  v1: { label: 'PROXY v1', hint: 'Text header carrying the real client address.' },
  v2: { label: 'PROXY v2', hint: 'Binary header, for services that prefer it.' },
};

// Common SRV consumers are presets. Admins can still enter a custom service.
const SRV_PRESETS = {
  minecraft: { label: 'Minecraft Java', service: 'minecraft', protocol: 'tcp' },
  mumble: { label: 'Mumble', service: 'mumble', protocol: 'tcp' },
  teamspeak: { label: 'TeamSpeak 3', service: 'ts3', protocol: 'udp' },
  sip_udp: { label: 'SIP (UDP)', service: 'sip', protocol: 'udp' },
  sip_tcp: { label: 'SIP (TCP)', service: 'sip', protocol: 'tcp' },
  xmpp_client: { label: 'XMPP client', service: 'xmpp-client', protocol: 'tcp' },
  xmpp_server: { label: 'XMPP server', service: 'xmpp-server', protocol: 'tcp' },
  ldap: { label: 'LDAP', service: 'ldap', protocol: 'tcp' },
  custom: { label: 'Custom service', service: '', protocol: 'tcp' },
};

// RULE_FIELDS describes what an access rule can look at.
const RULE_FIELDS = {
  country: { label: 'Country', placeholder: 'EE' },
  ip: { label: 'Client IP', placeholder: '203.0.113.0/24' },
  host: { label: 'Hostname', placeholder: 'admin.example.com' },
  path: { label: 'Path', placeholder: '/admin' },
  account: { label: 'Account', placeholder: 'admin' },
};

// RULE_OPERATORS is how a comparison reads in the UI.
const RULE_OPERATORS = {
  is: 'is',
  'is-not': 'is not',
  contains: 'contains',
  'starts-with': 'starts with',
  'ends-with': 'ends with',
  matches: 'matches',
};

// ruleOperatorsFor mirrors the control node: a country code or an address is an
// exact value, while text can be matched as a substring, prefix, suffix or regex.
function ruleOperatorsFor(field) {
  if (field === 'country' || field === 'ip') return ['is', 'is-not'];
  return Object.keys(RULE_OPERATORS);
}

// ruleRow renders one editable access rule.
function ruleRow(rule, onRemove) {
  const value = rule && rule.values ? rule.values.join(', ') : '';
  const initialField = rule && rule.field && RULE_FIELDS[rule.field] ? rule.field : 'country';
  const valueInput = h('input', {
    name: 'ruleValues', spellcheck: 'false', value,
    placeholder: RULE_FIELDS[initialField].placeholder,
  });
  const operatorSelect = h('select', { name: 'ruleOperator' });
  // fillOperators rebuilds the list for a field, keeping the chosen comparison
  // when that field still supports it.
  const fillOperators = (field, selected) => {
    clear(operatorSelect);
    const allowed = ruleOperatorsFor(field);
    const wanted = allowed.indexOf(selected) >= 0 ? selected : allowed[0];
    allowed.forEach((op) => operatorSelect.append(h('option', {
      value: op, selected: op === wanted ? true : null,
    }, RULE_OPERATORS[op])));
  };
  fillOperators(initialField, rule && rule.operator ? rule.operator : 'is');
  const fieldSelect = h('select', { name: 'ruleField' },
    Object.entries(RULE_FIELDS).map(([key, info]) => h('option', {
      value: key, selected: initialField === key ? true : null,
    }, info.label)));
  fieldSelect.addEventListener('change', () => {
    valueInput.placeholder = RULE_FIELDS[fieldSelect.value].placeholder;
    fillOperators(fieldSelect.value, operatorSelect.value);
  });
  const row = h('div', { class: 'rule-row' },
    h('label', { class: 'field' }, h('span', null, 'If'), fieldSelect),
    h('label', { class: 'field' }, h('span', null, 'Matches'), operatorSelect),
    h('label', { class: 'field' }, h('span', null, 'Value'), valueInput),
    h('label', { class: 'field' }, h('span', null, 'Then'),
      h('select', { name: 'ruleAction' },
        h('option', { value: 'block', selected: rule && rule.action === 'allow' ? null : true }, 'BLOCK'),
        h('option', { value: 'allow', selected: rule && rule.action === 'allow' ? true : null }, 'ALLOW'))),
    h('button', { class: 'btn btn-sm btn-danger', type: 'button', onclick: () => onRemove(row) }, 'Remove'));
  row.syncFields = (allowed) => {
    const selected = allowed.includes(fieldSelect.value) ? fieldSelect.value : allowed[0];
    clear(fieldSelect);
    allowed.forEach((key) => fieldSelect.append(h('option', { value: key, selected: key === selected ? true : null }, RULE_FIELDS[key].label)));
    fieldSelect.value = selected;
    valueInput.placeholder = RULE_FIELDS[selected].placeholder;
    fillOperators(selected, operatorSelect.value);
  };
  return row;
}

// readRules turns the rule rows into the API shape.
function readRules(container) {
  return Array.from(container.querySelectorAll('.rule-row')).map((row) => ({
    field: row.querySelector('[name=ruleField]').value,
    operator: row.querySelector('[name=ruleOperator]').value,
    action: row.querySelector('[name=ruleAction]').value,
    values: row.querySelector('[name=ruleValues]').value
      .split(',').map((value) => value.trim()).filter(Boolean),
  })).filter((rule) => rule.values.length);
}

function protocolChip(protocol) {
  const info = PROTOCOL_INFO[protocol] || { label: protocol };
  return h('span', { class: 'chip chip-relay', title: info.hint || '' }, info.label);
}

function resourceStatus(resource) {
  if (!resource.enabled) return { dot: 'dot-off', label: 'disabled' };
  if (resource.lastError) return { dot: 'dot-warn', label: 'error' };
  if (resource.listening) return { dot: 'dot-on', label: 'listening' };
  return { dot: 'dot-off', label: 'stopped' };
}

// publicAddress shows how a resource is reached. A web resource is a link to open
// in a new tab; a tcp or udp service is an address and a port, which nothing can
// open, so it stays plain text (and carries no scheme).
function publicAddress(resource) {
  const text = String(resource.public || '');
  if (/^https?:\/\//.test(text)) {
    return h('a', {
      class: 'mono tiny',
      href: text,
      target: '_blank',
      rel: 'noreferrer noopener',
      title: 'Open ' + text + ' in a new tab',
    }, text);
  }
  return h('span', { class: 'mono tiny', text });
}

// errorLink turns an error into something to click: it opens Logs, the Errors tab,
// and highlights the entry that belongs to this resource or target, so the reason
// is one click away instead of a hunt through the log.
function errorLink(message, match) {
  return h('button', {
    class: 'chip chip-warn chip-link',
    type: 'button',
    title: message + ' — open Logs, Errors',
    'data-action': 'show-error',
    'data-match': match || message,
  }, 'error');
}

function renderResources(node, subNode, resources) {
  if (!node) return;
  resources = resources || [];
  const filtered = canAdmin() && !!state.resourceFilterEmail;
  clear(node);
  // Keep the add button beside the account filter in every list state.
  if (shell && shell.resourcesAdd) {
    shell.resourcesAdd.hidden = !canManageMesh();
  }
  const listening = resources.filter((r) => r.listening).length;
  if (subNode) {
    subNode.textContent = filtered && !state.resourceFilterData ? 'Searching account...'
      : filtered && !state.resourceFilterData.matched ? 'No account with that email'
      : filtered && resources.length === 0 ? 'No resources for ' + state.resourceFilterEmail
      : filtered ? resources.length + ' resources for ' + state.resourceFilterEmail
      : resources.length === 0
      ? 'Nothing published yet'
      : resources.length + ' published · ' + listening + ' listening';
  }
  if (!resources.length) {
    if (filtered) {
      node.append(h('div', { class: 'empty' }, h('p', { class: 'muted', text: subNode.textContent })));
      return;
    }
    node.append(h('div', { class: 'empty' },
      h('h3', null, 'Publish a service'),
      h('p', { class: 'muted', text: 'Expose something running on an agent — a web UI, SSH, a game server — on a public address of the control node, without opening any port on the agent.' }),
    ));
    return;
  }
  const rows = resources.map((resource) => {
    const status = resourceStatus(resource);
    const targets = resource.targets || [];
    const targetCell = targets.length
      ? targets.map((target) => h('div', { class: 'stack', style: 'gap:2px' },
        h('div', { class: 'row' },
          h('span', { class: 'mono tiny', text: target.address }),
          target.enabled ? null : h('span', { class: 'chip chip-off' }, 'off'),
          target.lastError ? errorLink(target.lastError, target.address) : null,
          // The diagnosis is only offered when something is wrong: with the whole
          // path working there is nothing to check.
          canAdmin() && target.lastError ? h('button', {
            class: 'link-btn tiny', title: 'Check this target from the control node',
            'data-action': 'diagnose-target', 'data-resource': resource.id, 'data-target': target.id,
          }, 'diagnose') : null),
        h('div', { class: 'muted tiny', text: (target.agentName || 'unknown agent') +
          (target.total ? ' · ' + target.total + ' served' : '') })))
      : [h('span', { class: 'muted tiny' }, 'no targets')];
    return h('tr', null,
      h('td', null, h('div', { class: 'row' },
        h('span', { class: 'dot ' + status.dot, title: resource.lastError || status.label }),
        h('span', null, resource.name),
        resource.lastError ? errorLink(resource.lastError, resource.name) : null,
        resource.proxyProtocol
          ? h('span', { class: 'chip chip-quiet', title: 'PROXY protocol ' + resource.proxyProtocol }, 'PROXY ' + resource.proxyProtocol)
          : null)),
      h('td', null, protocolChip(resource.protocol),
        targets.length > 1 ? h('div', { class: 'muted tiny', text: resource.strategy }) : null),
      h('td', null, targetCell),
      h('td', null,
        h('div', { class: 'row' },
          publicAddress(resource),
          copyButton(resource.public, 'Copy'))),
      // The dot next to the name already says whether this resource is healthy, so
      // there is no separate status column.
      h('td', null,
        h('div', null, fmtBytes(resource.rxBytes) + ' / ' + fmtBytes(resource.txBytes)),
        resource.monthlyQuotaBytes ? h('div', { class: 'muted tiny', text: 'This month ' + fmtBytes(resource.monthlyUsedBytes || 0) + ' / ' + fmtBytes(resource.monthlyQuotaBytes) }) : null,
        resource.monthlyRequestQuota ? h('div', { class: 'muted tiny', text: 'Requests ' + (resource.monthlyUsedRequests || 0).toLocaleString() + ' / ' + resource.monthlyRequestQuota.toLocaleString() + ' this month' }) : null),
      h('td', null, canManageMesh() ? h('div', { class: 'row', style: 'flex-wrap:wrap' },
        h('button', { class: 'btn btn-sm', 'data-action': 'resource-edit', 'data-id': resource.id }, 'Edit'),
        filtered ? null : h('button', {
          class: 'btn btn-sm',
          'data-action': 'resource-toggle',
          'data-id': resource.id,
          'data-enabled': resource.enabled ? 'false' : 'true',
        }, resource.enabled ? 'Disable' : 'Enable'),
        filtered ? null : h('button', {
          class: 'btn btn-sm btn-danger',
          'data-action': 'resource-delete',
          'data-id': resource.id,
          'data-name': resource.name,
        }, 'Delete')) : h('span', { class: 'muted tiny' }, 'read only')));
  });
  node.append(h('table', null,
    h('thead', null, h('tr', null,
      h('th', null, 'Resource'), h('th', null, 'Type'), h('th', null, 'Targets'),
      h('th', null, 'Public address'), h('th', null, 'Traffic in/out'), h('th', null, 'Actions'))),
    h('tbody', null, rows)));
}

// protocolIsByDomain reports whether a client reaches this kind of resource by
// name: http and https are routed by the Host header, TLS passthrough by the
// server name, and everything else by its port.
function protocolIsByDomain(protocol) {
  return protocol === 'http' || protocol === 'https' || protocol === 'https-passthrough';
}

function renderDomains(node, subNode, domains) {
  if (!node) return;
  domains = domains || [];
  clear(node);
  // Same single-button rule as resources.
  if (shell && shell.domainsAdd) {
    shell.domainsAdd.hidden = !canManageMesh() || domains.length === 0;
  }
  if (subNode) {
    subNode.textContent = domains.length === 0
      ? 'No domains yet'
      : domains.length + ' domain' + (domains.length === 1 ? '' : 's');
  }
  if (!domains.length) {
    node.append(h('div', { class: 'empty' },
      h('h3', null, 'Add a domain'),
      h('p', { class: 'muted', text: 'Domains let HTTP and HTTPS resources be reached by name instead of by port.' }),
      canManageMesh() ? h('button', { class: 'btn btn-primary', 'data-action': 'add-domain' }, 'Add domain') : null));
    return;
  }
  node.append(h('table', null,
    h('thead', null, h('tr', null,
      h('th', null, 'Domain'), h('th', null, 'DNS'), h('th', null, 'Used by'), h('th', null, ''))),
    h('tbody', null, domains.map((domain) => h('tr', null,
      // A wildcard domain is stored as its base name plus a kind: show the
      // pattern the operator typed, so "*.example.com" stays recognisable.
      h('td', null, h('div', { class: 'row', style: 'gap:6px; flex-wrap:wrap' },
        h('span', { class: 'mono', text: domain.pattern || domain.hostname }),
        domain.publicPool ? h('span', { class: 'chip chip-direct' }, 'public pool') : null,
        !domain.verified && domain.ownerId ? h('span', { class: 'chip chip-warn' }, 'verify ownership') : null),
        !domain.verified && domain.ownerId && domain.verificationName ? h('div', { class: 'muted tiny' },
          'TXT ', h('code', { text: domain.verificationName }), ' = ', h('code', { text: domain.verificationToken })) : null),
      h('td', { class: 'muted tiny' },
        h('div', { class: 'row', style: 'gap:6px' },
          h('span', { class: 'mono tiny', text: domain.address || '—' }),
          domain.providerId
            ? (domain.lastError
                ? h('span', { class: 'chip chip-warn', title: domain.lastError }, 'error')
                : domain.synced ? h('span', { class: 'chip chip-direct' }, 'in sync')
                : h('span', { class: 'chip chip-quiet' }, 'pending'))
            : h('span', { class: 'chip chip-off' }, 'manual')),
        h('div', { class: 'muted tiny', text: domain.exitNodeName || 'control node' })),
      h('td', null, domain.resources && domain.resources.length
        ? (domain.resources.length === 1
            ? h('span', { class: 'chip chip-quiet' }, domain.resources[0])
            : h('span', { class: 'chip chip-quiet' }, domain.resources.length + ' resources'))
        : h('span', { class: 'muted tiny' }, 'nothing yet')),
      h('td', null, h('div', { class: 'row', style: 'flex-wrap:wrap' },
        !domain.verified && domain.ownerId ? h('button', { class: 'btn btn-sm', 'data-action': 'domain-verify', 'data-hostname': domain.hostname }, 'Verify') : null,
        canAdmin() ? h('button', { class: 'btn btn-sm', 'data-action': 'domain-edit', 'data-hostname': domain.hostname }, 'Edit') : null,
        (!domain.publicPool || canAdmin()) ? h('button', { class: 'btn btn-sm btn-danger', 'data-action': 'domain-delete', 'data-hostname': domain.hostname }, 'Delete') : null)))))));
}

/* ---------- publish page ---------- */

function enrolledAgents() {
  const source = state.resourceFilterEmail && state.resourceFilterData?.matched
    ? state.resourceFilterData.agents : state.data.agents;
  return (source || []).filter((agent) => agent.publicKey);
}

function openResourceEditor(id) {
  if (!enrolledAgents().length && id === null) {
    toast('Enroll an agent first: services are published through an agent.', 'fail');
    return;
  }
  const enabled = (state.data.exitNodes || []).filter((node) => node.enabled);
  if (!enabled.length) {
    toast('Enable an exit node first: resources are published on a public address.', 'fail');
    return;
  }
  state.resourceForm = { id: id === null || id === undefined ? null : Number(id) };
  state.resourceEditorKey = '';
  if (state.resourceForm.id !== null && window.history && window.history.pushState) {
    const target = '/resources/' + state.resourceForm.id +
      (state.resourceFilterEmail ? '?email=' + encodeURIComponent(state.resourceFilterEmail) : '');
    if (window.location.pathname + window.location.search !== target) window.history.pushState({ view: 'resources', resourceId: state.resourceForm.id }, '', target);
  }
  renderShell();
}

function closeResourceEditor(push = true) {
  state.resourceForm = null;
  state.resourceEditorKey = '';
  if (push && window.history && window.history.pushState && window.location.pathname !== '/resources') {
    window.history.pushState({ view: 'resources' }, '', '/resources');
  }
  if (shell && shell.resourceEditor) clear(shell.resourceEditor);
  renderShell();
}

// renderResourceEditor keeps the page mounted while it is open: rebuilding it on
// every live update would wipe whatever is being typed.
function renderResourceEditor() {
  if (!shell || !shell.resourceEditor) return;
  if (!state.resourceForm) {
    shell.resourceEditor.hidden = true;
    if (state.resourceEditorKey !== '') {
      clear(shell.resourceEditor);
      state.resourceEditorKey = '';
    }
    shell.resourceList.hidden = false;
    return;
  }
  const isEdit = state.resourceForm.id !== null;
  const existing = isEdit ? findResource(state.resourceForm.id) : null;
  if (isEdit && !existing) {
    state.resourceForm = null;
    state.resourceEditorKey = '';
    if (window.history && window.history.replaceState) {
      window.history.replaceState({ view: 'resources' }, '', '/resources');
    }
    shell.resourceEditor.hidden = true;
    clear(shell.resourceEditor);
    shell.resourceList.hidden = false;
    toast('That resource no longer exists.', 'fail');
    return;
  }
  const key = isEdit ? 'edit:' + state.resourceForm.id : 'add';
  shell.resourceList.hidden = true;
  shell.resourceEditor.hidden = false;
  if (state.resourceEditorKey === key && shell.resourceEditor.firstChild) return;
  state.resourceEditorKey = key;
  shell.resourceEditor.replaceChildren(resourceEditorPage(existing));
}

// cardPicker renders selectable cards. The same control is used for the service
// type, the load balancing strategy and the PROXY protocol, instead of mixing
// cards and dropdowns.
function cardPicker(name, options, choice, onChange) {
  const grid = h('div', { class: 'type-grid' });
  options.forEach((option) => {
    const input = h('input', {
      type: 'radio', name, value: option.value,
      checked: choice.value === option.value ? true : null,
    });
    const card = h('label', { class: 'type-card' + (choice.value === option.value ? ' is-selected' : '') },
      input,
      option.icon ? option.icon() : null,
      h('span', { class: 'type-card-body' },
        h('strong', null, option.label),
        option.hint ? h('span', { class: 'muted tiny', text: option.hint }) : null));
    input.addEventListener('change', () => {
      if (!input.checked) return;
      choice.value = option.value;
      Array.from(grid.children).forEach((el) => el.classList.toggle('is-selected', el === card));
      if (onChange) onChange();
    });
    grid.append(card);
  });
  return grid;
}

function setCardValue(grid, value) {
  Array.from(grid.children).forEach((card) => {
    const input = card.querySelector('input');
    input.checked = input.value === value;
    card.classList.toggle('is-selected', input.value === value);
  });
}

function setCardEnabled(grid, enabled) {
  Array.from(grid.children).forEach((card) => {
    const input = card.querySelector('input');
    if (enabled) input.removeAttribute('disabled');
    else input.setAttribute('disabled', '');
    card.classList.toggle('is-disabled', !enabled);
  });
}

// targetRow is one editable backend of a resource.
function targetRow(agents, target, onRemove) {
  const selected = agents.find((agent) => target && agent.id === target.agentId) || agents[0];
  const row = h('div', { class: 'target-row' },
    h('label', { class: 'field' }, h('span', null, 'Agent'),
      h('select', { name: 'targetAgent' },
        agents.map((agent) => h('option', {
          value: String(agent.id),
          selected: selected && agent.id === selected.id ? true : null,
        }, agent.name + ' — ' + agent.address)))),
    h('label', { class: 'field' }, h('span', null, 'Address'),
      h('input', {
        name: 'targetHost', required: true, spellcheck: 'false',
        value: target && target.host ? target.host : (selected ? selected.address : ''),
        placeholder: '10.77.0.2 or 192.168.1.10',
      })),
    h('label', { class: 'field' }, h('span', null, 'Port'),
      h('input', {
        name: 'targetPort', type: 'number', min: '1', max: '65535', required: true,
        value: target && target.port ? String(target.port) : '', placeholder: '8123',
      })),
    h('button', { class: 'btn btn-sm btn-danger', type: 'button', onclick: () => onRemove(row) }, 'Remove'));
  return row;
}

// resourceEditorPage builds the publish form as a page.
function resourceEditorPage(existing) {
  const foreign = canAdmin() && !!state.resourceFilterEmail && !state.resourceFilterData?.own;
  const agents = canAdmin() && !foreign ? enrolledAgents().concat([{ id: 0, name: 'Control node', address: '127.0.0.1' }]) : enrolledAgents();
  const isEdit = !!existing;
  const domains = domainOptions();
  // Disabled exit nodes are not offered, except the one this resource already
  // uses, so editing never silently moves a resource somewhere else.
  const exitNodes = (state.data.exitNodes || []).filter((node) => {
    if (node.enabled) return true;
    return isEdit && (existing.exitNodeId || '') === (node.kind === 'control' ? '' : node.id);
  });
  const type = { value: isEdit ? existing.protocol : 'https' };
  const strategy = { value: isEdit ? existing.strategy || 'round-robin' : 'round-robin' };
  const proxyProtocol = { value: isEdit ? existing.proxyProtocol || '' : '' };

  // Declared first: the domain preview below reads it as the name is typed.
  const nameInput = h('input', {
    name: 'name', required: true, value: isEdit ? existing.name : '',
    placeholder: 'home assistant', autocomplete: 'off',
  });
  const nameField = h('label', { class: 'field' }, h('span', null, 'Name'), nameInput);

  const typeCards = cardPicker('protocol',
    Object.entries(PROTOCOL_INFO).map(([value, info]) => ({ value, label: info.label, hint: info.hint })),
    type, () => syncProtocol());
  const strategyCards = cardPicker('strategy',
    Object.entries(STRATEGY_INFO).map(([value, info]) => ({ value, label: info.label, hint: info.hint })),
    strategy);
  const strategyField = h('div', { class: 'field' }, h('span', null, 'Load balancing'), strategyCards);
  const proxyCards = cardPicker('proxyProtocol',
    Object.entries(PROXY_PROTOCOL_INFO).map(([value, info]) => ({ value, label: info.label, hint: info.hint })),
    proxyProtocol);

  const targetList = h('div', { class: 'targets' });
  const removeRow = (row) => {
    row.remove();
    if (!targetList.children.length) addTarget(null);
    syncStrategy();
  };
  function addTarget(target) {
    const selected = agents[0];
    targetList.append(targetRow(agents, target, removeRow));
    if (!target && selected) {
      // Fresh rows start on the first agent's own address.
      const last = targetList.lastElementChild;
      const hostInput = last.querySelector('[name=targetHost]');
      if (hostInput && !hostInput.value) hostInput.value = selected.address;
    }
  }
  if (isEdit && existing.targets && existing.targets.length) {
    existing.targets.forEach((target) => addTarget(targetFromView(target)));
  } else {
    addTarget(null);
  }
  // Targets live in their own box with the add button in its top right corner,
  // like every other panel.
  const targetsBox = h('div', { class: 'subpanel' },
    h('div', { class: 'panel-head' },
      h('div', null,
        h('h3', null, 'Targets'),
        h('p', { class: 'muted tiny', text: 'The services behind this resource. Add more than one to share traffic or to fail over.' })),
      h('button', { class: 'btn btn-sm', type: 'button', onclick: () => { addTarget(null); syncStrategy(); } }, 'Add target')),
    targetList);

  const listenInput = h('input', {
    name: 'listenPort', type: 'number', min: '1', max: '65535',
    value: isEdit ? String(existing.listenPort) : '', placeholder: '443',
  });
  const listenHint = h('div', { class: 'muted tiny' });
  const listenField = h('label', { class: 'field' }, h('span', null, 'Listening port'), listenInput);
  const quotaInput = h('input', { type: 'number', name: 'quotaGB', min: '1', step: '1', value: isEdit && existing.monthlyQuotaBytes ? String(existing.monthlyQuotaBytes / 1e9) : '100' });
  const requestInput = h('input', { type: 'number', name: 'monthlyRequests', min: '1', step: '1', value: isEdit && existing.monthlyRequestQuota ? String(existing.monthlyRequestQuota) : '3000000' });
  const sustainedInput = h('input', { type: 'number', name: 'sustainedMbps', min: '0.064', step: '0.001', value: isEdit && existing.sustainedBps ? String(existing.sustainedBps / 1e6) : '15' });
  const burstInput = h('input', { type: 'number', name: 'burstMbps', min: '0.064', step: '0.001', value: isEdit && existing.burstBps ? String(existing.burstBps / 1e6) : '30' });
  const peakInput = h('input', { type: 'number', name: 'peakMbps', min: '0.064', step: '0.001', value: isEdit && existing.peakBps ? String(existing.peakBps / 1e6) : '100' });
  const overInput = h('input', { type: 'number', name: 'overQuotaMbps', min: '0.064', step: '0.001', value: isEdit && existing.overQuotaBps ? String(existing.overQuotaBps / 1e6) : '0.512' });
  const quotaField = h('label', { class: 'field' }, h('span', null, 'Monthly bandwidth quota (GB)'), quotaInput);
  const requestField = h('label', { class: 'field' }, h('span', null, 'Monthly requests'), requestInput);
  const peakField = h('label', { class: 'field' }, h('span', null, 'Peak'), peakInput);
  const speedField = h('div', { class: 'field' }, h('span', null, 'Speed (Mbps)'),
    h('div', { class: 'limit-speed-grid' },
      h('label', { class: 'field' }, h('span', null, 'Sustained'), sustainedInput),
      h('label', { class: 'field' }, h('span', null, 'Burst'), burstInput),
      peakField,
      h('label', { class: 'field' }, h('span', null, 'After quota'), overInput)));
  const usageMetric = (label, used, limit, format) => h('div', { class: 'limit-usage-metric' },
    h('div', { class: 'limit-usage-label' },
      h('span', { text: label }),
      h('strong', { text: format(used) + ' / ' + (limit ? format(limit) : 'unlimited') })),
    h('div', { class: 'limit-usage-track' }, h('span', { style: 'width:' + (limit ? Math.min(100, used / limit * 100) : 0) + '%' })));
  const requestUsage = isEdit ? usageMetric('Requests', existing.monthlyUsedRequests || 0, existing.monthlyRequestQuota || 0, (n) => Number(n).toLocaleString()) : null;
  const usageBox = isEdit ? h('div', { class: 'subpanel limit-usage' },
    h('strong', null, 'This month'),
    usageMetric('Bandwidth', existing.monthlyUsedBytes || 0, existing.monthlyQuotaBytes || 0, fmtBytes),
    requestUsage) : null;
  const uncappedInput = h('input', { type: 'checkbox', name: 'uncapped', checked: canAdmin() && (!isEdit || existing.uncapped) ? true : null });
  const uncappedField = canAdmin() ? h('label', { class: 'switch' }, uncappedInput,
    h('span', null, h('strong', null, 'Uncapped'), h('em', null, 'No monthly quota, request quota, or speed limit. Usage is still recorded.')))
    : isEdit && existing.uncapped ? h('p', { class: 'muted', text: 'Uncapped by an administrator. Usage is still recorded.' }) : null;
  const limitsControls = h('div', { class: 'fields' },
    h('div', { class: 'limit-quota-grid' }, quotaField, requestField),
    speedField,
    h('p', { class: 'muted tiny', text: 'After the bandwidth quota, the resource stays available at the reduced speed. HTTP and HTTPS stop accepting new requests after their monthly request quota.' }));
  function syncUncapped() { limitsControls.hidden = canAdmin() ? uncappedInput.checked : isEdit && existing.uncapped; }
  uncappedInput.addEventListener('change', syncUncapped);
  syncUncapped();
  if (!canAdmin()) { [quotaInput, requestInput, sustainedInput, burstInput, peakInput, overInput].forEach((input) => { input.disabled = true; }); }
  let limitsProtocol = null;

  const exitNodeSelect = h('select', { name: 'exitNodeId' },
    exitNodes.map((node) => {
      const value = node.kind === 'control' ? '' : node.id;
      const selected = isEdit ? (existing.exitNodeId || '') === value : node.kind === 'control';
      return h('option', {
        value,
        selected: selected ? true : null,
        disabled: node.enabled ? null : true,
      }, node.name + (node.public ? ' — ' + node.public : '') + (node.enabled ? '' : ' (disabled)'));
    }));
  const exitNodeHint = h('div', { class: 'muted tiny', text: 'Extra public addresses are managed in the Exit nodes tab.' });
  if (!exitNodes.length) {
    exitNodeHint.textContent = 'No enabled exit node: enable one, or add an extra public address in the Exit nodes tab.';
  }

  const domainSelect = h('select', { name: 'domain' },
    domains.map((domain) => h('option', {
      value: domain.value,
      selected: isEdit
        ? (domain.kind === 'wildcard'
            ? String(existing.domain || '').endsWith('.' + domain.value)
            : existing.domain === domain.value)
        : domain.value === (domains[0] && domains[0].value),
    }, domain.value)));
  const domainNote = h('div', { class: 'muted tiny' });
  const domainField = h('label', { class: 'field' }, h('span', null, 'Domain'), domainSelect);
  // The subdomain is a separate choice from the resource name: the name is for
  // humans, this is the first label of the hostname.
  const subdomainInput = h('input', {
    name: 'subdomain', spellcheck: 'false', placeholder: 'app', autocomplete: 'off',
    value: isEdit ? subdomainPrefix(existing.domain, domains) : '',
  });
  const subdomainField = h('label', { class: 'field' },
    h('span', null, 'Subdomain'), subdomainInput);
  const domainRow = h('div', { class: 'grid-2 domain-row' }, subdomainField, domainField);
  let subdomainTouched = isEdit;
  // The publish preview: exactly what the resource will answer on.
  const domainPreview = h('div', { class: 'callout' });

  const existingSRV = isEdit ? existing.srv : null;
  const existingPreset = existingSRV
    ? (Object.entries(SRV_PRESETS).find(([key, preset]) => key !== 'custom' &&
        preset.service === existingSRV.service && preset.protocol === existingSRV.protocol) || ['custom'])[0]
    : 'minecraft';
  const srvToggle = h('input', { type: 'checkbox', name: 'createSrv', checked: existingSRV ? true : null });
  const srvPreset = h('select', { name: 'srvPreset' },
    Object.entries(SRV_PRESETS).filter(([value]) => canAdmin() || value !== 'custom').map(([value, preset]) => h('option', {
      value, selected: value === existingPreset ? true : null,
    }, preset.label)));
  const srvService = h('input', {
    name: 'srvService', spellcheck: 'false', placeholder: 'minecraft',
    value: existingSRV ? existingSRV.service : '',
  });
  const srvProtocol = h('select', { name: 'srvProtocol' },
    h('option', { value: 'tcp', selected: !existingSRV || existingSRV.protocol === 'tcp' ? true : null }, 'TCP'),
    h('option', { value: 'udp', selected: existingSRV && existingSRV.protocol === 'udp' ? true : null }, 'UDP'));
  const srvHint = h('div', { class: 'muted tiny' });
  const srvCustomFields = h('div', { class: 'grid-2' },
    h('label', { class: 'field' }, h('span', null, 'Custom service'), srvService),
    h('label', { class: 'field' }, h('span', null, 'Transport'), srvProtocol));
  const srvDetails = h('div', { class: 'fields' },
    h('label', { class: 'field' }, h('span', null, 'Application preset'), srvPreset),
    srvCustomFields);
  const srvField = h('div', { class: 'subpanel' },
    h('label', { class: 'switch' }, srvToggle,
      h('span', null, h('strong', null, 'Create SRV record'),
        h('em', null, 'Let compatible clients discover this service without typing its public port.'))),
    srvDetails,
    srvHint);
  // A name is optional for everything that is not routed by name, so the choice
  // to publish it on a port only is explicit rather than implied.
  const noNameOption = h('option', { value: '' }, '(no name - reachable on the port only)');
  // An empty choice means "no name", which a tcp or udp resource is allowed to
  // have: the port carries the traffic either way. Without that option the select
  // shows its first domain, which is what a resource routed by name wants.
  const selectedDomain = () => {
    if (domainSelect.value === '' && !protocolIsByDomain(type.value)) return null;
    const found = domains.find((d) => d.value === domainSelect.value);
    if (found) return found;
    return domains[0] || null;
  };
  const syncSRV = () => {
    const stream = type.value === 'tcp' || type.value === 'udp';
    for (const option of srvPreset.options) {
      const value = option.getAttribute('value') || option.value;
      const preset = SRV_PRESETS[value];
      option.hidden = option.disabled = value !== 'custom' && (!preset || preset.protocol !== type.value);
    }
    const selectedOption = Array.from(srvPreset.options).find((option) =>
      (option.getAttribute('value') || option.value) === srvPreset.value);
    if (!selectedOption || selectedOption.disabled) {
      const available = Array.from(srvPreset.options).find((option) => !option.disabled);
      if (available) srvPreset.value = available.getAttribute('value') || available.value;
    }
    const preset = SRV_PRESETS[srvPreset.value];
    srvCustomFields.hidden = !canAdmin() || srvPreset.value !== 'custom';
    if (preset && srvPreset.value !== 'custom') {
      srvService.value = preset.service;
      srvProtocol.value = preset.protocol;
    }
    const domain = selectedDomain();
    const automatic = !!domain && !!domain.srvAvailable;
    srvField.hidden = !stream || !domain;
    srvToggle.disabled = !stream || (!automatic && !srvToggle.checked);
    if (!stream || !domain) srvToggle.checked = false;
    srvDetails.hidden = !srvToggle.checked;
    if (!domain) srvHint.textContent = 'Choose a domain before creating an SRV record.';
    else if (!automatic) srvHint.textContent = 'Enable DNS automation for this domain before creating an SRV record.';
    else srvHint.textContent = 'Creates _' + (srvService.value || 'service') + '._' + srvProtocol.value + '.' + resolvedHostname() +
      ' pointing to ' + resolvedHostname() + ':' + listenPort() + '.';
  };
  srvToggle.addEventListener('change', syncSRV);
  srvPreset.addEventListener('change', syncSRV);
  [srvService, srvProtocol].forEach((input) => input.addEventListener('input', syncSRV));
  const syncDomainOptions = () => {
    const byDomain = protocolIsByDomain(type.value);
    const present = domainSelect.contains(noNameOption);
    if (byDomain) {
      if (present) noNameOption.remove();
      return;
    }
    if (!present) domainSelect.append(noNameOption);
    // A new tcp or udp resource starts without a name; editing one keeps whatever
    // it already has.
    if (!isEdit && domains.some((d) => d.value === domainSelect.value)) {
      domainSelect.value = '';
    }
  };
  // listenPort is what a tcp or udp resource answers on: the port field, or the
  // protocol's default when it is left empty.
  const listenPort = () => String(listenInput.value || listenInput.placeholder || '').trim();
  // The note under the domain field says what the name does for this protocol:
  // routing for http and https, a DNS record and a name to show for the rest.
  const syncDomainNote = () => {
    const protocol = type.value;
    const byDomain = protocolIsByDomain(protocol);
    domainNote.hidden = false;
    if (!domains.length) {
      domainNote.textContent = 'No domains configured yet. Add one in the Domains tab to reach this by name, ' +
        'or publish it on a port instead.';
    } else if (!byDomain && !domainSelect.value) {
      domainNote.textContent = 'No name: this ' + protocol.toUpperCase() + ' service is reachable on its port only. ' +
        'Give it a domain to create a DNS record for it as well.';
    } else if (protocol === 'https') {
      domainNote.textContent = 'The control node serves this on port 443 with a certificate for the domain' +
        ' (self-signed unless --acme-email is set), then proxies to your service over plain HTTP.';
    } else if (!byDomain) {
      domainNote.textContent = 'A name for this service: the domain gets a DNS record, and people reach it at ' +
        domainSelect.value + ':' + listenPort() + '. ' + protocol.toUpperCase() +
        ' has no name inside the stream, so the port is what carries it.';
    } else {
      domainNote.textContent = 'Requests are routed by the Host header.';
    }
  };
  const refreshPreview = () => {
    const domain = selectedDomain();
    // Each option shows the name the resource will actually get, so it follows
    // whatever is typed in the name field.
    if (!domain) {
      domainPreview.hidden = true;
      return;
    }
    domainPreview.hidden = domainField.hidden;
    const hostname = resolvedHostname();
    const scheme = type.value === 'https' ? 'https' : 'http';
    // Built as a list: replaceChildren(null) would put the literal text "null"
    // on the page for every domain that is not a wildcard.
    const lines = [
      h('strong', null, 'Will be published at'),
      h('span', { class: 'mono', text: type.value === 'http' || type.value === 'https'
        ? scheme + '://' + hostname
        // A name for a tcp or udp service is still reached on its port: there is
        // no host header or server name inside the stream to route by.
        : hostname + (listenPort() ? ':' + listenPort() : '') }),
    ];
    if (domain.kind === 'wildcard') {
      lines.push(h('span', { class: 'muted tiny', text: 'from the wildcard domain ' + domain.value +
        ' — rename the resource and this name follows.' }));
    }
    domainPreview.replaceChildren(...lines);
  };
  // resolvedHostname combines the chosen domain with the subdomain label.
  function resolvedHostname() {
    const domain = selectedDomain();
    if (!domain) return '';
    if (domain.kind === 'wildcard') {
      const label = slugify(subdomainInput.value) || slugify(nameInput.value) || 'resource';
      return label + '.' + domain.value;
    }
    return domain.value;
  }
  function syncSubdomainField() {
    const domain = selectedDomain();
    const wildcard = !!domain && domain.kind === 'wildcard';
    subdomainField.hidden = !wildcard;
    domainRow.classList.toggle('is-single', !wildcard);
    if (wildcard && !subdomainInput.value) subdomainInput.value = slugify(nameInput.value);
  }
  nameInput.addEventListener('input', () => {
    const domain = selectedDomain();
    // The subdomain follows the resource name until it is typed in by hand.
    if (!subdomainTouched && domain && domain.kind === 'wildcard') {
      subdomainInput.value = slugify(nameInput.value);
    }
    refreshPreview();
  });
  subdomainInput.addEventListener('input', () => {
    subdomainTouched = true;
    refreshPreview();
  });
  domainSelect.addEventListener('change', () => {
    syncSubdomainField();
    syncDomainNote();
    refreshPreview();
    syncSRV();
  });
  listenInput.addEventListener('input', () => {
    syncDomainNote();
    refreshPreview();
    syncSRV();
  });

  const proxyHint = h('div', { class: 'muted tiny' });
  // Security controls live on the final step.
  const ruleList = h('div', { class: 'rules' });
  const ruleFieldsForProtocol = () => type.value === 'http' || type.value === 'https'
    ? Object.keys(RULE_FIELDS) : ['country', 'ip'];
  const syncRuleFields = () => Array.from(ruleList.children).forEach((row) => row.syncFields(ruleFieldsForProtocol()));
  const addRule = (rule) => {
    const row = ruleRow(rule, (item) => item.remove());
    ruleList.append(row);
    row.syncFields(ruleFieldsForProtocol());
  };
  if (isEdit && existing.rules && existing.rules.length) existing.rules.forEach((rule) => addRule(rule));
  const rulesBox = h('div', { class: 'subpanel' },
    h('div', { class: 'panel-head' },
      h('div', null,
        h('h3', null, 'Access rules'),
        h('p', { class: 'muted tiny', text: 'Applied in order, first match wins. TCP and UDP support country and client IP rules.' })),
      h('button', { class: 'btn btn-sm', type: 'button', onclick: () => addRule(null) }, 'Add rule')),
    ruleList);
  const identityToggle = h('input', { type: 'checkbox', name: 'identity', checked: isEdit && existing.identity ? true : null });
  const identityMode = { value: isEdit && existing.identityMode === 'login' ? 'login' : 'basic' };
  const identityModeCards = cardPicker('identityMode', [
    { value: 'basic', label: 'HTTP Basic', hint: 'Use the browser\'s built-in username and password prompt.' },
    { value: 'login', label: 'Noobtunnel login', hint: 'Show a branded login page, then continue automatically to the resource.' },
  ], identityMode);
  const identityModeField = h('div', { class: 'field' }, h('span', null, 'Identity experience'), identityModeCards);
  const identityEmailsInput = h('textarea', { name: 'identityEmails', rows: '3', placeholder: 'you@example.com' });
  identityEmailsInput.value = isEdit ? (existing.identityEmails || []).join('\n') : '';
  const identityEmailsField = h('label', { class: 'field' }, h('span', null, 'Allowed account emails'), identityEmailsInput,
    h('span', { class: 'muted tiny' }, 'One verified account email per line. Your account is always allowed by identity control.'));
  const identityField = h('label', { class: 'switch' },
    identityToggle,
    h('span', null, h('strong', null, 'Identity controlled'),
      h('em', null, 'Require a control node account before a request is forwarded.')));
  const syncIdentity = () => { identityModeField.hidden = !identityToggle.checked; identityEmailsField.hidden = !identityToggle.checked; };
  identityToggle.addEventListener('change', syncIdentity);
  syncIdentity();
  const exploitField = h('label', { class: 'switch' },
    h('input', { type: 'checkbox', name: 'blockExploits', checked: isEdit && existing.blockExploits ? true : null }),
    h('span', null, h('strong', null, 'Block common exploits'),
      h('em', null, 'Reject high-confidence traversal, secret-file, SQL injection, script injection, Shellshock and Log4Shell probes. Does not inspect request bodies or replace a full WAF.')));
  const highRiskField = h('label', { class: 'switch' },
    h('input', { type: 'checkbox', name: 'blockHighRiskIps', checked: isEdit && existing.blockHighRiskIps ? true : null }),
    h('span', null, h('strong', null, 'Block high-risk IPs'),
      h('em', null, 'Reject clients with an abuse confidence score of 80 or higher.')));
  // WebSockets: on for every existing resource, and the switch is only shown for
  // the protocols that can carry an upgrade.
  const websocketField = h('label', { class: 'switch' },
    h('input', { type: 'checkbox', name: 'websockets', checked: !isEdit || existing.websockets ? true : null }),
    h('span', null, h('strong', null, 'WebSockets'),
      h('em', null, 'Let a browser upgrade the connection, for chat, live updates and terminals.')));
  const enabledField = h('label', { class: 'switch' },
    h('input', { type: 'checkbox', name: 'enabled', checked: !isEdit || existing.enabled ? true : null }),
    h('span', null, h('strong', null, 'Published'),
      h('em', null, 'Turn this off to keep the definition but stop listening.')));

  function syncStrategy() {
    // Balancing only means something with more than one target.
    const many = targetList.children.length > 1;
    strategyField.hidden = !many;
    if (!many) {
      strategy.value = 'round-robin';
      setCardValue(strategyCards, 'round-robin');
    }
  }

  function syncProxy() {
    const web = type.value === 'http' || type.value === 'https';
    identityField.hidden = !web;
    identityModeField.hidden = !web || !identityToggle.checked;
    identityEmailsField.hidden = !web || !identityToggle.checked;
    exploitField.hidden = !web;
    websocketField.hidden = !web;
    rulesBox.hidden = false;
    syncRuleFields();
    if (type.value === 'udp') {
      proxyProtocol.value = '';
      setCardValue(proxyCards, '');
      setCardEnabled(proxyCards, false);
      proxyHint.textContent = 'The PROXY protocol is a TCP extension, so UDP resources do not use it.';
      return;
    }
    setCardEnabled(proxyCards, true);
    proxyHint.textContent = type.value === 'http'
      ? 'Adds the header for services that expect it. With it off, HTTP backends still see the client in X-Forwarded-For.'
      : 'Tells the service the real client address, for software that trusts a reverse proxy.';
  }

  function syncProtocol() {
    const protocol = type.value;
    const defaults = { http: 80, https: 443, tcp: 0, udp: 0 };
    const fallback = defaults[protocol];
    listenInput.placeholder = !canAdmin() && (protocol === 'tcp' || protocol === 'udp') ? 'automatic' : fallback ? String(fallback) : 'required';
    listenHint.textContent = !canAdmin() && (protocol === 'tcp' || protocol === 'udp')
      ? (isEdit ? 'Public port ' + existing.listenPort + ' was assigned automatically.' : 'An unused public port is assigned automatically.')
      : fallback
      ? 'Leave empty for port ' + fallback + '. Several ' + protocol.toUpperCase() +
        ' resources can share it when each has its own domain.'
      : 'Required: ' + protocol.toUpperCase() + ' resources each need their own port.';
    syncDomainOptions();
    const byDomain = protocolIsByDomain(protocol);
    // HTTPS is always 443: the control node answers with its own certificate, so
    // there is no port for the operator to pick.
    const fixedPort = protocol === 'https';
    listenField.hidden = fixedPort || (!canAdmin() && (protocol === 'tcp' || protocol === 'udp'));
    const web = protocol === 'http' || protocol === 'https';
    requestField.hidden = !web;
    peakField.hidden = !web;
    if (requestUsage) requestUsage.hidden = !web;
    if (limitsProtocol !== protocol && (!isEdit || limitsProtocol !== null || !canAdmin() || existing.uncapped)) {
      const defaults = web ? ['100', '3000000', '15', '30', '100', '0.512'] :
        protocol === 'tcp' ? (canAdmin() ? ['10000', '0', '100', '1000', '0', '10'] : ['250', '0', '5', '30', '0', '1']) :
          (canAdmin() ? ['10000', '0', '100', '1000', '0', '10'] : ['100', '0', '3', '20', '0', '0.512']);
      [quotaInput, requestInput, sustainedInput, burstInput, peakInput, overInput].forEach((input, index) => { input.value = defaults[index]; });
    }
    limitsProtocol = protocol;
    // The hint belongs to the field: hiding one hides both, so no orphan label
    // is left behind.
    listenHint.hidden = fixedPort;
    if (fixedPort) listenInput.setAttribute('disabled', '');
    else listenInput.removeAttribute('disabled');
    // A domain is a name for any resource. For http and https it is also how the
    // control node routes requests; for tcp and udp there is no name inside the
    // stream, so it is the DNS record and the name to show, and the port still
    // carries the traffic.
    const usableDomain = domains.length > 0;
    domainField.hidden = !usableDomain;
    if (usableDomain) domainSelect.removeAttribute('disabled');
    else domainSelect.setAttribute('disabled', '');
    syncDomainNote();
    syncProxy();
    refreshPreview();
    syncSRV();
  }

  syncProtocol();
  syncStrategy();
  syncSubdomainField();
  refreshPreview();
  syncSRV();
  new MutationObserver(syncStrategy).observe(targetList, { childList: true });

  const error = h('div', { class: 'field-error', 'data-error': 'resource', hidden: true });

  // The form is split into steps: a name and type, then the targets, then how it
  // is published. Each step is a small page instead of one long wall of fields.
  const stepBodies = [
    h('div', { class: 'fields' },
      nameField,
      h('div', { class: 'field' }, h('span', null, 'Type'), typeCards)),
    h('div', { class: 'fields' },
      targetsBox,
      strategyField),
    h('div', { class: 'fields' },
      h('label', { class: 'field' }, h('span', null, 'Exit node'), exitNodeSelect, exitNodeHint),
      domainRow,
      listenField,
      h('div', { class: 'stack', style: 'gap:4px' }, listenHint, domainNote, domainPreview),
      srvField,
      h('div', { class: 'field' }, h('span', null, 'PROXY protocol'), proxyCards, proxyHint),
      enabledField),
    h('div', { class: 'fields' },
      usageBox,
      uncappedField,
      limitsControls),
    h('div', { class: 'fields' },
      identityField,
      identityModeField,
      identityEmailsField,
      exploitField,
      highRiskField,
      websocketField,
      rulesBox,
      error),
  ];
  const stepTitles = ['Service', 'Targets', 'Publishing', 'Limits', 'Security'];
  let step = 0;

  const stepPills = stepTitles.map((title, index) => h('button', {
    class: 'step-pill' + (index === 0 ? ' is-active' : ''),
    type: 'button',
    onclick: () => showStep(index),
  }, (index + 1) + '. ' + title));
  const stepPanels = stepBodies.map((body, index) => h('div', { class: 'form-step', hidden: index !== 0 }, body));
  const backButton = h('button', { class: 'btn', type: 'button', onclick: () => showStep(step - 1) }, 'Back');
  const nextButton = h('button', { class: 'btn btn-primary', type: 'button', onclick: nextStep }, 'Next');
  const saveButton = h('button', { class: 'btn btn-primary', type: 'submit' }, isEdit ? 'Save resource' : 'Publish service');

  function showStep(index) {
    step = Math.max(0, Math.min(stepTitles.length - 1, index));
    stepPanels.forEach((panel, i) => { panel.hidden = i !== step; });
    stepPills.forEach((pill, i) => pill.classList.toggle('is-active', i === step));
    backButton.hidden = step === 0;
    nextButton.hidden = step === stepTitles.length - 1;
    saveButton.hidden = step !== stepTitles.length - 1;
    error.hidden = true;
  }

  // nextStep validates just what the current step is about.
  function nextStep() {
    if (step === 1) {
      const rows = Array.from(targetList.children);
      if (!rows.length) {
        error.hidden = false;
        error.textContent = 'Add at least one target.';
        return;
      }
      for (const row of rows) {
        const host = row.querySelector('[name=targetHost]').value.trim();
        const port = row.querySelector('[name=targetPort]').value.trim();
        if (!host || !port) {
          error.hidden = false;
          error.textContent = 'Every target needs an address and a port.';
          return;
        }
      }
    }
    if (step === 0 && !nameInput.value.trim()) {
      error.hidden = false;
      error.textContent = 'Give the resource a name.';
      return;
    }
    showStep(step + 1);
  }

  // The step buttons live inside the card so each step reads as one page.
  const stepFoot = h('div', { class: 'panel-foot' },
    h('button', { class: 'btn', type: 'button', 'data-action': 'resource-cancel' }, 'Cancel'),
    backButton,
    nextButton,
    saveButton);

  const form = h('form', { class: 'form-page' },
    h('div', { class: 'panel-head' },
      h('div', null,
        h('h2', { text: isEdit ? 'Edit resource' : 'Publish a service' }),
        h('p', { class: 'muted', text: 'Traffic arrives on a public address of this control node and is forwarded through an agent.' })),
      h('button', { class: 'btn', type: 'button', 'data-action': 'resource-cancel' }, '← Back to resources')),
    h('div', { class: 'panel' },
      h('div', { class: 'steps-bar' }, stepPills),
      ...stepPanels,
      stepFoot));
  showStep(0);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const rows = Array.from(targetList.children);
    if (!rows.length) {
      error.hidden = false;
      error.textContent = 'Add at least one target.';
      return;
    }
    const targets = rows.map((row) => ({
      agentId: Number(row.querySelector('[name=targetAgent]').value),
      host: row.querySelector('[name=targetHost]').value.trim(),
      port: Number(row.querySelector('[name=targetPort]').value),
    }));
    const data = new FormData(form);
    const listenPort = String(data.get('listenPort') || '').trim();
    const body = {
      name: String(data.get('name') || ''),
      protocol: type.value,
      targets,
      strategy: strategy.value,
      exitNodeId: exitNodeSelect.value,
      listenPort: listenPort === '' ? 0 : Number(listenPort),
      domain: domainField.hidden ? '' : resolvedHostname(),
      srv: srvToggle.checked ? {
        service: srvService.value.trim().replace(/^_+/, ''),
        protocol: srvProtocol.value,
        priority: canAdmin() && existingSRV ? existingSRV.priority || 0 : 0,
        weight: canAdmin() && existingSRV ? existingSRV.weight || 0 : 0,
      } : null,
      proxyProtocol: type.value === 'udp' ? '' : proxyProtocol.value,
      rules: readRules(ruleList),
      identity: data.get('identity') !== null,
      identityMode: data.get('identity') !== null ? identityMode.value : '',
      identityEmails: data.get('identity') !== null ? identityEmailsInput.value.split(/[\n,]/).map((email) => email.trim()).filter(Boolean) : [],
      uncapped: canAdmin() && uncappedInput.checked,
      monthlyQuotaBytes: canAdmin() ? Math.round(Number(quotaInput.value) * 1e9) : 0,
      monthlyRequestQuota: canAdmin() && (type.value === 'http' || type.value === 'https') ? Math.round(Number(requestInput.value)) : 0,
      sustainedBps: canAdmin() ? Math.round(Number(sustainedInput.value) * 1e6) : 0,
      burstBps: canAdmin() ? Math.round(Number(burstInput.value) * 1e6) : 0,
      peakBps: canAdmin() && (type.value === 'http' || type.value === 'https') ? Math.round(Number(peakInput.value) * 1e6) : 0,
      overQuotaBps: canAdmin() ? Math.round(Number(overInput.value) * 1e6) : 0,
      blockExploits: data.get('blockExploits') !== null,
      blockHighRiskIps: data.get('blockHighRiskIps') !== null,
      websockets: data.get('websockets') !== null,
      enabled: data.get('enabled') !== null,
    };
    try {
      if (isEdit) await api('/api/resources/' + existing.id, { method: 'PATCH', body });
      else await api('/api/resources', { method: 'POST', body });
      state.resourceForm = null;
      state.resourceEditorKey = '';
      if (window.history && window.history.pushState && window.location.pathname !== '/resources') {
        window.history.pushState({ view: 'resources' }, '', '/resources');
      }
      await refresh();
      if (state.resourceFilterEmail) await filterResourcesByEmail(state.resourceFilterEmail);
      toast(isEdit ? 'Resource updated' : 'Service published', 'ok');
    } catch (err) {
      error.hidden = false;
      error.textContent = err.message;
      form.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
  return form;
}

// targetFromView turns a target from the API back into the shape the editor uses.
function targetFromView(target) {
  const parts = String(target.address || '').split(':');
  return { agentId: target.agentId, host: parts[0], port: Number(parts[1]) };
}

function findResource(id) {
  const resources = state.resourceFilterEmail && state.resourceFilterData?.matched
    ? state.resourceFilterData.resources : state.data.resources;
  return (resources || []).find((r) => r.id === Number(id)) || null;
}

// resourceBody rebuilds an API payload from a resource view.
function resourceBody(resource, overrides) {
  const body = {
    name: resource.name,
    protocol: resource.protocol,
    targets: (resource.targets || []).map((target) => ({
      agentId: target.agentId,
      host: String(target.address).split(':')[0],
      port: Number(String(target.address).split(':')[1]),
      enabled: target.enabled,
    })),
    strategy: resource.strategy || 'round-robin',
    exitNodeId: resource.exitNodeId || '',
    listenPort: resource.listenPort,
    domain: resource.domain || '',
    srv: resource.srv || null,
    proxyProtocol: resource.proxyProtocol || '',
    // Carried through every edit, so toggling a resource cannot silently change
    // what it forwards.
    identity: !!resource.identity,
    identityMode: resource.identityMode || 'basic',
    identityEmails: resource.identityEmails || [],
    monthlyQuotaBytes: resource.monthlyQuotaBytes || 0,
    monthlyRequestQuota: resource.monthlyRequestQuota || 0,
    sustainedBps: resource.sustainedBps || 0,
    burstBps: resource.burstBps || 0,
    peakBps: resource.peakBps || 0,
    overQuotaBps: resource.overQuotaBps || 0,
    blockExploits: !!resource.blockExploits,
    blockHighRiskIps: !!resource.blockHighRiskIps,
    websockets: resource.websockets !== false,
    rules: resource.rules || [],
    enabled: resource.enabled,
  };
  return Object.assign(body, overrides || {});
}

async function toggleResource(id, enabled) {
  const resource = findResource(id);
  if (!resource) return;
  try {
    await api('/api/resources/' + id, { method: 'PATCH', body: resourceBody(resource, { enabled }) });
    await refresh();
    toast(enabled ? 'Resource enabled' : 'Resource disabled', 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}

async function deleteResource(id, name) {
  confirmModal('Delete resource', 'Stop publishing ' + name + '? The services behind it keep running.',
    'Delete resource', async () => {
      try {
        await api('/api/resources/' + id, { method: 'DELETE' });
        await refresh();
        toast('Resource deleted', 'ok');
      } catch (err) {
        toast(err.message, 'fail');
      }
    });
}

/* ---------- domain modal ---------- */

// openDomainModal adds a domain, or edits an existing one. Editing is where the
// DNS mode is chosen: manual, or automatic through a provider.
function openDomainModal(hostname) {
  const existing = hostname ? (state.data.domains || []).find((d) => d.hostname === hostname) : null;
  const isEdit = !!existing;
  const mode = { value: isEdit && existing.providerId ? 'auto' : 'manual' };
  const providers = dnsProviders();

  const modeCards = cardPicker('dnsMode', [
    { value: 'manual', label: 'Manual DNS', hint: 'You create and update the A record yourself.' },
    { value: 'auto', label: 'Automation', hint: 'The control node keeps the record pointed at the right address.' },
  ], mode, () => syncMode());

  const hostInput = h('input', {
    name: 'hostname', required: true, spellcheck: 'false',
    value: isEdit ? existing.pattern || existing.hostname : '', placeholder: 'app.example.com or *.example.com',
  });
  if (isEdit) hostInput.setAttribute('readonly', '');
  const hostField = h('label', { class: 'field' },
    h('span', null, isEdit ? 'Domain' : 'Domain (use *.example.com for subdomains)'), hostInput);

  const providerSelect = h('select', { name: 'providerId' },
    providers.map((provider) => h('option', {
      value: provider.id,
      selected: isEdit && existing.providerId === provider.id ? true : null,
    }, provider.name + (provider.enabled ? '' : ' (disabled)'))));
  const providerField = h('label', { class: 'field' }, h('span', null, 'Provider'), providerSelect);
  const providerNote = h('div', { class: 'muted tiny' });
  const publicPoolInput = h('input', { type: 'checkbox', name: 'publicPool', checked: isEdit && existing.publicPool ? true : null });
  const publicPoolField = h('label', { class: 'switch' }, publicPoolInput,
    h('span', null, h('strong', null, 'Add to public pool'), h('em', null, 'Let regular accounts publish distinct hostnames under this wildcard.')));
  publicPoolField.hidden = !canAdmin() || !isEdit || existing.kind !== 'wildcard';

  function syncMode() {
    const auto = canAdmin() && mode.value === 'auto';
    providerField.hidden = !auto;
    if (!auto) {
      providerNote.hidden = true;
      return;
    }
    providerNote.hidden = false;
    providerNote.textContent = providers.length
      ? 'Records are updated automatically whenever a resource moves.'
      : 'No provider configured yet — add one with the Automation button.';
    providerSelect.disabled = providers.length === 0;
  }
  syncMode();

  const form = h('form', { class: 'stack' },
    h('div', { class: 'fields' },
      hostField,
      canAdmin() ? h('div', { class: 'field' }, h('span', null, 'DNS'), modeCards) : h('p', { class: 'muted tiny' }, 'Add a DNS TXT record to verify ownership before publishing on this domain.'),
      providerField,
      providerNote,
      canAdmin() && isEdit ? publicPoolField : null),
    h('div', { class: 'field-error', 'data-error': 'domain', hidden: true }),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'submit' }, isEdit ? 'Save domain' : 'Add domain')));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const providerID = mode.value === 'auto' ? providerSelect.value : '';
    try {
      if (isEdit) {
        if (canAdmin()) {
          await api('/api/domains/' + encodeURIComponent(existing.hostname), { method: 'PATCH', body: { providerId: providerID, publicPool: publicPoolInput.checked } });
        }
      } else {
        const created = await api('/api/domains', {
          method: 'POST',
          body: { hostname: String(new FormData(form).get('hostname') || '') },
        });
        if (providerID) await setDomainProvider(created.hostname, providerID);
      }
      closeModal();
      await refresh();
      toast(isEdit ? 'Domain updated' : (canAdmin() ? 'Domain added' : 'Domain added. Set the TXT record and verify ownership.'), 'ok');
    } catch (err) {
      const box = $('[data-error=domain]', form);
      box.hidden = false;
      box.textContent = err.message;
    }
  });
  modal(isEdit ? 'Edit domain' : 'Add domain',
    isEdit ? existing.hostname : 'A name that resources can be reached on', form);
}

async function verifyDomain(hostname) {
  try {
    await api('/api/domains/' + encodeURIComponent(hostname) + '/verify', { method: 'POST', body: {} });
    await refresh();
    toast('Domain ownership verified', 'ok');
  } catch (err) { toast(err.message, 'fail'); }
}

async function deleteDomain(hostname) {
  confirmModal('Delete domain', 'Remove ' + hostname + '? Domains still used by a resource cannot be deleted.',
    'Delete domain', async () => {
      try {
        await api('/api/domains/' + encodeURIComponent(hostname), { method: 'DELETE' });
        await refresh();
        toast('Domain removed', 'ok');
      } catch (err) {
        toast(err.message, 'fail');
      }
    });
}
// slugify turns a resource name into a DNS label.
function slugify(value) {
  const slug = String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-');
  return slug.slice(0, 40);
}

// domainOptions lists direct domains as-is and wildcard domains as suffixes.
function domainOptions() {
  const domains = state.resourceFilterEmail && state.resourceFilterData?.matched
    ? state.resourceFilterData.domains : state.data.domains;
  return (domains || []).filter((domain) => domain.verified || !domain.ownerId).map((domain) => ({
    value: domain.hostname,
    kind: domain.kind === 'wildcard' ? 'wildcard' : 'direct',
    pattern: domain.pattern || domain.hostname,
    srvAvailable: !!domain.srvAvailable,
  }));
}

// hostnameFor computes the name a resource will actually be published on.
// subdomainPrefix returns the label a stored hostname gets from a wildcard
// domain, so editing a resource shows the subdomain that was chosen.
function subdomainPrefix(hostname, domains) {
  const name = String(hostname || '');
  for (const domain of domains) {
    if (domain.kind === 'wildcard' && name.endsWith('.' + domain.value)) {
      return name.slice(0, name.length - domain.value.length - 1);
    }
  }
  return '';
}

function hostnameFor(domain, resourceName) {
  if (!domain) return '';
  if (domain.kind === 'wildcard') {
    const label = slugify(resourceName) || 'resource';
    return label + '.' + domain.value;
  }
  return domain.value;
}
