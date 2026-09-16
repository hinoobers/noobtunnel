'use strict';
/* Exit nodes: the public addresses resources can be published on. */

const EXIT_KIND_INFO = {
  address: {
    label: 'Extra address',
    hint: 'An address this host already has, for example a second public IP from your provider.',
  },
  gre: {
    label: 'GRE tunnel',
    hint: 'Carry a public IP from another machine here over a GRE tunnel.',
  },
};

function exitStatusChip(node) {
  switch (node.status) {
    case 'ready': return h('span', { class: 'chip chip-direct' }, 'ready');
    case 'not-configured': return h('span', { class: 'chip chip-warn' }, 'not configured');
    case 'disabled': return h('span', { class: 'chip chip-off' }, 'disabled');
    default: return h('span', { class: 'chip chip-quiet' }, node.status || 'unknown');
  }
}

function renderExitNodes(node, subNode, nodes) {
  if (!node) return;
  nodes = nodes || [];
  clear(node);
  if (shell && shell.exitNodesAdd) {
    // The list always has at least the built-in node, so there is no empty state
    // to hold the button: admins always get it in the header.
    shell.exitNodesAdd.hidden = !canAdmin();
  }
  if (subNode) {
    const ready = nodes.filter((n) => n.status === 'ready').length;
    subNode.textContent = nodes.length + ' configured · ' + ready + ' ready';
  }
  if (!nodes.length) {
    node.append(h('div', { class: 'empty' },
      h('p', { class: 'muted', text: 'No exit nodes.' }),
      canAdmin() ? h('button', { class: 'btn btn-primary', 'data-action': 'add-exitnode' }, 'Add exit node') : null));
    return;
  }
  node.append(h('table', null,
    h('thead', null, h('tr', null,
      h('th', null, 'Exit node'), h('th', null, 'Public address'), h('th', null, 'Status'),
      h('th', null, 'Published on it'), h('th', null, 'Actions'))),
    h('tbody', null, nodes.map((exitNode) => h('tr', null,
      h('td', null, h('div', { class: 'row' },
        h('span', { class: 'dot ' + (exitNode.status === 'ready' ? 'dot-on' : exitNode.status === 'disabled' ? 'dot-off' : 'dot-warn') }),
        h('span', null, exitNode.name),
        exitNode.kind === 'control' ? h('span', { class: 'chip chip-quiet', title: 'built in, always available' }, 'default') : null,
        exitNode.kind === 'gre' ? h('span', { class: 'chip chip-relay' }, 'GRE') : null)),
      h('td', null, h('div', { class: 'mono tiny', text: exitNode.public || '—' }),
        h('div', { class: 'muted tiny', text: exitNode.statusDetail || '' })),
      h('td', null, exitStatusChip(exitNode)),
      h('td', null, exitNode.resources && exitNode.resources.length
        ? exitNode.resources.map((name) => h('span', { class: 'chip chip-quiet' }, name))
        : h('span', { class: 'muted tiny' }, 'nothing yet')),
      h('td', null, canAdmin() ? h('div', { class: 'row', style: 'flex-wrap:wrap' },
        h('button', {
          class: 'btn btn-sm',
          'data-action': 'exitnode-toggle',
          'data-id': exitNode.id,
          'data-name': exitNode.name,
          'data-enabled': exitNode.enabled ? 'false' : 'true',
        }, exitNode.enabled ? 'Disable' : 'Enable'),
        exitNode.kind !== 'control' ? h('button', { class: 'btn btn-sm', 'data-action': 'exitnode-edit', 'data-id': exitNode.id }, 'Edit') : null,
        exitNode.kind !== 'control' && exitNode.status === 'not-configured'
          ? h('button', { class: 'btn btn-sm btn-primary', 'data-action': 'exitnode-apply', 'data-id': exitNode.id }, 'Set up here')
          : null,
        // Only nodes that actually need setup offer it; the control node has
        // nothing to configure.
        exitNode.kind !== 'control'
          ? h('button', { class: 'btn btn-sm', 'data-action': 'copy-exitnode-setup', 'data-id': exitNode.id }, 'Setup')
          : null,
        exitNode.deletable
          ? h('button', { class: 'btn btn-sm btn-danger', 'data-action': 'exitnode-delete', 'data-id': exitNode.id, 'data-name': exitNode.name }, 'Delete')
          : null) : h('span', { class: 'muted tiny' }, 'read only')))))));
}

// Adding an exit node is a small modal: only the address and, for a tunnel, the
// peer's public IP are asked for; everything else is derived.
function openExitNodeModal(id) {
  const existing = id ? findExitNode(String(id)) : null;
  const isEdit = !!existing;

  // An address the operator must supply is gre, otherwise it is an extra address.
  const choice = { value: isEdit ? (existing.kind === 'gre' ? 'gre' : 'address') : 'address' };
  const cards = cardPicker('exitKind', Object.entries(EXIT_KIND_INFO).map(([value, info]) => ({
    value, label: info.label, hint: info.hint,
  })), choice, () => sync());

  const nameInput = h('input', {
    name: 'name', required: true, value: isEdit ? existing.name : '',
    placeholder: 'second public ip', autocomplete: 'off',
  });
  const addressInput = h('input', {
    name: 'address', required: true, spellcheck: 'false',
    value: isEdit ? existing.address || '' : '', placeholder: '203.0.113.44',
  });
  const addressHint = h('div', { class: 'muted tiny' });
  const peerInput = h('input', {
    name: 'peerEndpoint', spellcheck: 'false',
    value: isEdit ? existing.peerEndpoint || '' : '', placeholder: '198.51.100.2',
  });
  const peerField = h('label', { class: 'field' },
    h('span', null, 'The other host\'s public IP'), peerInput,
    h('div', { class: 'muted tiny', text: 'The machine that owns this address and will route it over the tunnel.' }));

  function sync() {
    const isGRE = choice.value === 'gre';
    peerField.hidden = !isGRE;
    peerInput.required = isGRE;
    addressHint.textContent = isGRE
      ? 'The public IP that will be carried here over the tunnel and published by resources.'
      : 'An address this host already owns, for example a second public IP from your provider. ' +
        'If it is not configured yet you will get the commands to add it.';
  }
  sync();

  const error = h('div', { class: 'field-error', 'data-error': 'exitnode', hidden: true });
  const form = h('form', { class: 'stack' },
    h('div', { class: 'fields' },
      h('label', { class: 'field' }, h('span', null, 'Name'), nameInput),
      h('div', { class: 'field' }, h('span', null, 'How the address gets here'), cards),
      h('label', { class: 'field' }, h('span', null, 'Public address'), addressInput, addressHint),
      peerField,
      error),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'submit' }, isEdit ? 'Save exit node' : 'Add exit node')));

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const body = {
      name: String(data.get('name') || ''),
      kind: choice.value,
      address: String(data.get('address') || '').trim(),
    };
    if (choice.value === 'gre') {
      body.peerEndpoint = String(data.get('peerEndpoint') || '').trim();
    }
    try {
      if (isEdit) await api('/api/exitnodes/' + existing.id, { method: 'PATCH', body });
      else await api('/api/exitnodes', { method: 'POST', body });
      closeModal();
      await refresh();
      toast(isEdit ? 'Exit node updated' : 'Exit node added', 'ok');
    } catch (err) {
      error.hidden = false;
      error.textContent = err.message;
    }
  });
  modal(isEdit ? 'Edit exit node' : 'Add exit node',
    'An extra public address that resources can listen on', form);
}

function findExitNode(id) {
  return (state.data.exitNodes || []).find((n) => n.id === id) || null;
}

function showExitNodeSetup(exitNode) {
  const setup = exitNode.setup || {};
  const body = h('div', { class: 'stack' });
  if (setup.local && setup.local.length) {
    body.append(h('div', { class: 'cmd', text: setup.local.join('\n') }),
      h('div', { class: 'cmd-actions' }, copyButton(setup.local.join('\n'), 'Copy for this host')));
  }
  if (setup.remote && setup.remote.length) {
    body.append(h('strong', null, 'On the other host'),
      h('div', { class: 'cmd', text: setup.remote.join('\n') }),
      h('div', { class: 'cmd-actions' }, copyButton(setup.remote.join('\n'), 'Copy for the other host')));
  }
  if (setup.notes) body.append(h('p', { class: 'muted tiny', text: setup.notes }));
  modal('Setup: ' + exitNode.name, exitNode.public, body);
}

async function applyExitNode(id) {
  try {
    const result = await api('/api/exitnodes/' + id + '/apply', { method: 'POST', body: {} });
    await refresh();
    modal('Setup output', 'Commands run on this host', h('div', { class: 'stack' },
      h('div', { class: 'cmd', text: result.output || '(no output)' }),
      result.ok
        ? h('div', { class: 'callout ok' }, h('strong', null, 'Address configured'))
        : h('div', { class: 'callout warn' }, h('strong', null, result.error || 'Setup incomplete'))));
    toast(result.ok ? 'Exit node configured' : 'Setup incomplete', result.ok ? 'ok' : 'fail');
  } catch (err) {
    toast(err.message, 'fail');
  }
}

async function deleteExitNode(id, name) {
  confirmModal('Delete exit node', 'Remove ' + name + '? Exit nodes that resources are published on cannot be deleted.',
    'Delete exit node', async () => {
      try {
        await api('/api/exitnodes/' + id, { method: 'DELETE' });
        await refresh();
        toast('Exit node removed', 'ok');
      } catch (err) {
        toast(err.message, 'fail');
      }
    });
}

// toggleExitNode enables or disables an exit node. Disabling the control node
// means resources may only live on additional exit nodes.
async function toggleExitNode(id, name, enabled) {
  try {
    await api('/api/exitnodes/' + id, { method: 'PATCH', body: { name, enabled } });
    await refresh();
    toast(enabled ? name + ' enabled' : name + ' disabled', 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}
