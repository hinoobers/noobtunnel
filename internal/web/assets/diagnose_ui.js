'use strict';
/* The "diagnose" action: what the control node can see about one target. */

// diagnoseTarget asks the control node to walk the path to one target: its own
// WireGuard device, the route and handshake to the agent hosting it, and a real
// connection attempt. It answers the question the Resources tab cannot: which
// side is broken.
async function diagnoseTarget(resourceID, targetID) {
  let result;
  try {
    result = await api('/api/diagnose', {
      method: 'POST',
      body: { resourceId: Number(resourceID), targetId: Number(targetID) },
    });
  } catch (err) {
    toast(err.message, 'fail');
    return;
  }
  const badge = (status) => status === 'ok'
    ? h('span', { class: 'chip chip-direct' }, 'ok')
    : status === 'warn'
      ? h('span', { class: 'chip chip-warn' }, 'check')
      : h('span', { class: 'chip chip-fail' }, 'failed');
  const body = h('div', { class: 'stack' },
    h('div', { class: result.verdictStatus === 'ok' ? 'callout ok' : 'callout' },
      h('strong', null, result.verdict),
      h('span', { class: 'muted tiny', text: result.resource + ' to ' + result.target })),
    h('table', null,
      h('thead', null, h('tr', null, h('th', null, 'Check'), h('th', null, 'Result'), h('th', null, 'Detail'))),
      h('tbody', null, (result.steps || []).map((step) => h('tr', null,
        h('td', null, step.name),
        h('td', null, badge(step.status)),
        h('td', null,
          h('div', { class: 'mono tiny', style: 'white-space:pre-wrap' }, step.detail),
          step.hint ? h('div', { class: 'muted tiny' }, step.hint) : null))))),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn btn-primary', 'data-action': 'modal-close' }, 'Close')));
  modal('Checking ' + result.target, 'Run from the control node, on the machine that publishes it', body);
}
