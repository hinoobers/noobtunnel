'use strict';
/* Logs tab: request analytics and the control node's activity feed. */

let logView = 'requests';

// requestData reads the aggregates the control node publishes.
function requestData() {
  const data = (state.data.server && state.data.server.requests) || {};
  return {
    summary: data.summary || { total: 0, blocked: 0, allowed: 0, unknown: 0, countries: [], hosts: [] },
    recent: data.recent || [],
  };
}

// renderCharts draws the "where is the traffic coming from" bars.
function renderCharts(node, summary) {
  if (!node) return;
  clear(node);
  node.append(trafficChart('Requests by country', summary.countries || []));
  node.append(trafficChart('Requests by hostname', summary.hosts || []));
}

function trafficChart(title, rows) {
  const chart = h('div', { class: 'chart' }, h('h3', null, title));
  if (!rows.length) {
    chart.append(h('p', { class: 'muted tiny', text: 'No requests recorded yet.' }));
    return chart;
  }
  const peak = rows.reduce((max, row) => Math.max(max, row.total), 1);
  rows.forEach((row) => {
    const label = String(row.country || '');
    const blockedShare = row.total ? Math.round((row.blocked / row.total) * 100) : 0;
    chart.append(h('div', {
      class: 'bar-row',
      title: row.total + ' requests, ' + row.blocked + ' blocked',
    },
      h('span', { class: 'code', text: label.length > 10 ? label.slice(0, 10) + '…' : label }),
      h('div', { class: 'bar-track' },
        h('div', {
          class: 'bar-fill' + (row.blocked === row.total ? ' is-blocked' : ''),
          style: 'width:' + Math.max(4, Math.round((row.total / peak) * 100)) + '%',
        })),
      h('span', { class: 'value', text: String(row.total) + (blockedShare ? ' · ' + blockedShare + '% blocked' : '') })));
  });
  return chart;
}

// renderRequests lists individual requests and their decision.
function renderRequests(node, recent) {
  if (!node) return;
  recent = recent || [];
  clear(node);
  if (!recent.length) {
    node.append(h('div', { class: 'empty' },
      h('p', { class: 'muted', text: 'No requests yet. They appear here as soon as a published service is used.' })));
    return;
  }
  node.append(h('table', null,
    h('thead', null, h('tr', null,
      h('th', null, 'Time'), h('th', null, 'Host'), h('th', null, 'Client'), h('th', null, 'Country'),
      h('th', null, 'Decision'), h('th', null, 'Resource'))),
    h('tbody', null, recent.map((entry) => h('tr', null,
      h('td', { title: absTime(entry.time) }, relTime(entry.time)),
      h('td', { class: 'mono tiny' }, entry.host || '—'),
      h('td', { class: 'mono tiny', title: entry.account ? 'signed in as ' + entry.account : '' }, entry.ip || '—'),
      h('td', null, entry.country
        ? h('span', { class: 'chip chip-quiet' }, entry.country)
        : h('span', { class: 'muted tiny' }, 'unknown')),
      h('td', null, entry.allowed
        ? h('span', { class: 'chip chip-direct' }, 'allowed')
        : h('span', { class: 'chip chip-fail', title: entry.reason || '' }, 'blocked')),
      h('td', { class: 'muted tiny' }, entry.resource || '—'))))));
}

// renderErrors lists everything that went wrong: DNS automation, certificate
// issuance and resources that could not listen. This is the "why is it not
// working" view, so each row carries the detail and the fix when there is one.
function renderErrors(node, subNode, entries) {
  if (!node) return;
  entries = entries || [];
  clear(node);
  // The tab carries the count, so a failure is visible without opening it.
  if (shell && shell.root) {
    const tab = $('[data-tab=errors]', shell.root);
    if (tab) tab.textContent = entries.length ? 'Errors (' + entries.length + ')' : 'Errors';
  }
  if (subNode) {
    subNode.textContent = entries.length === 0
      ? 'Nothing has failed since the control node started'
      : entries.length + ' error' + (entries.length === 1 ? '' : 's') +
        ', newest first \u00b7 ' + relTime(entries[0].time) +
        ' \u00b7 history: an entry stays until you clear it, the dashboard shows what is true now';
  }
  if (!entries.length) {
    node.append(h('div', { class: 'empty' },
      h('h3', null, 'No errors'),
      h('p', { class: 'muted', text: 'Certificate, DNS and listener failures appear here with the reason and what to check.' })));
    return;
  }
  node.append(h('table', null,
    h('thead', null, h('tr', null,
      h('th', null, 'Time'), h('th', null, 'Source'), h('th', null, 'Error'), h('th', null, 'What to check'))),
    h('tbody', null, entries.map((entry) => h('tr', null,
      h('td', { title: absTime(entry.time) }, relTime(entry.time)),
      h('td', null, h('span', { class: 'chip chip-quiet' }, entry.source || 'control')),
      h('td', null,
        h('div', null, entry.message || ''),
        entry.detail ? h('div', { class: 'muted tiny mono', style: 'white-space:pre-wrap' }, entry.detail) : null),
      h('td', { class: 'muted tiny' }, entry.hint || '\u2014'))))));
}

// clearErrors empties the error list; the control node keeps recording new ones.
async function clearErrors() {
  try {
    await api('/api/errors', { method: 'DELETE' });
    await refresh();
    toast('Error log cleared', 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}

// installTabs wires every tab group. The group is whatever view the clicked tab
// lives in, so one handler serves the main navigation, Logs and Settings.
function installTabs(root) {
  root.addEventListener('click', (event) => {
    const tab = event.target.closest('[data-tab]');
    if (!tab) return;
    const scope = tab.closest('[data-view-panel]') || root;
    const wanted = tab.dataset.tab;
    Array.from(scope.querySelectorAll('[data-tab]')).forEach((el) => {
      el.classList.toggle('is-active', el.dataset.tab === wanted);
    });
    Array.from(scope.querySelectorAll('[data-tab-panel]')).forEach((el) => {
      el.hidden = el.dataset.tabPanel !== wanted;
    });
  });
}
