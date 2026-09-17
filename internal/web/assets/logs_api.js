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
      // The stylesheet clips a long label, so pass the whole name through: the
      // row's title carries the numbers and the span its name.
      h('span', { class: 'code', title: label, text: label }),
      h('div', { class: 'bar-track' },
        h('div', {
          class: 'bar-fill' + (row.blocked === row.total ? ' is-blocked' : ''),
          style: 'width:' + Math.max(4, Math.round((row.total / peak) * 100)) + '%',
        })),
      h('span', { class: 'value', text: String(row.total) + (blockedShare ? ' · ' + blockedShare + '% blocked' : '') })));
  });
  return chart;
}

// fmtMs renders a request duration: the difference between a slow tunnel and a
// slow service is visible at a glance.
function fmtMs(value) {
  const ms = Number(value) || 0;
  if (ms <= 0) return '—';
  if (ms < 1000) return ms + ' ms';
  return (ms / 1000).toFixed(ms < 10000 ? 1 : 0) + ' s';
}

// requestsPerPage is how many rows the Requests tab shows at once: the control
// node keeps the last few hundred, far more than anyone reads in one go.
const requestsPerPage = 30;
// requestPage is which page of the request list is on screen.
let requestPage = 1;

// renderRequests lists individual requests and their decision, one page at a time.
function renderRequests(node, recent) {
  if (!node) return;
  recent = recent || [];
  clear(node);
  if (!recent.length) {
    requestPage = 1;
    node.append(h('div', { class: 'empty' },
      h('p', { class: 'muted', text: 'No requests yet. They appear here as soon as a published service is used.' })));
    return;
  }
  const pages = Math.max(1, Math.ceil(recent.length / requestsPerPage));
  if (requestPage > pages) requestPage = pages;
  if (requestPage < 1) requestPage = 1;
  const start = (requestPage - 1) * requestsPerPage;
  const page = recent.slice(start, start + requestsPerPage);
  node.append(h('table', null,
    h('thead', null, h('tr', null,
      h('th', null, 'Timestamp'), h('th', null, 'Took'), h('th', null, 'Host'), h('th', null, 'Client'),
      h('th', null, 'Country'), h('th', null, 'Resource'), h('th', null, 'Decision'))),
    h('tbody', null, page.map((entry) => h('tr', { class: entry.allowed ? 'is-allowed' : 'is-blocked' },
      // The exact time, with the relative one on hover: a log is read by
      // timestamps, and "2m ago" is unhelpful once a row is a few hours old.
      h('td', { class: 'mono tiny', title: relTime(entry.time) }, absTime(entry.time)),
      h('td', { class: 'mono tiny' }, fmtMs(entry.durationMs), timingBreakdown(entry)),
      h('td', { class: 'mono tiny' }, entry.host || '—'),
      h('td', { class: 'mono tiny', title: entry.account ? 'signed in as ' + entry.account : '' }, entry.ip || '—'),
      h('td', null, countryCell(entry)),
      h('td', { class: 'muted tiny', title: entry.target ? 'sent to ' + entry.target : '' }, entry.resource || '—'),
      h('td', { title: entry.allowed ? '' : entry.reason || '' }, entry.allowed ? 'allowed' : 'blocked'))))));
  if (pages > 1) node.append(requestPager(recent.length, pages, start, page.length));
}

// setRequestPage walks the request list without asking the control node for
// anything: the rows are already in the page.
function setRequestPage(page) {
  if (!Number.isFinite(page) || page < 1) return;
  requestPage = page;
  renderShell();
}

// timingBreakdown says where a slow request spent its time, under the total.
//
// "Took" alone cannot tell a slow tunnel from a slow service: connecting through
// the mesh and waiting for the answer are both inside it. Connecting is measured
// separately, so the difference between the two is the service's own time.
function timingBreakdown(entry) {
  const total = entry.durationMs || 0;
  const dial = entry.dialMs || 0;
  if (!total) return null;
  // Only worth a line when the path is a real part of the total: a reused
  // connection has no dial time at all.
  if (!dial || dial < 5 || total < 100) return null;
  const service = Math.max(0, total - dial);
  const note = h('div', { class: 'muted tiny' },
    dial > service ? 'connect ' + fmtMs(dial) : 'service ' + fmtMs(service));
  note.title = 'connect ' + fmtMs(dial) + ', service ' + fmtMs(service) + ' (total ' + fmtMs(total) + ')';
  return note;
}

// countryCell says what is known about where a request came from, and why when
// nothing is: "unknown" with no reason is the least useful cell in the table.
function countryCell(entry) {
  if (entry.country) return h('span', { class: 'chip chip-quiet' }, entry.country);
  const geo = (state.data && state.data.server && state.data.server.geoip) || {};
  const why = !geo.configured
    ? 'no IP API is configured (Settings -> IP API), so no country is known'
    : (geo.lastError
      ? 'the IP API is not answering: ' + geo.lastError
      : 'the IP API has no country for ' + (entry.ip || 'this address'));
  return h('span', { class: 'muted tiny', title: why }, 'unknown');
}

// requestPager walks the list: newest first, thirty at a time.
function requestPager(total, pages, start, shown) {
  return h('div', { class: 'pager' },
    h('span', { class: 'muted tiny' },
      'Showing ' + (start + 1) + '-' + (start + shown) + ' of ' + total + ', newest first'),
    h('button', {
      class: 'btn btn-sm', type: 'button', 'data-action': 'requests-page',
      'data-page': String(requestPage - 1), disabled: requestPage <= 1,
    }, 'Previous'),
    h('span', { class: 'muted tiny' }, 'Page ' + requestPage + ' of ' + pages),
    h('button', {
      class: 'btn btn-sm', type: 'button', 'data-action': 'requests-page',
      'data-page': String(requestPage + 1), disabled: requestPage >= pages,
    }, 'Next'));
}

// showError is what an "error" chip in another view does: open Logs, select the
// Errors tab, and mark the entry the operator came for.
async function showError(match) {
  state.errorMatch = match || '';
  setView('logs');
  const tab = shell && shell.root ? $('[data-view-panel=logs] [data-tab=errors]', shell.root) : null;
  if (tab) tab.click();
  renderShell();
  await refresh();
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
    h('tbody', null, entries.map((entry) => h('tr', {
      // Something on another tab sends the operator here with a match: the entry
      // it belongs to is highlighted and scrolled to, so "error" in a table is one
      // click from the reason instead of a hunt through the log.
      class: errorMatches(entry, state.errorMatch) ? 'row-highlight' : null,
    },
      h('td', { title: absTime(entry.time) }, relTime(entry.time)),
      h('td', null, h('span', { class: 'chip chip-quiet' }, entry.source || 'control')),
      h('td', null,
        h('div', null, entry.message || ''),
        entry.detail ? h('div', { class: 'muted tiny mono', style: 'white-space:pre-wrap' }, entry.detail) : null),
      h('td', { class: 'muted tiny' }, entry.hint || '\u2014'))))));
  if (state.errorMatch) highlightFirstMatch(node);
}

// errorMatches reports whether an entry is the one a resource sent the operator to
// see. The match is the resource name or the target address, both of which appear
// in the message or the detail.
function errorMatches(entry, match) {
  if (!match) return false;
  const text = [entry.message, entry.detail].join(' ');
  return text.indexOf(match) !== -1;
}

// highlightFirstMatch scrolls the highlighted row into view once it is in the page.
function highlightFirstMatch(node) {
  const row = node.querySelector('tr.row-highlight');
  if (row && typeof row.scrollIntoView === 'function') row.scrollIntoView({ block: 'center' });
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
