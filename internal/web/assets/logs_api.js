'use strict';
/* Logs tab: request analytics and the control node's activity feed. */

let requestSort = { key: 'time', direction: 'desc' };
const requestFilters = {
  host: new Set(), path: new Set(), client: new Set(), country: new Set(), resource: new Set(), decision: new Set(),
};
const requestSearch = { host: '', path: '', client: '', country: '', resource: '', decision: '' };
let requestLoadID = 0;

const requestColumns = [
  { key: 'time', label: 'Timestamp', sort: true },
  { key: 'durationMs', label: 'Took', sort: true, title: 'HTTP request duration; TCP, UDP and TLS passthrough connection setup time. Hover for details.' },
  { key: 'host', label: 'Host', sort: true, filter: true },
  { key: 'path', label: 'Path', sort: true, filter: true },
  { key: 'client', label: 'Client', sort: true, filter: true },
  { key: 'country', label: 'Country', sort: true, filter: true },
  { key: 'resource', label: 'Resource', sort: true, filter: true },
  { key: 'decision', label: 'Decision', sort: true, filter: true },
];

// requestData reads the aggregates the control node publishes.
function requestData() {
  const data = state.requestPageData || {};
  return {
    summary: data.summary || { total: 0, blocked: 0, allowed: 0, unknown: 0, countries: [], hosts: [] },
    recent: data.recent || [],
  };
}

function requestPageURL() {
  const params = new URLSearchParams({ page: String(state.requestPage) });
  if (requestSort.key !== 'time' || requestSort.direction !== 'desc') {
    params.set('sort', requestSort.key);
    params.set('dir', requestSort.direction);
  }
  for (const [field, values] of Object.entries(requestFilters)) {
    for (const value of values) params.append(field, value);
  }
  for (const [field, value] of Object.entries(requestSearch)) {
    if (value) params.set('search_' + field, value);
  }
  return '/activity/requests?' + params.toString();
}

function hasRequestFilters() {
  return requestSort.key !== 'time' || requestSort.direction !== 'desc' ||
    Object.values(requestFilters).some((values) => values.size > 0) ||
    Object.values(requestSearch).some((value) => value.trim() !== '');
}

function clearRequestFilters() {
  requestSort = { key: 'time', direction: 'desc' };
  for (const field of Object.keys(requestFilters)) requestFilters[field] = new Set();
  for (const field of Object.keys(requestSearch)) requestSearch[field] = '';
  state.requestPage = 1;
  window.history.pushState({ view: 'activity' }, '', requestPageURL());
  loadRequestPage();
}

// Fetch just the visible page. The control node applies sort and filters across
// the entire history before returning these rows.
async function loadRequestPage(silent = false) {
  if (!state.authenticated) return;
  const loadID = ++requestLoadID;
  state.requestPageLoading = true;
  if (!silent) {
    state.requestPageData = null;
    renderShell();
  }
  try {
    const params = new URLSearchParams(requestPageURL().split('?')[1]);
    params.set('limit', String(requestsPerPage));
    const result = await api('/api/requests?' + params.toString());
    if (loadID !== requestLoadID) return;
    const pages = Math.max(1, Math.ceil(result.total / requestsPerPage));
    if (state.requestPage > pages) {
      state.requestPage = pages;
      window.history.replaceState({ view: 'activity' }, '', requestPageURL());
      return loadRequestPage();
    }
    const changed = JSON.stringify(state.requestPageData) !== JSON.stringify(result);
    state.requestPageData = result;
    if (state.data && state.data.server && state.data.server.requests) {
      state.data.server.requests.summary = result.summary;
    }
    if (silent && changed && shell && state.view === 'activity' && state.logTab === 'requests') {
      renderRequests(shell.requestTable, result);
      renderRequestSubtitle();
    }
  } catch (err) {
    if (loadID === requestLoadID && !silent) toast('Could not load request page: ' + err.message, 'fail');
  } finally {
    if (loadID === requestLoadID) {
      state.requestPageLoading = false;
      if (!silent) renderShell();
    }
  }
}

function renderRequestSubtitle() {
  if (!shell || !shell.requestsSub) return;
  const summary = requestData().summary;
  shell.requestsSub.textContent = summary.total === 0
    ? 'Traffic through your published services'
    : summary.total + ' requests · ' + summary.allowed + ' allowed · ' + summary.blocked + ' blocked' +
      (summary.avgMs ? ' · ' + summary.avgMs + ' ms average inside the control node' : '');
}

// renderCharts keeps the overall split visible above the detailed bars.
function renderCharts(node, summary) {
  if (!node) return;
  clear(node);
  const total = Number(summary.total) || 0;
  node.append(pieChart('Decisions', [
    { label: 'Allowed', total: Number(summary.allowed) || 0 },
    { label: 'Blocked', total: Number(summary.blocked) || 0 },
  ], total, ['#34d399', '#fb7185']));
  node.append(pieChart('Countries', (summary.countries || []).map((row) => ({
    label: row.country === 'unknown' ? 'Unknown' : countryName(row.country), total: row.total,
  })), total));
  node.append(pieChart('Hostnames', (summary.hosts || []).map((row) => ({
    label: row.country || '(no host)', total: row.total,
  })), total));
  node.append(trafficChart('Requests by country', summary.countries || []));
  node.append(trafficChart('Requests by hostname', summary.hosts || []));
}

function pieChart(title, rows, total, colors = ['#818cf8', '#22d3ee', '#34d399', '#fbbf24', '#fb7185', '#a78bfa']) {
  const chart = h('div', { class: 'chart pie-chart' }, h('h3', null, title));
  if (!total) {
    chart.append(h('p', { class: 'muted tiny', text: 'No requests recorded yet.' }));
    return chart;
  }
  const slices = rows.filter((row) => Number(row.total) > 0).slice(0, 5);
  const shown = slices.reduce((sum, row) => sum + Number(row.total), 0);
  if (shown < total) slices.push({ label: 'Other', total: total - shown });
  const radius = 78;
  const circumference = 2 * Math.PI * radius;
  const centerCount = h('strong', { text: total.toLocaleString() });
  const centerLabel = h('span', { text: 'requests' });
  const resetCenter = () => {
    centerCount.textContent = total.toLocaleString();
    centerLabel.textContent = 'requests';
  };
  const ring = svg('svg', { class: 'pie-svg', viewBox: '0 0 200 200', role: 'img',
    'aria-label': title + ' request breakdown' });
  let offset = 0;
  slices.forEach((row, index) => {
    const count = Number(row.total);
    const length = count / total * circumference;
    const label = row.label + ': ' + count.toLocaleString() + ' requests';
    ring.append(svg('circle', {
      class: 'pie-slice', cx: 100, cy: 100, r: radius, fill: 'none',
      stroke: colors[index % colors.length], 'stroke-width': 36,
      'stroke-dasharray': length + ' ' + (circumference - length),
      'stroke-dashoffset': -offset, transform: 'rotate(-90 100 100)',
      tabindex: '0', 'aria-label': label,
      onpointerenter: () => { centerCount.textContent = count.toLocaleString(); centerLabel.textContent = row.label; },
      onpointerleave: resetCenter,
      onfocus: () => { centerCount.textContent = count.toLocaleString(); centerLabel.textContent = row.label; },
      onblur: resetCenter,
    }, svg('title', null, label)));
    offset += length;
  });
  const legend = h('div', { class: 'pie-legend' }, slices.map((row, index) =>
    h('div', { class: 'pie-legend-row', title: row.label + ': ' + row.total + ' requests' },
      h('i', { class: 'pie-key', style: 'background:' + colors[index % colors.length] }),
      h('span', { class: 'pie-label', text: row.label }),
      h('span', { class: 'pie-value', text: Math.round(Number(row.total) / total * 100) + '%' }))));
  chart.append(h('div', { class: 'pie-layout' },
    h('div', { class: 'pie-visual' }, ring,
      h('div', { class: 'pie-hole', 'aria-hidden': 'true' }, centerCount, centerLabel)), legend));
  return chart;
}

function trafficChart(title, rows) {
  const chart = h('div', { class: 'chart bar-chart' }, h('h3', null, title));
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

// requestsPerPage is how many retained rows the Requests tab shows at once.
const requestsPerPage = 30;
// renderRequests shows only the page returned by the control node.
function renderRequests(node, result) {
  if (!node) return;
  const signature = JSON.stringify([result, state.requestPage,
    result && result.page === state.requestPage ? false : state.requestPageLoading]);
  if (node._requestRenderSignature === signature) return;
  node._requestRenderSignature = signature;
  clear(node);
  if (!result || result.page !== state.requestPage) {
    node.append(h('div', { class: 'empty muted', text: state.requestPageLoading ? 'Loading requests…' : 'Request page unavailable.' }));
    return;
  }
  const recent = result.requests || [];
  const total = Number(result.total) || 0;
  if (!recent.length && total === 0) {
    node.append(h('div', { class: 'empty' },
      h('p', { class: 'muted', text: result.retained ? 'No requests match these filters.' : 'No requests yet. They appear here as soon as a published service is used.' })));
  } else {
    node.append(h('table', null,
      h('thead', null, h('tr', null, requestColumns.map((column) => requestHeader(column)))),
      h('tbody', null, recent.map((entry) => h('tr', { class: entry.allowed ? 'is-allowed' : 'is-blocked' },
        h('td', { class: 'mono tiny', title: relTime(entry.time) }, absTime(entry.time)),
        h('td', { class: 'mono tiny' }, fmtMs(entry.durationMs), timingBreakdown(entry)),
        h('td', { class: 'mono tiny' }, entry.host || '—'),
        h('td', { class: 'mono tiny', title: entry.status ? 'HTTP ' + entry.status : '' }, entry.path || ''),
        h('td', { class: 'mono tiny', title: entry.account ? 'signed in as ' + entry.account : '' }, entry.ip || '—'),
        h('td', null, countryCell(entry)),
        h('td', { class: 'muted tiny', title: entry.target ? 'sent to ' + entry.target : '' }, entry.resource || '—'),
        h('td', null, entry.allowed ? 'allowed' : h('div', null,
          h('div', null, 'blocked'),
          entry.reason ? h('div', { class: 'muted tiny', text: entry.reason }) : null)))))));
  }
  node.append(requestPager(total, (state.requestPage - 1) * requestsPerPage, recent.length));
}

function requestHeader(column) {
  const selected = requestFilters[column.key];
  const activeFilter = (selected && selected.size) || requestSearch[column.key];
  const direction = requestSort.key === column.key ? requestSort.direction : '';
  const title = [column.title || '', 'Click to sort' + (column.filter ? ' or filter' : '')].filter(Boolean).join(' ');
  return h('th', { title }, h('button', {
    class: 'table-header-button' + (activeFilter ? ' has-filter' : ''), type: 'button',
    'data-sort': direction, onclick: () => openRequestColumn(column),
  }, column.label));
}

function requestValue(entry, key) {
  switch (key) {
  case 'time': return new Date(entry.time || 0).getTime();
  case 'durationMs': return Number(entry.durationMs) || 0;
  case 'client': return entry.ip || '—';
  case 'country': return entry.country ? String(entry.country).toUpperCase() : 'unknown';
  case 'decision': return entry.allowed ? 'allowed' : 'blocked';
  default: return entry[key] || '—';
  }
}

function sortAndFilterRequests(recent) {
  return recent.filter((entry) => Object.keys(requestFilters).every((key) => {
    const selected = requestFilters[key];
    return !selected.size || selected.has(String(requestValue(entry, key)));
  })).slice().sort((left, right) => {
    const a = requestValue(left, requestSort.key);
    const b = requestValue(right, requestSort.key);
    const compared = typeof a === 'number' && typeof b === 'number'
      ? a - b : String(a).localeCompare(String(b), undefined, { sensitivity: 'base' });
    return requestSort.direction === 'asc' ? compared : -compared;
  });
}

function openRequestColumn(column) {
  const current = requestFilters[column.key] || new Set();
  const selected = new Set(current);
  const containsInput = column.filter && column.key !== 'country'
    ? h('input', { class: 'input', type: 'search', value: requestSearch[column.key] || '',
      placeholder: 'Contains text in any stored request',
      'aria-label': 'Filter all requests by ' + column.label }) : null;
  const choiceSearch = column.filter
    ? h('input', { class: 'input', type: 'search', placeholder: column.key === 'country' ? 'Search countries' : 'Find a value in all requests',
      'aria-label': 'Find ' + column.label + ' values' }) : null;
  const choices = column.filter ? h('div', { class: 'request-filter-list', text: 'Loading values…' }) : null;
  const body = h('div', { class: 'stack request-column-options' },
    h('div', { class: 'row' },
      h('button', { class: 'btn', type: 'button', onclick: () => applyRequestColumn(column.key, 'asc', selected, containsInput && containsInput.value) },
        column.key === 'time' ? 'Oldest first' : column.key === 'durationMs' ? 'Fastest first' : 'A to Z'),
      h('button', { class: 'btn', type: 'button', onclick: () => applyRequestColumn(column.key, 'desc', selected, containsInput && containsInput.value) },
        column.key === 'time' ? 'Newest first' : column.key === 'durationMs' ? 'Slowest first' : 'Z to A')),
    containsInput ? h('label', { class: 'field' }, h('span', null, 'Filter matching requests'), containsInput) : null,
    column.filter ? h('label', { class: 'field' }, h('span', null, column.key === 'country' ? 'Countries' : 'Choose exact values'), choiceSearch) : null,
    choices);
  const footer = column.filter ? h('div', { class: 'modal-foot' },
    h('button', { class: 'btn', type: 'button', onclick: () => applyRequestColumn(column.key, requestSort.direction, new Set(), '') }, 'Show all'),
    h('button', { class: 'btn btn-primary', type: 'button', onclick: () => applyRequestColumn(column.key, requestSort.direction, selected, containsInput && containsInput.value) }, 'Apply')) : null;
  modal(column.label, column.filter ? 'Sorting and filters use the complete request history.' : 'Sort the complete request history.', body, footer);
  if (!column.filter) return;

  let lookupID = 0;
  let countryValues = null;
  let timer = null;
  const showChoices = (values, more) => {
    clear(choices);
    if (!values.length) {
      choices.append(h('p', { class: 'muted tiny', text: 'No matching values.' }));
      return;
    }
    values.forEach(({ value, count }) => {
      const checkbox = h('input', { type: 'checkbox', checked: selected.has(value), onchange: (event) => {
        if (event.target.checked) selected.add(value); else selected.delete(value);
      } });
      choices.append(h('div', { class: 'row request-facet-row' },
        h('label', { class: 'switch' }, checkbox,
          h('span', null, h('strong', null, requestOptionLabel(column.key, value)),
            h('em', null, count + ' requests')))));
    });
    if (more) choices.append(h('p', { class: 'muted tiny', text: 'More values exist. Search to find them.' }));
  };
  const loadChoices = async () => {
    const id = ++lookupID;
    const query = choiceSearch.value.trim();
    if (column.key === 'country' && countryValues) {
      const visible = countryValues.filter(({ value }) =>
        (requestOptionLabel('country', value) + ' ' + value).toLowerCase().includes(query.toLowerCase()));
      showChoices(visible, false);
      return;
    }
    choices.textContent = 'Loading values…';
    try {
      const params = new URLSearchParams(requestPageURL().split('?')[1]);
      params.delete('page');
      params.delete('sort');
      params.delete('dir');
      params.delete(column.key);
      params.delete('search_' + column.key);
      params.set('facet', column.key);
      if (query && column.key !== 'country') params.set('q', query);
      const result = await api('/api/requests?' + params.toString());
      if (id !== lookupID || !choices.isConnected) return;
      if (column.key === 'country') {
        countryValues = result.values || [];
        const visible = countryValues.filter(({ value }) =>
          (requestOptionLabel('country', value) + ' ' + value).toLowerCase().includes(query.toLowerCase()));
        showChoices(visible, result.more);
      } else {
        showChoices(result.values || [], result.more);
      }
    } catch (err) {
      if (id === lookupID && choices.isConnected) choices.textContent = 'Could not load values: ' + err.message;
    }
  };
  choiceSearch.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(loadChoices, column.key === 'country' ? 0 : 250);
  });
  loadChoices();
}

function applyRequestColumn(key, direction, selected, search) {
  requestSort = { key, direction: direction === 'asc' ? 'asc' : 'desc' };
  if (requestFilters[key]) requestFilters[key] = new Set(selected);
  if (key in requestSearch) requestSearch[key] = String(search || '').trim();
  state.requestPage = 1;
  window.history.pushState({ view: 'activity' }, '', requestPageURL());
  closeModal();
  loadRequestPage();
}

function requestOptionLabel(key, value) {
  if (key === 'country') return value === 'unknown' ? 'Unknown' : countryName(value) + ' (' + value + ')';
  return value;
}

// setRequestPage updates the deep link before asking the control node for rows.
function setRequestPage(page) {
  if (!Number.isSafeInteger(page) || page < 1) return;
  state.requestPage = page;
  window.history.pushState({ view: 'activity' }, '', requestPageURL());
  loadRequestPage();
}

// timingBreakdown says where a slow request spent its time, under the total.
//
// Split the proxy total into connection setup, time until backend headers, and
// response transfer. This is still server-side elapsed time, not raw tunnel RTT.
function timingBreakdown(entry) {
  const total = entry.durationMs || 0;
  const dial = entry.dialMs || 0;
  if (!total) return null;
  if (['tcp', 'udp', 'https-passthrough'].includes(entry.protocol)) {
    const note = h('div', { class: 'muted tiny' }, entry.allowed ? 'setup' : 'policy');
    note.title = 'Connection setup ' + fmtMs(total) + ', policy ' + fmtMs(entry.policyMs) +
      ', connect ' + fmtMs(dial) + '. Excludes the connection lifetime and application response time.';
    return note;
  }
  const headers = entry.headerMs || total;
  const policy = entry.policyMs || (entry.allowed === false &&
    [401, 403, 429, 501].includes(entry.status) && !entry.target && !entry.headerMs && !dial ? total : 0);
  const queue = entry.queueMs || 0;
  // Older servers did not report the exact request-written -> first-byte span,
  // so retain their former estimate while a page is rolling through an update.
  const backend = entry.backendMs === undefined
    ? Math.max(0, headers - dial - policy - queue) : Math.max(0, entry.backendMs || 0);
  const transfer = Math.max(0, entry.transferMs || total - headers);
  const phases = [
    ['policy', policy],
    ['connect', dial],
    ['queue', queue],
    ['backend', backend],
    ['send', transfer],
  ];
  const dominant = phases.reduce((best, phase) => phase[1] > best[1] ? phase : best, phases[0]);
  const note = h('div', { class: 'muted tiny' },
    dominant[0] + ' ' + fmtMs(dominant[1]));
  note.title = 'policy (rules and any country lookup) ' + fmtMs(policy) + ', connect ' + fmtMs(dial) +
    (entry.reusedConn ? ' (reused connection)' : ' (new connection)') +
    ', queue/write ' + fmtMs(queue) + ', backend first byte ' + fmtMs(backend) +
    ', response transfer ' + fmtMs(transfer) + ' (proxy total ' + fmtMs(total) + ')';
  return note;
}

// countryCell says what is known about where a request came from, and why when
// nothing is: "unknown" with no reason is the least useful cell in the table.
function countryCell(entry) {
  if (entry.country) return h('span', { class: 'chip chip-quiet', title: countryName(entry.country) }, entry.country);
  const geo = (state.data && state.data.server && state.data.server.geoip) || {};
  const why = !geo.configured
    ? 'no IP API is configured (Settings -> IP API), so no country is known'
    : (geo.lastError
      ? 'the IP API is not answering: ' + geo.lastError
      : 'the IP API has no country for ' + (entry.ip || 'this address'));
  return h('span', { class: 'muted tiny', title: why }, 'unknown');
}

function countryName(code) {
  code = String(code || '').toUpperCase();
  if (!code) return 'Unknown';
  try {
    if (typeof Intl !== 'undefined' && Intl.DisplayNames) {
      return new Intl.DisplayNames([navigator.language || 'en'], { type: 'region' }).of(code) || code;
    }
  } catch (_) { /* Older browsers simply keep the country code. */ }
  return code;
}

// The URL carries the page number; the pager only needs a count and two arrows.
function requestPager(total, start, shown) {
  return h('div', { class: 'pager' },
    h('span', { class: 'muted tiny' },
      'Showing ' + (shown ? (start + 1) + '-' + (start + shown) : '0-0') + ' of ' + total),
    h('button', {
      class: 'btn btn-sm', type: 'button', 'data-action': 'requests-page',
      'data-page': String(state.requestPage - 1), disabled: state.requestPage <= 1,
      'aria-label': 'Previous page', title: 'Previous page',
    }, '←'),
    h('button', {
      class: 'btn btn-sm', type: 'button', 'data-action': 'requests-page',
      'data-page': String(state.requestPage + 1), disabled: state.requestPage * requestsPerPage >= total,
      'aria-label': 'Next page', title: 'Next page',
    }, '→'));
}

// showError is what an "error" chip in another view does: open Logs, select the
// Errors tab, and mark the entry the operator came for.
async function showError(match) {
  state.errorMatch = match || '';
  state.logTab = 'errors';
  setView('activity');
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
        ' \u00b7 active failures are rechecked every 30 seconds and clear after three clean checks';
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

// installTabs connects sidebar subtabs to their view panels.
function installTabs(root) {
  root.addEventListener('click', (event) => {
    const tab = event.target.closest('[data-tab]');
    if (!tab) return;
    const subnav = tab.closest('[data-subnav]');
    if (!subnav) return;
    const wanted = tab.dataset.tab;
    const group = subnav.dataset.subnav;
    if (group === 'activity') state.logTab = wanted;
    else state.settingsTab = wanted;
    const target = group === 'activity' && wanted === 'requests' ? requestPageURL() : '/' + group + '/' + wanted;
    window.history.pushState({ view: group }, '', target);
    state.sidebarOpen = false;
    renderShell();
    if (group === 'activity' && wanted === 'requests') loadRequestPage();
    if (group === 'settings' && wanted === 'smtp' && canAdmin()) loadSMTP();
    if (group === 'settings' && wanted === 'users' && canAdmin()) loadSignupSettings();
  });
}
