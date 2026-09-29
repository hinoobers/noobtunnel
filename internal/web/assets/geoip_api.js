'use strict';
/* The IP API that answers country lookups for country rules on resources. */

// renderGeoIP shows the state of the country lookup.
function renderGeoIP() {
  if (!shell || !shell.geoipForm) return;
  const geo = (state.data.server && state.data.server.geoip) || {};
  const chip = shell.geoipStatus;
  if (!chip) return;
  const lookups = geo.lookups || 0;
  if (!shell.geoipForm.dataset.providerSelection) shell.geoipForm.dataset.providerSelection = geo.provider || 'self';
  renderGeoIPProvider();
  if (geo.ready) {
    chip.className = 'chip chip-direct';
    chip.textContent = lookups + ' lookup' + (lookups === 1 ? '' : 's') + ' answered';
  } else if (geo.configured) {
    chip.className = 'chip chip-warn';
    chip.textContent = 'set, no answer yet';
  } else {
    chip.className = 'chip chip-off';
    chip.textContent = 'not configured';
  }
  if (shell.geoipDetail) {
    const parts = [];
    if (geo.configured) parts.push((geo.provider === 'ipapi' ? 'Public ipapi.is' : 'Host ' + geo.host) + (geo.hasToken ? ' with a token' : ' without a token'));
    if (geo.configured && (geo.provider !== 'ipapi' || geo.fallbackHost)) {
      const selectedAgent = (state.data.agents || []).find((agent) => agent.id === geo.agentId);
      parts.push((geo.provider === 'ipapi' ? 'iplog fallback ' + geo.fallbackHost + ' via ' : 'via ') +
        (selectedAgent ? selectedAgent.name : geo.agentId ? 'missing agent #' + geo.agentId : 'control node'));
    }
    if (geo.fallbackLookups) parts.push(geo.fallbackLookups + ' fallback lookup' + (geo.fallbackLookups === 1 ? '' : 's'));
    if (geo.lastFallbackReason) parts.push('last fallback: ' + geo.lastFallbackReason);
    if (geo.lastAt) parts.push('last answer ' + relTime(geo.lastAt));
    if (geo.configured) parts.push('average response ' + (geo.avgResponseMs ? Math.round(geo.avgResponseMs) + ' ms' : 'not measured yet'));
    parts.push((geo.cached || 0) + ' address' + (geo.cached === 1 ? '' : 'es') + ' cached');
    if (geo.lastError) parts.push('last error: ' + geo.lastError);
    if (!geo.configured) parts.push('Resources with country rules deny requests until an API is configured.');
    shell.geoipDetail.textContent = parts.join(' \u00b7 ');
  }
  const host = shell.geoipForm.querySelector('input[name=host]');
  if (host && document.activeElement !== host && geo.host && geo.host !== 'https://api.ipapi.is') host.value = geo.host;
  const agentSelect = shell.geoipForm.querySelector('select[name=agentId]');
  if (agentSelect) {
    const agents = (state.data.agents || []).filter((agent) => agent.publicKey && agent.enabled);
    const signature = JSON.stringify([geo.agentId || 0, agents.map((agent) => [agent.id, agent.name])]);
    if (agentSelect.dataset.optionsKey !== signature) {
      const chosen = document.activeElement === agentSelect ? agentSelect.value : String(geo.agentId || 0);
      const option = (label, value) => {
        const node = document.createElement('option');
        node.textContent = label;
        node.value = value;
        return node;
      };
      const options = [option('Control node (direct connection)', '0')];
      agents.forEach((agent) => options.push(option(agent.name + ' (' + agent.address + ')', String(agent.id))));
      if (geo.agentId && !agents.some((agent) => agent.id === geo.agentId)) {
        options.push(option('Missing or disabled agent #' + geo.agentId, String(geo.agentId)));
      }
      agentSelect.replaceChildren(...options);
      agentSelect.value = chosen;
      agentSelect.dataset.optionsKey = signature;
    } else if (document.activeElement !== agentSelect) {
      agentSelect.value = String(geo.agentId || 0);
    }
  }
}

function renderGeoIPProvider() {
  const form = shell.geoipForm;
  const provider = form.dataset.providerSelection || 'self';
  const radio = form.querySelector('input[name=provider][value=' + provider + ']');
  if (radio) radio.checked = true;
  const selfFields = form.querySelector('[data-geoip-self]');
  if (selfFields) selfFields.hidden = provider !== 'self';
  const publicToken = form.querySelector('[data-geoip-public-token]');
  if (publicToken) publicToken.hidden = provider !== 'ipapi';
  const fallback = form.querySelector('[data-geoip-fallback]');
  const fallbackInput = form.querySelector('input[name=fallbackEnabled]');
  const configured = !!((state.data.server || {}).geoip || {}).iplogConfigured;
  if (fallback) fallback.hidden = provider !== 'ipapi';
  if (fallbackInput) {
    if (form.dataset.fallbackSelection === undefined) {
      form.dataset.fallbackSelection = String(!!((state.data.server || {}).geoip || {}).fallbackEnabled);
    }
    fallbackInput.disabled = !configured;
    fallbackInput.checked = configured && form.dataset.fallbackSelection === 'true';
  }
  const fallbackNote = form.querySelector('[data-geoip-fallback-note]');
  if (fallbackNote) fallbackNote.textContent = configured
    ? 'Use the saved self-hosted iplog API if ipapi.is cannot answer.'
    : 'Configure and save self-hosted iplog first to enable this option.';
  const note = form.querySelector('[data-geoip-provider-note]');
  if (note) note.textContent = provider === 'ipapi'
    ? 'The public API key enables country and risk lookups. Leave it empty to keep the stored key.'
    : 'The control node asks /checkip?ip=ADDRESS on this API. Leave the token empty to keep the stored one.';
}

async function saveGeoIP(event) {
  event.preventDefault();
  const form = shell.geoipForm;
  const error = $('[data-geoip-error]', form);
  error.hidden = true;
  const data = new FormData(form);
  try {
    const result = await api('/api/geoip', {
      method: 'POST',
      body: {
        provider: String(data.get('provider') || 'self'),
        host: String(data.get('host') || ''),
        agentId: Number(data.get('agentId') || 0),
        token: String(data.get('token') || ''),
        publicToken: String(data.get('publicToken') || ''),
        fallbackEnabled: String(data.get('provider') || 'self') === 'ipapi' && data.get('fallbackEnabled') === 'on',
        check: true,
      },
    });
    form.querySelector('input[name=token]').value = '';
    form.querySelector('input[name=publicToken]').value = '';
    delete form.dataset.providerSelection;
    delete form.dataset.fallbackSelection;
    await refresh();
    if (result && result.error) {
      toast('Saved, but the API did not answer: ' + result.error, 'fail');
      return;
    }
    const country = result && result.check ? result.check.country : '';
    toast('API answered for ' + (result.checkedFor || 'a test address') +
      (country ? ' with ' + country : ''), 'ok');
  } catch (err) {
    error.hidden = false;
    error.textContent = err.message;
  }
}

async function clearGeoIP() {
  try {
    await api('/api/geoip', { method: 'POST', body: { clear: true } });
    delete shell.geoipForm.dataset.providerSelection;
    delete shell.geoipForm.dataset.fallbackSelection;
    await refresh();
    toast('IP API removed', 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}
