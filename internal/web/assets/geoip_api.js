'use strict';
/* The IP API that answers country lookups for country rules on resources. */

// renderGeoIP shows the state of the country lookup.
function renderGeoIP() {
  if (!shell || !shell.geoipForm) return;
  const geo = (state.data.server && state.data.server.geoip) || {};
  const chip = shell.geoipStatus;
  if (!chip) return;
  const lookups = geo.lookups || 0;
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
    if (geo.configured) parts.push('Host ' + geo.host + (geo.hasToken ? ' with a token' : ' without a token'));
    if (geo.lastAt) parts.push('last answer ' + relTime(geo.lastAt));
    if (geo.cached) parts.push(geo.cached + ' address' + (geo.cached === 1 ? '' : 'es') + ' cached');
    if (geo.lastError) parts.push('last error: ' + geo.lastError);
    if (!geo.configured) parts.push('Country rules stay inactive until an API is configured.');
    shell.geoipDetail.textContent = parts.join(' \u00b7 ');
  }
  const host = shell.geoipForm.querySelector('input[name=host]');
  if (host && document.activeElement !== host && geo.host) host.value = geo.host;
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
        host: String(data.get('host') || ''),
        token: String(data.get('token') || ''),
        check: true,
      },
    });
    form.querySelector('input[name=token]').value = '';
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
    await refresh();
    toast('IP API removed', 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}
