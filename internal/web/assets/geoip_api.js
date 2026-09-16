'use strict';
/* MaxMind credentials for country access rules. */

// renderGeoIP shows the state of the country database.
function renderGeoIP() {
  if (!shell || !shell.geoipForm) return;
  const geo = (state.data.server && state.data.server.geoip) || {};
  const chip = shell.geoipStatus;
  if (!chip) return;
  if (geo.ready) {
    chip.className = 'chip chip-direct';
    chip.textContent = geo.networks + ' networks';
  } else if (geo.hasKey) {
    chip.className = 'chip chip-warn';
    chip.textContent = 'key saved, not loaded';
  } else {
    chip.className = 'chip chip-off';
    chip.textContent = 'not configured';
  }
  if (shell.geoipDetail) {
    shell.geoipDetail.textContent = geo.ready
      ? 'Loaded ' + relTime(geo.loadedAt) + ' from ' + (geo.source || 'cache') + '.'
      : (geo.lastError
        ? 'Last attempt failed: ' + geo.lastError
        : 'Country rules stay inactive until the database is loaded.');
  }
  const account = shell.geoipForm.querySelector('input[name=accountId]');
  if (account && document.activeElement !== account && geo.accountId) account.value = geo.accountId;
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
        licenseKey: String(data.get('licenseKey') || ''),
        accountId: String(data.get('accountId') || ''),
        fetch: true,
      },
    });
    form.querySelector('input[name=licenseKey]').value = '';
    await refresh();
    if (result && result.error) {
      toast('Saved, but the download failed: ' + result.error, 'fail');
      return;
    }
    toast('Country data loaded', 'ok');
  } catch (err) {
    error.hidden = false;
    error.textContent = err.message;
  }
}

async function clearGeoIP() {
  try {
    await api('/api/geoip', { method: 'POST', body: { clear: true } });
    await refresh();
    toast('Credentials removed', 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}
