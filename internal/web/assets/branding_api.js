'use strict';
/* Branding: the logo, the service name and the custom stylesheet. */

// brandName is what the operator calls this deployment; it falls back to the
// bundled name so an unconfigured control node never renders an empty header.
function brandName() {
  const server = state.data && state.data.server;
  return (server && server.brandName) || state.brandName || 'noobtunnel';
}

// applyBranding writes the service name into every place it is shown.
function applyBranding() {
  const name = brandName();
  document.querySelectorAll('.brand-text').forEach((node) => {
    if (node.textContent !== name) node.textContent = name;
  });
  if (document.title !== name) document.title = name;
}

async function uploadLogo(event) {
  event.preventDefault();
  const form = shell.brandingForm;
  const input = form.querySelector('input[type=file]');
  const error = $('[data-web-logo-error]', form);
  error.hidden = true;
  if (!input.files || !input.files.length) {
    error.hidden = false;
    error.textContent = 'Pick an image first.';
    return;
  }
  try {
    const raw = await input.files[0].arrayBuffer();
    await api('/api/logo', { method: 'POST', raw, contentType: input.files[0].type || 'application/octet-stream' });
    form.reset();
    await refresh();
    applyLogo();
    toast('Logo updated', 'ok');
  } catch (err) {
    error.hidden = false;
    error.textContent = err.message;
  }
}

async function resetLogo() {
  try {
    await api('/api/logo', { method: 'DELETE' });
    await refresh();
    applyLogo();
    toast('Default logo restored', 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}

// saveBrandName renames the service. It posts the whole settings object because
// the settings endpoint replaces what it is given.
async function saveBrandName(event) {
  event.preventDefault();
  const form = shell.brandNameForm;
  const error = $('[data-brand-error]', form);
  error.hidden = true;
  const name = form.brandName.value.trim();
  if (!name) {
    error.hidden = false;
    error.textContent = 'Give the service a name.';
    return;
  }
  const body = Object.assign({}, state.data.settings, { brandName: name });
  try {
    const result = await api('/api/settings', { method: 'POST', body });
    if (state.data) state.data.settings = result.settings;
    state.brandName = result.settings.brandName || name;
    state.brandingSignature = '';
    applyBranding();
    toast('Service renamed', 'ok');
    await refresh();
  } catch (err) {
    error.hidden = false;
    error.textContent = err.message;
  }
}

// renderBranding refreshes the name field and, when the stored stylesheet
// changed, the CSS editor. It only touches the editor on a version change so a
// live update cannot wipe out what the admin is typing.
function renderBranding(server) {
  if (!shell || !server) return;
  const signature = String(server.brandName || '') + '|' + String(server.brandCSS || '') + '|' + (server.customCss ? 'custom' : 'default');
  if (signature === state.brandingSignature) return;
  state.brandingSignature = signature;
  if (shell.brandNameForm && shell.brandNameForm.brandName) {
    shell.brandNameForm.brandName.value = server.brandName || '';
  }
  if (shell.cssStatus) shell.cssStatus.textContent = server.customCss ? 'custom' : 'bundled default';
  loadCSSEditor();
}

// loadCSSEditor fills the editor with the stylesheet the control node serves:
// the operator's own one when it exists, the bundled default otherwise.
async function loadCSSEditor() {
  const form = shell && shell.brandCSSForm;
  if (!form) return;
  try {
    const result = await api('/api/css');
    form.css.value = result.css || '';
    if (shell.cssStatus) shell.cssStatus.textContent = result.custom ? 'custom' : 'bundled default';
    if (shell.cssError) shell.cssError.hidden = true;
  } catch (err) {
    if (shell.cssError) {
      shell.cssError.hidden = false;
      shell.cssError.textContent = err.message;
    }
  }
}

async function saveBrandCSS(event) {
  event.preventDefault();
  const form = shell.brandCSSForm;
  const error = shell.cssError;
  error.hidden = true;
  try {
    await api('/api/css', { method: 'POST', raw: form.css.value, contentType: 'text/css; charset=utf-8' });
    toast('Stylesheet saved', 'ok');
    await refresh();
  } catch (err) {
    error.hidden = false;
    error.textContent = err.message;
  }
}

async function resetBrandCSS() {
  try {
    await api('/api/css', { method: 'DELETE' });
    toast('Default stylesheet restored', 'ok');
    await refresh();
  } catch (err) {
    toast(err.message, 'fail');
  }
}

// applyLogo refreshes every logo image, bypassing the browser cache when the
// uploaded image changed.
function applyLogo() {
  const version = (state.data && state.data.logoVersion) || 'default';
  document.querySelectorAll('.brand-logo, .brand-logo-preview').forEach((img) => {
    img.src = '/logo?v=' + encodeURIComponent(version);
  });
}
