'use strict';

async function loadSMTP() {
  const form = shell && $('form[data-form=smtp]', shell.root);
  if (!form) return;
  try {
    const { smtp } = await api('/api/smtp');
    form.elements.host.value = smtp.host || '';
    form.elements.port.value = smtp.port || 465;
    form.elements.security.value = smtp.security || 'tls';
    form.elements.username.value = smtp.username || '';
    form.elements.from.value = smtp.from || '';
    form.elements.password.value = '';
    const status = $('[data-smtp-status]', form);
    status.textContent = smtp.configured ? 'connected' : 'not configured';
    form.elements.password.placeholder = smtp.hasPassword ? 'Leave blank to keep saved password' : 'SMTP password';
  } catch (err) { toast(err.message, 'fail'); }
}

async function saveSMTP(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const error = $('[data-smtp-error]', form);
  error.hidden = true;
  const data = new FormData(form);
  const body = Object.fromEntries(data.entries());
  body.port = Number(body.port);
  try {
    const result = await api('/api/smtp', { method: 'POST', body });
    form.elements.password.value = '';
    $('[data-smtp-status]', form).textContent = 'connected';
    toast(result.tested ? 'SMTP settings saved and test email sent' : 'SMTP settings saved', 'ok');
  } catch (err) {
    error.hidden = false;
    error.textContent = err.message;
  }
}
