'use strict';
/* DNS automation: providers that create the records for published domains. */

const DNS_KIND_INFO = {
  cloudflare: {
    label: 'Cloudflare',
    hint: 'Create an API token with Zone → DNS → Edit for the zone, then paste it here.',
  },
};

function dnsProviders() {
  return state.data.dnsProviders || [];
}

function providerName(id) {
  const provider = dnsProviders().find((p) => p.id === id);
  return provider ? provider.name : '';
}

// openDNSAutomation manages the providers used to keep domain records current.
function openDNSAutomation() {
  const body = h('div', { class: 'stack' });
  body.append(
    h('div', { class: 'callout' },
      h('strong', null, 'What this does'),
      h('span', { class: 'muted', text: 'Give the control node a DNS provider once, then pick it for a domain. ' +
        'Whenever a resource is published, moved to another exit node, or removed, the A record for that domain is ' +
        'updated automatically to point at the right public address.' })),
    h('div', { class: 'row', style: 'justify-content:space-between' },
      h('h3', null, 'Providers'),
      h('button', { class: 'btn btn-primary btn-sm', 'data-action': 'dns-provider-edit' }, 'Add provider')));

  const providers = dnsProviders();
  if (!providers.length) {
    body.append(h('div', { class: 'empty' },
      h('p', { class: 'muted', text: 'No providers yet. Add one to automate DNS.' })));
  } else {
    const list = h('div', { class: 'stack' });
    providers.forEach((provider) => {
      list.append(h('div', { class: 'subpanel' },
        h('div', { class: 'panel-head' },
          h('div', null,
            h('div', { class: 'row' },
              h('strong', null, provider.name),
              h('span', { class: 'chip chip-relay' }, provider.kind),
              provider.enabled ? h('span', { class: 'chip chip-direct' }, 'enabled') : h('span', { class: 'chip chip-off' }, 'disabled'),
              provider.hasToken ? null : h('span', { class: 'chip chip-warn' }, 'no token')),
            h('p', { class: 'muted tiny', text: 'added ' + relTime(provider.createdAt) })),
          h('div', { class: 'row', style: 'flex-wrap:wrap' },
            h('button', { class: 'btn btn-sm', 'data-action': 'dns-provider-edit', 'data-id': provider.id }, 'Edit'),
            h('button', {
              class: 'btn btn-sm',
              'data-action': 'dns-provider-toggle',
              'data-id': provider.id,
              'data-enabled': provider.enabled ? 'false' : 'true',
            }, provider.enabled ? 'Disable' : 'Enable'),
            h('button', {
              class: 'btn btn-sm btn-danger',
              'data-action': 'dns-provider-delete',
              'data-id': provider.id,
              'data-name': provider.name,
            }, 'Delete')))));
    });
    body.append(list);
  }
  body.append(h('div', { class: 'panel-foot' },
    h('button', { class: 'btn btn-primary', 'data-action': 'modal-close' }, 'Done')));
  modal('DNS automation', 'Let the control node create domain records', body);
}

// openDNSProviderModal adds or edits one provider.
function openDNSProviderModal(id) {
  const existing = id ? dnsProviders().find((p) => p.id === id) : null;
  const isEdit = !!existing;
  const choice = { value: isEdit ? existing.kind : 'cloudflare' };
  const cards = cardPicker('dnsKind', Object.entries(DNS_KIND_INFO).map(([value, info]) => ({
    value, label: info.label, hint: info.hint,
  })), choice);

  const nameInput = h('input', {
    name: 'name', required: true, value: isEdit ? existing.name : '',
    placeholder: 'cloudflare', autocomplete: 'off',
  });
  const tokenInput = h('input', {
    name: 'token', type: 'password', spellcheck: 'false',
    required: !isEdit,
    placeholder: isEdit && existing.hasToken ? 'unchanged' : 'API token',
    autocomplete: 'new-password',
  });
  const error = h('div', { class: 'field-error', 'data-error': 'dnsprovider', hidden: true });

  const form = h('form', { class: 'stack' },
    h('div', { class: 'fields' },
      h('label', { class: 'field' }, h('span', null, 'Provider'), cards),
      h('label', { class: 'field' }, h('span', null, 'Name'), nameInput),
      h('label', { class: 'field' }, h('span', null, 'API token'), tokenInput,
        h('div', { class: 'muted tiny', text: isEdit
          ? 'Leave empty to keep the stored token.'
          : 'Stored on this control node and used only to update your own records.' })),
      error),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'submit' }, isEdit ? 'Save provider' : 'Add provider')));

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const body = {
      name: String(data.get('name') || ''),
      kind: choice.value,
      token: String(data.get('token') || ''),
    };
    try {
      if (isEdit) await api('/api/dns/providers/' + existing.id, { method: 'PATCH', body });
      else await api('/api/dns/providers', { method: 'POST', body });
      closeModal();
      await refresh();
      toast(isEdit ? 'Provider updated' : 'Provider added', 'ok');
      openDNSAutomation();
    } catch (err) {
      error.hidden = false;
      error.textContent = err.message;
    }
  });
  modal(isEdit ? 'Edit DNS provider' : 'Add DNS provider',
    'Used to create the records for your published domains', form);
}

async function toggleDNSProvider(id, enabled) {
  const provider = dnsProviders().find((p) => p.id === id);
  if (!provider) return;
  try {
    await api('/api/dns/providers/' + id, {
      method: 'PATCH',
      body: { name: provider.name, kind: provider.kind, enabled },
    });
    await refresh();
    closeModal();
    openDNSAutomation();
    toast(enabled ? 'Provider enabled' : 'Provider disabled', 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}

async function deleteDNSProvider(id, name) {
  confirmModal('Delete provider', 'Remove ' + name + '? Domains using it will need to be updated by hand.',
    'Delete provider', async () => {
      try {
        await api('/api/dns/providers/' + id, { method: 'DELETE' });
        await refresh();
        closeModal();
        openDNSAutomation();
        toast('Provider removed', 'ok');
      } catch (err) {
        toast(err.message, 'fail');
      }
    });
}

// setDomainProvider attaches (or clears) the provider used for one domain.
async function setDomainProvider(hostname, providerID) {
  try {
    await api('/api/domains/' + encodeURIComponent(hostname), {
      method: 'PATCH',
      body: { providerId: providerID },
    });
    await refresh();
    toast(providerID ? 'Automatic DNS enabled' : 'Automatic DNS disabled', 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}

async function syncDomain(hostname) {
  try {
    await api('/api/domains/' + encodeURIComponent(hostname) + '/sync', { method: 'POST', body: {} });
    await refresh();
    toast('DNS updated for ' + hostname, 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}

async function syncAllDomains() {
  try {
    const result = await api('/api/domains/sync', { method: 'POST', body: {} }).catch(() => null);
    await refresh();
    toast('Domains updated', 'ok');
    if (result && result.domains) state.data.domains = result.domains;
    renderShell();
  } catch (err) {
    toast(err.message, 'fail');
  }
}
