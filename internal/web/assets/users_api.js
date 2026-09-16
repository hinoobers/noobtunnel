'use strict';
/* User management for the control node UI. */

async function loadUsers(force) {
  if (!canAdmin()) return;
  if (!force && state.users && Date.now() - state.usersAt < 5000) return;
  try {
    const result = await api('/api/users');
    state.users = result.users || [];
    state.usersAt = Date.now();
    renderShell();
  } catch (err) {
    toast(err.message, 'fail');
  }
}

function openAddUser() {
  const form = h('form', { class: 'stack' },
    h('div', { class: 'fields' },
      h('label', { class: 'field' }, h('span', null, 'Username'),
        h('input', { name: 'username', required: true, minlength: 3, maxlength: 32, placeholder: 'sam', autocomplete: 'off' })),
      h('label', { class: 'field' }, h('span', null, 'Password (at least 8 characters)'),
        h('input', { type: 'password', name: 'password', required: true, minlength: 8, autocomplete: 'new-password' })),
      h('label', { class: 'field' }, h('span', null, 'Role'),
        h('select', { name: 'role' },
          h('option', { value: 'viewer' }, 'Viewer — can see the mesh, cannot change it'),
          h('option', { value: 'admin' }, 'Admin — full control')))),
    h('div', { class: 'callout' },
      h('strong', null, 'Roles'),
      h('span', { class: 'muted', text: 'Admins manage agents, settings and other users. Viewers can watch the mesh, ping agents and read configuration.' })),
    h('div', { class: 'field-error', 'data-error': 'user', hidden: true }),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'submit' }, 'Create user')));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    try {
      await api('/api/users', {
        method: 'POST',
        body: {
          username: String(data.get('username') || ''),
          password: String(data.get('password') || ''),
          role: String(data.get('role') || 'viewer'),
        },
      });
      closeModal();
      await loadUsers(true);
      toast('User created', 'ok');
    } catch (err) {
      const box = $('[data-error=user]', form);
      box.hidden = false;
      box.textContent = err.message;
    }
  });
  modal('Add user', 'Create an account for this control node', form);
}

function openUserPassword(username, id) {
  const form = h('form', { class: 'stack' },
    h('label', { class: 'field' }, h('span', null, 'New password for ' + username),
      h('input', { type: 'password', name: 'password', required: true, minlength: 8, autocomplete: 'new-password' })),
    h('div', { class: 'field-error', 'data-error': 'userpw', hidden: true }),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'submit' }, 'Set password')));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const password = String(new FormData(form).get('password') || '');
    try {
      await api('/api/users/' + id + '/password', { method: 'POST', body: { password } });
      closeModal();
      toast('Password updated for ' + username, 'ok');
    } catch (err) {
      const box = $('[data-error=userpw]', form);
      box.hidden = false;
      box.textContent = err.message;
    }
  });
  modal('Set password', username, form);
}

// openRoleModal lets an admin pick a role for an account.
function openRoleModal(id) {
  const user = (state.users || []).find((u) => u.id === id);
  if (!user) return;
  const choice = { value: user.role || 'viewer' };
  const cards = cardPicker('role', [
    { value: 'viewer', label: 'Viewer', hint: 'Can see the mesh, ping agents and read configuration.' },
    { value: 'admin', label: 'Admin', hint: 'Full control: agents, resources, domains, exit nodes and users.' },
  ], choice);
  const form = h('form', { class: 'stack' },
    h('div', { class: 'fields' },
      h('div', { class: 'field' }, h('span', null, 'Role for ' + user.username), cards)),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'submit' }, 'Save role')));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      await setUserRole(id, choice.value);
      closeModal();
    } catch (err) {
      toast(err.message, 'fail');
    }
  });
  modal('Change role', user.username, form);
}

async function setUserRole(id, role) {
  try {
    await api('/api/users/' + id, { method: 'PATCH', body: { role } });
    await loadUsers(true);
    toast('Role changed to ' + role, 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}

async function toggleUser(id, disabled) {
  try {
    await api('/api/users/' + id, { method: 'PATCH', body: { disabled } });
    await loadUsers(true);
    toast(disabled ? 'Account disabled' : 'Account enabled', 'ok');
  } catch (err) {
    toast(err.message, 'fail');
  }
}

async function deleteUser(id, username) {
  confirmModal('Delete user', 'Remove ' + username + ' and end their sessions? ' +
    'Anyone signed in as this account is locked out immediately.', 'Delete user', async () => {
    try {
      await api('/api/users/' + id, { method: 'DELETE' });
      await loadUsers(true);
      toast('User deleted', 'ok');
    } catch (err) {
      toast(err.message, 'fail');
    }
  });
}

// openChangePassword lets any signed-in account change its own password.
function openChangePassword() {
  const form = h('form', { class: 'stack' },
    h('div', { class: 'fields' },
      h('label', { class: 'field' }, h('span', null, 'Current password'),
        h('input', { type: 'password', name: 'current', required: true, autocomplete: 'current-password' })),
      h('label', { class: 'field' }, h('span', null, 'New password (at least 8 characters)'),
        h('input', { type: 'password', name: 'password', required: true, minlength: 8, autocomplete: 'new-password' }))),
    h('div', { class: 'field-error', 'data-error': 'selfpw', hidden: true }),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'submit' }, 'Update password')));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    try {
      await api('/api/password', {
        method: 'POST',
        body: { current: String(data.get('current') || ''), password: String(data.get('password') || '') },
      });
      closeModal();
      toast('Password updated', 'ok');
    } catch (err) {
      const box = $('[data-error=selfpw]', form);
      box.hidden = false;
      box.textContent = err.message;
    }
  });
  modal('Change my password', state.session.username, form);
}
