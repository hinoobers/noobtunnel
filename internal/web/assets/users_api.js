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
      h('label', { class: 'field' }, h('span', null, 'Email address'),
        h('input', { type: 'email', name: 'email', required: true, placeholder: 'sam@example.com', autocomplete: 'email' })),
      h('label', { class: 'field' }, h('span', null, 'Password (at least 8 characters)'),
        h('input', { type: 'password', name: 'password', required: true, minlength: 8, autocomplete: 'new-password' })),
      h('label', { class: 'field' }, h('span', null, 'Role'),
        h('select', { name: 'role' },
          h('option', { value: 'regular' }, 'Regular — private mesh'),
          h('option', { value: 'admin' }, 'Admin — full control')))),
    h('div', { class: 'callout' },
      h('strong', null, 'Roles'),
       h('span', { class: 'muted', text: 'Admins manage the control node. Regular users manage their own mesh and resources.' })),
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
          email: String(data.get('email') || ''),
          password: String(data.get('password') || ''),
          role: String(data.get('role') || 'regular'),
        },
      });
      closeModal();
      await loadUsers(true);
      toast('User created; confirmation email sent', 'ok');
    } catch (err) {
      const box = $('[data-error=user]', form);
      box.hidden = false;
      box.textContent = err.message;
    }
  });
  modal('Add user', 'Create an account for this control node', form);
}

function openEditUser(id) {
  const user = (state.users || []).find((u) => u.id === id);
  if (!user) return;
  const choice = { value: user.role || 'regular' };
  const cards = cardPicker('role', [
    { value: 'regular', label: 'Regular', hint: 'Manages their own private mesh and resources.' },
    { value: 'admin', label: 'Admin', hint: 'Manages the control node and users.' },
  ], choice);
  cards.classList.add('role-picker');
  const form = h('form', { class: 'stack' },
    h('div', { class: 'fields' },
      h('label', { class: 'field' }, h('span', null, 'Username'),
        h('input', { name: 'username', value: user.username, required: true, minlength: 3, maxlength: 32 })),
      h('label', { class: 'field' }, h('span', null, 'Email'),
        h('input', { type: 'email', name: 'email', value: user.email || '', autocomplete: 'email' })),
      h('label', { class: 'field' }, h('span', null, 'New password (leave blank to keep current)'),
        h('input', { type: 'password', name: 'password', minlength: 8, autocomplete: 'new-password' })),
      h('div', { class: 'field' }, h('span', null, 'Role'), cards),
      h('label', { class: 'switch' },
        h('input', { type: 'checkbox', name: 'disabled', checked: !!user.disabled }),
        h('span', null,
          h('strong', null, 'Account disabled'),
          h('em', null, 'Prevent this account from signing in.')))),
    h('div', { class: 'field-error', 'data-error': 'useredit', hidden: true }),
    h('div', { class: 'modal-foot' },
      h('button', { class: 'btn', type: 'button', 'data-action': 'modal-close' }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'submit' }, 'Save changes')));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const username = String(data.get('username') || '').trim();
    const email = String(data.get('email') || '').trim();
    const password = String(data.get('password') || '');
    const changes = {};
    if (username !== user.username) changes.username = username;
    if (email !== (user.email || '')) changes.email = email;
    if (choice.value !== user.role) changes.role = choice.value;
    if (form.elements.disabled.checked !== !!user.disabled) changes.disabled = form.elements.disabled.checked;
    try {
      if (Object.keys(changes).length) await api('/api/users/' + id, { method: 'PATCH', body: changes });
      if (password) await api('/api/users/' + id + '/password', { method: 'POST', body: { password } });
      closeModal();
      await loadUsers(true);
      toast(changes.email ? 'Changes saved; email confirmation sent' : 'User updated', 'ok');
    } catch (err) {
      await loadUsers(true);
      const box = $('[data-error=useredit]', form);
      box.hidden = false;
      box.textContent = err.message;
    }
  });
  modal('Edit user', user.username, form);
}

function openUserResources(id) {
  const user = (state.users || []).find((u) => u.id === id);
  if (!user || !user.email) return;
  setView('resources');
  filterResourcesByEmail(user.email);
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
  const choice = { value: user.role || 'regular' };
  const cards = cardPicker('role', [
    { value: 'regular', label: 'Regular', hint: 'Manages their own private mesh and resources.' },
    { value: 'admin', label: 'Admin', hint: 'Full control: agents, resources, domains, exit nodes and users.' },
  ], choice);
  cards.classList.add('role-picker');
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

async function loadSignupSettings() {
  const form = shell && $('form[data-form=signup-settings]', shell.root);
  if (!form) return;
  try {
    const settings = await api('/api/signup/settings');
    form.elements.enabled.checked = !!settings.enabled;
    form.elements.maxUsers.value = settings.maxUsers || 25;
    form.elements.enabled.disabled = !settings.available && !settings.enabled;
    const count = $('[data-signup-count]', form);
    if (count) count.textContent = (settings.registeredUsers || 0) + ' of ' + settings.maxUsers + ' regular accounts registered, including unverified accounts.';
    const error = $('[data-error]', form);
    error.hidden = !!settings.available;
    if (!settings.available) error.textContent = 'Private mesh isolation or SMTP is unavailable.';
  } catch (err) { toast(err.message, 'fail'); }
}

async function saveSignupSettings(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const error = $('[data-error]', form);
  error.hidden = true;
  try {
    const maxUsers = Number(form.elements.maxUsers.value);
    if (!Number.isInteger(maxUsers) || maxUsers < 1 || maxUsers > 255) throw new Error('Enter a maximum between 1 and 255.');
    await api('/api/signup/settings', { method: 'POST', body: { enabled: form.elements.enabled.checked, maxUsers } });
    await loadSignupSettings();
    toast('Signup settings saved', 'ok');
  } catch (err) { error.textContent = err.message; error.hidden = false; }
}
