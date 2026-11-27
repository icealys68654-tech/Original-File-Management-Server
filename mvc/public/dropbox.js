const $ = id => document.getElementById(id);
let csrf = '';
async function request(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { ...(options.body ? { 'content-type': 'application/json' } : {}), ...(options.method && options.method !== 'GET' ? { 'x-csrf-token': csrf } : {}), ...options.headers } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}
function message(text) { $('dropboxStatus').textContent = text; }
async function refreshDropbox() {
  try {
    const auth = await request('/api/auth/me');
    if (!auth.authenticated) return;
    csrf = auth.csrf || '';
    const status = await request('/api/dropbox/status');
    if (!status.configured) { message('Dropbox is not configured by the server administrator.'); $('dropboxConnect').hidden = true; return; }
    $('dropboxConnect').hidden = status.connected;
    $('dropboxDisconnect').hidden = !status.connected;
    if (!status.connected) { message('Not connected. Connect Dropbox to browse your account.'); $('dropboxFiles').textContent = 'No Dropbox account connected.'; return; }
    message(`Connected as ${status.account?.email || status.account?.name || 'Dropbox user'}`);
    const result = await request('/api/dropbox/files');
    const list = $('dropboxFiles'); list.replaceChildren();
    if (!result.entries.length) { list.textContent = 'Your Dropbox root folder is empty.'; return; }
    for (const entry of result.entries) {
      const row = document.createElement('div'); row.className = 'registry-row';
      const name = document.createElement('strong'); name.textContent = entry.name;
      const meta = document.createElement('small'); meta.textContent = entry.type === 'folder' ? 'Folder' : `${entry.size.toLocaleString()} bytes`;
      row.append(name, meta);
      if (entry.type === 'file') {
        const button = document.createElement('button'); button.type = 'button'; button.textContent = 'Download';
        button.addEventListener('click', async () => {
          try { const file = await request('/api/dropbox/download', { method: 'POST', body: JSON.stringify({ path: entry.path }) }); const bytes = Uint8Array.from(atob(file.content), c => c.charCodeAt(0)); const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([bytes])); link.download = file.name; link.click(); URL.revokeObjectURL(link.href); }
          catch (e) { message(e.message); }
        }); row.append(button);
      }
      list.append(row);
    }
  } catch (e) { message(e.message); }
}
document.addEventListener('DOMContentLoaded', () => {
  if (!$('dropboxPanel')) return;
  $('dropboxRefresh').addEventListener('click', refreshDropbox);
  $('dropboxDisconnect').addEventListener('click', async () => { try { await request('/api/dropbox/disconnect', { method: 'DELETE' }); await refreshDropbox(); } catch (e) { message(e.message); } });
  $('dropboxUploadForm').addEventListener('submit', async event => {
    event.preventDefault(); const file = $('dropboxUpload').files[0]; if (!file) return;
    if (file.size > 9 * 1024 * 1024) { message('Choose a file smaller than 9 MiB.'); return; }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer()); let binary = ''; for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      const path = '/' + file.name.replaceAll('/', '_');
      await request('/api/dropbox/upload', { method: 'POST', body: JSON.stringify({ path, content: btoa(binary) }) });
      message(`Uploaded ${file.name} to Dropbox.`); $('dropboxUploadForm').reset(); await refreshDropbox();
    } catch (e) { message(e.message); }
  });
  refreshDropbox();
});
