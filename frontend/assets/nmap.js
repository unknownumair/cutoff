/* CUTOFF nmap console */
(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const state = { token: '', data: null, timer: null, wasRunning: false };

  const readToken = () => (typeof (window.__CUTOFF_TOKEN__ || window.__NPENT_TOKEN__) === 'string' && (window.__CUTOFF_TOKEN__ || window.__NPENT_TOKEN__).trim())
    || (localStorage.getItem('cutoff.token') || localStorage.getItem('npent.token') || '');

  async function api(path, options = {}) {
    const response = await fetch(path, {
      method: options.method || 'GET',
      headers: { 'X-API-Token': state.token, ...(options.body ? { 'Content-Type': 'application/json' } : {}) },
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    if (response.status === 401) { location.href = '/'; throw new Error('unauthorized'); }
    let payload = {};
    try { payload = await response.json(); } catch { /* empty */ }
    if (!response.ok) throw new Error(payload.error || `request failed (${response.status})`);
    return payload;
  }

  function toast(kind, title, message = '') {
    const root = $('#toasts');
    const item = document.createElement('div');
    item.className = `toast ${kind}`;
    item.innerHTML = `<div><b>${esc(title)}</b>${message ? `<span>${esc(message)}</span>` : ''}</div>`;
    root.appendChild(item);
    setTimeout(() => item.remove(), kind === 'err' ? 7000 : 4500);
  }

  function renderTargets() {
    const data = state.data;
    const select = $('#nmapTarget');
    const previous = select.value;
    select.innerHTML = (data.targets || []).map((t) => `<option value="${esc(t.id)}">${esc(t.label)} — ${esc(t.value)}</option>`).join('')
      + '<option value="custom">Custom IP / CIDR</option>';
    if (previous && [...select.options].some((o) => o.value === previous)) select.value = previous;
  }

  function renderPresets() {
    const data = state.data;
    const privileged = data.capabilities.privileged;
    const running = Boolean(data.status?.running);
    $('#presetCount').textContent = data.presets.length;
    $('#presetGrid').innerHTML = data.presets.map((preset) => {
      const blocked = (preset.needs_root && !privileged) || running;
      const tags = [preset.needs_root ? '<span class="tag">root</span>' : '',
        preset.warn ? '<span class="tag danger">slow</span>' : ''].join('');
      return `<button class="preset-card" data-preset="${esc(preset.id)}" ${blocked ? 'disabled' : ''}>
        <span class="preset-head"><b>${esc(preset.label)}</b>${tags}</span>
        <small>${esc(preset.desc)}</small>
        <span class="preset-time">~${Math.round(preset.timeout / 60)} min max</span>
      </button>`;
    }).join('');
    $('#presetGrid').querySelectorAll('[data-preset]').forEach((button) => {
      button.addEventListener('click', () => runPreset(button.dataset.preset));
    });
  }

  function renderStats() {
    const data = state.data;
    const status = data.status || {};
    const caps = data.capabilities || {};
    $('#statNmapVersion').textContent = (caps.version || 'missing').replace(/^Nmap version\s*/i, '').split(' (')[0].slice(0, 22);
    $('#statNmapPath').textContent = caps.path ? 'bundled · ready' : (caps.note || 'not found');
    $('#statNmapState').textContent = status.running ? (status.label || 'running') : 'Idle';
    $('#statNmapNote').textContent = status.running ? `against ${status.target}` : 'no scan running';
    $('#statNmapNetwork').textContent = data.network || '—';
    $('#statNmapTargets').textContent = `${(data.targets || []).length} targets`;
    const responsive = (status.hosts || []).filter((h) => h.responsive !== false).length;
    $('#statNmapHosts').textContent = responsive;
    $('#statNmapDuration').textContent = status.duration_s
      ? `${status.duration_s}s · ${status.touched || 0} synced online` : '—';
    $('#nmapStatus').textContent = status.running
      ? `${status.label} · ${status.target} · ${status.duration_s}s`
      : (status.error || (status.finished_at ? 'Last scan finished.' : 'Select a preset below. All targets are restricted to your local subnet.'));
    $('#nmapCommand').textContent = status.command || '';
    $('#btnNmapStop').disabled = !status.running;
    $('#targetPill').textContent = $('#nmapTarget').value?.split(':')[0] || 'subnet';
    const badge = $('#modeBadge');
    badge.className = `badge ${caps.privileged ? 'live' : 'sim'}`;
    badge.textContent = caps.privileged ? 'Live' : 'Simulation';
    $('#netchipText').textContent = data.network ? `${data.network}` : 'no network';
    const banner = $('#nmapBanner');
    if (!caps.available) {
      banner.classList.remove('hidden');
      $('#nmapBannerText').innerHTML = '<strong>nmap missing.</strong> Run <code>tools/install-nmap-rpm.sh</code>.';
    } else if (!caps.privileged) {
      banner.classList.remove('hidden');
      $('#nmapBannerText').innerHTML = '<strong>Unprivileged.</strong> TCP connect scans work; OS detection needs <code>sudo ./run.sh</code>.';
    } else {
      banner.classList.add('hidden');
    }
  }

  function renderHosts() {
    const hosts = state.data?.status?.hosts || [];
    $('#hostCount').textContent = hosts.filter((h) => h.responsive !== false).length;
    $('#nmapHosts').innerHTML = hosts.map((host) => {
      const names = (host.hostnames || []).join(', ') || '—';
      const ports = (host.ports || []).map((p) => `${p.port}/${p.proto} ${p.service || ''}`.trim()).join(', ') || '—';
      const os = (host.os || [])[0]?.name || '—';
      const scripts = Object.keys(host.scripts || {}).join(', ') || '—';
      const responsive = host.responsive !== false;
      return `<tr class="${responsive ? '' : 'offline'}">
        <td><div class="dev-name">${esc(names)}${responsive ? '' : ' <span class="tag">no response</span>'}</div></td>
        <td class="mono">${esc(host.ip || '—')}</td>
        <td class="mono" style="max-width:280px;white-space:normal">${esc(ports)}</td>
        <td>${esc(os)}</td>
        <td class="mono" style="max-width:180px;white-space:normal">${esc(scripts)}</td>
      </tr>`;
    }).join('') || '<tr><td colspan="5"><span class="muted">No hosts yet.</span></td></tr>';
  }

  function renderOutput() {
    const status = state.data?.status || {};
    const output = status.output || '';
    const pre = $('#nmapOutput');
    const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 30;
    pre.textContent = output || 'No scan output yet.';
    if (atBottom) pre.scrollTop = pre.scrollHeight;
  }

  function render() {
    if (!state.data) return;
    renderTargets();
    renderStats();
    renderHosts();
    renderOutput();
    renderPresets();
    const running = Boolean(state.data.status?.running);
    if (state.wasRunning && !running) {
      const status = state.data.status;
      toast(status.error ? 'err' : 'ok', status.error ? 'Scan failed' : 'Scan finished',
        status.error || `${(status.hosts || []).length} hosts in ${status.duration_s}s`);
    }
    state.wasRunning = running;
    clearTimeout(state.timer);
    state.timer = setTimeout(refresh, running ? 1000 : 5000);
  }

  async function refresh() {
    try {
      state.data = await api('/api/nmap');
      render();
    } catch (error) {
      if (error.message !== 'unauthorized') toast('err', 'Nmap unavailable', error.message);
      state.timer = setTimeout(refresh, 5000);
    }
  }

  async function runPreset(preset) {
    const target = $('#nmapTarget').value;
    const custom = $('#nmapCustom').value.trim();
    const meta = state.data.presets.find((p) => p.id === preset);
    if (meta?.warn && !window.confirm(`${meta.label} can take several minutes and is loud on the network. Continue?`)) return;
    if (target === 'custom' && !custom) { toast('warn', 'Custom target required'); return; }
    try {
      const result = await api('/api/nmap/run', {
        method: 'POST', body: { preset, target, custom },
      });
      toast('ok', 'Scan started', result.message);
      clearTimeout(state.timer);
      state.timer = setTimeout(refresh, 400);
    } catch (error) {
      toast('err', 'Cannot start scan', error.message);
    }
  }

  async function stopScan() {
    try {
      const result = await api('/api/nmap/stop', { method: 'POST' });
      toast('ok', result.stopped ? 'Scan stopped' : 'Nothing to stop');
      refresh();
    } catch (error) {
      toast('err', 'Stop failed', error.message);
    }
  }

  function bind() {
    $('#btnRefresh').addEventListener('click', refresh);
    $('#btnNmapStop').addEventListener('click', stopScan);
    $('#nmapTarget').addEventListener('change', () => {
      const custom = $('#nmapTarget').value === 'custom';
      $('#customWrap').style.display = custom ? '' : 'none';
      $('#targetPill').textContent = $('#nmapTarget').value.split(':')[0];
    });
  }

  function boot() {
    state.token = readToken();
    if (!state.token) { location.href = '/'; return; }
    bind();
    refresh();
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
