/* CUTOFF bettercap console */
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
    const select = $('#bcTarget');
    const previous = select.value;
    const devices = state.data.devices || [];
    select.innerHTML = '<option value="">Whole LAN (all clients)</option>'
      + devices.map((d) => `<option value="${esc(d.ip)}">${esc(d.name || d.ip)} — ${esc(d.ip)}</option>`).join('');
    if (previous && [...select.options].some((o) => o.value === previous)) select.value = previous;
  }

  function renderPresets() {
    const caps = state.data.capabilities || {};
    const running = state.data.running;
    $('#bcPresets').innerHTML = (caps.presets || []).map((preset) => {
      const blocked = (preset.needs_root && !caps.privileged) || running;
      return `<button class="preset-card" data-preset="${esc(preset.id)}" ${blocked ? 'disabled' : ''}>
        <span class="preset-head"><b>${esc(preset.label)}</b>${preset.warn ? '<span class="tag danger">warning</span>' : ''}</span>
        <small>${esc(preset.desc)}</small>
      </button>`;
    }).join('');
    $('#bcPresets').querySelectorAll('[data-preset]').forEach((button) => {
      button.addEventListener('click', () => start(button.dataset.preset));
    });
  }

  function render() {
    const data = state.data;
    const caps = data.capabilities || {};
    $('#statBcVersion').textContent = (caps.version || 'missing').replace(/^bettercap\s*/i, '').split(' (')[0].slice(0, 22) || 'missing';
    $('#statBcPath').textContent = caps.available ? 'bundled · ready' : 'binary missing';
    $('#statBcState').textContent = data.running ? 'Running' : 'Idle';
    $('#statBcNote').textContent = data.running ? (data.preset || 'session') : 'not running';
    $('#statBcIface').textContent = data.iface || '—';
    $('#statBcScope').textContent = data.targets ? `target: ${data.targets}` : 'whole LAN';
    $('#statBcLog').textContent = (data.log || []).length;
    $('#statBcPid').textContent = data.pid ? `pid ${data.pid}` : '—';
    $('#bcLines').textContent = (data.log || []).length;
    $('#bcState').textContent = data.running ? (data.preset || 'running') : 'idle';
    const badge = $('#modeBadge');
    badge.className = `badge ${caps.privileged ? 'live' : 'sim'}`;
    badge.textContent = caps.privileged ? 'Live' : 'Simulation';
    $('#netchipText').textContent = data.network || data.iface || 'no network';
    $('#btnBcStart').disabled = data.running || !caps.privileged;
    $('#btnBcStop').disabled = !data.running;
    $('#bcStatus').textContent = data.running
      ? `${data.preset} on ${data.iface}${data.targets ? ` · targets ${data.targets}` : ' · whole LAN'}`
      : 'Choose a preset and start. Bettercap needs root for ARP/sniffing.';

    const banner = $('#bcBanner');
    if (!caps.available) {
      banner.classList.remove('hidden');
      $('#bcBannerText').innerHTML = '<strong>Bettercap missing.</strong> Run <code>tools/install-bettercap.sh</code> to bundle it.';
    } else if (!caps.privileged) {
      banner.classList.remove('hidden');
      $('#bcBannerText').innerHTML = '<strong>Unprivileged.</strong> Bettercap needs <code>sudo ./run.sh</code> for ARP spoofing and sniffing.';
    } else {
      banner.classList.add('hidden');
    }

    const log = (data.log || []).join('\n');
    const pre = $('#bcLog');
    const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 30;
    pre.textContent = log || 'No output yet.';
    if (atBottom) pre.scrollTop = pre.scrollHeight;

    renderPresets();
    if (state.wasRunning && !data.running) {
      toast(data.error ? 'err' : 'ok', data.error ? 'Session ended' : 'Session stopped',
        data.error || 'bettercap exited');
    }
    state.wasRunning = Boolean(data.running);
    clearTimeout(state.timer);
    state.timer = setTimeout(refresh, data.running ? 1500 : 5000);
  }

  async function refresh() {
    try {
      state.data = await api('/api/bettercap');
      renderTargets();
      render();
    } catch (error) {
      if (error.message !== 'unauthorized') toast('err', 'Bettercap unavailable', error.message);
      state.timer = setTimeout(refresh, 5000);
    }
  }

  async function start(preset) {
    const meta = state.data.capabilities.presets.find((p) => p.id === preset);
    if (meta?.warn && !window.confirm(`${meta.label} puts this host in-path and can disrupt the LAN. Continue?`)) return;
    try {
      const result = await api('/api/bettercap/start', {
        method: 'POST', body: { preset, targets: $('#bcTarget').value },
      });
      toast('ok', 'Bettercap started', result.message);
      clearTimeout(state.timer);
      state.timer = setTimeout(refresh, 600);
    } catch (error) {
      toast('err', 'Cannot start bettercap', error.message);
    }
  }

  async function stop() {
    try {
      const result = await api('/api/bettercap/stop', { method: 'POST' });
      toast('ok', result.stopped ? 'Session stopped' : 'Nothing to stop');
      refresh();
    } catch (error) {
      toast('err', 'Stop failed', error.message);
    }
  }

  async function clearLog() {
    try {
      await api('/api/bettercap/clear', { method: 'POST' });
      toast('ok', 'Console cleared');
      refresh();
    } catch (error) {
      toast('err', 'Clear failed', error.message);
    }
  }

  function bind() {
    $('#btnRefresh').addEventListener('click', refresh);
    $('#btnBcStart').addEventListener('click', () => {
      const first = state.data?.capabilities?.presets?.find((p) => p.id === 'recon');
      start(first ? first.id : 'recon');
    });
    $('#btnBcStop').addEventListener('click', stop);
    $('#btnBcClear').addEventListener('click', clearLog);
  }

  function boot() {
    state.token = readToken();
    if (!state.token) { location.href = '/'; return; }
    bind();
    refresh();
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
