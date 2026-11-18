/* CUTOFF dashboard — vanilla JS, no build step */
(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const state = {
    token: '',
    devices: [],
    status: null,
    events: [],
    search: '',
    filter: 'all',
    auto: true,
    loading: false,
    scanning: false,
    scanDeep: false,
    lastUpdate: null,
  };

  /* ---------------------------------------------------------------- icons */
  const I = {
    scan: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2v2M8 12v2M2 8h2M12 8h2" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><circle cx="8" cy="8" r="3.2" stroke="currentColor" stroke-width="1.7" fill="none"/></svg>',
    block: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="5.6" stroke="currentColor" stroke-width="1.5" fill="none"/><path d="M4 12 12 4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>',
    check: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="5.6" stroke="currentColor" stroke-width="1.5" fill="none"/><path d="m5.4 8.2 1.7 1.7 3.5-3.8" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    wifi: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M2.2 6.4a8.6 8.6 0 0 1 11.6 0M4.4 8.9a5.4 5.4 0 0 1 7.2 0M6.5 11.2a2.4 2.4 0 0 1 3 0" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round"/><circle cx="8" cy="13.2" r=".9" fill="currentColor"/></svg>',
    pencil: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M10.7 2.9 13 5.2 5.8 12.4l-3 .6.6-3 7.3-7.1Z" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linejoin="round"/></svg>',
    restore: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 3a5 5 0 1 0 5 5" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round"/><path d="M8 1v4h4" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    shield: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2.2 2.9 4.3v3.4c0 2.7 2.2 4.7 5.1 5.6 2.9-.9 5.1-2.9 5.1-5.6V4.3L8 2.2Z" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linejoin="round"/><path d="m5.9 8 1.4 1.4 2.6-2.8" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    alert: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2 1.5 13h13L8 2Z" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linejoin="round"/><path d="M8 6.5v3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><circle cx="8" cy="11.4" r=".9" fill="currentColor"/></svg>',
    info: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="5.8" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M8 7.2v3.2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><circle cx="8" cy="5.2" r=".9" fill="currentColor"/></svg>',
    laptop: '<svg viewBox="0 0 16 16" aria-hidden="true"><rect x="3" y="3.4" width="10" height="6.6" rx="1.2" stroke="currentColor" stroke-width="1.3" fill="none"/><path d="M1.8 12.4h12.4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>',
    phone: '<svg viewBox="0 0 16 16" aria-hidden="true"><rect x="4.6" y="1.8" width="6.8" height="12.4" rx="1.5" stroke="currentColor" stroke-width="1.3" fill="none"/><path d="M7 12.6h2" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>',
    router: '<svg viewBox="0 0 16 16" aria-hidden="true"><rect x="2.2" y="8.4" width="11.6" height="4.4" rx="1.3" stroke="currentColor" stroke-width="1.3" fill="none"/><path d="M5 6.2 8 3.6l3 2.6M8 3.8v3.6" stroke="currentColor" stroke-width="1.3" fill="none" stroke-linecap="round" stroke-linejoin="round"/><circle cx="5.2" cy="10.6" r=".7" fill="currentColor"/><circle cx="7.4" cy="10.6" r=".7" fill="currentColor"/></svg>',
    edit: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 13h2.2l6.4-6.4-2.2-2.2L3 10.8V13Z" stroke="currentColor" stroke-width="1.3" fill="none" stroke-linejoin="round"/><path d="M9.6 3.2 11.8 5.4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>',
  };

  const MOBILE_VENDORS = /apple|samsung|xiaomi|vivo|oppo|oneplus|huawei|lg|sony|google|motorola|realme/i;

  /* --------------------------------------------------------------- helpers */
  const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));

  function relTime(epochOrIso) {
    let ts = epochOrIso;
    if (typeof ts === 'string') ts = Date.parse(ts);
    if (!ts) return '—';
    const diff = Math.max(0, (Date.now() - ts) / 1000);
    if (diff < 45) return `${Math.round(diff)}s ago`;
    if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
    return `${Math.round(diff / 86400)}d ago`;
  }

  function devTitle(dev) {
    if (dev.display_name) return dev.display_name;
    if (dev.name) return dev.name;
    if (dev.hostname) return dev.hostname;
    if (dev.is_self) return 'This host';
    if (dev.vendor && dev.vendor !== 'Unknown' && dev.vendor !== 'Private / randomised MAC') {
      return `${dev.vendor} device`;
    }
    return 'Unknown device';
  }

  function toast(kind, heading, message = '') {
    const root = $('#toasts');
    const el = document.createElement('div');
    el.className = `toast ${kind}`;
    const icon = kind === 'ok' ? I.check : kind === 'err' ? I.block : I.alert;
    el.innerHTML = `${icon}<div><b>${esc(heading)}</b>${message ? `<span>${esc(message)}</span>` : ''}</div>`;
    root.appendChild(el);
    setTimeout(() => {
      el.style.transition = 'opacity .25s, transform .25s';
      el.style.opacity = '0';
      el.style.transform = 'translateY(6px)';
      setTimeout(() => el.remove(), 260);
    }, kind === 'err' ? 7000 : 4600);
  }

  /* ----------------------------------------------------------------- token */
  function readTokenFromUrl() {
    // The backend bakes the token into the page for loopback clients.
    const injected = typeof (window.__CUTOFF_TOKEN__ || window.__NPENT_TOKEN__) === 'string'
      ? (window.__CUTOFF_TOKEN__ || window.__NPENT_TOKEN__).trim()
      : '';
    if (injected) {
      localStorage.setItem('cutoff.token', injected);
      return injected;
    }
    const hash = new URLSearchParams(location.hash.replace(/^#/, ''));
    const query = new URLSearchParams(location.search);
    const token = hash.get('token') || query.get('token');
    if (token) {
      localStorage.setItem('cutoff.token', token);
      history.replaceState(null, '', location.pathname);
      return token;
    }
    return (localStorage.getItem('cutoff.token') || localStorage.getItem('npent.token') || '');
  }

  function showTokenGate(message = '') {
    const root = $('#modalRoot');
    root.innerHTML = `
      <div class="modal" style="width:min(440px,100%)">
        <div class="modal-head">
          <span class="m-icon">${I.shield}</span>
          <div><h3>Unlock CUTOFF</h3><p>Paste the API token generated on the server.</p></div>
        </div>
        <div class="modal-body">
          ${message ? `<div class="note danger">${I.alert}<span>${esc(message)}</span></div>` : ''}
          <label class="field"><span>API token</span>
            <input class="input" id="tokenInput" type="password" autocomplete="off" spellcheck="false" placeholder="token from backend/data/api_token">
          </label>
          <p class="muted" style="font-size:11.5px">Read it with <code>cat /home/blackhat/Documents/CUTOFF/backend/data/api_token</code></p>
        </div>
        <div class="modal-foot">
          <button class="btn primary" id="tokenSave">Unlock</button>
        </div>
      </div>`;
    root.classList.remove('hidden');
    const input = $('#tokenInput');
    setTimeout(() => input.focus(), 40);
    const submit = () => {
      const value = input.value.trim();
      if (!value) return;
      state.token = value;
      localStorage.setItem('cutoff.token', value);
      root.classList.add('hidden');
      root.innerHTML = '';
      refresh();
    };
    $('#tokenSave').addEventListener('click', submit);
    input.addEventListener('keydown', (event) => { if (event.key === 'Enter') submit(); });
  }

  /* ------------------------------------------------------------------- api */
  async function api(path, { method = 'GET', body = null } = {}) {
    const response = await fetch(path, {
      method,
      headers: {
        'X-API-Token': state.token,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    let payload = {};
    try { payload = await response.json(); } catch { /* non-JSON error page */ }
    if (response.status === 401) {
      showTokenGate(payload.detail || 'The API token was rejected.');
      throw new Error('Unauthorized');
    }
    if (!response.ok) {
      const err = new Error(payload.error || `Request failed (${response.status})`);
      err.payload = payload;
      throw err;
    }
    return payload;
  }

  /* -------------------------------------------------------------- rendering */
  function renderStatus() {
    const s = state.status;
    if (!s) return;
    const net = s.network;
    const nl = s.counts;

    $('#statActive').textContent = nl.active;
    $('#statTotal').textContent = `${nl.devices} known · ${nl.offline} offline`;
    $('#statBlocked').textContent = nl.blocked;
    $('#statBlockedNote').textContent = s.simulate ? 'simulated rules' : 'enforced rules';
    $('#statNetwork').textContent = net ? `${net.ip}/${net.prefix}` : 'offline';
    $('#statGateway').textContent = net ? `${net.name}${net.gateway ? ` → ${net.gateway}` : ''}` : 'no route';
    $('#statMode').textContent = s.simulate ? 'Simulated' : 'Live';
    $('#statPriv').textContent = s.privileges.can_enforce
      ? `privilege: ${s.privileges.mode}`
      : 'unprivileged process';

    const chip = $('#netchip');
    const platform = s.platform || {};
    chip.classList.toggle('warn', !net);
    chip.title = `${platform.platform || ''} · ${platform.privilege_mode || ''}` +
      (platform.windows ? ` · ${platform.npcap ? 'Npcap ready' : 'Npcap missing'}` : '');
    $('#netchipText').textContent = net
      ? `${net.name} · ${net.network}${net.wireless ? ' · wi-fi' : ''}`
      : 'no ipv4 network';

    const badge = $('#modeBadge');
    badge.className = `badge ${s.simulate ? 'sim' : 'live'}`;
    badge.textContent = s.simulate ? 'Simulation' : 'Live enforcement';

    $('#simBanner').classList.toggle('hidden', !s.simulate);
    $('#topologyChip').textContent = s.topology === 'gateway'
      ? 'gateway topology'
      : platform.windows
        ? 'host topology · ARP + Windows Firewall'
        : 'host topology · arp interception for internet cuts';
    $('#devCount').textContent = nl.devices;

    const scan = s.scan || {};
    const nmap = s.nmap || {};
    const deepBtn = $('#btnDeepScan');
    if (deepBtn) {
      deepBtn.disabled = Boolean(scan.running) || !nmap.available;
      deepBtn.title = nmap.available
        ? `${nmap.version || 'nmap'} · ports, services, OS, NSE names`
        : (nmap.note || 'nmap not installed');
    }
    if (scan.running) {
      const phase = { discovering: 'discovering…', fingerprinting: 'fingerprinting…', nmap: 'nmap deep scan…' }[scan.phase] || 'scanning…';
      $('#scanMeta').textContent = `${phase}${scan.deep ? ' (deep)' : ''}`;
    } else if (scan.finished_at) {
      const nmapNote = scan.nmap && scan.nmap.ok ? ` · nmap ${scan.nmap.hosts}` : '';
      $('#scanMeta').textContent = `last scan: ${scan.found} found via ${scan.method || '—'}${scan.deep ? ' (deep)' : ''}${nmapNote}`;
    } else {
      $('#scanMeta').textContent = 'scanner idle';
    }
  }

  function deviceIcon(dev) {
    if (dev.is_gateway) return { cls: 'router', svg: I.router };
    if (MOBILE_VENDORS.test(dev.vendor || '')) return { cls: 'phone', svg: I.phone };
    return { cls: '', svg: I.laptop };
  }

  function rowFor(dev) {
    const icon = deviceIcon(dev);
    const name = devTitle(dev);
    const subParts = [];
    if (dev.name && dev.hostname) subParts.push(dev.hostname);
    if (dev.model) subParts.push(dev.model);
    if (dev.device_type) subParts.push(dev.device_type);
    if (!subParts.length) subParts.push(dev.vendor || 'unknown vendor');
    const sub = subParts.join(' · ');
    const v6 = Array.isArray(dev.ip6) ? dev.ip6 : [];
    const tags = [
      dev.is_self ? '<span class="tag self">this host</span>' : '',
      dev.is_gateway ? '<span class="tag gw">gateway</span>' : '',
      v6.length ? `<span class="tag" title="${esc(v6.join('\n'))}">v6 ×${v6.length}</span>` : '',
    ].join('');
    const blocked = dev.blocked;
    const status = blocked ? 'blocked' : dev.active ? 'active' : 'offline';
    const statusLabel = blocked ? 'Blocked' : dev.active ? 'Online' : 'Offline';
    const simTag = blocked && dev.block && dev.block.simulated ? ' <span class="tag">sim</span>' : '';
    const isoTag = blocked && dev.block && dev.block.isolation === 'full' ? ' <span class="tag danger">full</span>' : '';

    return `
      <tr class="${blocked ? 'blocked' : ''} ${status === 'offline' ? 'offline' : ''}" data-mac="${esc(dev.mac)}">
        <td>
          <div class="dev">
            <span class="avatar ${icon.cls}">${icon.svg}</span>
            <div class="dev-text">
              <div class="dev-name">${esc(name)}${tags}</div>
              <div class="dev-sub">${esc(sub)}</div>
            </div>
          </div>
        </td>
        <td><span class="mono">${esc(dev.ip || '—')}</span></td>
        <td><span class="mono dim">${esc(dev.mac)}</span></td>
        <td class="col-vendor"><span class="vendor">${esc(dev.vendor || 'Unknown')}${dev.services && dev.services.length ? `<span class="svc-count" title="${esc(dev.services.join(', '))}">${dev.services.length} svc</span>` : ''}</span></td>
        <td class="col-seen"><span class="seen">${relTime(dev.last_seen_epoch ? dev.last_seen_epoch * 1000 : Date.parse(dev.last_seen || 0))}</span></td>
        <td><span class="status ${status}">${statusLabel}${simTag}${isoTag}</span></td>
        <td class="col-actions">
          <div class="row-actions">
            ${blocked
              ? `<button class="btn sm ghost" data-action="unblock" title="Remove firewall rules and interception">${I.check} Unblock</button>`
              : `<button class="btn sm danger" data-action="block" ${dev.is_self ? 'disabled title="This is your own machine"' : ''}>${I.block} Block</button>`}
            <button class="btn sm ghost icon" data-action="details" title="All discovered details">${I.info}</button>
            <button class="btn sm ghost icon" data-action="wifi" title="Send Wi-Fi deauthentication">${I.wifi}</button>
            <button class="btn sm ghost icon" data-action="rename" title="Rename device">${I.pencil}</button>
          </div>
        </td>
      </tr>`;
  }

  function renderDevices() {
    const query = state.search.trim().toLowerCase();
    const rows = state.devices.filter((dev) => {
      if (state.filter === 'active' && dev.status !== 'active') return false;
      if (state.filter === 'blocked' && dev.status !== 'blocked') return false;
      if (state.filter === 'offline' && dev.status !== 'offline') return false;
      if (!query) return true;
      return [dev.name, dev.hostname, dev.ip, dev.mac, dev.vendor]
        .filter(Boolean).join(' ').toLowerCase().includes(query);
    });

    $('#deviceRows').innerHTML = rows.map(rowFor).join('');
    const empty = $('#emptyState');
    empty.classList.toggle('hidden', rows.length > 0);
    if (!rows.length) {
      const filtering = query || state.filter !== 'all';
      $('#emptyTitle').textContent = filtering ? 'No matching devices' : 'No devices yet';
      $('#emptyText').textContent = filtering
        ? 'Try a different search or filter.'
        : 'Run a scan to discover the devices on your network.';
      $('#emptyScan').classList.toggle('hidden', Boolean(filtering));
    }
    $('#devCount').textContent = state.devices.length;
  }

  function eventIcon(kind) {
    if (kind === 'block') return { cls: 'block', svg: I.block };
    if (kind === 'unblock' || kind === 'panic') return { cls: 'ok', svg: I.check };
    if (kind === 'wifi') return { cls: 'warn', svg: I.wifi };
    if (kind === 'scan') return { cls: '', svg: I.scan };
    if (kind === 'name') return { cls: '', svg: I.pencil };
    return { cls: '', svg: I.info };
  }

  function renderEvents() {
    const list = $('#events');
    const data = state.events.slice(0, 40);
    list.innerHTML = data.map((event) => {
      const icon = eventIcon(event.kind);
      return `
        <li>
          <span class="ev-icon ${icon.cls}">${icon.svg}</span>
          <div class="ev-body">
            <div class="ev-msg">${esc(event.message)}</div>
            <div class="ev-meta">
              <span>${esc(event.ts.replace('T', ' ').replace('+00:00', ' UTC'))}</span>
              ${event.mac ? `<span>${esc(event.mac)}</span>` : ''}
              ${event.simulated ? '<span class="ev-sim">simulated</span>' : ''}
            </div>
          </div>
        </li>`;
    }).join('');
    $('#eventCount').textContent = state.events.length;
    $('#eventsEmpty').classList.toggle('hidden', state.events.length > 0);
  }

  /* ----------------------------------------------------------------- loading */
  async function doRefresh({ quiet = false } = {}) {
    if (!state.token) return;
    state.loading = true;
    try {
      const [status, devices, events] = await Promise.all([
        api('/api/status'),
        api('/api/devices'),
        api('/api/events?limit=60'),
      ]);
      state.status = status;
      state.devices = devices.devices || [];
      state.events = events.events || [];
      state.lastUpdate = Date.now();
      renderStatus();
      renderDevices();
      renderEvents();
      $('#lastUpdated').textContent = `updated ${relTime(state.lastUpdate)}`;
      if (status.scan && status.scan.running) startScanPolling();
    } catch (err) {
      if (!quiet && err.message !== 'Unauthorized') toast('err', 'Cannot reach backend', err.message);
    } finally {
      state.loading = false;
    }
  }

  // Serialise refreshes: an action-triggered refresh must never be dropped
  // just because the periodic poll happened to be in flight.
  let refreshChain = Promise.resolve();
  function refresh(options = {}) {
    refreshChain = refreshChain.then(() => doRefresh(options)).catch(() => {});
    return refreshChain;
  }

  /* ------------------------------------------------------------------- scan */
  function setScanning(on, deep = state.scanDeep) {
    state.scanning = on;
    state.scanDeep = Boolean(deep);
    const btn = $('#btnScan');
    btn.disabled = on;
    btn.classList.toggle('busy', on);
    $('#scanLabel').textContent = on ? (deep ? 'Deep scanning…' : 'Scanning…') : 'Scan network';
    const deepBtn = $('#btnDeepScan');
    if (deepBtn) {
      const nmapReady = !!(state.status && state.status.nmap && state.status.nmap.available);
      deepBtn.disabled = on || !nmapReady;
      deepBtn.classList.toggle('busy', on && deep);
      $('#deepScanLabel').textContent = on && deep ? 'Deep scanning…' : 'Deep scan';
    }
  }

  async function startScan(deep = false) {
    if (state.scanning) return;
    setScanning(true, deep);
    try {
      await api('/api/scan', { method: 'POST', body: { deep } });
      toast('ok', deep ? 'Deep scan started' : 'Scan started',
        deep ? 'nmap ports, services, OS and name scripts are running.' : 'Probing the local network for live hosts.');
      startScanPolling();
    } catch (err) {
      setScanning(false);
      toast('err', 'Scan failed', err.message);
    }
  }

  let scanTimer = null;
  function startScanPolling() {
    if (scanTimer) return;
    setScanning(true);
    const phaseText = { discovering: 'discovering…', fingerprinting: 'fingerprinting…', nmap: 'nmap deep scan…' };
    scanTimer = setInterval(async () => {
      try {
        const scan = await api('/api/scan');
        if (scan.running) {
          setScanning(true, scan.deep);
          $('#scanMeta').textContent = phaseText[scan.phase] || 'scanning…';
          return;
        }
        clearInterval(scanTimer);
        scanTimer = null;
        setScanning(false);
        if (scan.error) {
          toast('err', 'Scan failed', scan.error);
        } else {
          const nmapNote = scan.nmap && scan.nmap.ok ? ` · nmap ${scan.nmap.hosts} hosts` : '';
          toast('ok', 'Scan complete', `${scan.found} devices found (${scan.new} new) via ${scan.method}${nmapNote}`);
        }
        if (scan.warnings && scan.warnings.length) {
          toast('warn', 'Scan warnings', scan.warnings.join(' · '));
        }
        refresh();
      } catch (err) {
        clearInterval(scanTimer);
        scanTimer = null;
        setScanning(false);
        if (err.message !== 'Unauthorized') toast('err', 'Scan status lost', err.message);
      }
    }, 900);
  }

  /* ----------------------------------------------------------------- modals */
  function closeModal() {
    const root = $('#modalRoot');
    root.classList.add('hidden');
    root.innerHTML = '';
  }

  function openModal({ tone = '', icon = I.info, heading, subtitle = '', body = '',
    confirmLabel = 'Confirm', confirmTone = 'primary', cancelLabel = 'Cancel',
    hideConfirm = false, wide = false, onConfirm = null }) {
    const root = $('#modalRoot');
    root.innerHTML = `
      <div class="modal ${wide ? 'modal-lg' : ''}">
        <div class="modal-head ${tone}">
          <span class="m-icon">${icon}</span>
          <div><h3>${esc(heading)}</h3>${subtitle ? `<p>${esc(subtitle)}</p>` : ''}</div>
          <button class="modal-close" data-close aria-label="Close">×</button>
        </div>
        <div class="modal-body">${body}</div>
        <div class="modal-foot">
          <button class="btn ghost" data-close>${esc(cancelLabel)}</button>
          ${hideConfirm ? '' : `<button class="btn ${confirmTone}" data-confirm>${esc(confirmLabel)}</button>`}
        </div>
      </div>`;
    root.classList.remove('hidden');
    const modal = $('.modal', root);
    root.onmousedown = (event) => { if (event.target === root) closeModal(); };
    $$('[data-close]', root).forEach((btn) => btn.addEventListener('click', closeModal));

    const confirm = $('[data-confirm]', root);
    if (confirm) {
      confirm.addEventListener('click', async () => {
        if (!onConfirm) return closeModal();
        const label = confirm.textContent;
        confirm.disabled = true;
        confirm.textContent = 'Working…';
        try {
          const keep = await onConfirm(modal);
          if (keep !== false) closeModal();
        } catch (err) {
          toast('err', 'Action failed', err.message);
          if (err.payload && err.payload.warnings && err.payload.warnings.length) {
            toast('warn', 'Warnings', err.payload.warnings.join(' · '));
          }
        } finally {
          confirm.disabled = false;
          confirm.textContent = label;
        }
      });
    }
    return modal;
  }

  function bindChoices(modal) {
    $$('.choice', modal).forEach((choice) => {
      const input = $('input', choice);
      const sync = () => {
        $$('.choice', modal).forEach((c) => c.classList.toggle('selected', $('input', c).checked));
      };
      input.addEventListener('change', sync);
      sync();
    });
  }

  /* ---------------------------------------------------------------- actions */
  function openDetails(dev) {
    const info = dev.info || {};
    const names = dev.names || {};
    const ports = Array.isArray(dev.ports) ? dev.ports : [];
    const scripts = (info.nmap && info.nmap.scripts) || {};
    const v6list = Array.isArray(dev.ip6) ? dev.ip6 : [];
    const identityRows = [
      ['Status', dev.status],
      ['IP address', dev.ip],
      ['IPv6', v6list.length ? v6list.join(', ') : ''],
      ['MAC address', dev.mac],
      ['Vendor', dev.vendor],
      ['Manufacturer', dev.manufacturer],
      ['Model', dev.model],
      ['Type', dev.device_type],
      ['OS', dev.os],
      ['Page title', dev.title],
      ['First seen', dev.first_seen],
      ['Last seen', dev.last_seen],
    ].filter(([, value]) => value)
      .map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('');

    const nameRows = Object.entries(names)
      .map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('');

    const sources = (dev.sources || []).map((source) => `<span class="chip">${esc(source)}</span>`).join('');

    const selfRows = info.self ? [
      ['Hostname', info.self.hostname],
      ['Platform', info.self.platform],
      ['Kernel', info.self.kernel],
      ['Architecture', info.self.machine],
      ['Python', info.self.python],
      ['Addresses', (info.self.addresses || []).join(', ')],
    ].filter(([, value]) => value)
      .map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('') : '';

    const portRows = ports.map((port) => `
      <tr>
        <td class="mono">${esc(port.port)}/${esc(port.proto || 'tcp')}</td>
        <td>${esc(port.service || '—')}</td>
        <td>${esc([port.product, port.version].filter(Boolean).join(' ') || '—')}</td>
      </tr>`).join('');

    const scriptBlocks = Object.entries(scripts).map(([id, output]) => `
      <div class="script-block">
        <div class="script-id">${esc(id)}</div>
        <pre>${esc(String(output).slice(0, 3000))}</pre>
      </div>`).join('');

    const body = `
      <div class="detail-section">
        <h4>Identity</h4>
        <dl class="detail-grid">${identityRows || '<div><dt>—</dt><dd>no identity data yet</dd></div>'}</dl>
      </div>
      ${sources ? `<div class="detail-section"><h4>Discovered via</h4><div class="chips">${sources}</div></div>` : ''}
      ${selfRows ? `<div class="detail-section"><h4>This machine</h4><dl class="detail-grid">${selfRows}</dl></div>` : ''}
      ${nameRows ? `<div class="detail-section"><h4>Names</h4><dl class="detail-grid">${nameRows}</dl></div>` : ''}
      <div class="detail-section">
        <h4>Open ports <span class="muted">${ports.length}</span></h4>
        ${portRows ? `<table class="port-table">
          <thead><tr><th>Port</th><th>Service</th><th>Product</th></tr></thead>
          <tbody>${portRows}</tbody></table>`
          : '<p class="muted">No ports recorded. Run <b>Deep scan</b> to enumerate services with nmap.</p>'}
      </div>
      ${scriptBlocks ? `<div class="detail-section"><h4>nmap scripts</h4>${scriptBlocks}</div>` : ''}
      <details class="raw">
        <summary>Raw evidence (JSON)</summary>
        <pre>${esc(JSON.stringify(info, null, 2))}</pre>
      </details>`;

    openModal({
      icon: I.info,
      heading: devTitle(dev),
      subtitle: `${dev.mac}${dev.ip ? ` · ${dev.ip}` : ''}`,
      body,
      wide: true,
      hideConfirm: true,
      cancelLabel: 'Close',
    });
  }


  function openBlock(dev) {
    const ip = dev.ip || '';
    const isHost = state.status && state.status.topology !== 'gateway';
    const v6 = Array.isArray(dev.ip6) ? dev.ip6 : [];
    const ip6Available = Boolean(state.status && state.status.ipv6 && state.status.ipv6.available);
    // Only a global/ULA address has a /64 worth blocking; fe80::/64 is shared
    // with this host, so the checkbox stays hidden for link-local-only devices.
    const v6Prefix = v6.find((a) => !a.startsWith('fe80:') && !a.startsWith('ff'));
    const body = `
      <dl class="kv">
        <dt>Device</dt><dd>${esc(devTitle(dev))}</dd>
        <dt>IPv4 address</dt><dd>${esc(ip || 'unknown')}</dd>
        <dt>IPv6 address</dt><dd>${v6.length ? v6.map((a) => `<span class="mono">${esc(a)}</span>`).join('<br>') : (ip6Available ? 'none seen yet — MAC rule still applies' : 'IPv6 unavailable on this host')}</dd>
        <dt>MAC address</dt><dd>${esc(dev.mac)}</dd>
        <dt>Vendor</dt><dd>${esc(dev.vendor || 'Unknown')}</dd>
      </dl>
      <div class="choices">
        <label class="choice"><input type="radio" name="mode" value="both" checked>
          <span><b>Everything (recommended)</b><small>Firewall rules on MAC + IP${isHost ? ', plus ARP interception to cut internet' : ''}.</small></span></label>
        <label class="choice"><input type="radio" name="mode" value="mac">
          <span><b>MAC address only</b><small>Layer-2 drop of every frame from this adapter.</small></span></label>
        <label class="choice ${ip ? '' : 'disabled'}"><input type="radio" name="mode" value="ip" ${ip ? '' : 'disabled'}>
          <span><b>IP address only</b><small>${ip ? 'Drops traffic from the current lease; DHCP renewal can evade it.' : 'No IP known for this device.'}</small></span></label>
      </div>
      ${ip6Available ? `<div class="field" style="margin-top:14px"><span>IPv6 (blocked in the same action)</span>
        <div class="note" style="margin-top:6px">${I.info}
          <span>${v6.length
            ? `MAC rule + <b>${v6.length}</b> known address(es): ${esc(v6.slice(0, 3).join(', '))}${v6.length > 3 ? ' …' : ''}`
            : 'No IPv6 address is known for this device yet, so only the MAC rule is installed. Rescan, or enable the /64 option below if the device has a global address.'}</span>
        </div>
        ${v6Prefix && !dev.is_self ? `<label class="choice" style="margin-top:8px"><input type="checkbox" id="prefix6">
          <span><b>Also block the whole IPv6 /64</b><small>SLAAC privacy addresses rotate; the covering prefix for ${esc(v6Prefix)} stays blocked. Every host inside that /64 loses IPv6 reachability.</small></span></label>` : ''}
      </div>` : ''}
      <div class="field" style="margin-top:14px"><span>Block depth</span>
        <div class="choices">
          <label class="choice"><input type="radio" name="isolation" value="full" checked>
            <span><b>Complete isolation</b><small>Blocks inbound and outbound, and poisons every known LAN peer so direct device-to-device traffic is dropped too.</small></span></label>
          <label class="choice"><input type="radio" name="isolation" value="internet">
            <span><b>Internet only</b><small>Blocks gateway traffic in both directions; LAN peers can still reach the device.</small></span></label>
        </div>
      </div>
      <div class="note ${isHost ? 'warn' : ''}">
        ${I.info}
        <span>${isHost
          ? 'This host is not the gateway. iptables drops traffic in both directions, and ARP black-holing cuts the device off the gateway; Complete isolation also poisons every known LAN peer. Refreshed every 2 s and fully restored on unblock.'
          : 'This host is forwarding as a gateway/AP, so the firewall rules cover the device’s whole path.'}</span>
      </div>
      ${dev.is_gateway ? `<div class="note danger">${I.alert}<span><b>This MAC is your gateway.</b> Blocking it disconnects the entire network, including this machine.</span>
        <label style="display:flex;gap:6px;align-items:center;margin-top:6px;font-size:11.5px"><input type="checkbox" id="forceBlock"> I understand, force the block</label></div>` : ''}
      <div class="note warn" style="display:none" id="forceNote">${I.alert}<span>Force is required to block the gateway; tick the box above.</span></div>`;

    const modal = openModal({
      tone: 'danger', icon: I.block, heading: 'Block device',
      subtitle: `${devTitle(dev)} · ${dev.mac}`,
      body, confirmLabel: 'Block device', confirmTone: 'danger',
      onConfirm: async () => {
        const mode = ($('input[name=mode]:checked', modal) || {}).value || 'both';
        const isolation = ($('input[name=isolation]:checked', modal) || {}).value || 'full';
        const forceBox = $('#forceBlock', modal);
        const prefix6Box = $('#prefix6', modal);
        if (dev.is_gateway && (!forceBox || !forceBox.checked)) {
          $('#forceNote', modal).style.display = 'flex';
          return false;
        }
        const result = await api('/api/block', {
          method: 'POST',
          body: {
            mac: dev.mac, mode, isolation,
            force: Boolean(forceBox && forceBox.checked),
            ip6: true,
            ip6_prefix: Boolean(prefix6Box && prefix6Box.checked),
          },
        });
        if (!result.ok) {
          toast('err', 'Block failed', result.error || 'unknown error');
          return false;
        }
        // One action, both families: say exactly what was cut, not how the
        // sausage is made.
        const v6count = (result.ip6 || []).length;
        const families = `IPv4${v6count ? ` + IPv6 (${v6count} addr${v6count === 1 ? '' : 's'})` : ''}`
          + `${(result.ip6_prefixes || []).length ? ` + /64 ${result.ip6_prefixes.join(', ')}` : ''}`;
        if (result.simulated) {
          toast('warn', 'Simulated block — IPv4 + IPv6 modelled',
            'Nothing written to the kernel. Run with sudo for live enforcement.');
        } else {
          toast('ok', `Blocked · ${families}`,
            (result.layers || []).join(' · ') || result.mode);
        }
        if (result.warnings && result.warnings.length) {
          toast('warn', 'Coverage', result.warnings.join(' · '));
        }
        await refresh({ quiet: true });
        return true;
      },
    });
    bindChoices(modal);
  }

  function openUnblock(dev) {
    openModal({
      icon: I.check, heading: 'Unblock device',
      subtitle: `${devTitle(dev)} · ${dev.mac}`,
      body: `<p>Remove every CUTOFF firewall rule for this MAC and stop ARP interception. The device keeps its normal network access again.</p>`,
      confirmLabel: 'Unblock', confirmTone: 'primary',
      onConfirm: async () => {
        const result = await api('/api/unblock', { method: 'POST', body: { mac: dev.mac } });
        toast('ok', 'Device unblocked', `${(result.removed_rules || []).length} rules removed`);
        await refresh({ quiet: true });
        return true;
      },
    });
  }

  function openWifi(dev) {
    const caps = (state.status && state.status.capabilities && state.status.capabilities.wifi) || {};
    const canDeauth = Boolean(caps.can_deauth);
    const body = `
      <dl class="kv">
        <dt>Device</dt><dd>${esc(devTitle(dev))}</dd>
        <dt>MAC address</dt><dd>${esc(dev.mac)}</dd>
        <dt>Adapter</dt><dd>${caps.monitor_interfaces && caps.monitor_interfaces.length ? esc(caps.monitor_interfaces.join(', ')) : 'no monitor-mode interface'}</dd>
        <dt>AP control</dt><dd>${caps.hostapd_cli ? 'hostapd_cli available' : 'hostapd not detected'}</dd>
      </dl>
      ${canDeauth ? '' : `<div class="note warn">${I.alert}<span>${esc(caps.note || 'No AP control or monitor-mode adapter detected.')} Deauth will fail; use <b>Block</b> to cut the device’s traffic instead.</span></div>`}
      <label class="field"><span>Deauth burst</span>
        <div class="range-row">
          <input type="range" id="wifiSeconds" min="2" max="30" value="8" step="1">
          <output id="wifiSecondsOut">8 s</output>
        </div>
      </label>
      <label class="field"><span>AP BSSID (optional, needed for frame injection)</span>
        <input class="input" id="wifiBssid" placeholder="aa:bb:cc:dd:ee:ff" autocomplete="off" spellcheck="false">
      </label>
      <div class="note">${I.info}<span>A deauth only kicks the client off Wi-Fi; it can reconnect unless the block is also active. Block and deauth are independent layers.</span></div>`;

    const modal = openModal({
      tone: 'warn', icon: I.wifi, heading: 'Cut Wi-Fi',
      subtitle: `${devTitle(dev)} · ${dev.mac}`,
      body, confirmLabel: 'Send deauth', confirmTone: 'danger',
      onConfirm: async () => {
        const seconds = Number($('#wifiSeconds', modal).value || 8);
        const bssid = $('#wifiBssid', modal).value.trim();
        const result = await api('/api/wifi/cut', {
          method: 'POST',
          body: { mac: dev.mac, seconds, ...(bssid ? { bssid } : {}) },
        });
        if (result.simulated) {
          toast('warn', 'Simulated deauth', result.detail || 'No frames sent in simulation mode.');
        } else {
          toast('ok', 'Deauth sent', `${result.method} · ${result.sent || 0} frames`);
        }
        await refresh({ quiet: true });
        return true;
      },
    });
    const range = $('#wifiSeconds', modal);
    const output = $('#wifiSecondsOut', modal);
    range.addEventListener('input', () => { output.textContent = `${range.value} s`; });
  }

  function openRename(dev) {
    openModal({
      icon: I.pencil, heading: 'Rename device',
      subtitle: dev.mac,
      body: `<label class="field"><span>Display name</span>
        <input class="input" id="renameInput" maxlength="64" value="${esc(dev.name || '')}" placeholder="e.g. Living room TV" autocomplete="off">
      </label>
      <p class="muted" style="font-size:11.5px">Stored locally in the CUTOFF inventory. Leave empty to fall back to the hostname or vendor.</p>`,
      confirmLabel: 'Save name',
      onConfirm: async (modal) => {
        const name = $('#renameInput', modal).value.trim();
        await api(`/api/devices/${encodeURIComponent(dev.mac)}/name`, { method: 'POST', body: { name } });
        toast('ok', 'Device renamed', name || 'cleared');
        await refresh({ quiet: true });
        return true;
      },
    });
    setTimeout(() => { const input = $('#renameInput'); if (input) { input.focus(); input.select(); } }, 40);
  }

  function openRestore() {
    openModal({
      tone: 'danger', icon: I.restore, heading: 'Restore the network',
      subtitle: 'Remove every CUTOFF rule and interception',
      body: `<p>This stops all ARP interception, deletes the <code>CUTOFF_BLOCK</code> chains, and clears every recorded block. Devices return to normal connectivity.</p>
        <div class="note danger">${I.alert}<span>Any block you configured will be lost. This is the emergency exit — use it if a device you blocked needs immediate access.</span></div>`,
      confirmLabel: 'Restore everything', confirmTone: 'danger',
      onConfirm: async () => {
        const result = await api('/api/panic', { method: 'POST' });
        toast('ok', 'Network restored', `${result.devices_cleared} blocks cleared · ${result.interceptors_stopped} interceptions stopped`);
        await refresh({ quiet: true });
        return true;
      },
    });
  }

  /* ------------------------------------------------------------------ events */
  function bindUi() {
    $('#btnScan').addEventListener('click', () => startScan(false));
    $('#btnDeepScan').addEventListener('click', () => startScan(true));
    $('#emptyScan').addEventListener('click', () => startScan(false));
    $('#btnRestore').addEventListener('click', openRestore);

    $('#search').addEventListener('input', (event) => {
      state.search = event.target.value;
      renderDevices();
    });

    $$('.seg').forEach((button) => {
      button.addEventListener('click', () => {
        $$('.seg').forEach((b) => b.classList.toggle('active', b === button));
        state.filter = button.dataset.filter;
        renderDevices();
      });
    });

    $('#autoRefresh').addEventListener('change', (event) => {
      state.auto = event.target.checked;
    });

    $('#deviceRows').addEventListener('click', (event) => {
      const button = event.target.closest('button[data-action]');
      if (!button) return;
      const row = button.closest('tr[data-mac]');
      const dev = state.devices.find((d) => d.mac === row.dataset.mac);
      if (!dev) return;
      if (button.dataset.action === 'block') openBlock(dev);
      if (button.dataset.action === 'unblock') openUnblock(dev);
      if (button.dataset.action === 'wifi') openWifi(dev);
      if (button.dataset.action === 'rename') openRename(dev);
      if (button.dataset.action === 'details') openDetails(dev);
    });

    $('#btnClearLog').addEventListener('click', async () => {
      try {
        await api('/api/events', { method: 'DELETE' });
        state.events = [];
        renderEvents();
        toast('ok', 'Activity log cleared');
      } catch (err) {
        toast('err', 'Cannot clear log', err.message);
      }
    });

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeModal();
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        $('#search').focus();
      }
    });
  }

  /* -------------------------------------------------------------------- init */
  function boot() {
    state.token = readTokenFromUrl();
    bindUi();
    if (!state.token) {
      showTokenGate();
      return;
    }
    refresh();
    setInterval(() => {
      if (!state.auto || state.scanning) return;
      if (document.visibilityState !== 'visible') return;
      refresh({ quiet: true });
    }, 6000);
    setInterval(() => {
      if (state.lastUpdate) $('#lastUpdated').textContent = `updated ${relTime(state.lastUpdate)}`;
    }, 5000);
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
