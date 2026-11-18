/* CUTOFF network map — draws the gateway and its clients */
(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const SVGNS = 'http://www.w3.org/2000/svg';
  const W = 1000;
  const H = 640;
  const CX = W / 2;
  const CY = H / 2 + 6;

  const state = { token: '', status: null, devices: [], auto: true, timer: null, selected: null, lastUpdate: null };

  const ICONS = {
    router: 'M2 13h20v6H2z M6 10l6-4 6 4 M12 6v7',
    phone: 'M8 2h8v20H8z M10.5 18.5h3',
    laptop: 'M4 4h16v11H4z M2 19h20',
    printer: 'M6 3h12v6H6z M3 9h18v7H3z M6 14h12v7H6z',
    camera: 'M3 7h18v12H3z M8 7l1.5-3h5L16 7 M12 10a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7',
    tv: 'M2 4h20v13H2z M8 21h8 M12 17v4',
    iot: 'M9 9h6v6H9z M12 2v3 M12 19v3 M2 12h3 M19 12h3',
    device: 'M4 4h16v16H4z',
  };

  const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));

  function readToken() {
    const injected = typeof (window.__CUTOFF_TOKEN__ || window.__NPENT_TOKEN__) === 'string' ? (window.__CUTOFF_TOKEN__ || window.__NPENT_TOKEN__).trim() : '';
    if (injected) return injected;
    return (localStorage.getItem('cutoff.token') || localStorage.getItem('npent.token') || '');
  }

  async function api(path) {
    const response = await fetch(path, { headers: { 'X-API-Token': state.token } });
    if (response.status === 401) {
      location.href = '/';
      throw new Error('unauthorized');
    }
    if (!response.ok) throw new Error(`request failed (${response.status})`);
    return response.json();
  }

  function relTime(ms) {
    if (!ms) return '—';
    const seconds = Math.max(0, (Date.now() - ms) / 1000);
    if (seconds < 45) return `${Math.round(seconds)}s ago`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
    return `${Math.round(seconds / 3600)}h ago`;
  }

  function svgEl(tag, attrs = {}, parent = null) {
    const node = document.createElementNS(SVGNS, tag);
    Object.entries(attrs).forEach(([key, value]) => {
      if (value !== undefined && value !== null) node.setAttribute(key, String(value));
    });
    if (parent) parent.appendChild(node);
    return node;
  }

  function devTitle(dev) {
    return dev.display_name || dev.name || dev.hostname || (dev.is_self ? 'This host' : 'Unknown device');
  }

  function iconFor(dev) {
    if (dev.is_gateway) return 'router';
    if (dev.is_self) return 'laptop';
    const type = (dev.device_type || '').toLowerCase();
    if (type === 'workstation' || type === 'computer') return 'laptop';
    if (ICONS[type]) return type;
    return 'device';
  }

  function statusOf(dev) {
    if (dev.blocked) return 'blocked';
    if (dev.active) return 'active';
    return 'offline';
  }

  function shortName(name) {
    const text = String(name || 'Unknown');
    return text.length > 22 ? `${text.slice(0, 21)}…` : text;
  }

  /* ------------------------------------------------------------- layout */
  function positions(count) {
    const points = [];
    if (!count) return points;
    const radiusX = count > 8 ? 360 : 320;
    const radiusY = count > 8 ? 250 : 225;
    for (let index = 0; index < count; index += 1) {
      const angle = -Math.PI / 2 + (index * 2 * Math.PI) / count;
      points.push({
        x: CX + Math.cos(angle) * radiusX,
        y: CY + Math.sin(angle) * radiusY,
      });
    }
    return points;
  }

  /* ------------------------------------------------------------- render */
  function render() {
    const svg = $('#mapSvg');
    svg.innerHTML = '';
    const devices = state.devices || [];
    const gateway = devices.find((dev) => dev.is_gateway);
    const clients = devices.filter((dev) => !dev.is_gateway);

    $('#mapCount').textContent = clients.length;

    if (!devices.length) {
      $('#mapEmpty').classList.remove('hidden');
      return;
    }
    $('#mapEmpty').classList.add('hidden');

    // faint orbit ring
    svgEl('ellipse', {
      cx: CX, cy: CY, rx: clients.length > 8 ? 360 : 320, ry: clients.length > 8 ? 250 : 225,
      fill: 'none', stroke: 'rgba(255,255,255,.05)', 'stroke-dasharray': '3 8',
    }, svg);

    const points = positions(clients.length);

    // links first so nodes sit on top
    clients.forEach((dev, index) => {
      const point = points[index];
      const link = svgEl('line', {
        x1: CX, y1: CY, x2: point.x, y2: point.y,
        class: `link ${statusOf(dev)}`,
      }, svg);
      if (dev.blocked) link.setAttribute('stroke-dasharray', '5 7');
    });

    // gateway node
    const gatewayLabel = gateway ? devTitle(gateway) : 'Gateway';
    const gatewayIp = gateway ? gateway.ip : (state.status?.network?.gateway || 'unknown');
    const gatewayGroup = svgEl('g', {
      class: 'node gateway active', transform: `translate(${CX},${CY})`,
      tabindex: '0', role: 'button', 'aria-label': `Gateway ${gatewayIp}`,
    }, svg);
    svgEl('circle', { r: 54, class: 'node-halo' }, gatewayGroup);
    svgEl('circle', { r: 42, class: 'node-core gateway-core' }, gatewayGroup);
    const gatewayIcon = svgEl('g', { class: 'glyph', transform: 'translate(-14,-14) scale(1.15)' }, gatewayGroup);
    svgEl('path', { d: ICONS.router }, gatewayIcon);
    svgEl('text', { y: 66, class: 'node-name gateway-name' }, gatewayGroup).textContent = 'Gateway';
    svgEl('text', { y: 80, class: 'node-ip' }, gatewayGroup).textContent = gatewayIp;
    const gatewayTip = gateway
      ? `${gatewayLabel} · ${gateway.mac || ''}`
      : `Gateway · ${gatewayIp}`;
    bindNode(gatewayGroup, gateway, gatewayTip);

    // client nodes
    clients.forEach((dev, index) => {
      const point = points[index];
      const status = statusOf(dev);
      const group = svgEl('g', {
        class: `node ${status} ${dev.is_self ? 'self' : ''}`,
        transform: `translate(${point.x},${point.y})`,
        tabindex: '0', role: 'button',
        'aria-label': `${devTitle(dev)} ${dev.ip || ''}`,
      }, svg);

      if (dev.is_self) svgEl('circle', { r: 40, class: 'node-halo self-halo' }, group);
      else if (dev.blocked) svgEl('circle', { r: 38, class: 'node-halo danger-halo' }, group);
      else svgEl('circle', { r: 36, class: 'node-halo' }, group);

      svgEl('circle', { r: 27, class: 'node-core' }, group);
      const glyph = svgEl('g', { class: 'glyph', transform: 'translate(-12,-12)' }, group);
      svgEl('path', { d: ICONS[iconFor(dev)] }, glyph);

      svgEl('text', { y: 48, class: 'node-name' }, group).textContent = shortName(devTitle(dev));
      svgEl('text', { y: 62, class: 'node-ip' }, group).textContent = dev.ip || '—';
      if (dev.blocked) {
        svgEl('text', { y: -34, class: 'node-badge' }, group).textContent = 'BLOCKED';
      }

      bindNode(group, dev, `${devTitle(dev)} · ${dev.ip || ''}`);
    });
  }

  function bindNode(group, dev, tip) {
    const show = (event) => {
      const tooltip = $('#mapTooltip');
      tooltip.textContent = tip;
      tooltip.classList.remove('hidden');
      const rect = $('#mapStage').getBoundingClientRect();
      tooltip.style.left = `${Math.min(event.clientX - rect.left + 14, rect.width - 220)}px`;
      tooltip.style.top = `${Math.max(8, event.clientY - rect.top - 36)}px`;
    };
    group.addEventListener('mouseenter', show);
    group.addEventListener('mousemove', show);
    group.addEventListener('mouseleave', () => $('#mapTooltip').classList.add('hidden'));
    group.addEventListener('click', () => {
      if (dev) showDetail(dev);
    });
    group.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        if (dev) showDetail(dev);
      }
    });
  }

  function showDetail(dev) {
    state.selected = dev.mac;
    const panel = $('#mapDetail');
    const rows = [
      ['IP address', dev.ip],
      ['MAC address', dev.mac],
      ['Type', dev.device_type],
      ['Vendor', dev.vendor],
      ['Model', dev.model],
      ['OS', dev.os],
      ['Status', dev.status || statusOf(dev)],
      ['Block', dev.block ? `${dev.block.isolation || 'internet'} · ${dev.block.mode}` : 'not blocked'],
      ['Last seen', dev.last_seen ? String(dev.last_seen).replace('T', ' ').replace('+00:00', ' UTC') : ''],
    ].filter(([, value]) => value);

    const services = (dev.services || []).map((service) => `<span class="chip">${esc(service)}</span>`).join('');
    panel.innerHTML = `
      <button class="map-detail-close" id="closeDetail" aria-label="Close">×</button>
      <div class="md-head">
        <span class="avatar ${dev.is_gateway ? 'router' : ''}">${iconSvg(iconFor(dev))}</span>
        <div><h3>${esc(devTitle(dev))}</h3><p>${esc(dev.ip || '—')} · ${esc(dev.mac)}</p></div>
      </div>
      ${dev.is_self ? '<div class="note" style="margin:10px 0">This is the machine running CUTOFF.</div>' : ''}
      ${dev.blocked ? `<div class="note danger" style="margin:10px 0">Blocked (${esc(dev.block?.isolation || 'internet')} isolation) — inbound and outbound traffic is dropped.</div>` : ''}
      <dl class="detail-grid detail-grid-one">${rows.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl>
      ${services ? `<div class="md-services"><span class="md-label">Services</span><div class="chips">${services}</div></div>` : ''}
      <div class="md-actions"><a class="btn ghost sm" href="/">Open in devices</a></div>`;
    panel.classList.remove('hidden');
    $('#closeDetail').addEventListener('click', hideDetail);
  }

  function iconSvg(name) {
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="${ICONS[name] || ICONS.device}"/></svg>`;
  }

  function hideDetail() {
    state.selected = null;
    $('#mapDetail').classList.add('hidden');
  }

  /* ------------------------------------------------------------- chrome */
  function renderChrome() {
    const status = state.status;
    if (!status) return;
    const net = status.network;
    const counts = status.counts || {};

    $('#statGateway').textContent = net ? (net.gateway || '—') : '—';
    $('#statGatewayMac').textContent = net?.gateway_mac ? net.gateway_mac : 'gateway MAC unknown';
    $('#statConnected').textContent = counts.active ?? '—';
    $('#statConnectedNote').textContent = `${counts.devices ?? 0} known · ${counts.offline ?? 0} offline`;
    $('#statBlocked').textContent = counts.blocked ?? '—';
    $('#statBlockedNote').textContent = status.simulate ? 'simulated rules' : 'inbound + outbound';
    $('#statSegments').textContent = net ? '1' : '—';
    $('#statSegmentsNote').textContent = net ? net.network : 'no network';

    const badge = $('#modeBadge');
    badge.className = `badge ${status.simulate ? 'sim' : 'live'}`;
    badge.textContent = status.simulate ? 'Simulation' : 'Live enforcement';
    $('#simBanner').classList.toggle('hidden', !status.simulate);

    const chip = $('#netchip');
    chip.classList.toggle('warn', !net);
    $('#netchipText').textContent = net ? `${net.name} · ${net.network}` : 'no ipv4 network';
    $('#mapMeta').textContent = net
      ? `${net.name} · ${net.wireless ? 'wi-fi' : 'wired'} · ${status.topology} topology`
      : 'no network';
  }

  /* -------------------------------------------------------------- loading */
  let loading = false;
  async function refresh() {
    if (loading) return;
    loading = true;
    try {
      const [status, devices] = await Promise.all([api('/api/status'), api('/api/devices')]);
      state.status = status;
      state.devices = devices.devices || [];
      state.lastUpdate = Date.now();
      renderChrome();
      render();
      $('#mapUpdated').textContent = `updated ${relTime(Date.now())}`;
      if (state.selected) {
        const again = state.devices.find((dev) => dev.mac === state.selected);
        if (again) showDetail(again);
      }
    } catch (error) {
      if (error.message !== 'unauthorized') {
        toast(`Cannot reach backend: ${error.message}`);
      }
    } finally {
      loading = false;
    }
  }

  function toast(message) {
    const root = $('#toasts');
    const item = document.createElement('div');
    item.className = 'toast err';
    item.innerHTML = `<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="5.6" stroke="currentColor" stroke-width="1.5" fill="none"/><path d="M4 12 12 4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg><div><b>Network map</b><span>${esc(message)}</span></div>`;
    root.appendChild(item);
    setTimeout(() => item.remove(), 5000);
  }

  function bind() {
    $('#btnRefresh').addEventListener('click', refresh);
    $('#autoRefresh').addEventListener('change', (event) => {
      state.auto = event.target.checked;
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') hideDetail();
    });
    setInterval(() => {
      if (!state.auto || document.visibilityState !== 'visible') return;
      refresh();
    }, 6000);
    setInterval(() => {
      $('#mapUpdated').textContent = `updated ${relTime(state.lastUpdate)}`;
    }, 5000);
  }

  function boot() {
    state.token = readToken();
    if (!state.token) {
      location.href = '/';
      return;
    }
    bind();
    refresh();
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
