/* CUTOFF IPv6 console: addresses, NDP neighbours, prefix + MAC rules. */
(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));

  const state = { token: '', data: null, timer: null, filter: 'all', busy: false };

  const readToken = () => (typeof (window.__CUTOFF_TOKEN__ || window.__NPENT_TOKEN__) === 'string' && (window.__CUTOFF_TOKEN__ || window.__NPENT_TOKEN__).trim())
    || (localStorage.getItem('cutoff.token') || localStorage.getItem('npent.token') || '');

  async function api(path, options = {}) {
    const response = await fetch(path, {
      method: options.method || 'GET',
      headers: {
        'X-API-Token': state.token,
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    if (response.status === 401) { location.href = '/'; throw new Error('unauthorized'); }
    let payload = {};
    try { payload = await response.json(); } catch { /* empty body */ }
    if (!response.ok) throw new Error(payload.error || `request failed (${response.status})`);
    return payload;
  }

  function toast(kind, title, message = '') {
    const item = document.createElement('div');
    item.className = `toast ${kind}`;
    item.innerHTML = `<div><b>${esc(title)}</b>${message ? `<span>${esc(message)}</span>` : ''}</div>`;
    $('#toasts').appendChild(item);
    setTimeout(() => item.remove(), kind === 'err' ? 7000 : 4500);
  }

  // Raw scope codes are internal; the table says what the rule actually does.
  const SCOPE_LABEL = {
    l2: 'mac · in', l3: 'addr · in', l3out: 'addr · out',
    v6l2: 'mac · in', v6l3: 'addr · in', v6l3out: 'addr · out',
    pfxl3: 'prefix · in', pfxout: 'prefix · out',
  };
  const scopeLabel = (scope) => SCOPE_LABEL[scope] || scope;

  const scopeTag = (scope) => {
    const cls = scope === 'global' ? 'self' : scope === 'ula' ? 'gw'
      : scope === 'link-local' ? '' : 'danger';
    return `<span class="tag ${cls}">${esc(scope || 'unknown')}</span>`;
  };

  /* ------------------------------------------------------------------ render */
  function renderHeader(data) {
    const caps = data.capabilities || {};
    $('#modeBadge').textContent = caps.simulated ? 'SIMULATION' : 'LIVE';
    $('#modeBadge').className = `badge ${caps.simulated ? 'sim' : 'live'}`;

    const banner = $('#v6Banner');
    const text = $('#v6BannerText');
    if (!data.supported) {
      banner.classList.remove('hidden');
      text.innerHTML = '<strong>IPv6 is disabled on this host.</strong> No address, no neighbour cache and no ip6tables work is possible until the stack is enabled.';
    } else if (caps.simulated) {
      banner.classList.remove('hidden');
      text.innerHTML = '<strong>Simulation mode.</strong> IPv6 rules are modelled and shown, but nothing is written to the kernel. Re-launch with <code>sudo ./run.sh</code> to enforce.';
    } else if (!data.has_global) {
      banner.classList.remove('hidden');
      text.innerHTML = '<strong>Link-local only.</strong> This link has no global IPv6 prefix, so peers can only reach you over <code>fe80::/10</code>. Prefix blocking has nothing global to act on.';
    } else {
      banner.classList.add('hidden');
    }

    $('#netchipText').textContent = data.interface
      ? `${data.interface} · ${data.has_global ? 'global v6' : 'link-local'}`
      : 'no interface';

    const addrs = data.addresses || [];
    const global = addrs.filter((a) => a.class === 'global').length;
    $('#statV6State').textContent = data.supported ? (data.enabled ? 'On' : 'Off') : 'Disabled';
    $('#statV6Note').textContent = `${addrs.length} address(es) · ${global} global`;
    $('#statV6Prefixes').textContent = (data.prefixes || []).length;
    $('#statV6Addrs').textContent = data.has_link_local ? 'link-local present' : 'no link-local';
    $('#statV6Neigh').textContent = (data.neighbours || []).length;
    $('#statV6Known').textContent = `${(data.neighbours || []).filter((n) => n.known).length} in inventory`;
    $('#statV6Rules').textContent = (data.rules || []).length;
    $('#statV6RuleNote').textContent = `${(data.prefix_rules || []).length} prefix rule(s)`;
    $('#v6Ifaces').textContent = data.interface ? `interface ${data.interface}` : 'no interface';
    $('#scopeNote').textContent = data.forwarding
      ? 'This host has IPv6 forwarding enabled: it is routing v6 traffic, so the FORWARD drops apply to every client that routes through it.'
      : 'On an ordinary LAN host, ip6tables only filters traffic addressed to this machine; a LAN-wide IPv6 block needs CUTOFF running on the gateway or AP. ARP interception does not cover IPv6 — the MAC and prefix rules above are what close that gap.';
  }

  function renderOwn(data) {
    const rows = data.addresses || [];
    $('#ownCount').textContent = rows.length;
    $('#ownRows').innerHTML = rows.length ? rows.map((a) => `
      <tr>
        <td class="mono">${esc(a.address)}</td>
        <td>${scopeTag(a.class)}</td>
        <td class="mono dim">${esc(a.network || '—')}</td>
        <td>${[a.dynamic ? '<span class="tag">slaac</span>' : '',
               a.temporary ? '<span class="tag">privacy</span>' : '',
               a.deprecated ? '<span class="tag danger">deprecated</span>' : ''].join(' ') || '<span class="muted">static</span>'}</td>
      </tr>`).join('')
      : '<tr><td colspan="4" class="muted">No IPv6 address on this interface.</td></tr>';
  }

  function renderPrefixes(data) {
    const detected = Object.entries(data.guest_prefixes || {});
    const blocked = data.prefix_rules || [];
    const blockedSet = new Set(blocked.map((r) => r.key));
    $('#prefixCount').textContent = blocked.length;

    const own = new Set(data.own_prefixes || []);
    $('#prefixChips').innerHTML = detected.length ? detected.map(([prefix, count]) => `
      <span class="chip">
        <span class="mono">${esc(prefix)}</span>
        <span class="muted">${count} host${count === 1 ? '' : 's'}</span>
        ${blockedSet.has(prefix)
          ? `<button class="btn sm ghost" data-unprefix="${esc(prefix)}">Unblock</button>`
          : own.has(prefix)
            ? '<span class="tag gw">this host</span>'
            : `<button class="btn sm danger" data-prefix="${esc(prefix)}">Block</button>`}
      </span>`).join('')
      : '<span class="muted" style="padding:2px 0">No peer prefix seen in the NDP cache yet.</span>';

    $('#prefixRows').innerHTML = blocked.length ? blocked.map((r) => `
      <tr>
        <td class="mono">${esc(r.key)}</td>
        <td><span class="tag">${esc(scopeLabel(r.scope))}</span></td>
        <td class="col-actions"><div class="row-actions">
          <button class="btn sm ghost" data-unprefix="${esc(r.key)}">Unblock</button>
        </div></td>
      </tr>`).join('')
      : '<tr><td colspan="3" class="muted">No prefix is blocked.</td></tr>';
  }

  function renderNeighbours(data) {
    const all = data.neighbours || [];
    const rows = all.filter((n) => state.filter === 'all' || n.class === state.filter);
    $('#neighCount').textContent = all.length;
    $('#neighEmpty').classList.toggle('hidden', rows.length > 0);
    $('#neighRows').innerHTML = rows.map((n) => `
      <tr${n.blocked ? ' style="background:rgba(255,92,114,.06)"' : ''}>
        <td class="mono">${esc(n.ip)}</td>
        <td>${scopeTag(n.class)}</td>
        <td class="mono dim">${esc(n.mac || '—')}</td>
        <td>${n.name ? esc(n.name) : (n.known ? '<span class="muted">unnamed</span>' : '<span class="muted">not in inventory</span>')}
            ${n.router ? '<span class="tag gw">router</span>' : ''}
            ${n.blocked ? '<span class="tag danger">blocked</span>' : ''}</td>
        <td><span class="tag ${n.state === 'REACHABLE' ? 'self' : ''}">${esc(n.state)}</span></td>
        <td class="col-actions"><div class="row-actions">
          ${n.mac ? (n.blocked
            ? `<button class="btn sm ghost" data-unblock="${esc(n.mac)}">Unblock</button>`
            : `<button class="btn sm danger" data-block="${esc(n.mac)}">Block</button>`) : '<span class="muted">no MAC</span>'}
        </div></td>
      </tr>`).join('');
  }

  function renderRules(data) {
    const rules = data.rules || [];
    $('#ruleCount').textContent = rules.length;
    $('#ruleEmpty').classList.toggle('hidden', rules.length > 0);
    $('#ruleRows').innerHTML = rules.map((r) => `
      <tr>
        <td class="mono dim">${esc(r.chain)}</td>
        <td><span class="tag">${esc(r.kind)}</span></td>
        <td class="mono">${esc(r.key)}</td>
        <td><span class="tag">${esc(scopeLabel(r.scope))}</span></td>
        <td class="col-actions"><div class="row-actions">
          ${r.kind === 'prefix'
            ? `<button class="btn sm ghost" data-unprefix="${esc(r.key)}">Remove</button>`
            : `<button class="btn sm ghost" data-unblock="${esc(r.key)}">Remove</button>`}
        </div></td>
      </tr>`).join('');
  }

  function render() {
    if (!state.data) return;
    renderHeader(state.data);
    renderOwn(state.data);
    renderPrefixes(state.data);
    renderNeighbours(state.data);
    renderRules(state.data);
    const can = state.data.capabilities && state.data.capabilities.can_block;
    $$('[data-block],[data-prefix],[data-unprefix],[data-unblock]').forEach((b) => {
      b.disabled = !can;
      if (!can) b.title = 'root or simulated mode required';
    });
  }

  /* ----------------------------------------------------------------- actions */
  async function act(label, fn) {
    if (state.busy) return;
    state.busy = true;
    try {
      const result = await fn();
      toast(result.simulated ? 'warn' : 'ok', label,
        result.simulated ? 'simulated — nothing written to the kernel'
          : (result.applied || result.removed || []).join(', '));
      await refresh();
    } catch (err) {
      toast('err', `${label} failed`, err.message);
    } finally {
      state.busy = false;
    }
  }

  const blockDevice = (mac) => act('IPv6 block', () => api('/api/ipv6/block', {
    method: 'POST', body: { mac, mode: 'both' },
  }));
  const unblockDevice = (mac) => act('IPv6 unblock', () => api('/api/ipv6/unblock', {
    method: 'POST', body: { mac },
  }));
  const blockPrefix = (prefix, force = false) => act('Prefix block', () => api('/api/ipv6/prefix', {
    method: 'POST', body: { prefix, force },
  }));
  const unblockPrefix = (prefix) => act('Prefix unblock', () => api('/api/ipv6/prefix/unblock', {
    method: 'POST', body: { prefix },
  }));

  function bind() {
    document.addEventListener('click', (event) => {
      const target = event.target.closest('[data-block],[data-unblock],[data-prefix],[data-unprefix]');
      if (!target || target.disabled) return;
      if (target.dataset.block) return blockDevice(target.dataset.block);
      if (target.dataset.unblock) return unblockDevice(target.dataset.unblock);
      if (target.dataset.prefix) return blockPrefix(target.dataset.prefix);
      if (target.dataset.unprefix) return unblockPrefix(target.dataset.unprefix);
      return undefined;
    });

    $('#btnPrefixBlock').addEventListener('click', async () => {
      const prefix = $('#prefixInput').value.trim();
      if (!prefix) return toast('err', 'No prefix', 'enter something like 2001:db8:1::/64');
      try {
        await blockPrefix(prefix);
        $('#prefixInput').value = '';
      } catch { /* toast already shown */ }
    });

    $('#btnRefresh').addEventListener('click', (e) => {
      e.currentTarget.classList.add('busy');
      refresh().finally(() => e.currentTarget.classList.remove('busy'));
    });

    $('#btnPanic').addEventListener('click', () => act('Restore all', () => api('/api/panic', { method: 'POST' })));

    $$('.segmented .seg').forEach((button) => {
      button.addEventListener('click', () => {
        state.filter = button.dataset.filter;
        $$('.segmented .seg').forEach((b) => b.classList.toggle('active', b === button));
        renderNeighbours(state.data);
        render();
      });
    });

    document.addEventListener('visibilitychange', () => {
      if (document.hidden) stop();
      else start();
    });
  }

  async function refresh() {
    try {
      state.data = await api('/api/ipv6');
      render();
    } catch (err) {
      toast('err', 'Could not load IPv6 state', err.message);
    }
  }

  function start() {
    if (state.timer) return;
    state.timer = setInterval(refresh, 8000);
  }

  function stop() {
    clearInterval(state.timer);
    state.timer = null;
  }

  state.token = readToken();
  if (!state.token) {
    location.href = '/';
  } else {
    bind();
    refresh().then(start);
  }
})();
