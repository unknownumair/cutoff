/* CUTOFF theme control: one persisted light/dark preference, no flash, no deps.
   The <head> bootstrap already set data-theme before paint; this file only
   handles the toggle, the labels and the system-preference follow. */
(() => {
  'use strict';

  const KEY = 'cutoff.theme';
  const LEGACY_KEY = 'npent.theme';
  const root = document.documentElement;
  const button = document.getElementById('themeToggle');
  const label = button && button.querySelector('.tt-label');
  const meta = document.querySelector('meta[name="color-scheme"]');
  const media = window.matchMedia('(prefers-color-scheme: light)');

  const stored = () => {
    try { return localStorage.getItem(KEY) || localStorage.getItem(LEGACY_KEY); } catch { return null; }
  };

  function sync() {
    const light = root.dataset.theme === 'light';
    if (button) {
      button.setAttribute('aria-pressed', String(light));
      button.setAttribute('title', light ? 'Switch to dark theme' : 'Switch to light theme');
      button.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme');
    }
    if (label) label.textContent = light ? 'Dark mode' : 'Light mode';
    if (meta) meta.setAttribute('content', light ? 'light dark' : 'dark light');
  }

  function apply(theme, persist) {
    root.dataset.theme = theme;
    if (persist) {
      try { localStorage.setItem(KEY, theme); } catch { /* private mode */ }
    }
    sync();
  }

  if (button) {
    button.addEventListener('click', () => {
      apply(root.dataset.theme === 'light' ? 'dark' : 'light', true);
    });
  }

  // Follow the OS only while the user has not made an explicit choice.
  const onSystemChange = (event) => {
    if (!stored()) apply(event.matches ? 'light' : 'dark', false);
  };
  if (typeof media.addEventListener === 'function') {
    media.addEventListener('change', onSystemChange);
  } else if (typeof media.addListener === 'function') {
    media.addListener(onSystemChange);
  }

  sync();
})();
