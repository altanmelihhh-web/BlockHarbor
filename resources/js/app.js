// Alpine is loaded via CDN in the layout. This file hooks app-wide behaviors.
document.addEventListener('alpine:init', () => {
  // Toast helper available as x-data="toast()" — extends in P3+
});

// HTMX — global config
document.body.addEventListener('htmx:configRequest', (e) => {
  const token = document.querySelector('meta[name="csrf-token"]')?.content;
  if (token) e.detail.headers['X-CSRF-Token'] = token;
});
