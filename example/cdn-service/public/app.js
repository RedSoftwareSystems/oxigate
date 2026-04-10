// app.js — minimal client-side JS for the Oxigate CDN example
'use strict';

// Mark the current nav link as active.
(function markActiveLink() {
  const links = document.querySelectorAll('.site-nav a');
  const path  = location.pathname;
  links.forEach(link => {
    if (link.getAttribute('href') === path) {
      link.classList.add('active');
      link.style.color = 'var(--brand)';
      link.style.fontWeight = '600';
    }
  });
})();
