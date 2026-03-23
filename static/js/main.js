/* Ring Zero Pirate — main.js */

document.addEventListener('DOMContentLoaded', () => {

  // ── Mobile nav toggle ─────────────────────
  const toggle = document.querySelector('.nav-toggle');
  const navList = document.querySelector('.nav-list');

  if (toggle && navList) {
    toggle.addEventListener('click', () => {
      const isOpen = navList.classList.toggle('open');
      toggle.setAttribute('aria-expanded', isOpen);
      toggle.classList.toggle('active', isOpen);
    });

    // Close on outside click
    document.addEventListener('click', (e) => {
      if (!toggle.contains(e.target) && !navList.contains(e.target)) {
        navList.classList.remove('open');
        toggle.setAttribute('aria-expanded', false);
        toggle.classList.remove('active');
      }
    });
  }

  // ── Terminal typing effect on hero subtitle ──
  const subtitle = document.querySelector('.hero-subtitle');
  if (subtitle) {
    const text = subtitle.textContent;
    subtitle.textContent = '';
    subtitle.style.visibility = 'visible';

    let i = 0;
    const type = () => {
      if (i < text.length) {
        subtitle.textContent += text[i++];
        setTimeout(type, 35 + Math.random() * 30);
      }
    };

    setTimeout(type, 800);
  }

  // ── Random glitch trigger on scroll ─────────
  const glitchTitle = document.querySelector('.glitch-title');
  if (glitchTitle) {
    // Extra random glitch burst on hover
    glitchTitle.addEventListener('mouseenter', () => {
      glitchTitle.style.animationDuration = '0.3s';
      setTimeout(() => {
        if (glitchTitle) glitchTitle.style.animationDuration = '';
      }, 800);
    });
  }

  // ── Highlight active nav link ────────────────
  const currentPath = window.location.pathname;
  document.querySelectorAll('.nav-link').forEach(link => {
    const href = link.getAttribute('href');
    if (href && currentPath.startsWith(href) && href !== '/') {
      link.classList.add('active');
    }
  });

});
