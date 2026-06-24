function showTab(tabId) {
  document.querySelectorAll('.demo-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.demo-content').forEach(c => c.classList.remove('active'));

  const tabs = ['blocked', 'approved', 'code'];
  const tabIndex = tabs.indexOf(tabId);
  document.querySelectorAll('.demo-tab')[tabIndex]?.classList.add('active');
  document.getElementById('tab-' + tabId)?.classList.add('active');
}

document.querySelectorAll('a[href^="#"]').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    document.querySelector(a.getAttribute('href'))?.scrollIntoView({ behavior: 'smooth' });
  });
});

document.addEventListener('DOMContentLoaded', () => {
  const observerOptions = { threshold: 0.1, rootMargin: '0px 0px -50px 0px' };
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
      }
    });
  }, observerOptions);

  document.querySelectorAll('.arch-card, .step, .feature, .deploy-card').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    observer.observe(el);
  });
});

let lastScroll = 0;
window.addEventListener('scroll', () => {
  const nav = document.querySelector('nav');
  if (window.scrollY > 100) {
    nav.style.background = 'rgba(10,10,15,0.95)';
  } else {
    nav.style.background = 'rgba(10,10,15,0.85)';
  }
});