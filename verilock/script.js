function showTab(tabId) {
  document.querySelectorAll('.demo-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.demo-content').forEach(c => c.classList.remove('active'));
  document.querySelector(`.demo-tab:nth-child(${tabId === 'blocked' ? 1 : tabId === 'approved' ? 2 : 3})`)?.classList.add('active');
  document.getElementById('tab-' + tabId)?.classList.add('active');
}

const deployments = [
  { label: 'Safe Wallet', address: '0xB7D6dd7f1a25fa5455b0cC8B6a8CD822fE247E11', status: 'Protected', url: 'https://app.safe.global/home?chain=basesep&safe=0xB7D6dd7f1a25fa5455b0cC8B6a8CD822fE247E11' },
  { label: 'Guard Contract', address: '0xB519fBAC8f59392200565BB4448aEcD498C1140c', status: 'Deployed', url: 'https://sepolia.basescan.org/address/0xB519fBAC8f59392200565BB4448aEcD498C1140c' },
  { label: 'Notary Server', address: '0x98A47f61eEfcC3AB387000FD824FCAC8f75EF36c', status: 'Running', url: '#' },
  { GP: 'Network', address: 'Base Sepolia (Chain ID: 84532)', status: 'Testnet', url: '#' },
];

const features = [
  { icon: '🛡️', title: 'Immutable Guard', desc: 'Once deployed, the Guard enforces rules at the blockchain level. No owner can bypass it.' },
  { icon: '📋', title: 'Hot-Reloadable Policy', desc: 'YAML policy updates in real-time without redeploying the contract.' },
  { icon: '🔐', title: 'EIP-712 Signatures', desc: 'Cryptographic proof that the Notary approved this specific transaction.' },
  { icon: '🔥', title: 'Escape Hatch', desc: 'Safe owners can always remove the Guard via setGuard(address(0)). No lock-in.' },
  { icon: '📊', title: 'Three-Tier Approval', desc: 'Auto-Tier 1 → Notify + Veto Tier 2 → Human Tier 3 based on amount and history.' },
  { icon: '🎭', title: 'Replay Protection', desc: 'Each token has a unique nonce consumed after use. Never reusable.' },
];

document.addEventListener('DOMContentLoaded', () => {
  const dg = document.getElementById('deploymentGrid');
  if (dg) {
    dg.innerHTML = deployments.map(d => `
      <div class="deploy-card">
        <h4>${d.label}</h4>
        <div class="address"><a href="${d.url}" target="_blank" rel="noopener">${d.address}</a></div>
        <span class="status-badge">${d.status}</span>
      </div>
    `).join('');
  }

  const fg = document.getElementById('featuresGrid');
  if (fg) {
    fg.innerHTML = features.map(f => `
      <div class="feature">
        <div class="feature-icon">${f.icon}</div>
        <h4>${f.title}</h4>
        <p>${f.desc}</p>
      </div>
    `).join('');
  }
});

document.querySelectorAll('a[href^="#"]').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    document.querySelector(a.getAttribute('href'))?.scrollIntoView({ behavior: 'smooth' });
  });
});