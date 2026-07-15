// Extension: when user clicks extension icon, verify badges appear
// on each image/audio. Each badge calls the verify API directly.

let badgesVisible = false;
const API_BASE = window.location.origin + '/api';

function getVerifyKind(el) {
  // Walk up the DOM looking for clues about authentic vs tampered
  let node = el;
  for (let i = 0; i < 10 && node; i++) {
    const text = (node.innerText || '').toLowerCase();
    const cls = (node.className || '').toLowerCase();
    const src = (el.src || '').toLowerCase();

    // Check tampered/unverified first (more specific)
    if (text.includes('tamper') || cls.includes('tamper') || src.includes('tamper')) return 'tampered';
    if (text.includes('unverified') || cls.includes('unverified')) return 'tampered';
    if (text.includes('edited') || cls.includes('edited')) return 'tampered';

    // Then check authentic/verified
    if (text.includes('authentic') || cls.includes('authentic') || src.includes('authentic')) return 'authentic';
    if (text.includes('original') || cls.includes('original') || src.includes('original')) return 'authentic';
    if (text.includes('verified') && !text.includes('unverified')) return 'authentic';

    node = node.parentElement;
  }
  return null;
}

function getMediaType(el) {
  if (el.tagName === 'AUDIO') return 'audio';
  return 'image';
}

function addBadges() {
  const mediaElements = document.querySelectorAll('img, audio');

  mediaElements.forEach(el => {
    if (el.dataset.hvBadged) return;
    if (el.tagName === 'IMG' && (el.width < 50 || el.height < 50)) return;
    el.dataset.hvBadged = '1';

    const parent = el.parentElement;
    if (parent && getComputedStyle(parent).position === 'static') {
      parent.style.position = 'relative';
    }

    const badge = document.createElement('button');
    badge.className = 'hv-verify-badge';
    badge.textContent = '🔒 Verify';
    badge.style.cssText = `
      position: absolute;
      top: 8px;
      right: 8px;
      z-index: 99999;
      padding: 6px 14px;
      background: rgba(30, 30, 30, 0.85);
      color: white;
      border: 1px solid rgba(255,255,255,0.3);
      border-radius: 20px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      backdrop-filter: blur(4px);
      transition: all 0.15s;
      display: none;
    `;
    badge.onmouseenter = () => { badge.style.background = 'rgba(50,50,50,0.95)'; badge.style.transform = 'scale(1.05)'; };
    badge.onmouseleave = () => { badge.style.background = 'rgba(30,30,30,0.85)'; badge.style.transform = 'scale(1)'; };

    badge.addEventListener('click', async (e) => {
      e.preventDefault();
      e.stopPropagation();

      const kind = getVerifyKind(el);
      const mediaType = getMediaType(el);

      if (!kind) {
        badge.textContent = '❓ Unknown';
        return;
      }

      badge.textContent = '⏳ Verifying...';
      badge.style.background = 'rgba(74, 85, 162, 0.9)';

      try {
        const endpoint = mediaType === 'audio'
          ? `${API_BASE}/audio-integrity-demo/verify/${kind}`
          : `${API_BASE}/integrity-demo/verify/${kind}`;

        const res = await fetch(endpoint, { method: 'POST' });
        const data = await res.json();

        if (data.verified) {
          badge.textContent = '✅ Verified';
          badge.style.background = 'rgba(27, 128, 52, 0.9)';
        } else {
          badge.textContent = '❌ Failed';
          badge.style.background = 'rgba(176, 27, 27, 0.9)';
        }
      } catch (err) {
        badge.textContent = '⚠️ Error';
        badge.style.background = 'rgba(180, 130, 0, 0.9)';
      }
    });

    parent.appendChild(badge);
  });
}

function toggleBadges() {
  badgesVisible = !badgesVisible;
  document.querySelectorAll('.hv-verify-badge').forEach(b => {
    b.style.display = badgesVisible ? 'block' : 'none';
  });
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === 'toggle') {
    addBadges();
    toggleBadges();
  }
});
