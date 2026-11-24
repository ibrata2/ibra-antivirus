// IBRA ANTIVIRUS — protection frame around every page + small shield tab on the left edge
(() => {
  if (window.top !== window || document.getElementById('ibra-av-frame-host')) return;
  const TXT = {
    ar: { safe: 'محمي بواسطة IBRA ANTIVIRUS', warn: 'انتبه: هذا الموقع مشكوك', http: 'انتبه: الاتصال غير مشفّر (http)', off: 'حماية المتصفح طافية', hide: 'إخفاء الإطار بهذه الصفحة',
          reasons: { brand: 'يحمل اسم شركة مو اسمه الحقيقي', homograph: 'حروف تقلّد موقع معروف', punycode: 'اسم الموقع بحروف مموهة', 'ip-login': 'صفحة دخول على عنوان IP', userinfo: 'رابط مخادع', 'deep-subdomain': 'عنوان طويل يخفي الموقع الحقيقي', http: 'الاتصال غير مشفّر', lure: 'اسمه من كلمات مواقع الاحتيال', cloud: 'مسجّل كخطر بالحماية السحابية', 'cloud-suspicious': 'مشكوك بالحماية السحابية' } },
    en: { safe: 'Protected by IBRA ANTIVIRUS', warn: 'Careful: this site looks suspicious', http: 'Careful: connection is not encrypted (http)', off: 'Browser protection is off', hide: 'Hide frame on this page',
          reasons: { brand: 'uses a brand name that is not its own', homograph: 'letters imitate a known site', punycode: 'disguised characters in the address', 'ip-login': 'login page on a raw IP address', userinfo: 'deceptive link', 'deep-subdomain': 'long address hiding the real site', http: 'connection is not encrypted', lure: 'name made of scam words', cloud: 'listed as dangerous by cloud protection', 'cloud-suspicious': 'suspicious in cloud protection' } }
  };
  const COLORS = { safe: '#12a150', warn: '#f07a12', off: '#9aa6a0' };

  chrome.runtime.sendMessage({ type: 'verdict', url: location.href }, v => {
    if (chrome.runtime.lastError || !v || !v.frame) return;
    const L = TXT[v.lang] || TXT.ar;
    const level = v.level;
    const color = COLORS[level] || COLORS.safe;
    const label = level === 'safe' ? L.safe : level === 'off' ? L.off : (v.reason === 'http' ? L.http : L.warn);
    const detail = level === 'warn' && v.reason && v.reason !== 'http' ? (L.reasons[v.reason] || '') + (v.brand ? ` (${v.brand})` : '') : '';

    const host = document.createElement('div');
    host.id = 'ibra-av-frame-host';
    host.style.cssText = 'all:initial;position:fixed;inset:0;pointer-events:none;z-index:2147483647;';
    const root = host.attachShadow({ mode: 'closed' });
    const shield = chrome.runtime.getURL(`icons/${level === 'warn' ? 'orange' : level === 'off' ? 'orange' : 'green'}-32.png`);
    root.innerHTML = `
      <style>
        .frame{position:fixed;inset:0;border:3px solid ${color};box-sizing:border-box;pointer-events:none;border-radius:0;
               box-shadow:inset 0 0 0 1px rgba(255,255,255,.35);transition:opacity .3s}
        .tab{position:fixed;left:0;top:50%;transform:translateY(-50%);pointer-events:auto;display:flex;flex-direction:column;align-items:center;gap:6px;
             padding:7px 5px;background:#fff;border:2px solid ${color};border-left:0;border-radius:0 12px 12px 0;
             box-shadow:2px 3px 12px rgba(0,0,0,.18);font:12px/1.4 "Segoe UI",Tahoma,Arial,sans-serif;direction:ltr;cursor:default}
        .tab img{width:20px;height:20px;display:block}
        .x{width:18px;height:18px;border-radius:50%;border:0;background:#1f2a24;color:#fff;font:bold 11px/18px Arial;cursor:pointer;padding:0;text-align:center}
        .x:hover{background:#d61f2c}
        .tip{position:absolute;left:calc(100% + 8px);top:50%;transform:translateY(-50%);white-space:nowrap;background:#13281c;color:#fff;
             padding:7px 11px;border-radius:9px;opacity:0;visibility:hidden;transition:.15s;unicode-bidi:plaintext}
        .tip small{display:block;opacity:.8}
        .tab:hover .tip{opacity:1;visibility:visible}
        .hidden{display:none}
      </style>
      <div class="frame"></div>
      <div class="tab"><img src="${shield}" alt=""><button class="x" title="${L.hide}">✕</button>
        <div class="tip">${label}${detail ? `<small>${detail}</small>` : ''}</div></div>`;
    const frame = root.querySelector('.frame');
    const tab = root.querySelector('.tab');
    window.__ibraWarn = text => {
      const c = COLORS.warn;
      frame.style.borderColor = c; tab.style.borderColor = c;
      root.querySelector('.tab img').src = chrome.runtime.getURL('icons/orange-32.png');
      root.querySelector('.tip').innerHTML = '';
      root.querySelector('.tip').append(L.warn, Object.assign(document.createElement('small'), { textContent: text }));
    };
    root.querySelector('.x').addEventListener('click', e => { e.stopPropagation(); frame.classList.add('hidden'); tab.classList.add('hidden'); });
    // never cover fullscreen videos
    document.addEventListener('fullscreenchange', () => { host.style.display = document.fullscreenElement ? 'none' : ''; });
    (document.body || document.documentElement).appendChild(host);
  });
})();

// ---------------------------------------------------------------------------------------------
// IBRA ANTIVIRUS — scam page detection: reads what the page shows (after scripts draw it) and
// recognises content lockers, fake "complete surveys / install apps to download" walls,
// fake virus / tech-support alerts, fake prizes and "click Allow" notification traps.
(() => {
  if (window.top !== window) return;
  // IBRAPROGRAM's own sites are never scam pages
  if (/(^|\.)ibraprogram\.netlify\.app$/i.test(location.hostname)) return;

  let done = false, warned = false, checks = 0, copiedCommand = null;
  // the page tried to put a command in the clipboard (reported by clipguard.js, which runs inside the page)
  window.addEventListener('message', e => {
    if (e.source !== window || !e.data || e.data.__ibraClip !== 1) return;
    const lvl = IBRA_PAGE.command(String(e.data.text || ''));
    if (!lvl) return;
    copiedCommand = lvl;
    if (lvl === 'block' && !done) {
      done = true;
      chrome.runtime.sendMessage({ type: 'page-scam', url: location.href, kind: 'clickfix', score: 10, command: String(e.data.text).slice(0, 500) });
    } else if (!warned) {
      warned = true;
      chrome.runtime.sendMessage({ type: 'page-suspicious', kind: 'command' }, r => { if (r && r.text && window.__ibraWarn) window.__ibraWarn(r.text); });
    }
  });
  function scan() {
    if (done || !document.body) return;
    checks++;
    const text = (document.body.innerText || '').slice(0, 40000);
    // scam walls are short pages; long articles that merely talk about scams need much more evidence (see rules.js)
    const r = IBRA_PAGE.score(text);
    const kind = r.kind, best = r.score;
    if (r.level === 'high' || (kind === 'clickfix' && best >= 5 && copiedCommand)) {
      done = true;
      chrome.runtime.sendMessage({ type: 'page-scam', url: location.href, kind, score: best });
    } else if (r.level === 'medium' && !warned) {
      warned = true;
      chrome.runtime.sendMessage({ type: 'page-suspicious', kind }, r => { if (r && r.text && window.__ibraWarn) window.__ibraWarn(r.text); });
    }
  }
  let t = null;
  const obs = new MutationObserver(() => { clearTimeout(t); t = setTimeout(scan, 600); });
  const start = () => {
    scan();
    if (!done && document.body) obs.observe(document.body, { childList: true, subtree: true, characterData: true });
    setTimeout(() => obs.disconnect(), 25000);   // pages usually draw their scam text within seconds
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
