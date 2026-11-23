// IBRA ANTIVIRUS — runs inside the page: watches what the page writes to the clipboard.
// Fake "I'm not a robot" pages (ClickFix) copy a PowerShell/mshta command and ask you to paste it in Win+R.
// A download-and-run command is replaced by a warning before it reaches the clipboard.
(() => {
  const TOOL = /(powershell|pwsh|mshta|\bcmd(\.exe)?\s*\/[ckr]|curl(\.exe)?\s|wget\s|bitsadmin|certutil|rundll32|regsvr32|msiexec|wscript|cscript|conhost|finger(\.exe)?\s|forfiles|\bstart\s+\/min)/i;
  const EVIL = /(https?:\/\/|\\\\\d{1,3}\.\d|-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|\biex\b|invoke-(expression|webrequest|restmethod)|\biwr\b|\birm\b|downloadstring|downloadfile|-w(indowstyle)?\s+h(idden)?|-nop\b|\|\s*(iex|powershell|cmd)|\$env:temp|%temp%|appdata)/i;
  const DECOY = /(✅|✔|robot|captcha|recaptcha|verification\s*(id|code|uid)?|human|cloudflare|ray\s*id)/i;
  const SAFE_TEXT = '⚠ IBRA ANTIVIRUS: blocked a dangerous command from this site. Do NOT paste anything into Win+R. / تم منع أمر خطير من هذا الموقع، لا تلصق أي شي بنافذة Run';
  const bad = t => typeof t === 'string' && t.length < 5000 && TOOL.test(t) && (EVIL.test(t) || (DECOY.test(t) && /#|rem\s|::/.test(t)));
  const report = t => { try { window.postMessage({ __ibraClip: 1, text: String(t).slice(0, 2000) }, '*'); } catch (e) {} };

  const cb = navigator.clipboard;
  if (cb && cb.writeText) {
    const orig = cb.writeText.bind(cb);
    cb.writeText = function (t) { if (TOOL.test(String(t))) report(t); return orig(bad(t) ? SAFE_TEXT : t); };
  }
  if (cb && cb.write && window.ClipboardItem) {
    const origW = cb.write.bind(cb);
    cb.write = async function (items) {
      try {
        for (const it of items || []) if (it.types && it.types.includes('text/plain')) {
          const t = await (await it.getType('text/plain')).text();
          if (TOOL.test(t)) report(t);
          if (bad(t)) return origW([new ClipboardItem({ 'text/plain': new Blob([SAFE_TEXT], { type: 'text/plain' }) })]);
        }
      } catch (e) {}
      return origW(items);
    };
  }
  // document.execCommand('copy') / copy events: runs after the page's own copy handlers (bubble phase on window)
  window.addEventListener('copy', e => {
    try {
      let t = e.clipboardData && e.clipboardData.getData('text/plain');
      if (!t) t = String(window.getSelection ? window.getSelection() : '');
      if (TOOL.test(t)) report(t);
      if (bad(t)) { e.clipboardData.setData('text/plain', SAFE_TEXT); e.preventDefault(); }
    } catch (err) {}
  }, false);
})();
