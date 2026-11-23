// IBRA ANTIVIRUS — shared scam-detection rules (used by the browser extension AND the desktop app's link checker)
// برمجة وتطوير ابراهيم الخزرجي — IBRAPROGRAM
(function (g) {
  const RULES = [
    // content lockers / offer walls
    ['locker', 3, /complete\s+(\d+|one|two|three|a\s+few)\s+(short\s+|quick\s+|simple\s+)?(surveys?|offers?|tasks?)/i],
    ['locker', 3, /install\s+(\d+|two|three|one)\s+(free\s+)?(apps?|applications?|games?)/i],
    ['locker', 2, /(run|open|play)\s+(them|it|the\s+apps?)\s+for\s+\d+\s+(seconds|minutes)/i],
    ['locker', 2, /(click|choose|select)\s+(on\s+)?(an?|another|any)\s+offer/i],
    ['locker', 1, /download\s+will\s+(start|begin|unlock)\s+automatically/i],
    ['locker', 1, /enter\s+(correct|valid|real)\s+(information|details|info)/i],
    ['locker', 2, /(content|file|download)\s+(is\s+)?locked|unlock\s+(the\s+)?(content|download|file)/i],
    ['locker', 2, /(human|bot)\s+verification|verify\s+(that\s+)?you(\s+a|')re\s+(a\s+)?human/i],
    ['locker', 3, /أكمل\s*(\d+|اثنين|ثلاث)?\s*(استبيان|استبيانات|استطلاع|عروض|عرض)/],
    ['locker', 2, /أدخل\s+رقم\s+(هاتفك|الهاتف|جوالك|التعريف)/],
    ['locker', 2, /(انقر|اضغط)\s+للحصول\s+على\s+(مكافأ|جائز|هدي)/],
    ['locker', 2, /(enter|submit)\s+your\s+(phone|mobile|cell)\s+(number)?\s*(to|and)\s+(download|unlock|get|receive|continue|win)/i],
    // fake virus / tech support
    ['support', 3, /(your\s+)?(computer|pc|windows|device|phone|iphone|android|system)\s+(is|has\s+been|may\s+be|was)\s+(infected|locked|blocked|compromised|hacked|damaged)/i],
    ['support', 3, /call\s+(now\s+)?(microsoft|windows|apple|technical|tech|customer)?\s*support|call\s+(this\s+)?toll[\s-]?free/i],
    ['support', 2, /(\d+)\s+viruses?\s+(detected|found)|virus(es)?\s+(alert|detected)\s*!/i],
    ['support', 1, /(\+?1[\s-]?)?\(?8\d\d\)?[\s-]\d{3}[\s-]\d{4}/],
    ['support', 3, /جهازك\s+(مصاب|مخترق|مقفل)|تم\s+(اختراق|قفل)\s+جهازك/],
    // fake prizes
    ['prize', 3, /congratulations?!?.{0,100}(you('ve|\s+have)?\s+(won|been\s+(selected|chosen))|winner)/is],
    ['prize', 2, /claim\s+your\s+(free\s+)?(prize|reward|gift|iphone|samsung)/i],
    ['prize', 2, /مبروك.{0,60}(ربحت|فزت|تم\s+اختيارك)/s],
    // "click Allow" notification traps
    ['allow', 5, /(click|press|tap)\s+["“']?allow["”']?\s+(to|if)\s+(continue|verify|watch|confirm|prove|download|play|access|you)/i],
    ['allow', 5, /(اضغط|انقر)\s+(على\s+)?["“']?(سماح|السماح)["”']?\s+(للمتابعة|للتحقق|لمشاهدة|للتحميل)/],
    // "I'm not a robot" / fake CAPTCHA traps (ClickFix): tell you to press Win+R and paste a command — the #1 way infostealers spread
    ['clickfix', 4, /(win(dows)?\s*(key|logo\s*key)?\s*(\+|and|&)\s*["“']?r["”']?\b|⊞\s*\+\s*r\b|press\s+(and\s+hold\s+)?the\s+windows\s+key)/i],
    ['clickfix', 3, /(ctrl|control)\s*\+\s*v|press\s+(ctrl|control)\s*v|paste\s+(the\s+)?(code|command|verification)/i],
    ['clickfix', 2, /(press|hit)\s+["“']?enter["”']?/i],
    ['clickfix', 2, /(verify|verification|confirm)\s+(that\s+)?you\s+are\s+(a\s+)?human|i('|\s+a)m\s+not\s+a\s+robot|verification\s+steps?|cloudflare\s+verification/i],
    ['clickfix', 2, /(run|"run")\s+(dialog|box|window)|open\s+the\s+run\b|windows\s+\+\s*x/i],
    ['clickfix', 4, /(اضغط|انقر)\s+(على\s+)?(زر\s+)?(ويندوز|الويندوز|windows)\s*\+\s*r/i],
    ['clickfix', 3, /الصق\s+(الكود|الأمر|الامر|النص)|(ctrl|كنترول)\s*\+\s*v/i],
    ['clickfix', 2, /(تحقق|للتحقق|أثبت|اثبت)\s+(أنك|انك)\s+(إنسان|انسان|لست\s+روبوت)|لست\s+روبوت/]
  ];
  // A command copied to the clipboard that downloads and runs something (what ClickFix pages copy)
  const CMD_TOOL = /(powershell|pwsh|mshta|\bcmd(\.exe)?\s*\/[ckr]|curl(\.exe)?\s|wget\s|bitsadmin|certutil|rundll32|regsvr32|msiexec|wscript|cscript|conhost|finger(\.exe)?\s|forfiles|\bstart\s+\/min)/i;
  const CMD_EVIL = /(https?:\/\/|\\\\\d{1,3}\.\d|-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|\biex\b|invoke-(expression|webrequest|restmethod)|\biwr\b|\birm\b|downloadstring|downloadfile|-w(indowstyle)?\s+h(idden)?|-nop\b|\|\s*(iex|powershell|cmd)|\$env:temp|%temp%|appdata)/i;
  const CMD_DECOY = /(✅|✔|robot|captcha|recaptcha|verification\s*(id|code|uid)?|human|cloudflare|ray\s*id)/i;
  /** 'block' = download-and-run command (or decorated with a fake verification text); 'warn' = some other command */
  function command(text) {
    if (!text || typeof text !== 'string' || text.length > 5000) return null;
    const t = text.trim();
    if (!CMD_TOOL.test(t)) return null;
    if (CMD_EVIL.test(t) || (CMD_DECOY.test(t) && /#|rem\s|::/.test(t))) return 'block';
    return 'warn';
  }
  const VERIFY = /(verify|verification|human|robot|captcha|cloudflare|security\s+check|تحقق|التحقق|إنسان|انسان|روبوت)/i;
  function score(text) {
    const sc = {};
    for (const [kind, w, re] of RULES) if (re.test(text)) sc[kind] = (sc[kind] || 0) + w;
    const [kind, best] = Object.entries(sc).sort((a, b) => b[1] - a[1])[0] || [null, 0];
    const need = text.length > 6000 ? 9 : 5;
    let level = best >= need ? 'high' : best >= 3 ? 'medium' : null;
    // Win+R / Ctrl+V instructions alone are normal (shortcut guides); a trap also pretends to verify you
    if (kind === 'clickfix' && level === 'high' && !VERIFY.test(text)) level = 'medium';
    return { kind, score: best, level, all: sc };
  }
  g.IBRA_PAGE = { RULES, command, score };
})(typeof self !== 'undefined' ? self : globalThis);
