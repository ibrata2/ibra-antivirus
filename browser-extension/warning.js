// Warning page shown instead of a dangerous site
const TXT = {
  ar: { title: 'موقع خطر!', lead: 'IBRA ANTIVIRUS أوقف فتح هذا الموقع لحمايتك.',
    why: { malware: 'هذا الموقع مسجّل بقوائم عالمية لأنه ينشر فيروسات أو برامج خبيثة.', phishing: 'هذا موقع تصيّد: يقلّد موقع معروف حتى يسرق حسابك أو كلمة السر أو فلوسك.', cloud: 'هذا الموقع مسجّل كخطر بقاعدة الحماية السحابية (تصيّد أو برامج خبيثة).',
      scam: { locker: 'صفحة احتيال: تطلب منك تنصّب برامج أو تكمّل استبيانات أو تدخل رقم هاتفك مقابل تحميل وهمي. هذي الصفحات تنصّب برامج خبيثة وتشترك برقمك بخدمات مدفوعة.',
              support: 'صفحة احتيال: تحذير فيروسات وهمي يحاول يخوفك حتى تتصل برقم أو تنزّل برنامج.', prize: 'صفحة احتيال: جائزة وهمية حتى تاخذ معلوماتك أو فلوسك.',
              allow: 'صفحة احتيال: تطلب «السماح» حتى تغرق جهازك بإشعارات وإعلانات خبيثة.' }, suspicious: 'هذا الموقع يستخدم حيل معروفة عند المواقع المزيفة.' },
    brand: b => ` يتظاهر إنه ${b}.`, words: w => ` اسمه مكوّن من كلمات تستخدمها مواقع الاحتيال (${w}).`, back: 'رجوع للأمان', more: 'تفاصيل وخيارات متقدمة',
    risk: 'إذا متأكد إن الموقع آمن تگدر تدخله. ننصح بعدم إدخال كلمات سر أو معلومات بطاقة.', anyway: 'أدخل رغم التحذير (غير آمن)', confirm: 'متأكد؟ الموقع ممكن يضر جهازك أو يسرق حساباتك.', credit: 'برمجة وتطوير ابراهيم الخزرجي' },
  en: { title: 'Dangerous website!', lead: 'IBRA ANTIVIRUS stopped this site to protect you.',
    why: { malware: 'This site is on global lists for spreading viruses or malware.', phishing: 'This is a phishing site: it imitates a known site to steal your account, password or money.', cloud: 'This site is listed as dangerous by the cloud protection database (phishing or malware).',
      scam: { locker: 'Scam page: it asks you to install apps, complete surveys or enter your phone number for a fake download. These pages install malware and subscribe your number to paid services.',
              support: 'Scam page: a fake virus alert trying to scare you into calling a number or installing software.', prize: 'Scam page: a fake prize to take your details or money.',
              allow: 'Scam page: it asks you to click "Allow" to flood your device with malicious notifications and ads.' }, suspicious: 'This site uses tricks typical of fake websites.' },
    brand: b => ` It pretends to be ${b}.`, words: w => ` Its name is made of words used by scam sites (${w}).`, back: 'Back to safety', more: 'Details and advanced options',
    risk: 'If you are sure this site is safe you can open it. Do not enter passwords or card details.', anyway: 'Enter anyway (unsafe)', confirm: 'Are you sure? This site may harm your PC or steal your accounts.', credit: 'by Ibrahim Al-Khazraji' }
};
const q = new URLSearchParams(location.search);
const reason = q.get('r') || 'malware';
const brand = q.get('b') || '';
const words = q.get('w') || '';
const kind = q.get('k') || 'locker';
const target = decodeURIComponent(location.hash.slice(1));

chrome.runtime.sendMessage({ type: 'blocked', url: target, reason }, res => {
  const lang = (res && res.lang) || ((navigator.language || 'ar').startsWith('ar') ? 'ar' : 'en');
  const L = TXT[lang] || TXT.ar;
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  document.title = 'IBRA ANTIVIRUS — ' + L.title;
  const $ = id => document.getElementById(id);
  $('title').textContent = L.title;
  $('lead').textContent = L.lead;
  $('url').textContent = target;
  $('why').textContent = (reason === 'scam' ? (L.why.scam[kind] || L.why.scam.locker) : (L.why[reason] || L.why.malware)) + (brand ? L.brand(brand) : words ? L.words(words) : '');
  $('back').textContent = L.back;
  $('more').textContent = L.more;
  $('risk').textContent = L.risk;
  $('anyway').textContent = L.anyway;
  $('credit').textContent = L.credit;
  $('back').onclick = () => chrome.runtime.sendMessage({ type: 'safe-exit' });
  $('anyway').onclick = () => {
    if (!/^https?:\/\//.test(target) || !confirm(L.confirm)) return;
    chrome.runtime.sendMessage({ type: 'allow', url: target }, () => location.replace(target));
  };
});
