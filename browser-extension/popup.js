const TXT = {
  ar: { on: 'حماية المتصفح شغالة', off: 'حماية المتصفح طافية', safe: '✔ موقع آمن', warn: '⚠ موقع مشكوك — انتبه', http: '⚠ الاتصال غير مشفّر', internal: 'صفحة داخلية للمتصفح',
    today: 'محظور اليوم', total: 'الكل', dl: 'تنزيلات موقوفة', enabled: 'حماية المتصفح', frame: 'إطار الحماية على المواقع', phish: 'كشف مواقع التصيّد', cloudL: 'الحماية السحابية الفورية', down: 'فحص التنزيلات بالبرنامج',
    lists: (n, d) => `${n.toLocaleString('ar')} موقع خطر بالقائمة${d ? ' · ' + d : ''}`, upd: 'تحديث', updating: '...', appOn: 'متصل ببرنامج IBRA ANTIVIRUS', appOff: 'البرنامج مو شغال — فحص التنزيلات متوقف', site: 'موقع برامجي — IBRAPROGRAM' },
  en: { on: 'Browser protection is on', off: 'Browser protection is off', safe: '✔ Safe site', warn: '⚠ Suspicious site — be careful', http: '⚠ Connection not encrypted', internal: 'Browser internal page',
    today: 'blocked today', total: 'total', dl: 'downloads stopped', enabled: 'Browser protection', frame: 'Protection frame on sites', phish: 'Phishing detection', cloudL: 'Real-time cloud protection', down: 'Scan downloads with the app',
    lists: (n, d) => `${n.toLocaleString('en')} dangerous sites listed${d ? ' · ' + d : ''}`, upd: 'Update', updating: '...', appOn: 'Connected to IBRA ANTIVIRUS app', appOff: 'App is not running — download scanning paused', site: 'My apps website — IBRAPROGRAM' }
};
const $ = id => document.getElementById(id);
async function render() {
  const st = await chrome.runtime.sendMessage({ type: 'status' });
  const L = TXT[st.lang] || TXT.ar;
  document.documentElement.lang = st.lang;
  $('shield').src = `icons/${st.enabled ? 'green' : 'orange'}-128.png`;
  $('status').textContent = st.enabled ? L.on : L.off;
  $('today').textContent = st.stats.day === new Date().toISOString().slice(0, 10) ? st.stats.today : 0;
  $('total').textContent = st.stats.total || 0;
  $('dl').textContent = st.stats.downloads || 0;
  $('lToday').textContent = L.today; $('lTotal').textContent = L.total; $('lDl').textContent = L.dl;
  $('lEnabled').textContent = L.enabled; $('lFrame').textContent = L.frame; $('lPhish').textContent = L.phish; $('lCloud').textContent = L.cloudL; $('lDown').textContent = L.down;
  document.querySelectorAll('.sw').forEach(b => b.classList.toggle('on', !!st[b.dataset.k]));
  const d = st.listsUpdated ? new Date(st.listsUpdated).toLocaleString(st.lang === 'ar' ? 'ar-IQ' : 'en-GB', { dateStyle: 'short', timeStyle: 'short' }) : '';
  $('lists').textContent = L.lists(st.listCount || 0, d);
  $('upd').textContent = L.upd;
  $('appDot').classList.toggle('on', st.appConnected);
  $('app').textContent = st.appConnected ? L.appOn : L.appOff;
  $('site').textContent = L.site;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab && tab.url || '';
  if (!/^https?:/.test(url)) { $('host').textContent = ''; $('verdict').textContent = L.internal; $('verdict').className = 'v'; return; }
  $('host').textContent = new URL(url).hostname;
  const v = await chrome.runtime.sendMessage({ type: 'verdict', url });
  $('verdict').textContent = v.level === 'safe' ? L.safe : v.reason === 'http' ? L.http : v.level === 'off' ? L.off : L.warn;
  $('verdict').className = 'v ' + (v.level === 'safe' ? 'ok' : 'warn');
}
document.querySelectorAll('.sw').forEach(b => b.onclick = async () => { await chrome.runtime.sendMessage({ type: 'set', key: b.dataset.k, value: !b.classList.contains('on') }); render(); });
$('upd').onclick = async () => { $('upd').textContent = '...'; await chrome.runtime.sendMessage({ type: 'update-lists' }); render(); };
render();
