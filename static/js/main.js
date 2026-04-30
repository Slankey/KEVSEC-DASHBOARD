// ══════════════════════════════════════════════════════════
//  KEVSEC EXECUTIVE INTELLIGENCE PORTAL — JS
// ══════════════════════════════════════════════════════════

// ── Theme ──────────────────────────────────────────────────
const THEMES = ['presidential','phantom','agency','midnight'];
function setTheme(name, el) {
  THEMES.forEach(t => document.getElementById('body').classList.remove('theme-'+t));
  document.getElementById('body').classList.add('theme-'+name);
  document.querySelectorAll('.theme-dot').forEach(d => d.classList.remove('active'));
  if (el) el.classList.add('active');
  localStorage.setItem('kevsec-theme', name);
}
(function initTheme() {
  const saved = localStorage.getItem('kevsec-theme') || 'presidential';
  const dot = document.querySelector('.t-'+saved);
  setTheme(saved, dot);
})();

// ── Clock ──────────────────────────────────────────────────
const TZ_LIST = [
  { tz: 'UTC',                cls: 'tz-zulu',    std: 'UTC',  dst: 'UTC'  },
  { tz: 'America/Los_Angeles',cls: 'tz-pacific', std: 'PST',  dst: 'PDT'  },
  { tz: 'America/Chicago',    cls: 'tz-chicago', std: 'CST',  dst: 'CDT'  },
  { tz: 'America/New_York',   cls: 'tz-eastern', std: 'EST',  dst: 'EDT'  },
  { tz: 'Europe/London',      cls: 'tz-london',  std: 'GMT',  dst: 'BST'  },
  { tz: 'Europe/Berlin',      cls: 'tz-berlin',  std: 'CET',  dst: 'CEDT' },
];
const _tzFmt = TZ_LIST.map(t => new Intl.DateTimeFormat('en-US', {
  timeZone: t.tz, hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true
}));
function _tzIsDST(tz, now) {
  // Compare current UTC offset to the standard (min) offset across Jan + Jul
  const getOff = d => {
    const utc = new Date(new Date(d).toLocaleString('en-US', { timeZone: 'UTC' }));
    const loc = new Date(new Date(d).toLocaleString('en-US', { timeZone: tz }));
    return (loc - utc) / 3600000;
  };
  const y = now.getFullYear();
  const std = Math.min(getOff(new Date(y, 0, 15)), getOff(new Date(y, 6, 15)));
  return getOff(now) > std;
}
function updateClock() {
  const bar = document.getElementById('clock-bar');
  if (!bar) return;
  const now = new Date();
  bar.innerHTML = TZ_LIST.map((t, i) => {
    const time  = _tzFmt[i].format(now);
    const label = _tzIsDST(t.tz, now) ? t.dst : t.std;
    return `<span class="clock-tz-item ${t.cls}"><span class="clock-tz-label">${label}</span><span class="clock-tz-time">${time}</span></span>`;
  }).join('');
}
setInterval(updateClock, 1000); updateClock();

// ── Desktop / Mobile mode toggle ───────────────────────────
(function() {
  const DESKTOP_VP = 'width=1280';
  const MOBILE_VP  = 'width=device-width,initial-scale=1';
  const btn = document.getElementById('desktop-mode-btn');
  let isDesktop = localStorage.getItem('viewportMode') === 'desktop';
  function applyMode(desktop) {
    const meta = document.getElementById('viewport-meta');
    if (meta) meta.setAttribute('content', desktop ? DESKTOP_VP : MOBILE_VP);
    if (btn) btn.textContent = desktop ? '🖥 Desktop' : '📱 Mobile';
    isDesktop = desktop;
    localStorage.setItem('viewportMode', desktop ? 'desktop' : 'mobile');
  }
  // Restore saved preference on load
  if (isDesktop) applyMode(true);
  window.toggleDesktopMode = function() { applyMode(!isDesktop); };
  // Only show the toggle button on narrow screens
  function checkBtn() {
    if (btn) btn.style.display = window.innerWidth <= 900 ? '' : 'none';
  }
  checkBtn();
  window.addEventListener('resize', checkBtn);
})();

// ── Tabs ───────────────────────────────────────────────────
const tabLoaded = {};
document.querySelectorAll('.tab[data-tab]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab[data-tab]').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    const id = 'tab-' + btn.dataset.tab;
    document.getElementById(id).classList.add('active');
    if (!tabLoaded[id]) { tabLoaded[id] = true; loadTab(btn.dataset.tab); }
  });
});

function loadTab(tab) {
  if (tab === 'intel')   { loadNews(); loadThreatLevel(); loadWikipedia(); loadAPOD(); loadStocks(false,'intel'); loadOzaukeeAlerts(); loadPresidentIntel(); loadCongressStatus(); loadMidtermIntel(); loadPolls(); loadF1(); loadPolTweets(); loadGovtIntel(); loadPodcasts(); }
  if (tab === 'command') { loadServerStats(); loadProxmox(); loadExtServices(); loadTarpitStats(); buildSvcControlGrid(); loadGoals(); loadDjStatus(); }
  if (tab === 'cyber')   { loadCVEs(); loadFirewallDrops(); loadSWPC(); loadServerHealth(); loadJailSummary(); }
  if (tab === 'weather') { loadGarden(); loadWeather(); loadEarthquakes(); loadGDACS(); loadLakeMichigan(); loadAirNow(); loadWildfires(); loadSWPC(); loadMETAR(); initWi511Map(); loadWIWarnings(); loadLNM(); loadGlerlImages(); loadBurnBan(); }
  if (tab === 'comms')   { loadNotepad(); loadReminders(); loadNotesList(); loadMemos(); }
}
function refreshAllCommand() {
  const btn = document.querySelector('[onclick="refreshAllCommand()"]');
  if (btn) { btn.textContent = '⟳ REFRESHING...'; btn.disabled = true; }
  loadServerStats(true); loadProxmox(true); loadExtServices(true);
  setTimeout(() => { if (btn) { btn.textContent = '⟳ REFRESH ALL'; btn.disabled = false; } }, 3000);
}

window.addEventListener('load', () => {
  tabLoaded['tab-intel'] = true;
  // Priority 1: fast/cached data — load immediately
  loadNews(); loadThreatLevel(); loadWikipedia(); loadAPOD(); loadOzaukeeAlerts();
  // Priority 2: stagger heavier panels to avoid blocking the browser
  setTimeout(() => { loadStocks(false, 'intel'); }, 200);
  setTimeout(() => { loadPresidentIntel(); }, 400);
  setTimeout(() => { loadCongressStatus(); }, 600);
  setTimeout(() => { loadMidtermIntel(); }, 800);
  setTimeout(() => { loadPolls(); }, 1000);
  setTimeout(() => { loadF1(); }, 1200);
  setTimeout(() => { loadPolTweets(); }, 1400);
  setTimeout(() => { loadGovtIntel(); }, 1600);
  setTimeout(() => { loadPodcasts(); }, 1800);
  // Intervals
  setInterval(loadServerStats, 30000);
  setInterval(refreshRadar, 300000);
});

// ── Threat Map Switcher ────────────────────────────────────
function switchMap(name, el) {
  document.querySelectorAll('.threatmap-frame').forEach(f => f.classList.remove('active'));
  document.querySelectorAll('.threatmap-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('map-'+name).classList.add('active');
  el.classList.add('active');
}

// ── Helpers ────────────────────────────────────────────────
function api(path, cb) {
  fetch(path).then(r => r.json()).then(cb).catch(e => console.error(path, e));
}
function loading(id, msg) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = `<div class="loading">${msg || 'Retrieving intelligence...'}</div>`;
}

// ══════════════════════════════════════════════════════════
//  INTEL FEED
// ══════════════════════════════════════════════════════════

let allArticles = [];
let activeSource = null;
let newsPage = 0;
const PAGE_SIZE = 9999;

// Source color mapping for CFP-style badges
const SOURCE_COLORS = {
  'Fox News':    '#e8501a',
  'CNN':         '#cc0000',
  'CNBC':        '#0d84c9',
  'NPR':         '#2a7ab5',
  'NYT':         '#333',
  'Reuters':     '#ff8c00',
  'AP News':     '#e63329',
  'BBC World':   '#b52020',
  'The Guardian':'#005689',
  'Washington Post':'#333',
  'The Hill':    '#666',
  'Politico':    '#2a5f8f',
  'WPR':         '#3a6e44',
  'TMJ4 (WI)':  '#0055a4',
  'CBS58 (WI)': '#215699',
  'Milwaukee Journal Sentinel':'#c4262d',
  'Yahoo Finance':'#5f01d1',
  'Investing.com':'#e8640a',
  'AllSides':    '#5a5a8a',
  'Steam':       '#1b2838',
};

function loadNews(force) {
  loading('news-feed');
  api(force ? '/api/news?force=1' : '/api/news', data => {
    allArticles = data.articles || [];
    newsPage = 0;
    buildSourceFilters();
    renderNews();
  });
}

function buildSourceFilters() {
  const sources = [...new Set(allArticles.map(a => a.source))];
  const wrap = document.getElementById('source-filters');
  wrap.innerHTML = '';
  const allBtn = makeSourceBtn('ALL', null, true);
  wrap.appendChild(allBtn);
  sources.forEach(s => wrap.appendChild(makeSourceBtn(s, s, false)));
}

function makeSourceBtn(label, value, active) {
  const btn = document.createElement('button');
  btn.className = 'source-btn' + (active ? ' active' : '');
  btn.textContent = label;
  const color = SOURCE_COLORS[value];
  if (color && !active) btn.style.borderColor = color + '80';
  btn.onclick = () => {
    activeSource = value;
    newsPage = 0;
    document.querySelectorAll('.source-btn').forEach(b => {
      b.classList.remove('active');
      b.style.background = '';
    });
    btn.classList.add('active');
    if (color) btn.style.background = color + '30';
    renderNews();
  };
  return btn;
}

function getFilteredArticles() {
  return activeSource ? allArticles.filter(a => a.source === activeSource) : allArticles;
}

function renderNews() {
  const articles = getFilteredArticles();
  const page = articles.slice(newsPage * PAGE_SIZE, (newsPage + 1) * PAGE_SIZE);
  const totalPages = Math.ceil(articles.length / PAGE_SIZE);
  const feed = document.getElementById('news-feed');
  if (!page.length) { feed.innerHTML = '<div class="no-data">No intelligence available.</div>'; return; }

  // CFP / Drudge-style: 3 columns of dense headlines
  const cols = [[], [], []];
  page.forEach((a, i) => cols[i % 3].push(a));

  const renderItem = a => {
    const color = SOURCE_COLORS[a.source] || 'var(--accent)';
    return `<div class="cfp-item">
      <span class="cfp-source" style="background:${color}20;border-color:${color}60;color:${color}">${a.source}</span>
      <a class="cfp-link" href="${a.link}" target="_blank" rel="noopener">${a.title}</a>
    </div>`;
  };

  let html = `<div class="cfp-grid">`;
  cols.forEach(col => {
    html += `<div class="cfp-col">${col.map(renderItem).join('')}</div>`;
  });
  html += `</div>`;

  // Pagination bar
  if (totalPages > 1) {
    html += `<div class="news-pager">`;
    html += `<button class="pager-btn" onclick="newsPage=Math.max(0,newsPage-1);renderNews()" ${newsPage===0?'disabled':''}>← Prev</button>`;
    const maxBtns = 8;
    let start = Math.max(0, newsPage - Math.floor(maxBtns/2));
    let end = Math.min(totalPages, start + maxBtns);
    if (end - start < maxBtns) start = Math.max(0, end - maxBtns);
    if (start > 0) html += `<span class="pager-ellipsis">…</span>`;
    for (let i = start; i < end; i++) {
      html += `<button class="pager-btn ${i===newsPage?'active':''}" onclick="newsPage=${i};renderNews()">${i+1}</button>`;
    }
    if (end < totalPages) html += `<span class="pager-ellipsis">…</span>`;
    html += `<button class="pager-btn" onclick="newsPage=Math.min(${totalPages-1},newsPage+1);renderNews()" ${newsPage===totalPages-1?'disabled':''}>Next →</button>`;
    html += `<span class="pager-count">${articles.length} articles</span>`;
    html += `</div>`;
  }

  feed.innerHTML = html;
}

// ── History ────────────────────────────────────────────────
function loadHistory() {
  api('/api/history', data => {
    document.getElementById('history-date').textContent = data.date || '';
    const render = (id, items) => {
      document.getElementById(id).innerHTML = (items||[]).slice(0,8).map(e =>
        `<div class="hist-item"><a href="${e.link}" target="_blank">${e.title}</a></div>`
      ).join('') || '<div class="dim" style="font-size:11px;padding:6px">No data available</div>';
    };
    render('hist-events', data.events);
    render('hist-births', data.births);
    render('hist-deaths', data.deaths);
  });
}

// ── Threat Level ───────────────────────────────────────────
function loadThreatLevel(force) {
  api(force ? '/api/threat_level?force=1' : '/api/threat_level', data => {
    const level = data.level || 'ELEVATED';
    document.getElementById('threat-level-text').textContent = level;
    document.getElementById('threat-level-badge').className = 'threat-badge threat-' + level;
    const wrap = document.getElementById('threat-alerts');
    if (data.alerts && data.alerts.length) {
      wrap.innerHTML = data.alerts.map(a =>
        `<div class="threat-alert-item">
          <a href="${a.link}" target="_blank">${a.title}</a>
          <div class="threat-alert-date">${a.published}</div>
        </div>`).join('');
    } else {
      wrap.innerHTML = '<div class="no-data" style="padding:8px 16px">✓ No active NTAS alerts</div>';
    }
    // CISA KEV
    const kevEl = document.getElementById('cisa-kev-list');
    if (!kevEl) return;
    const kevs = data.cisa_kev || [];
    if (!kevs.length) { kevEl.innerHTML = '<div class="no-data">No KEV data</div>'; return; }
    kevEl.innerHTML = kevs.map(v => `
      <div style="padding:8px 16px;border-bottom:1px solid var(--border)">
        <div style="display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;margin-bottom:3px">
          <a href="https://nvd.nist.gov/vuln/detail/${v.id}" target="_blank" rel="noopener"
             style="font-family:var(--font-m);font-size:10px;color:var(--red2);letter-spacing:1px;flex-shrink:0;text-decoration:none"
             onmouseover="this.style.textDecoration='underline'" onmouseout="this.style.textDecoration='none'">${v.id}</a>
          <a href="https://nvd.nist.gov/vuln/detail/${v.id}" target="_blank" rel="noopener"
             style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px;color:var(--text);line-height:1.4;text-decoration:none"
             onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--text)'">${v.name}</a>
        </div>
        <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:11px;color:var(--text-dim);display:flex;gap:16px;flex-wrap:wrap">
          <span>${v.vendor} · ${v.product}</span>
          <span>Added ${v.added}</span>
          <span style="color:var(--accent)">Due ${v.due}</span>
        </div>
      </div>`).join('');
  });
}

// ══════════════════════════════════════════════════════════
//  WIKIPEDIA
// ══════════════════════════════════════════════════════════

function loadWikipedia(force) {
  api(force ? '/api/wikipedia?force=1' : '/api/wikipedia', data => {
    const date = document.getElementById('wiki-date');
    if (date) date.textContent = data.date || '';

    // Shared wiki font style
    const wikiFont = "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Lato,sans-serif";

    // On This Day
    const otd = document.getElementById('wiki-otd');
    if (otd) {
      const items = data.onthisday || [];
      if (items.length) {
        otd.innerHTML = '<div style="max-height:700px;overflow-y:auto">' + items.map(e => `
            <div style="padding:8px 16px;border-bottom:1px solid var(--border);display:flex;gap:14px;align-items:baseline">
              <span style="font-family:var(--font-h);font-size:15px;color:var(--accent);min-width:48px;flex-shrink:0;text-align:right">${e.year}</span>
              <a href="${e.url}" target="_blank"
                 style="${wikiFont};color:var(--text);text-decoration:none;font-size:13px;line-height:1.55"
                 onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--text)'">${e.text}</a>
            </div>`).join('') + '</div>';
      } else {
        otd.innerHTML = '<div class="no-data">No events available</div>';
      }
    }

    // Today's Featured Article
    const tfa = data.tfa || {};
    const tfaEl = document.getElementById('wiki-tfa');
    if (tfaEl) {
      tfaEl.innerHTML = `
        <div style="display:flex;gap:16px;padding:16px;align-items:flex-start">
          ${tfa.thumbnail ? `<img src="${tfa.thumbnail}" style="width:110px;height:110px;object-fit:cover;border:1px solid var(--border);flex-shrink:0;border-radius:2px" alt="">` : ''}
          <div style="min-width:0">
            <div style="font-size:16px;font-weight:600;color:var(--accent);margin-bottom:8px;${wikiFont}">
              <a href="${tfa.url || '#'}" target="_blank" style="color:var(--accent);text-decoration:none">${tfa.title || '---'}</a>
            </div>
            <div style="${wikiFont};font-size:13px;color:var(--text);line-height:1.65;opacity:.9">${tfa.extract || ''}</div>
            <a href="${tfa.url || '#'}" target="_blank" style="${wikiFont};font-size:11px;color:var(--blue2);margin-top:10px;display:inline-block;text-decoration:none">Read full article on Wikipedia ↗</a>
          </div>
        </div>`;
    }

    // Did You Know
    const dykEl = document.getElementById('wiki-dyk');
    if (dykEl) {
      const items = data.dyk || [];
      dykEl.innerHTML = items.length
        ? `<ul style="margin:0;padding:0 16px 8px 32px;list-style:disc">` +
          items.map(t => `<li style="${wikiFont};font-size:13px;color:var(--text);line-height:1.6;padding:5px 0;opacity:.9;border-bottom:1px solid rgba(30,58,92,.25)">${t}</li>`).join('') +
          `</ul>`
        : '<div class="no-data" style="padding:10px">No DYK available</div>';
    }

    // In the News
    const newsEl = document.getElementById('wiki-news');
    if (newsEl) {
      const items = data.news || [];
      newsEl.innerHTML = items.length
        ? items.map(n => `
            <div style="padding:10px 16px;border-bottom:1px solid var(--border)">
              <a href="${n.url}" target="_blank"
                 style="${wikiFont};color:var(--text);font-size:13px;line-height:1.55;text-decoration:none"
                 onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--text)'">${n.text}</a>
            </div>`).join('')
        : '<div class="no-data">No news items available</div>';
    }
  });
}

// ── APOD ───────────────────────────────────────────────────
function loadAPOD(force) {
  api(force ? '/api/apod?force=1' : '/api/apod', data => {
    const el = document.getElementById('apod-panel');
    const dateEl = document.getElementById('apod-date');
    if (!el) return;
    if (dateEl) dateEl.textContent = data.date || (data._stale ? data.date + ' (cached)' : '');
    if (data.error) {
      el.innerHTML = `
        <div style="padding:24px;text-align:center">
          <div style="font-size:13px;color:var(--text-dim);margin-bottom:16px">${data.error}</div>
          <a href="${data.apod_url || 'https://apod.nasa.gov/apod/astropix.html'}" target="_blank"
             style="display:inline-block;padding:10px 28px;background:var(--bg3);border:1px solid var(--accent);color:var(--accent);font-family:var(--font-m);font-size:11px;letter-spacing:3px;text-decoration:none">
            VIEW TODAY'S APOD ↗
          </a>
        </div>`;
      return;
    }

    if (data.media_type === 'video') {
      el.innerHTML = `
        <div style="padding:14px 16px">
          <div style="font-family:var(--font-h);font-size:18px;color:var(--accent);margin-bottom:10px">${data.title}</div>
          <iframe src="${data.url}" style="width:100%;height:400px;border:none" allowfullscreen></iframe>
          <div style="font-size:12px;color:var(--text-dim);line-height:1.6;margin-top:12px">${data.explanation}</div>
          <div style="font-size:10px;color:var(--text-dim);margin-top:6px">© ${data.copyright || 'NASA'}</div>
        </div>`;
    } else {
      el.innerHTML = `
        <div style="display:flex;gap:0;align-items:stretch">
          <a href="${data.hdurl || data.url}" target="_blank" style="flex-shrink:0;display:block">
            <img src="${data.url}" style="max-height:340px;max-width:480px;object-fit:cover;display:block;border-right:1px solid var(--border)" alt="${data.title}">
          </a>
          <div style="padding:16px 18px;flex:1;overflow:hidden">
            <div style="font-family:var(--font-h);font-size:18px;color:var(--accent);margin-bottom:10px;line-height:1.3">${data.title}</div>
            <div style="font-size:12px;color:var(--text-dim);line-height:1.7;max-height:260px;overflow-y:auto">${data.explanation}</div>
            <div style="font-size:10px;color:var(--text-dim);margin-top:10px;border-top:1px solid var(--border);padding-top:8px">
              © ${data.copyright || 'NASA'} &nbsp;|&nbsp;
              <a href="https://apod.nasa.gov/apod/astropix.html" target="_blank" style="color:var(--accent)">View on APOD ↗</a>
              &nbsp;|&nbsp; <a href="${data.hdurl || data.url}" target="_blank" style="color:var(--blue2)">Full Resolution ↗</a>
            </div>
          </div>
        </div>`;
    }
  });
}

// ══════════════════════════════════════════════════════════
//  COMMAND CENTER
// ══════════════════════════════════════════════════════════

function loadServerStats(force) {
  api(force ? '/api/server_stats?force=1' : '/api/server_stats', data => {
    if (data.error) return;
    document.getElementById('server-ts').textContent = data.ts || '';
    const bar = (pct) => `<div class="stat-bar"><div class="stat-bar-fill ${pct>85?'crit':pct>65?'warn':''}" style="width:${Math.min(pct,100)}%"></div></div>`;
    document.getElementById('server-stats').innerHTML = `
      <div class="stat-box">
        <div class="stat-label">CPU Load</div>
        <div class="stat-value">${data.cpu}%</div>
        <div class="stat-sub">Load avg: ${(data.load||[]).join(' ')}</div>
        ${bar(data.cpu)}
      </div>
      <div class="stat-box">
        <div class="stat-label">Memory</div>
        <div class="stat-value">${data.mem_pct}%</div>
        <div class="stat-sub">${data.mem_used}MB / ${data.mem_total}MB</div>
        ${bar(data.mem_pct)}
      </div>
      <div class="stat-box">
        <div class="stat-label">Disk /mnt/hdd</div>
        <div class="stat-value">${data.disk_pct}%</div>
        <div class="stat-sub">${data.disk_used} / ${data.disk_total}</div>
        ${bar(parseInt(data.disk_pct))}
      </div>
      <div class="stat-box">
        <div class="stat-label">Swap</div>
        <div class="stat-value">${data.swap_pct !== undefined ? data.swap_pct + '%' : 'N/A'}</div>
        <div class="stat-sub">${data.swap_used !== undefined ? data.swap_used + 'MB / ' + data.swap_total + 'MB' : ''}</div>
        ${data.swap_pct !== undefined ? bar(data.swap_pct) : ''}
      </div>`;

    const svcs = data.services || {};
    const friendlyName = n => n.replace('@slankey','').replace('kevsec-','').replace('-',' ').toUpperCase();
    document.getElementById('services-grid').innerHTML = Object.entries(svcs).map(([name,status]) =>
      `<div class="service-item">
        <span class="service-name">${friendlyName(name)}</span>
        <span class="${status==='active'?'svc-active':'svc-inactive'}">${status==='active'?'● Active':'○ Offline'}</span>
      </div>`).join('');
  });
}

// ══════════════════════════════════════════════════════════
//  OPS CONFIRM MODAL — reusable countdown confirm for server/service actions
// ══════════════════════════════════════════════════════════

let _opsTimer = null;
let _opsSeconds = 10;
let _opsArmed = false;
let _opsCallback = null;
let _opsNeedCheck = false;

const OPS_THEMES = {
  warn:    { color: '#cc7700', dimcolor: '#7a4400', bg: '#0d0700' },
  danger:  { color: '#cc2200', dimcolor: '#7a1500', bg: '#0d0000' },
  info:    { color: '#0077cc', dimcolor: '#004477', bg: '#00070d' },
};

function _opsBeep(freq, dur, vol) {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain); gain.connect(ctx.destination);
    osc.frequency.value = freq;
    osc.type = 'sine';
    gain.gain.setValueAtTime(vol || 0.08, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + dur);
    osc.start(); osc.stop(ctx.currentTime + dur);
  } catch(e) {}
}

function _opsConfirmTone() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    [440, 550, 660].forEach((f, i) => {
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.connect(g); g.connect(ctx.destination);
      o.frequency.value = f; o.type = 'sine';
      g.gain.setValueAtTime(0.1, ctx.currentTime + i * 0.1);
      g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + i * 0.1 + 0.12);
      o.start(ctx.currentTime + i * 0.1);
      o.stop(ctx.currentTime + i * 0.1 + 0.13);
    });
  } catch(e) {}
}

function _opsAbortTone() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    [440, 330, 220].forEach((f, i) => {
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.connect(g); g.connect(ctx.destination);
      o.frequency.value = f; o.type = 'sine';
      g.gain.setValueAtTime(0.08, ctx.currentTime + i * 0.1);
      g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + i * 0.1 + 0.12);
      o.start(ctx.currentTime + i * 0.1);
      o.stop(ctx.currentTime + i * 0.1 + 0.13);
    });
  } catch(e) {}
}

/**
 * openOpsModal({ icon, title, sub, countdown, theme, checkbox, checkboxText, onConfirm })
 * theme: 'warn' | 'danger' | 'info'
 */
function openOpsModal({ icon='⚡', title='CONFIRM ACTION', sub='', countdown=10,
                        theme='warn', checkbox=false, checkboxText='', onConfirm }) {
  _opsCallback  = onConfirm;
  _opsSeconds   = countdown;
  _opsArmed     = false;
  _opsNeedCheck = checkbox;

  const t = OPS_THEMES[theme] || OPS_THEMES.warn;
  const inner = document.getElementById('ops-modal-inner');
  inner.style.border = `2px solid ${t.color}`;
  inner.style.background = t.bg;
  inner.style.boxShadow = `0 0 40px ${t.color}55`;

  // Apply theme CSS vars on the modal element
  const m = document.getElementById('ops-modal');
  m.style.setProperty('--ops-color',    t.color);
  m.style.setProperty('--ops-dimcolor', t.dimcolor);

  document.getElementById('ops-modal-icon').textContent  = icon;
  document.getElementById('ops-modal-title').textContent = title;
  document.getElementById('ops-modal-title').style.color = t.color;
  document.getElementById('ops-modal-sub').textContent   = sub;
  document.getElementById('ops-modal-sub').style.color   = t.dimcolor;
  document.getElementById('ops-countdown').textContent   = String(countdown).padStart(2, '0');
  document.getElementById('ops-countdown').style.color   = t.color;
  document.getElementById('ops-countdown').style.textShadow = `0 0 16px ${t.color}`;
  document.getElementById('ops-countdown-bar').style.background   = t.color;
  document.getElementById('ops-countdown-bar').style.width        = '0%';
  document.getElementById('ops-countdown-bar').style.transition   = 'none';

  // Confirm button
  const btn = document.getElementById('ops-confirm-btn');
  btn.disabled = true;
  btn.style.color = t.dimcolor.replace('7a', '2a').replace('00', '00');
  btn.style.borderColor = '#2a1a00';
  btn.style.cursor = 'not-allowed';
  btn.style.boxShadow = 'none';

  // Checkbox
  const cbWrap = document.getElementById('ops-checkbox-wrap');
  const cbEl   = document.getElementById('ops-confirm-check');
  cbWrap.style.display = checkbox ? 'block' : 'none';
  cbEl.checked  = false;
  cbEl.disabled = true;
  if (checkbox) document.getElementById('ops-checkbox-text').textContent = checkboxText;

  m.style.display = 'flex';
  _opsBeep(330, 0.2, 0.07);

  setTimeout(() => {
    document.getElementById('ops-countdown-bar').style.transition = 'width 1s linear';
  }, 50);

  const total = countdown;
  _opsTimer = setInterval(() => {
    _opsSeconds--;
    const pct = ((total - _opsSeconds) / total * 100).toFixed(1);
    document.getElementById('ops-countdown').textContent = String(Math.max(_opsSeconds, 0)).padStart(2, '0');
    document.getElementById('ops-countdown-bar').style.width = pct + '%';

    if (_opsSeconds <= 3 && _opsSeconds > 0) {
      _opsBeep(550, 0.07, 0.09);
    } else if (_opsSeconds > 0) {
      _opsBeep(330, 0.05, 0.05);
    }

    if (_opsSeconds <= 0) {
      clearInterval(_opsTimer); _opsTimer = null;
      _opsArmed = true;
      _opsConfirmTone();
      document.getElementById('ops-countdown').textContent = '00';
      if (checkbox) { cbEl.disabled = false; }
      else { _opsEnableConfirm(t); }
    }
  }, 1000);
}

function opsCheckReady() {
  if (!_opsArmed) return;
  const t = OPS_THEMES[document.getElementById('ops-modal').dataset.theme || 'warn'];
  const tc = OPS_THEMES.warn; // fallback
  if (!_opsNeedCheck || document.getElementById('ops-confirm-check').checked) {
    _opsEnableConfirm(tc);
  }
}

function _opsEnableConfirm(t) {
  const c = OPS_THEMES.warn; // read from CSS var instead
  const color = getComputedStyle(document.getElementById('ops-modal')).getPropertyValue('--ops-color').trim() || '#cc7700';
  const btn = document.getElementById('ops-confirm-btn');
  btn.disabled = false;
  btn.style.color = color;
  btn.style.borderColor = color;
  btn.style.cursor = 'pointer';
  btn.style.boxShadow = `0 0 16px ${color}55`;
}

function opsAbort() {
  _opsAbortTone();
  if (_opsTimer) { clearInterval(_opsTimer); _opsTimer = null; }
  const cd = document.getElementById('ops-countdown');
  const prev = cd.textContent;
  cd.textContent = 'ABORT';
  cd.style.fontSize = '24px';
  setTimeout(() => {
    document.getElementById('ops-modal').style.display = 'none';
    cd.style.fontSize = '56px';
    cd.textContent = prev;
    _opsArmed = false;
    _opsCallback = null;
  }, 700);
}

function opsExecute() {
  if (!_opsArmed || !_opsCallback) return;
  if (_opsNeedCheck && !document.getElementById('ops-confirm-check').checked) return;
  document.getElementById('ops-modal').style.display = 'none';
  _opsArmed = false;
  const cb = _opsCallback;
  _opsCallback = null;
  cb();
}

document.getElementById('ops-modal').addEventListener('click', function(e) {
  if (e.target === this) opsAbort();
});

// ── Service Control ────────────────────────────────────────

const SVC_LABELS = {
  'jellyfin':          '🎬 Jellyfin',
  'rtorrent@slankey':  '🌱 rTorrent',
  'honeypot':          '🍯 Honeypot',
  'endlessh':          '🐢 SSH Tarpit',
  'nginx':             '🌐 Nginx',
  'librarian-bot':     '📚 Librarian Bot',
  'reminder-bot':      '⏰ Reminder Bot',
  'presidential-sim':  '🏛 Pres. Sim',
  'prowlarr':          '🔍 Prowlarr',
  'radarr':            '🎥 Radarr',
  'sonarr':            '📺 Sonarr',
  'autobrr':           '⚡ Autobrr',
  'kevsec-dashboard':  '🖥 Dashboard',
  'dj-atticus':        '🎵 DJ Atticus',
};

function _svcFeedback(msg, color) {
  const el = document.getElementById('svc-feedback');
  if (!el) return;
  el.textContent = msg;
  el.style.color = color || 'var(--accent)';
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.textContent = ''; }, 4000);
}

function _postControl(url, body, cb) {
  const csrf = document.querySelector('meta[name="csrf-token"]');
  fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf ? csrf.content : '' },
    body: JSON.stringify(body)
  }).then(r => r.json()).then(cb).catch(e => _svcFeedback('⚠ ' + e, '#cc4400'));
}

function serviceAction(action, service, btn) {
  const label = SVC_LABELS[service] || service;
  const isDangerous = action === 'stop';
  const isDash = service === 'kevsec-dashboard';

  const doAction = () => {
    if (btn) { btn.disabled = true; btn.textContent = '…'; }
    _svcFeedback(`${action.toUpperCase()} ${label}…`, 'var(--text-dim)');
    _postControl('/api/service_control', { action, service }, data => {
      if (btn) { btn.disabled = false; btn.textContent = action === 'restart' ? '⟳' : action === 'stop' ? '■' : '▶'; }
      if (data.error) { _svcFeedback('✕ ' + data.error, '#cc4400'); return; }
      const st = data.status;
      _svcFeedback(`${label} → ${st}`, st === 'active' ? '#4a9c4a' : '#cc7700');
      setTimeout(() => loadServerStats(true), 1500);
      setTimeout(buildSvcControlGrid, 1600);
    });
  };

  if (!isDangerous && action !== 'stop') {
    // Restarts and starts: short 5s modal, no checkbox
    openOpsModal({
      icon: action === 'restart' ? '🔁' : '▶',
      title: `${action.toUpperCase()} ${label.replace(/^[^ ]+ /, '')}`,
      sub: `SYSTEMD SERVICE CONTROL // ${service}`,
      countdown: 5,
      theme: 'warn',
      checkbox: false,
      onConfirm: doAction,
    });
  } else {
    // Stop: 10s countdown, checkbox if it's a critical service
    openOpsModal({
      icon: '■',
      title: `STOP ${label.replace(/^[^ ]+ /, '')}`,
      sub: isDash ? 'WARNING — STOPPING DASHBOARD KILLS THIS PAGE' : `SYSTEMD SERVICE CONTROL // ${service}`,
      countdown: 10,
      theme: isDash ? 'danger' : 'warn',
      checkbox: isDash,
      checkboxText: 'I understand stopping the dashboard will disconnect me until it is restarted manually.',
      onConfirm: doAction,
    });
  }
}

function serverAction(action, delay) {
  if (action === 'cancel') {
    // Cancel needs no countdown
    _svcFeedback('Cancelling…', '#cc7700');
    _postControl('/api/server_control', { action, delay: 0 }, data => {
      _svcFeedback(data.error ? '✕ ' + data.error : '✓ Scheduled restart cancelled.', data.error ? '#cc4400' : '#4a9c4a');
    });
    return;
  }

  const configs = {
    'restart': {
      icon: '🔁', title: 'SYSTEM RESTART',
      sub: delay > 0 ? `SCHEDULED IN ${delay} MINUTE(S)` : 'IMMEDIATE REBOOT',
      countdown: delay > 0 ? 8 : 12, theme: 'warn',
      checkbox: false,
    },
    'shutdown': {
      icon: '⏹', title: 'SYSTEM SHUTDOWN',
      sub: 'SERVER WILL GO OFFLINE — PROXMOX REQUIRED TO RESTORE',
      countdown: 15, theme: 'danger',
      checkbox: true,
      checkboxText: 'I understand the server will be fully offline and requires Proxmox or physical access to restart.',
    },
    'update-restart': {
      icon: '📦', title: 'UPDATE + RESTART',
      sub: 'APT UPGRADE WILL RUN — SERVER OFFLINE SEVERAL MINUTES',
      countdown: 10, theme: 'warn',
      checkbox: true,
      checkboxText: 'I understand the server will run apt upgrade and then reboot. This may take several minutes.',
    },
  };

  const cfg = configs[action];
  if (!cfg) return;

  openOpsModal({
    ...cfg,
    onConfirm: () => {
      const feedback = {
        'restart':        delay > 0 ? `✓ Restart scheduled in ${delay} min` : 'Restarting — reconnect shortly.',
        'shutdown':       'Shutting down — goodbye.',
        'update-restart': '✓ Updating — reconnect in a few minutes.',
      };
      _svcFeedback(feedback[action] || '…', '#cc7700');
      _postControl('/api/server_control', { action, delay }, data => {
        if (data.error) _svcFeedback('✕ ' + data.error, '#cc4400');
      });
    },
  });
}

function buildSvcControlGrid() {
  const grid = document.getElementById('svc-control-grid');
  if (!grid) return;
  // Get current statuses from server-stats data if available
  _postControl || true; // noop to avoid lint
  fetch('/api/server_stats').then(r => r.json()).then(data => {
    const svcs = data.services || {};
    grid.innerHTML = Object.keys(SVC_LABELS).map(svc => {
      const label = SVC_LABELS[svc];
      const active = svcs[svc] === 'active';
      const isDash = svc === 'kevsec-dashboard';
      const dotColor = active ? '#4a9c4a' : '#aa2200';
      const dotLabel = active ? '● Active' : '○ Offline';
      return `<div class="svc-card">
        <span class="svc-card-name">${label}</span>
        <span class="svc-card-status" style="color:${dotColor}">${dotLabel}</span>
        <span class="svc-card-btns">
          ${active
            ? `<button class="svc-btn svc-btn-ok" onclick="serviceAction('restart','${svc}',this)" title="Restart">⟳</button>
               <button class="svc-btn svc-btn-danger" onclick="serviceAction('stop','${svc}',this)" title="Stop"${isDash?' style="opacity:0.5" title="Stopping dashboard kills this page"':''}>■</button>`
            : `<button class="svc-btn svc-btn-ok" onclick="serviceAction('start','${svc}',this)" title="Start">▶</button>`
          }
        </span>
      </div>`;
    }).join('');
  }).catch(() => {
    grid.innerHTML = '<div class="no-data">Could not load service status</div>';
  });
}

function loadExtServices(force) {
  const el = document.getElementById('ext-services-grid');
  const localEl = document.getElementById('local-services-grid');
  if (!el && !localEl) return;
  api(force ? '/api/ext_services?force=1' : '/api/ext_services', data => {
    const ts = document.getElementById('ext-svc-ts');
    if (ts) ts.textContent = data.fetched || '';

    // External services (status pages)
    if (el) {
      const svcs = data.services || [];
      if (!svcs.length) { el.innerHTML = '<div class="no-data">No data</div>'; }
      else {
        const indColor = i => i === 'none' ? 'var(--text-dim)' : i === 'minor' ? 'var(--accent)' : 'var(--red2)';
        const indDot  = i => i === 'none' ? '●' : i === 'minor' ? '◐' : '●';
        el.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:6px;padding:10px 14px">
          ${svcs.map(s => `
            <div style="background:var(--bg3);border:1px solid var(--border);border-radius:3px;padding:8px 10px;display:flex;flex-direction:column;gap:3px">
              <span style="font-family:var(--font-m);font-size:10px;letter-spacing:1px;color:var(--text-hi)">${s.name}</span>
              <span style="font-size:11px;color:${indColor(s.indicator)};letter-spacing:1px">
                ${indDot(s.indicator)} ${s.status === 'operational' ? 'OK' : s.status === 'degraded' ? 'Degraded' : s.status === 'outage' ? 'Outage' : 'Unknown'}
              </span>
              ${s.desc && s.status !== 'operational' ? `<span style="font-size:9px;color:var(--text-dim)">${s.desc}</span>` : ''}
            </div>`).join('')}
        </div>`;
      }
    }

    // Local systemd services
    if (localEl) {
      const local = data.local || [];
      if (!local.length) { localEl.innerHTML = '<div class="no-data">No local service data</div>'; return; }
      localEl.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:6px;padding:10px 14px">
        ${local.map(s => {
          const up = s.status === 'operational';
          const col = up ? '#4caf50' : '#f44336';
          return `<div style="background:var(--bg3);border:1px solid ${up ? 'var(--border)' : '#f4433644'};border-radius:3px;padding:8px 10px;display:flex;flex-direction:column;gap:3px;${up ? '' : 'box-shadow:0 0 8px #f4433620'}">
            <span style="font-family:var(--font-m);font-size:10px;letter-spacing:1px;color:var(--text-hi)">${s.name}</span>
            <span style="font-size:11px;color:${col};letter-spacing:1px">● ${up ? 'RUNNING' : 'DOWN'}</span>
          </div>`;
        }).join('')}
      </div>`;
    }
  });
}

function loadProxmox(force) {
  api(force ? '/api/proxmox?force=1' : '/api/proxmox', data => {
    document.getElementById('pve-ts').textContent = data.fetched || '';
    if (data.error) {
      document.getElementById('proxmox-nodes').innerHTML = `<div class="error-msg">⚠ ${data.error}</div>`;
      return;
    }
    document.getElementById('proxmox-nodes').innerHTML = (data.nodes||[]).map(n => {
      const mp = n.maxmem ? Math.round(n.mem/n.maxmem*100) : 0;
      const gb = n.maxmem ? `${(n.mem/1073741824).toFixed(1)}/${(n.maxmem/1073741824).toFixed(0)}GB` : '';
      return `<div class="pve-node">
        <div class="pve-node-name">Node: ${n.node}</div>
        <div class="stat-label">CPU ${n.cpu}%</div>
        <div class="stat-bar" style="margin:4px 0 8px"><div class="stat-bar-fill" style="width:${n.cpu}%"></div></div>
        <div class="stat-label">MEM ${mp}% — ${gb}</div>
        <div class="stat-bar"><div class="stat-bar-fill ${mp>80?'warn':''}" style="width:${mp}%"></div></div>
      </div>`;
    }).join('') || '<div class="loading">No nodes</div>';

    document.getElementById('proxmox-vms').innerHTML = (data.vms||[]).map(vm => {
      const mem = vm.maxmem ? `${(vm.maxmem/1073741824).toFixed(1)}GB` : '?';
      return `<div class="pve-vm">
        <span class="vm-id">VM ${vm.vmid}</span>
        <span class="vm-name">${vm.name}</span>
        <span class="vm-status-${vm.status}">${vm.status==='running'?'▶ Running':'■ Stopped'}</span>
        <span class="vm-meta">${vm.cpu}% CPU</span>
        <span class="vm-meta">${mem}</span>
      </div>`;
    }).join('') || '<div class="loading">No VMs</div>';
  });
}

const STOCK_TOOLTIPS = {
  'S&P 500':      'Tracks 500 large US companies. The broadest gauge of US equity market health and investor sentiment.',
  'Dow Jones':    'Price-weighted index of 30 blue-chip US stocks. A historic proxy for overall US economic direction.',
  'NASDAQ':       'Tech-heavy composite of ~3,300 stocks. Leads on growth/innovation sentiment; sensitive to rate changes.',
  'Russell 2000': 'Tracks 2,000 small-cap US companies. Outperforms in domestic-growth cycles; underperforms in risk-off.',
  'VIX':          '"Fear index." Measures expected S&P 500 volatility over 30 days. >20 = elevated anxiety; >30 = fear.',
  'Nikkei 225':   'Japan\'s flagship large-cap index. Sensitive to JPY moves and global export demand; major Asia benchmark.',
  'FTSE 100':     'UK\'s top 100 companies by market cap. Heavy in energy, financials, miners — a global revenue proxy.',
  'DAX':          'Germany\'s top 30 companies. Europe\'s industrial and export bellwether; closely tied to China demand.',
  'Hang Seng':    'Hong Kong\'s benchmark. Tracks Chinese and HK blue chips; a key China growth and sentiment barometer.',
  'Oil (WTI)':    'US benchmark crude. Drives inflation, transportation costs, and petro-state fiscal health globally.',
  'Brent Crude':  'International oil benchmark (~2/3 of global supply priced off it). Key inflation and geopolitical input.',
  'Gold':         'Safe-haven asset. Rises on inflation, USD weakness, geopolitical risk, or central bank reserve buying.',
  'Silver':       'Dual role: safe-haven store of value AND industrial metal (solar, EVs). Amplifies gold\'s moves.',
  'Copper':       '"Dr. Copper" — strong leading indicator of global economic activity due to ubiquitous industrial use.',
  'Nat Gas':      'Natural gas futures. Volatile based on weather, LNG exports, storage levels, and European energy demand.',
  'Bitcoin':      'Largest cryptocurrency by market cap. Tracks macro liquidity and serves as a risk-on/risk-off barometer.',
  'Ethereum':     'Second-largest crypto; underpins DeFi and NFT ecosystems. More correlated to tech sentiment than BTC.',
  '10Y Treasury': 'Benchmark US government bond yield. Rising = tighter financial conditions. Key rate-sensitive anchor.',
  'EUR/USD':      'World\'s most-traded currency pair. EUR strength signals European resilience vs. USD safe-haven demand.',
  'GBP/USD':      'British pound vs. USD. Sensitive to UK economic data, Bank of England policy, and post-Brexit trade.',
  'USD/JPY':      'Dollar vs. yen. Rising = risk-on or Fed hawkishness. Yen is a traditional safe-haven currency.',
  'USD/CAD':      'Dollar vs. Canadian dollar. CAD is highly correlated with oil prices and North American trade flows.',
  'AUD/USD':      'Aussie dollar vs. USD. AUD is a commodity/China proxy — rises with risk appetite and raw material demand.',
  'USD Index':    'Dollar\'s value vs. basket of 6 major currencies. Stronger dollar tightens global financial conditions.',
};

function loadStocks(force, target) {
  const gridId  = target === 'intel' ? 'stocks-grid-intel' : 'stocks-grid';
  const tsId    = target === 'intel' ? 'stock-ts-intel'    : 'stock-ts';
  loading(gridId);
  api(force ? '/api/stocks?force=1' : '/api/stocks', data => {
    const ts = document.getElementById(tsId);
    if (ts) ts.textContent = data.fetched || '';
    const html = (data.stocks||[]).map(s => {
      const cls   = s.change > 0 ? 'pos' : s.change < 0 ? 'neg' : 'flat';
      const arrow = s.change > 0 ? '▲'   : s.change < 0 ? '▼'   : '─';
      const price = s.price > 100
        ? s.price.toLocaleString('en-US',{maximumFractionDigits:2})
        : s.price.toFixed(2);
      const tip = (STOCK_TOOLTIPS[s.name] || '').replace(/"/g, '&quot;');
      return `<div class="stock-item"${tip ? ` data-tooltip="${tip}"` : ''}>
        <div class="stock-name">${s.name}</div>
        <div class="stock-price">${s.price > 0 ? price : '---'}</div>
        <div class="stock-${cls}">${arrow} ${Math.abs(s.change).toFixed(2)} (${s.pct>0?'+':''}${s.pct.toFixed(2)}%)</div>
      </div>`;
    }).join('');
    // Render in both grids simultaneously if data is available
    ['stocks-grid','stocks-grid-intel'].forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.innerHTML = html; }
    });
    ['stock-ts','stock-ts-intel'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = data.fetched || '';
    });
  });
}

function loadUpdates() {
  const wrap = document.getElementById('updates-list');
  wrap.innerHTML = '<div class="loading">Scanning package manifest...</div>';
  api('/api/pending_updates', data => {
    if (data.error) { wrap.innerHTML = `<div class="error-msg">${data.error}</div>`; return; }
    if (data._pending) {
      // Background scan just kicked off — poll until ready
      wrap.innerHTML = '<div class="loading">⟳ Scanning… (this takes ~10s)</div>';
      setTimeout(loadUpdates, 4000);
      return;
    }
    wrap.innerHTML = !data.count
      ? '<div class="no-data">✓ System fully patched — no updates pending</div>'
      : `<div class="update-count">${data.count} updates pending</div>` +
        data.updates.map(p => `<div class="update-pkg">▸ ${p}</div>`).join('');
  });
}


// ══════════════════════════════════════════════════════════
//  CYBER OPS
// ══════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════
//  INTELLIGENCE FEED — NEW PANELS
// ══════════════════════════════════════════════════════════

function loadOzaukeeAlerts() {
  api('/api/ozaukee_alerts', data => {
    const banner = document.getElementById('ozaukee-alert-banner');
    if (!banner) return;
    const alerts = data.alerts || [];
    if (!alerts.length) { banner.style.display = 'none'; return; }
    banner.style.display = 'block';
    banner.innerHTML = alerts.map(a =>
      `⚠ <strong>OZAUKEE COUNTY ALERT</strong> — ${a.event}: ${a.headline || a.desc}`
    ).join('<br>');
  });
}

function loadPresidentIntel(force) {
  const el = document.getElementById('president-feed');
  if (!el) return;
  api(force ? '/api/president_intel?force=1' : '/api/president_intel', data => {
    const ts = document.getElementById('president-ts');
    if (ts) ts.textContent = data.fetched || '';

    // President's schedule from Factbase iCal
    const sched = data.schedule || [];
    const schedEl = document.getElementById('president-schedule');
    if (schedEl) {
      if (sched.length) {
        schedEl.innerHTML = sched.map(ev => `
          <div style="padding:8px 14px;border-bottom:1px solid var(--border);display:flex;gap:12px;align-items:flex-start">
            <div style="min-width:90px;flex-shrink:0">
              <div style="font-size:9px;color:var(--accent);font-family:var(--font-m);letter-spacing:1px">${ev.date}</div>
              <div style="font-size:10px;color:var(--text-dim)">${ev.time}</div>
            </div>
            <div style="flex:1">
              <div style="font-size:11px;color:var(--text-hi);line-height:1.4">${ev.title}</div>
              ${ev.location ? `<div style="font-size:10px;color:var(--text-dim);margin-top:2px">📍 ${ev.location}</div>` : ''}
            </div>
          </div>`).join('');
      } else {
        schedEl.innerHTML = `<div style="padding:10px 14px;font-size:11px;color:var(--text-dim)">
          No upcoming schedule events found ·
          <a href="${data.schedule_url||'https://www.whitehouse.gov/briefings-statements/'}" target="_blank" style="color:var(--accent)">WH Briefings ↗</a>
        </div>`;
      }
    }

    // WH press releases grid
    const items = data.items || [];
    if (!items.length) {
      el.innerHTML = `<div style="padding:12px 16px;font-size:11px;color:var(--text-dim)">
        No recent White House activity.
        <a href="${data.wh_url||'https://www.whitehouse.gov/news/'}" target="_blank" style="color:var(--accent)">Open WH News ↗</a>
      </div>`;
      return;
    }
    el.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:1px;background:var(--border)">
      ${items.map(item => `
        <div style="background:var(--bg2);padding:10px 14px">
          <div style="font-size:9px;letter-spacing:2px;color:var(--text-dim);margin-bottom:4px">${item.source} · ${item.date||''}</div>
          <a href="${item.link}" target="_blank" style="color:var(--text-hi);font-size:12px;text-decoration:none;line-height:1.4;display:block;margin-bottom:4px">${item.title}</a>
          ${item.summary ? `<div style="font-size:10px;color:var(--text-dim);line-height:1.5">${item.summary}</div>` : ''}
        </div>`).join('')}
    </div>`;
  });
}

function loadCongressStatus(force) {
  const ts = document.getElementById('congress-ts');
  api(force ? '/api/congress_status?force=1' : '/api/congress_status', data => {
    if (ts) ts.textContent = data.fetched || '';

    // Session badge
    const badge = document.getElementById('congress-session-badge');
    if (badge) {
      const active = data.in_session;
      const returnLine = (!active && data.next_session_date)
        ? `<div style="font-size:10px;color:#cc9933;margin-top:3px">Returns: ${data.next_session_date}</div>` : '';
      const votesLink = data.votes_url
        ? `<a href="${data.votes_url}" target="_blank" style="font-size:9px;color:var(--accent);margin-left:10px;text-decoration:none">ROLL CALL VOTES ↗</a>` : '';
      badge.innerHTML = `
        <div style="display:flex;align-items:center;gap:14px">
          <div style="font-size:28px">${active ? '🟢' : '🔴'}</div>
          <div>
            <div style="font-size:13px;color:${active?'#4a9c4a':'#cc4400'};font-family:var(--font-m);letter-spacing:2px">
              ${active ? 'IN SESSION' : 'IN RECESS'}${votesLink}
            </div>
            <div style="font-size:10px;color:var(--text-dim);letter-spacing:1px;margin-top:2px">${data.session_label||''} — ${data.congress||'119th'} Congress</div>
            ${returnLine}
          </div>
        </div>`;
    }

    // Seat composition bars
    const seatsEl = document.getElementById('congress-seats');
    if (seatsEl && data.seats) {
      const s = data.seats.senate  || {};
      const h = data.seats.house   || {};
      const sRpct = Math.round((s.R||0) / (s.total||100) * 100);
      const hRpct = Math.round((h.R||0) / (h.total||435) * 100);
      const senateMaj = (s.R||0) > 50 ? 'R' : 'D';
      const houseMaj  = (h.R||0) > Math.floor((h.total||435)/2) ? 'R' : 'D';
      seatsEl.innerHTML = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
          <div>
            <div style="font-size:9px;letter-spacing:3px;color:var(--text-dim);margin-bottom:6px">
              SENATE — ${senateMaj==='R'?'<span style="color:#cc4444">R MAJ</span>':'<span style="color:#4466cc">D MAJ</span>'}
              &nbsp;R:${s.R} D:${s.D} I:${s.I||0}
            </div>
            <div style="height:20px;border-radius:3px;overflow:hidden;display:flex;background:#222">
              <div style="width:${sRpct}%;background:#cc4444;display:flex;align-items:center;justify-content:center;font-size:9px;font-family:var(--font-m);color:#fff">${s.R||0}</div>
              <div style="flex:1;background:#4466cc;display:flex;align-items:center;justify-content:center;font-size:9px;font-family:var(--font-m);color:#fff">${(s.D||0)+(s.I||0)}</div>
            </div>
            <div style="font-size:9px;color:var(--text-dim);margin-top:3px">Majority: 51 needed · ${s.note||''}</div>
          </div>
          <div>
            <div style="font-size:9px;letter-spacing:3px;color:var(--text-dim);margin-bottom:6px">
              HOUSE — ${houseMaj==='R'?'<span style="color:#cc4444">R MAJ</span>':'<span style="color:#4466cc">D MAJ</span>'}
              &nbsp;R:${h.R} D:${h.D}${h.vacant?` V:${h.vacant}`:''}
            </div>
            <div style="height:20px;border-radius:3px;overflow:hidden;display:flex;background:#222">
              <div style="width:${hRpct}%;background:#cc4444;display:flex;align-items:center;justify-content:center;font-size:9px;font-family:var(--font-m);color:#fff">${h.R||0}</div>
              <div style="flex:1;background:#4466cc;display:flex;align-items:center;justify-content:center;font-size:9px;font-family:var(--font-m);color:#fff">${h.D||0}</div>
            </div>
            <div style="font-size:9px;color:var(--text-dim);margin-top:3px">Majority: 218 needed · ${h.note||''}</div>
          </div>
        </div>`;
    }

    // Seat map SVG in congress panel
    const cSeatMap = document.getElementById('congress-seatmap');
    if (cSeatMap) cSeatMap.innerHTML = _renderSeatMap();

    // Bills — sorted by date (backend already sorted, display as-is)
    const billsEl = document.getElementById('congress-bills');
    if (billsEl) {
      const bills = data.bills || [];
      if (!bills.length) { billsEl.innerHTML = '<div class="no-data">No bill data available</div>'; return; }
      billsEl.innerHTML = bills.map(b => `
        <div style="padding:7px 14px;border-bottom:1px solid var(--border)">
          <div style="font-size:9px;letter-spacing:1px;color:var(--accent);margin-bottom:2px">${b.source} · ${b.date||''}</div>
          <a href="${b.link||'#'}" target="_blank" style="font-size:11px;color:var(--text);text-decoration:none;line-height:1.4">${b.title}</a>
        </div>`).join('');
    }
  });
}

function loadGovtIntel(force) {
  const el = document.getElementById('govt-intel-feed');
  if (!el) return;
  api(force ? '/api/govt_intel?force=1' : '/api/govt_intel', data => {
    const ts = document.getElementById('govt-intel-ts');
    if (ts) ts.textContent = data.fetched || '';
    const items = data.items || [];
    if (!items.length) {
      el.innerHTML = `<div style="padding:12px 16px;font-size:11px;color:var(--text-dim)">No agency feeds available.</div>`;
      return;
    }
    const srcColor = s => ({
      'FBI':'#cc3333','CENTCOM':'#336699','DOJ':'#993399',
      'State Dept':'#336633','Pentagon':'#334499','DHS':'#cc7700'
    })[s] || 'var(--accent)';
    // Group by source
    const grouped = {};
    items.forEach(it => {
      if (!grouped[it.source]) grouped[it.source] = [];
      if (grouped[it.source].length < 6) grouped[it.source].push(it);
    });
    el.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:1px;background:var(--border)">
      ${Object.entries(grouped).map(([src, its]) => `
        <div style="background:var(--bg2);padding:10px 14px">
          <div style="font-size:9px;letter-spacing:2px;color:${srcColor(src)};font-family:var(--font-m);margin-bottom:8px;border-bottom:1px solid var(--border);padding-bottom:5px">${src}</div>
          ${its.map(it => `
            <div style="margin-bottom:8px">
              <div style="font-size:9px;color:var(--text-dim);margin-bottom:2px">${it.date||''}</div>
              <a href="${it.link}" target="_blank" style="color:var(--text-hi);font-size:11px;text-decoration:none;line-height:1.4;display:block">${it.title}</a>
            </div>`).join('')}
        </div>`).join('')}
    </div>`;
  });
}

function loadBurnBan(force) {
  const el = document.getElementById('burnban-counties');
  const oz = document.getElementById('burnban-ozaukee');
  api(force ? '/api/burn_ban?force=1' : '/api/burn_ban', data => {
    const ts = document.getElementById('burnban-ts');
    if (ts) ts.textContent = data.fetched || '';
    if (data.error && !data.ozaukee) { if(el) el.innerHTML = `<div class="error-msg">${data.error}</div>`; return; }

    // Ozaukee spotlight
    if (oz) {
      const o = data.ozaukee;
      if (o) {
        const dangerColor = o.danger_code >= 4 ? '#cc4400' : o.danger_code >= 3 ? '#cc7700' : '#4a9c4a';
        oz.innerHTML = `
          <div style="display:flex;align-items:center;gap:14px;padding:4px 0">
            <div>
              <div style="font-size:9px;letter-spacing:3px;color:var(--text-dim)">OZAUKEE COUNTY</div>
              <div style="font-size:16px;color:${dangerColor};font-family:var(--font-m);letter-spacing:2px;margin-top:2px">${o.danger||'Unknown'}</div>
              <div style="font-size:10px;color:${o.restricted?'#cc4400':'#4a9c4a'};margin-top:2px">
                ${o.restricted ? '⛔ BURN RESTRICTIONS IN EFFECT' : '✓ No Current Burn Restrictions'}
              </div>
              ${o.comments ? `<div style="font-size:10px;color:var(--text-dim);margin-top:3px">${o.comments}</div>` : ''}
            </div>
          </div>`;
      } else {
        oz.innerHTML = '<div style="color:var(--text-dim);font-size:11px;padding:4px 0">Ozaukee County data unavailable</div>';
      }
    }

    // High danger counties table
    if (el) {
      const high = data.high_danger || [];
      if (!high.length) { el.innerHTML = '<div class="no-data">No high-danger counties currently</div>'; return; }
      el.innerHTML = `<table class="fw-table" style="width:100%">
        <thead><tr><th>County</th><th>Danger Level</th><th>Restrictions</th></tr></thead>
        <tbody>${high.map(c => `<tr>
          <td style="font-family:var(--font-m)">${c.name}</td>
          <td style="color:${c.danger_code>=4?'#cc4400':'#cc7700'}">${c.danger}</td>
          <td style="color:${c.restricted?'#cc4400':'var(--text-dim)'}">${c.restricted?'⛔ Yes':'—'}</td>
        </tr>`).join('')}</tbody>
      </table>`;
    }
  });
}

function loadGarden(force) {
  const el = document.getElementById('garden-panel');
  if (el) el.innerHTML = '<div class="loading">Running watering model...</div>';

  Promise.all([
    fetch(force ? '/api/watering?force=1' : '/api/watering').then(r => r.json()).catch(() => ({})),
    fetch(force ? '/api/garden?force=1'  : '/api/garden').then(r => r.json()).catch(() => ({})),
  ]).then(([wdata, gdata]) => {
    const ts = document.getElementById('garden-ts');
    if (ts) ts.textContent = wdata.fetched || gdata.fetched || '';
    if (!el) return;

    const schedules = wdata.schedules || {};
    const rain7     = gdata.rain_7d ?? wdata.rain_7d ?? 0;
    const frost     = gdata.frost || {};
    const frostColor = wdata.frost_color || frost.color || '#999';
    const frostRisk  = wdata.frost_risk  || frost.risk  || '—';
    const hist       = gdata.precip_history || [];

    // ── Decision cell ──────────────────────────────────────────────────
    function decCell(day) {
      if (!day) return '<td style="color:var(--text-dim)">—</td>';
      const dec = day.decision;
      if (dec === 'WATER') return `<td style="text-align:center">
        <div style="background:#0d2200;border:2px solid #4a9c4a;border-radius:6px;
             padding:8px 10px;color:#6dc96d;font-family:var(--font-m);font-size:14px;font-weight:bold">💧 WATER</div>
      </td>`;
      return `<td style="text-align:center">
        <div style="background:#1a0505;border:2px solid #553333;border-radius:6px;
             padding:8px 10px;color:#cc5555;font-family:var(--font-m);font-size:14px;font-weight:bold">🚫 DON'T WATER</div>
      </td>`;
    }

    // ── Mini rain bars ─────────────────────────────────────────────────
    const maxR = Math.max(...hist.map(h => h.precip_in), 0.5);
    const bars = hist.map(h => {
      const bh = Math.max(1, Math.round((h.precip_in / maxR) * 36));
      return `<div style="display:flex;flex-direction:column;align-items:center;gap:2px">
        <span style="font-size:8px;color:var(--accent)">${h.precip_in>0?h.precip_in+'"':''}</span>
        <svg width="22" height="36"><rect x="2" y="${36-bh}" width="18" height="${bh}"
          fill="${h.precip_in>=0.25?'#3a6ccc':h.precip_in>0?'#335588':'#1e1e2a'}" rx="2"/></svg>
        <span style="font-size:8px;color:var(--text-dim)">${h.date.slice(5)}</span>
      </div>`;
    }).join('');

    // ── Day labels ─────────────────────────────────────────────────────
    const dayLabel = (sched, i) => {
      const d = sched[i];
      if (!d) return '—';
      const dt = new Date(d.date + 'T12:00:00');
      const names = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
      const label = i === 0 ? 'Today' : i === 1 ? 'Tomorrow' : names[dt.getDay()];
      return `${d.icon} ${label}<br><span style="font-size:9px;color:var(--text-dim)">${d.date.slice(5)} · ${d.tmax_f??'?'}°/${d.tmin_f??'?'}° · ${d.rain_in}"</span>`;
    };

    const lawnSched   = (schedules.lawn        || {}).schedule || [];
    const azaleaSched = (schedules.azalea       || {}).schedule || [];
    const flowerSched = (schedules.wildflowers  || {}).schedule || [];

    const hasData = lawnSched.length > 0;

    el.innerHTML = `
      <!-- Summary stats -->
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:8px;
                  padding:12px 16px;border-bottom:1px solid var(--border)">
        <div class="stat-box">
          <div class="stat-label">7-Day Rain</div>
          <div class="stat-value">${rain7}"</div>
          <div class="stat-sub">Port Washington</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Frost Risk</div>
          <div class="stat-value" style="color:${frostColor};font-size:13px">${frostRisk}</div>
          <div class="stat-sub">${frost.label||'Zone 5b'}</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Last Spring Frost</div>
          <div class="stat-value" style="font-size:12px">May 7</div>
          <div class="stat-sub">Safe transplant after May 15</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">First Fall Frost</div>
          <div class="stat-value" style="font-size:12px">Oct 8</div>
          <div class="stat-sub">~153 day season</div>
        </div>
      </div>

      <!-- Rain history -->
      ${hist.length ? `<div style="padding:10px 16px 8px;border-bottom:1px solid var(--border)">
        <div style="font-size:9px;letter-spacing:2px;color:var(--text-dim);margin-bottom:6px">RAINFALL LAST 7 DAYS</div>
        <div style="display:flex;gap:8px;align-items:flex-end">${bars}</div>
      </div>` : ''}

      <!-- Watering table -->
      ${hasData ? `
      <div style="padding:12px 16px">
        <div style="font-size:9px;letter-spacing:2px;color:var(--text-dim);margin-bottom:10px">
          7-DAY WATERING OUTLOOK — DO I NEED TO WATER?
        </div>
        <div style="overflow-x:auto">
          <table class="fw-table" style="width:100%">
            <thead><tr>
              <th style="width:160px"></th>
              <th style="text-align:center">🌿 Lawn</th>
              <th style="text-align:center">🌸 Azaleas</th>
              <th style="text-align:center">🌻 Wildflowers</th>
            </tr></thead>
            <tbody>
              ${Array.from({length: Math.max(lawnSched.length, azaleaSched.length, flowerSched.length)}, (_,i) => `
              <tr ${i%2===0 ? 'style="background:rgba(255,255,255,0.03)"' : ''}>
                <td style="font-size:10px;white-space:nowrap">${dayLabel(lawnSched,i)}</td>
                ${decCell(lawnSched[i])}${decCell(azaleaSched[i])}${decCell(flowerSched[i])}
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
        <!-- USDA zone context -->
        <div style="margin-top:12px;padding:10px 12px;background:rgba(74,156,74,0.08);border:1px solid rgba(74,156,74,0.25);border-radius:4px">
          <div style="font-size:9px;letter-spacing:2px;color:#6a9c4a;font-family:var(--font-m);margin-bottom:6px">USDA ZONE 5b — PORT WASHINGTON GUIDANCE</div>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:6px;font-size:10px;color:var(--text-dim)">
            <div>🌡 <strong style="color:var(--text-hi)">Hardiness:</strong> -15°F to -10°F min winter</div>
            <div>🌱 <strong style="color:var(--text-hi)">Lawn water:</strong> 1–1.5" per week in growing season</div>
            <div>🌸 <strong style="color:var(--text-hi)">Azaleas:</strong> Deep soak every 7–10 days; hate wet roots</div>
            <div>🌻 <strong style="color:var(--text-hi)">Wildflowers:</strong> Drought tolerant once established; 1x/week new plants</div>
            <div>📅 <strong style="color:var(--text-hi)">Transplant safe:</strong> After May 15 (last frost ~May 7)</div>
            <div>🍂 <strong style="color:var(--text-hi)">First fall frost:</strong> ~Oct 8 · 153-day season</div>
          </div>
        </div>
        <div style="font-size:9px;color:var(--text-dim);margin-top:8px">
          Model: soil moisture balance · defers if ≥${wdata.model?.rain_threshold_in||0.20}" rain expected at ≥${wdata.model?.prob_threshold_pct||45}% in next ${wdata.model?.defer_window_days||3} days ·
          <a href="https://planthardiness.ars.usda.gov/" target="_blank" style="color:var(--accent);text-decoration:none">USDA Zone Map ↗</a> ·
          <a href="https://www.nws.noaa.gov/om/water/watering.shtml" target="_blank" style="color:var(--accent);text-decoration:none">NWS Lawn Watering ↗</a>
        </div>
      </div>` : `
      <div style="padding:16px;color:var(--text-dim);font-size:11px">
        No schedule yet — hit ⟳ Refresh to run the watering model now.
      </div>`}`;
  });
}


function loadMidtermIntel(force) {
  api(force ? '/api/midterm_intel?force=1' : '/api/midterm_intel', data => {
    const ts = document.getElementById('midterm-ts');
    if (ts) ts.textContent = data.fetched || '';

    const ratingColor = r => r.includes('D') ? '#4466cc' : r.includes('R') ? '#cc4444' : '#cc9900';

    // Macro indicators
    const macrosEl = document.getElementById('midterm-macros');
    if (macrosEl) {
      macrosEl.innerHTML = (data.macros||[]).map(m => `
        <div class="stat-box" ${m.url ? `style="cursor:pointer" onclick="window.open('${m.url}','_blank')" title="Click to view source"` : ''}>
          <div class="stat-label">${m.label}${m.url ? ' <span style="opacity:0.5;font-size:8px">↗</span>' : ''}</div>
          <div class="stat-value" style="font-size:14px">${m.value}</div>
          <div class="stat-sub">${m.note}</div>
        </div>`).join('');
    }

    // Key races
    const racesEl = document.getElementById('midterm-races');
    if (racesEl) {
      racesEl.innerHTML = `<table class="fw-table" style="width:100%">
        <thead><tr><th>Chamber</th><th>State</th><th>Race</th><th>Rating</th></tr></thead>
        <tbody>${(data.key_races||[]).map(r => `<tr>
          <td style="color:var(--text-dim);font-size:10px">${r.chamber}</td>
          <td style="font-family:var(--font-m)">${r.url ? `<a href="${r.url}" target="_blank" style="color:var(--text-hi);text-decoration:none">${r.state} ↗</a>` : r.state}</td>
          <td style="font-size:10px;color:var(--text-dim)">${r.desc}</td>
          <td style="color:${ratingColor(r.rating)};font-size:10px;letter-spacing:1px">${r.rating}</td>
        </tr>`).join('')}</tbody>
      </table>`;
    }

    // Primary calendar
    const primsEl = document.getElementById('midterm-primaries');
    if (primsEl) {
      primsEl.innerHTML = (data.primaries||[]).map(p => `
        <div style="padding:6px 0;border-bottom:1px solid var(--border)">
          <div style="font-size:10px;color:var(--accent);font-family:var(--font-m)">${p.date}</div>
          <div style="font-size:11px;color:var(--text-hi);margin-top:1px">${p.states}</div>
          <div style="font-size:10px;color:var(--text-dim)">${p.note}</div>
        </div>`).join('');
    }

  });
}

function _renderSeatMap() {
  // Current 119th Congress composition
  const senate = { R: 53, D: 45, I: 2, total: 100, majority: 51 };
  const house  = { R: 220, D: 213, vacant: 2, total: 435, majority: 218 };

  function semicircle(chamber, data) {
    const seats = data.total;
    const rows = chamber === 'senate' ? 5 : 9;
    const W = 280, H = 160, cx = W/2, cy = H - 10;
    const innerR = 40, outerR = H - 20;

    // Sort: R on right, D/I on left (standard US convention)
    // Seats arranged in arcs from right to left: R first, then I, then D
    const order = [];
    for (let i = 0; i < data.R; i++) order.push('R');
    if (data.I) for (let i = 0; i < data.I; i++) order.push('I');
    for (let i = 0; i < data.D; i++) order.push('D');

    const rowSeats = Math.ceil(seats / rows);
    const dots = [];
    const totalAngle = Math.PI; // half circle
    const startAngle = Math.PI; // left side
    let idx = 0;

    for (let row = 0; row < rows && idx < seats; row++) {
      const r = innerR + (outerR - innerR) * (row / (rows - 1));
      const nInRow = Math.min(rowSeats, seats - idx);
      for (let s = 0; s < nInRow && idx < seats; s++, idx++) {
        const angle = startAngle + (totalAngle / (nInRow + 1)) * (s + 1);
        const x = cx + r * Math.cos(angle);
        const y = cy + r * Math.sin(angle);
        const party = order[idx];
        const color = party === 'R' ? '#cc3333' : party === 'I' ? '#999933' : '#3355cc';
        dots.push(`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3.5" fill="${color}" opacity="0.9"/>`);
      }
    }

    const majLabel = data.R >= data.majority ? `<tspan fill="#cc3333">R MAJ</tspan>` : `<tspan fill="#3355cc">D MAJ</tspan>`;
    return `
      <div style="text-align:center;margin-bottom:4px">
        <span style="font-size:9px;letter-spacing:2px;color:var(--text-dim)">${chamber.toUpperCase()} · </span>${
          data.R >= data.majority
            ? `<span style="font-size:9px;color:#cc3333;font-family:var(--font-m)">R ${data.R}</span> <span style="font-size:9px;color:var(--text-dim)">vs</span> <span style="font-size:9px;color:#3355cc;font-family:var(--font-m)">D ${data.D}${data.I?'+'+data.I+'I':''}</span>`
            : `<span style="font-size:9px;color:#3355cc;font-family:var(--font-m)">D ${data.D}${data.I?'+'+data.I+'I':''}</span> <span style="font-size:9px;color:var(--text-dim)">vs</span> <span style="font-size:9px;color:#cc3333;font-family:var(--font-m)">R ${data.R}</span>`}
        <span style="font-size:9px;color:var(--text-dim)"> · need ${data.majority}</span>
      </div>
      <svg width="${W}" height="${H}" style="display:block;margin:0 auto">
        ${dots.join('')}
        <line x1="10" y1="${cy}" x2="${W-10}" y2="${cy}" stroke="var(--border)" stroke-width="1"/>
      </svg>`;
  }

  return `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
      <div style="background:rgba(0,0,0,0.3);border-radius:6px;padding:10px">${semicircle('senate', senate)}</div>
      <div style="background:rgba(0,0,0,0.3);border-radius:6px;padding:10px">${semicircle('house', house)}</div>
    </div>
    <div style="display:flex;gap:16px;justify-content:center;margin-top:8px;font-size:10px">
      <span><span style="color:#cc3333">■</span> Republican</span>
      <span><span style="color:#3355cc">■</span> Democrat</span>
      <span><span style="color:#999933">■</span> Independent</span>
    </div>`;
}

function loadPolls(force) {
  api(force ? '/api/polls?force=1' : '/api/polls', data => {
    const ts = document.getElementById('polls-ts');
    if (ts) ts.textContent = data.fetched || '';

    // Poll headlines
    const newsEl = document.getElementById('polls-news');
    if (newsEl) {
      const items = data.news || [];
      if (!items.length) {
        newsEl.innerHTML = `<div style="color:var(--text-dim);font-size:11px">No recent polling headlines found.<br>
          Check aggregators for latest data →</div>`;
      } else {
        newsEl.innerHTML = items.map(p => `
          <div style="padding:7px 0;border-bottom:1px solid var(--border)">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:2px">
              <span style="font-size:9px;color:var(--accent);font-family:var(--font-m);letter-spacing:1px">${p.source}</span>
              <span style="font-size:9px;color:var(--text-dim)">${p.published||''}</span>
            </div>
            <a href="${p.link||'#'}" target="_blank"
               style="font-size:11px;color:var(--text-hi);text-decoration:none;line-height:1.4;
                      display:block;transition:color 0.15s"
               onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--text-hi)'">
              ${p.title} ↗
            </a>
          </div>`).join('');
      }
    }

    // Aggregator links
    const aggEl = document.getElementById('polls-aggregators');
    if (aggEl) {
      aggEl.innerHTML = (data.aggregators || []).map(a => `
        <a href="${a.url}" target="_blank" style="display:block;padding:7px 10px;margin-bottom:4px;
           background:rgba(255,255,255,0.03);border:1px solid var(--border);border-radius:4px;
           font-size:11px;color:var(--accent);text-decoration:none;transition:background 0.2s"
           onmouseover="this.style.background='rgba(255,255,255,0.07)'"
           onmouseout="this.style.background='rgba(255,255,255,0.03)'">
          ${a.name} ↗
        </a>`).join('');
    }
  });
}

function loadPolTweets(force) {
  const el = document.getElementById('pol-tweets-grid');
  const ts = document.getElementById('pol-tweets-ts');
  const age = document.getElementById('pol-tweets-age');
  if (el) el.innerHTML = '<div class="loading">Loading politician feeds...</div>';
  api(force ? '/api/pol_tweets?force=1' : '/api/pol_tweets', data => {
    if (ts) ts.textContent = data.fetched || '';
    if (age && data.cache_age_hrs != null) age.textContent = `(${data.cache_age_hrs}h old)`;

    if (!el) return;
    if (data.error && !(data.politicians||[]).length) {
      el.innerHTML = `<div style="color:var(--text-dim);padding:16px;font-size:11px">${data.error}</div>`;
      return;
    }

    const pols = data.politicians || [];
    if (!pols.length) { el.innerHTML = '<div class="no-data">No politician data available</div>'; return; }

    el.innerHTML = pols.map(pol => {
      const partyColor = pol.party === 'D' ? '#3355cc' : '#cc3333';
      const tweets = pol.tweets || [];
      const tweetHtml = tweets.length
        ? tweets.slice(0, 3).map(t => `
            <div style="padding:5px 0;border-bottom:1px solid rgba(255,255,255,0.05)">
              <div style="font-size:9px;color:var(--text-dim);margin-bottom:2px">${t.published||''}</div>
              <a href="${t.link||pol.twitter_url}" target="_blank" rel="noopener"
                 style="font-size:10px;color:var(--text);text-decoration:none;line-height:1.4;display:block"
                 onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--text)'">
                ${t.text}
              </a>
            </div>`).join('')
        : `<div style="color:var(--text-dim);font-size:10px;padding:6px 0">No recent tweets fetched</div>`;

      return `
        <div style="background:rgba(0,0,0,0.25);border:1px solid var(--border);border-radius:6px;padding:10px 12px">
          <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:8px">
            <div>
              <a href="${pol.twitter_url}" target="_blank" rel="noopener"
                 style="color:var(--text-hi);font-family:var(--font-m);font-size:12px;text-decoration:none">
                ${pol.name}
              </a>
              ${pol.handle ? `<span style="color:var(--text-dim);font-size:10px;margin-left:6px">@${pol.handle}</span>` : ''}
            </div>
            <span style="background:${partyColor};color:#fff;font-size:9px;font-family:var(--font-m);
                         padding:2px 6px;border-radius:3px;letter-spacing:1px">${pol.party}</span>
          </div>
          <div style="font-size:9px;color:var(--text-dim);letter-spacing:1px;margin-bottom:6px">${pol.race}</div>
          ${tweetHtml}
        </div>`;
    }).join('');
  });
}

function loadF1(force) {
  const el = document.getElementById('f1-panel');
  if (el) el.innerHTML = '<div class="loading">Loading F1 data...</div>';
  api(force ? '/api/f1?force=1' : '/api/f1', data => {
    const ts = document.getElementById('f1-ts');
    if (ts) ts.textContent = data.fetched || '';
    if (!el) return;

    const teamColor = name => {
      const n = (name||'').toLowerCase();
      if (n.includes('ferrari'))   return '#e8002d';
      if (n.includes('mclaren'))   return '#ff8000';
      if (n.includes('red bull'))  return '#3671c6';
      if (n.includes('mercedes'))  return '#27f4d2';
      if (n.includes('aston'))     return '#229971';
      if (n.includes('alpine'))    return '#ff87bc';
      if (n.includes('haas'))      return '#b6babd';
      if (n.includes('williams'))  return '#64c4ff';
      if (n.includes('sauber') || n.includes('stake')) return '#52e252';
      if (n.includes('racing bulls') || n.includes('rb')) return '#6692ff';
      return '#888';
    };

    const drivers = data.driver_standings || [];
    const teams   = data.constructor_standings || [];
    const races   = data.upcoming || [];
    const last    = data.last_result || {};

    const podiumHtml = last.podium ? `
      <div style="padding:12px 16px;border-bottom:1px solid var(--border)">
        <div style="font-size:10px;letter-spacing:2px;color:var(--text-dim);margin-bottom:10px">LAST RACE — ${last.name||''} (${last.date||''})</div>
        <div style="display:flex;gap:12px">
          ${last.podium.map((p,i) => `
            <div style="flex:1;background:rgba(0,0,0,0.2);border-radius:6px;padding:10px 12px;
                        border-top:3px solid ${i===0?'#ffd700':i===1?'#c0c0c0':'#cd7f32'}">
              <div style="font-size:11px;color:var(--text-dim)">P${p.pos}</div>
              <div style="font-size:14px;color:var(--text-hi);font-family:var(--font-m);margin:2px 0">${p.name}</div>
              <div style="font-size:11px;color:${teamColor(p.team)}">${p.team}</div>
              ${p.time?`<div style="font-size:11px;color:var(--text-dim);margin-top:2px">${p.time}</div>`:''}
            </div>`).join('')}
        </div>
      </div>` : '';

    const upcomingHtml = races.length ? `
      <div style="padding:12px 16px;border-bottom:1px solid var(--border)">
        <div style="font-size:10px;letter-spacing:2px;color:var(--text-dim);margin-bottom:10px">UPCOMING RACES</div>
        ${races.map((r,i) => `
          <div style="padding:9px 0;${i<races.length-1?'border-bottom:1px solid rgba(255,255,255,0.05)':''}">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <div><span style="font-size:11px;color:var(--accent);font-family:var(--font-m)">RD ${r.round}</span>
                <span style="font-size:13px;color:var(--text-hi);font-family:var(--font-m);margin-left:8px">${r.name}</span></div>
              <span style="font-size:12px;color:var(--text-dim)">${r.date}${r.time?' · '+r.time+' UTC':''}</span>
            </div>
            <div style="font-size:12px;color:var(--text-dim);margin-top:3px">📍 ${r.location} — ${r.circuit}</div>
          </div>`).join('')}
      </div>` : '';

    el.innerHTML = `
      ${podiumHtml}${upcomingHtml}
      <div style="display:flex;gap:16px;flex-wrap:wrap;padding:12px 16px">
        <div style="flex:1;min-width:240px">
          <div style="font-size:10px;letter-spacing:2px;color:var(--text-dim);margin-bottom:8px">DRIVER CHAMPIONSHIP</div>
          <table class="fw-table" style="width:100%;font-size:13px">
            <thead><tr><th>#</th><th>Driver</th><th>Team</th><th style="text-align:right">Pts</th></tr></thead>
            <tbody>${drivers.map(d=>`<tr>
              <td style="color:var(--text-dim)">${d.pos}</td>
              <td style="font-family:var(--font-m)"><span style="color:${teamColor(d.team)}">▌</span> ${d.name}${d.wins>0?` <span style="font-size:10px;color:var(--text-dim)">${d.wins}W</span>`:''}</td>
              <td style="font-size:11px;color:var(--text-dim)">${d.team}</td>
              <td style="text-align:right;font-family:var(--font-m);font-size:14px;font-weight:600">${d.points}</td>
            </tr>`).join('')}</tbody>
          </table>
        </div>
        <div style="flex:1;min-width:200px">
          <div style="font-size:10px;letter-spacing:2px;color:var(--text-dim);margin-bottom:8px">CONSTRUCTOR CHAMPIONSHIP</div>
          <table class="fw-table" style="width:100%;font-size:13px">
            <thead><tr><th>#</th><th>Team</th><th style="text-align:right">Pts</th></tr></thead>
            <tbody>${teams.map(t=>`<tr>
              <td style="color:var(--text-dim)">${t.pos}</td>
              <td><span style="color:${teamColor(t.name)}">▌</span> <span style="font-family:var(--font-m)">${t.name}</span>${t.wins>0?` <span style="font-size:10px;color:var(--text-dim)">${t.wins}W</span>`:''}</td>
              <td style="text-align:right;font-family:var(--font-m);font-size:14px;font-weight:600">${t.points}</td>
            </tr>`).join('')}</tbody>
          </table>
        </div>
      </div>
      <div style="padding:4px 16px 10px;font-size:11px;color:var(--text-dim)">
        ${data.season} F1 World Championship · Jolpica/Ergast API · Refreshes Sundays
      </div>`;
  });
}

function loadCVEs(force) {
  loading('cve-list');
  api(force ? '/api/cves?force=1' : '/api/cves', data => {
    document.getElementById('cve-ts').textContent = data.fetched || '';
    const cves = data.cves || [];
    if (!cves.length) { document.getElementById('cve-list').innerHTML = '<div class="no-data">No CVE data available</div>'; return; }
    document.getElementById('cve-list').innerHTML = cves.map(c => {
      const cls = c.score >= 9 ? 'crit' : c.score >= 7 ? 'high' : c.score >= 4 ? 'med' : 'low';
      let epssHtml = '';
      if (c.epss != null) {
        const epssClass = c.epss >= 10 ? 'epss-high' : c.epss >= 1 ? 'epss-med' : 'epss-low';
        epssHtml = `<span class="epss-badge ${epssClass}" title="EPSS: probability of exploitation within 30 days">EPSS ${c.epss}% · P${c.epss_pct || '?'}</span>`;
      }
      const cveLink = c.id ? `<a href="https://nvd.nist.gov/vuln/detail/${c.id}" target="_blank" style="color:var(--accent);text-decoration:none">${c.id}</a>` : '—';
      return `<div class="cve-item">
        <div><div class="cve-id">${cveLink}</div><div class="cve-date">${c.published}</div><div class="dim" style="font-size:10px;margin-top:2px">${c.severity}</div>${epssHtml}</div>
        <div class="cve-score score-${cls}">${c.score || 'N/A'}</div>
        <div class="cve-desc">${c.desc}</div>
      </div>`;
    }).join('');
  });
}

function loadFirewallDrops() {
  api('/api/firewall_drops', data => {
    const ts = document.getElementById('fw-ts');
    if (ts) ts.textContent = data.fetched || '';

    // UFW raw drops
    const drops = data.drops || [];
    const tbody = document.getElementById('fw-tbody');
    if (tbody) {
      if (!drops.length) { tbody.innerHTML = '<tr><td colspan="4" class="no-data">No recent honeypot catches</td></tr>'; }
      else tbody.innerHTML = drops.map(d => {
        let abuseHtml = '';
        if (d.abuse) {
          const cls = d.abuse.score >= 50 ? 'abuse-high' : d.abuse.score >= 10 ? 'abuse-med' : '';
          const country = d.abuse.country ? ` · ${d.abuse.country}` : '';
          abuseHtml = `<br><span class="fw-abuse ${cls}">${d.abuse.score}% abuse${country}</span>`;
        }
        return `<tr>
        <td style="color:var(--text-dim);white-space:nowrap">${d.time}</td>
        <td class="fw-src">${d.src}${abuseHtml}</td>
        <td class="fw-port">${d.port || '—'}</td>
        <td>${d.proto || '—'}</td>
      </tr>`;
      }).join('');
    }

    // Fail2ban bans
    const f2bs = data.f2b || [];
    const f2bEl = document.getElementById('f2b-tbody');
    if (f2bEl) {
      if (!f2bs.length) { f2bEl.innerHTML = '<tr><td colspan="3" class="no-data">No fail2ban bans in log</td></tr>'; }
      else f2bEl.innerHTML = f2bs.map(d => `<tr>
        <td style="color:var(--text-dim);white-space:nowrap">${d.time}</td>
        <td class="fw-src">${d.src}</td>
        <td style="color:var(--accent);font-size:10px;letter-spacing:1px">${d.source}</td>
      </tr>`).join('');
    }
  });
}

function loadTarpitStats(force) {
  const errEl = document.getElementById('tarpit-error');
  api(force ? '/api/tarpit_stats?force=1' : '/api/tarpit_stats', data => {
    const ts = document.getElementById('tarpit-ts');
    if (ts) ts.textContent = data.fetched || '';
    if (errEl) errEl.style.display = 'none';

    if (data.error) {
      if (errEl) { errEl.style.display = 'block'; errEl.textContent = '⚠ ' + data.error; }
      return;
    }

    const bgp = ip => `https://bgp.tools/prefix/${ip}#bgpinfo`;
    const ipLink = (ip, extra) =>
      `<a href="${bgp(ip)}" target="_blank" rel="noopener"
          style="color:var(--accent);text-decoration:none;font-family:var(--font-m)"
          title="Look up ${ip} on bgp.tools">${ip}</a>${extra||''}`;

    // SSH tarpit stats
    const sshEl = document.getElementById('tarpit-ssh-stats');
    if (sshEl) {
      const totalMins = Math.round((data.total_seconds || 0) / 60);
      const totalHrs  = (totalMins / 60).toFixed(1);
      sshEl.innerHTML = `
        <div class="stat-box">
          <div class="stat-label">Connections</div>
          <div class="stat-value">${data.accepts || 0}</div>
          <div class="stat-sub">${data.closes || 0} disconnected</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Unique IPs</div>
          <div class="stat-value">${data.unique_ips || 0}</div>
          <div class="stat-sub">distinct bots</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Time Wasted</div>
          <div class="stat-value">${totalHrs}h</div>
          <div class="stat-sub">${totalMins} min total</div>
        </div>`;
    }

    // Tarpit log table
    const tlogEl = document.getElementById('tarpit-recent-ips');
    if (tlogEl) {
      const log = data.tarpit_log || [];
      if (!log.length) {
        tlogEl.innerHTML = '<span style="color:var(--text-dim);font-size:11px">No catches yet</span>';
      } else {
        tlogEl.innerHTML = `<table class="fw-table" style="width:100%;margin-top:4px">
          <thead><tr><th>Time</th><th>IP</th><th>Port</th><th>Trapped</th></tr></thead>
          <tbody>${log.map(e => `<tr>
            <td style="color:var(--text-dim);white-space:nowrap;font-size:10px">${e.ts||'—'}</td>
            <td>${ipLink(e.ip)}</td>
            <td style="color:var(--text-dim)">${e.port||'—'}</td>
            <td style="color:var(--accent)">${e.seconds != null ? e.seconds+'s' : '—'}</td>
          </tr>`).join('')}</tbody>
        </table>`;
      }
    }

    // Honeypot stats
    const hpEl = document.getElementById('tarpit-honeypot-stats');
    if (hpEl) {
      hpEl.innerHTML = `
        <div class="stat-box">
          <div class="stat-label">Total Hits</div>
          <div class="stat-value">${data.honeypot_hits || 0}</div>
          <div class="stat-sub">${data.honeypot_unique_ips || 0} unique IPs</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Trap Hits</div>
          <div class="stat-value">${data.honeypot_bans || 0}</div>
          <div class="stat-sub">creds submitted</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Perm Bans</div>
          <div class="stat-value">${data.permanent_bans || 0}</div>
          <div class="stat-sub">nftables</div>
        </div>`;
    }

    // Honeypot log table
    const hlogEl = document.getElementById('tarpit-honeypot-log');
    if (hlogEl) {
      const hlog = data.honeypot_log || [];
      if (!hlog.length) {
        hlogEl.innerHTML = '<span style="color:var(--text-dim);font-size:11px">No external probes yet</span>';
      } else {
        hlogEl.innerHTML = `<table class="fw-table" style="width:100%;margin-top:4px">
          <thead><tr><th>Time</th><th>IP</th><th>Path</th><th>Event</th></tr></thead>
          <tbody>${hlog.map(e => `<tr>
            <td style="color:var(--text-dim);white-space:nowrap;font-size:10px">${e.ts||'—'}</td>
            <td>${ipLink(e.ip)}</td>
            <td style="color:var(--text-dim);font-size:10px;max-width:160px;overflow:hidden;text-overflow:ellipsis">${e.path||'—'}</td>
            <td style="color:${e.event==='TRAP_HIT'||e.event==='TRAP_CREDS'?'var(--red2)':'var(--accent)'}; font-size:10px">${e.event||'—'}</td>
          </tr>`).join('')}</tbody>
        </table>`;
      }
    }
  });
}

// ══════════════════════════════════════════════════════════
//  PODCASTS
// ══════════════════════════════════════════════════════════
function loadPodcasts(force) {
  const list = document.getElementById('podcast-list');
  if (!list) return;
  list.innerHTML = '<div class="loading">Loading podcasts...</div>';

  api(force ? '/api/podcasts?force=1' : '/api/podcasts', data => {
    const ts = document.getElementById('podcast-ts');
    if (ts) ts.textContent = data.fetched || '';
    const pods = data.podcasts || [];
    if (!pods.length) {
      list.innerHTML = '<div style="padding:12px 16px;color:var(--muted);font-size:12px">No podcasts available</div>';
      return;
    }
    list.innerHTML = pods.map((p, i) => {
      const dur = p.duration ? ` · ${p.duration}` : '';
      const pub = p.published ? ` · ${p.published.slice(0,10)}` : '';
      return `<div class="feed-item" style="cursor:pointer;padding:12px 16px;border-bottom:1px solid var(--border);display:flex;gap:14px;align-items:flex-start;transition:background .15s"
        onclick="playPodcast(${JSON.stringify(p.audio_url)}, ${JSON.stringify(p.name)}, ${JSON.stringify(p.episode)})"
        onmouseover="this.style.background='var(--bg2)'" onmouseout="this.style.background=''">
        <div style="flex-shrink:0;width:32px;height:32px;border:1px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:14px;color:var(--accent)">▶</div>
        <div style="flex:1;min-width:0">
          <div style="font-size:10px;color:var(--accent);letter-spacing:2px;text-transform:uppercase;margin-bottom:3px">${esc(p.name)}</div>
          <div style="font-size:12px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(p.episode)}</div>
          <div style="font-size:10px;color:var(--muted);margin-top:3px">${pub.trim()}${dur}</div>
        </div>
      </div>`;
    }).join('');
  });
}

function playPodcast(url, show, title) {
  const player = document.getElementById('podcast-player');
  const audio = document.getElementById('pod-audio');
  const showEl = document.getElementById('pod-now-show');
  const titleEl = document.getElementById('pod-now-title');
  if (!audio || !player) return;
  player.style.display = 'flex';
  player.style.flexDirection = 'column';
  showEl.textContent = show;
  titleEl.textContent = title;
  audio.src = url;
  audio.play().catch(() => {});
}

// ══════════════════════════════════════════════════════════
//  WEATHER OPS
// ══════════════════════════════════════════════════════════

function loadWeather(force) {
  loading('wx-forecast');
  api(force ? '/api/weather?force=1' : '/api/weather', data => {
    document.getElementById('wx-ts').textContent = data.fetched || '';

    const bannerEl = document.getElementById('wx-alert-banner');
    if (data.alerts && data.alerts.length) {
      bannerEl.style.display = 'block';
      bannerEl.innerHTML = data.alerts.map(a => {
        const sevCls = a.severity === 'Extreme' || a.urgency === 'Immediate' ? 'alert-extreme'
                     : a.severity === 'Severe' ? 'alert-severe' : 'alert-moderate';
        const link = a.url ? `href="${a.url}" target="_blank"` : '';
        return `<a ${link} class="wx-alert-banner-item ${sevCls}">
          <span class="wx-alert-banner-event">⚠ ${a.event}</span>
          <span class="wx-alert-banner-detail">${a.effective ? a.effective + ' UTC' : ''} — Ozaukee Co. / Lake Michigan</span>
        </a>`;
      }).join('');
    } else {
      bannerEl.style.display = 'none';
    }

    // 7-day forecast — 4 columns, compact
    const fc = data.forecast || [];
    document.getElementById('wx-forecast').innerHTML = fc.length
      ? `<div class="wx-forecast-grid">${fc.map(p => `
          <div class="wx-period">
            <div class="wx-period-name">${p.name}</div>
            <div class="wx-temp">${p.temp}°${p.unit}</div>
            <div class="wx-short">${p.short}</div>
            <div class="wx-wind">${p.wind}</div>
          </div>`).join('')}</div>`
      : '<div class="no-data">No forecast data</div>';

    // Current conditions from NWS obs station
    const obs = data.obs || {};
    const fc0 = fc[0] || {};
    const feels = obs.wind_chill_f ?? obs.heat_index_f;
    document.getElementById('wx-current').innerHTML = Object.keys(obs).length ? `
      <div class="wx-obs-grid">
        <div class="wx-obs-main">
          <div class="wx-obs-condition">${obs.condition || fc0.short || '---'}</div>
          <div class="wx-obs-temp">${obs.temp_f != null ? obs.temp_f + '°F' : '--'}</div>
          ${feels != null ? `<div class="wx-obs-feels">Feels Like ${feels}°F</div>` : ''}
        </div>
        <div class="wx-obs-details">
          ${row_obs('Dew Point',  obs.dewpoint_f != null ? obs.dewpoint_f + '°F' : '---')}
          ${row_obs('Humidity',   obs.humidity   != null ? obs.humidity   + '%'  : '---')}
          ${row_obs('Heat Index', obs.heat_index_f != null ? obs.heat_index_f + '°F' : '---')}
          ${row_obs('UV Index',   obs.uv_index   != null ? obs.uv_index + (obs.uv_index < 3 ? ' Low' : obs.uv_index < 6 ? ' Moderate' : obs.uv_index < 8 ? ' High' : obs.uv_index < 11 ? ' Very High' : ' Extreme') : '---')}
          ${row_obs('Wind',       obs.wind_speed_mph != null
            ? `${windArrow(obs.wind_dir_deg)} ${obs.wind_dir} @ ${obs.wind_speed_mph} mph` : '---')}
          ${row_obs('Gust',       obs.wind_gust_mph  != null ? obs.wind_gust_mph + ' mph' : '---')}
          ${row_obs('Visibility', obs.visibility_mi  != null ? obs.visibility_mi + ' mi'  : '---')}
          ${obs.clouds && obs.clouds.length ? row_obs('Sky',
            obs.clouds.map(c => `${c.amount}${c.base_ft ? ' @ '+c.base_ft.toLocaleString()+"'" : ''}`).join(', ')) : ''}
        </div>
      </div>
      <div class="wx-obs-station">OBS STATION: ${obs.station || '?'} — ${obs.time || ''}</div>
    ` : `<div style="padding:16px">
      <div class="wx-obs-condition">${fc0.short || '---'}</div>
      <div class="wx-obs-temp">${fc0.temp != null ? fc0.temp + '°' + fc0.unit : '--'}</div>
      <div style="color:var(--text-dim);font-size:11px;margin-top:8px">${fc0.detail || ''}</div>
    </div>`;

    // Severe weather alerts — Ozaukee County + LMZ645
    const alerts = data.alerts || [];
    document.getElementById('wx-alerts-list').innerHTML = alerts.length
      ? alerts.map(a => {
          const sevCls = a.severity === 'Extreme' || a.urgency === 'Immediate' ? 'alert-extreme'
                       : a.severity === 'Severe' ? 'alert-severe' : 'alert-moderate';
          const link = a.url ? `href="${a.url}" target="_blank"` : '';
          return `<div class="wx-alert-item ${sevCls}">
            <div style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap">
              ${a.url ? `<a ${link} style="color:inherit;text-decoration:none;flex:1">` : '<div style="flex:1">'}
                <span class="wx-alert-event">⚠ ${a.event}</span>
              ${a.url ? '</a>' : '</div>'}
              <span class="wx-alert-sev">${a.severity}${a.urgency ? ' · ' + a.urgency : ''}</span>
            </div>
            <div class="wx-alert-headline">${a.headline}</div>
            ${a.effective ? `<div class="wx-alert-time">Effective: ${a.effective} UTC — Expires: ${a.expires} UTC</div>` : ''}
            ${a.areas ? `<div class="wx-alert-areas">Areas: ${a.areas}</div>` : ''}
            ${a.description ? `<details style="margin-top:6px">
              <summary style="font-size:10px;color:var(--text-dim);cursor:pointer;letter-spacing:1px">FULL TEXT ▸</summary>
              <pre style="font-size:10px;color:var(--text-dim);white-space:pre-wrap;line-height:1.5;margin-top:6px;padding:8px;background:var(--bg3);border-radius:3px">${a.description}${a.instruction ? '\n\nINSTRUCTIONS:\n'+a.instruction : ''}</pre>
            </details>` : ''}
          </div>`;
        }).join('')
      : '<div class="no-data">✓ No active alerts for Ozaukee County or Lake Michigan Zone LMZ645</div>';
  });
}

function row_obs(label, val) {
  return `<div class="wx-obs-row"><span class="wx-obs-label">${label}</span><span class="wx-obs-val">${val}</span></div>`;
}

function loadAirNow(force) {
  api(force ? '/api/airnow?force=1' : '/api/airnow', data => {
    const el = document.getElementById('airnow-panel');
    if (!el) return;
    const aqi = data.aqi ?? 0;
    const bar = Math.min(Math.round(aqi / 500 * 100), 100);
    el.innerHTML = `
      <div style="display:flex;align-items:center;gap:20px;padding:16px;border-bottom:1px solid var(--border)">
        <div style="text-align:center;min-width:100px">
          <div style="font-family:var(--font-h);font-size:52px;line-height:1;color:${data.color || '#888'}">${aqi}</div>
          <div style="font-size:9px;letter-spacing:3px;color:var(--text-dim);margin-top:4px">US AQI</div>
        </div>
        <div style="flex:1">
          <div style="font-family:var(--font-h);font-size:18px;color:${data.color || 'var(--text-hi)'};margin-bottom:8px">${data.category || '---'}</div>
          <div style="height:6px;background:var(--border);border-radius:3px;margin-bottom:12px">
            <div style="height:100%;width:${bar}%;background:${data.color};border-radius:3px;transition:width .5s"></div>
          </div>
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;font-size:11px">
            ${aqi_row('PM2.5', data.pm25, 'μg/m³')}
            ${aqi_row('PM10',  data.pm10, 'μg/m³')}
            ${aqi_row('Ozone', data.ozone,'μg/m³')}
            ${aqi_row('NO₂',   data.no2,  'μg/m³')}
            ${aqi_row('CO',    data.co,   'μg/m³')}
          </div>
        </div>
      </div>
      <div class="wx-obs-station">SOURCE: OPEN-METEO / CAMS GLOBAL — PORT WASHINGTON AREA — ${data.fetched || ''}</div>
    `;
  });
}
function aqi_row(label, val, unit) {
  return `<div style="background:var(--bg3);padding:6px 8px">
    <div style="font-size:8px;letter-spacing:2px;color:var(--text-dim)">${label}</div>
    <div style="color:var(--text-hi);margin-top:2px">${val ?? '---'} <span style="color:var(--text-dim);font-size:9px">${unit}</span></div>
  </div>`;
}

function loadWildfires(force) {
  api(force ? '/api/wildfires?force=1' : '/api/wildfires', data => {
    const el = document.getElementById('wildfires-panel');
    if (!el) return;
    const fires = data.fires || [];
    if (!fires.length) {
      el.innerHTML = '<div class="no-data">No large active wildfires reported</div>';
      return;
    }
    el.innerHTML = `
      <div style="overflow-x:auto">
        <table style="width:100%;border-collapse:collapse;font-size:12px">
          <thead>
            <tr style="font-size:9px;letter-spacing:2px;color:var(--text-dim);border-bottom:1px solid var(--border2)">
              <th style="text-align:left;padding:6px 12px;font-weight:normal">FIRE NAME</th>
              <th style="text-align:right;padding:6px 8px;font-weight:normal">ACRES</th>
              <th style="text-align:right;padding:6px 8px;font-weight:normal">CONTAINED</th>
              <th style="text-align:left;padding:6px 8px;font-weight:normal">STATE</th>
              <th style="text-align:left;padding:6px 8px;font-weight:normal">COUNTY</th>
              <th style="text-align:right;padding:6px 8px;font-weight:normal">DISCOVERED</th>
            </tr>
          </thead>
          <tbody>
            ${fires.map((f, i) => {
              const pct = f.contained ?? null;
              const pctColor = pct === null ? 'var(--text-dim)' : pct >= 75 ? '#4caf50' : pct >= 40 ? '#ff9800' : '#f44336';
              const acresFmt = f.acres >= 1000 ? (f.acres/1000).toFixed(1)+'K' : f.acres.toLocaleString();
              return `<tr style="border-bottom:1px solid var(--border);${i%2===1?'background:rgba(255,255,255,0.02)':''}">
                <td style="padding:7px 12px;color:var(--text-hi);font-weight:500">${f.name}</td>
                <td style="padding:7px 8px;text-align:right;color:var(--accent);font-family:var(--font-m)">${acresFmt}</td>
                <td style="padding:7px 8px;text-align:right;color:${pctColor};font-family:var(--font-m)">${pct !== null ? pct+'%' : '—'}</td>
                <td style="padding:7px 8px;color:var(--text-dim)">${f.state}</td>
                <td style="padding:7px 8px;color:var(--text-dim);font-size:11px">${f.county}</td>
                <td style="padding:7px 8px;text-align:right;color:var(--text-dim);font-size:11px">${f.discovered}</td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>
      <div class="wx-obs-station">SOURCE: NIFC / WFIGS IRWIN — FIRES > 100 ACRES — ${data.fetched || ''}</div>
    `;
  });
}

// ── Wisconsin Warnings ─────────────────────────────────────
function loadWIWarnings(force) {
  const el = document.getElementById('wi-warnings-list');
  if (!el) return;
  loading('wi-warnings-list');
  // Refresh the map image with cache-busting
  const mapImg = document.getElementById('wi-warn-map');
  if (mapImg) mapImg.src = 'https://forecast.weather.gov/wwamap/png/WI.png?_=' + Date.now();
  api(force ? '/api/wi_warnings?force=1' : '/api/wi_warnings', data => {
    const alerts = data.alerts || [];
    if (!alerts.length) {
      el.innerHTML = '<div class="no-data">No active warnings for Wisconsin</div>';
      return;
    }
    const sevColor = { Extreme:'#ff2020', Severe:'#ff6600', Moderate:'#ffcc00', Minor:'#4caf50', Unknown:'#888' };
    el.innerHTML = alerts.map(a => {
      const color = sevColor[a.severity] || sevColor.Unknown;
      const url = a.url ? `href="${a.url}" target="_blank"` : '';
      return `<div class="wi-warn-item" style="border-left:3px solid ${color}">
        <div style="display:flex;align-items:baseline;gap:8px;flex-wrap:wrap">
          <a class="wi-warn-event" ${url}>${a.event}</a>
          <span class="wi-warn-area">${a.areas || ''}</span>
        </div>
        <div class="wi-warn-meta">
          <span style="color:${color}">${a.severity}</span>
          <span>${a.urgency || ''}</span>
          <span>${a.effective ? a.effective.slice(0,16).replace('T',' ') : ''} → ${a.expires ? a.expires.slice(0,16).replace('T',' ') : ''}</span>
        </div>
        ${a.headline ? `<div class="wi-warn-headline">${a.headline}</div>` : ''}
      </div>`;
    }).join('') + `<div class="wx-obs-station">SOURCE: NWS — ${data.fetched || ''}</div>`;
  });
}

// ── USCG Local Notice to Mariners ─────────────────────────
function loadLNM(force) {
  const el = document.getElementById('lnm-panel');
  if (!el) return;
  loading('lnm-panel');
  api(force ? '/api/lnm?force=1' : '/api/lnm', data => {
    const notices = data.notices || [];
    if (!notices.length) {
      el.innerHTML = `<div class="no-data" style="padding:16px">${data.error || 'No notices available'}</div>`;
      return;
    }
    el.innerHTML = notices.map(n => `
      <div style="padding:8px 14px;border-bottom:1px solid var(--border)">
        <a href="${n.url}" target="_blank"
           style="color:var(--text);text-decoration:none;font-size:12px;line-height:1.5"
           onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--text)'">${n.title}</a>
      </div>`).join('')
    + `<div class="wx-obs-station">SOURCE: USCG NAVCEN DISTRICT 9 — <a href="${data.source_url}" target="_blank" style="color:var(--accent)">VIEW ALL ↗</a> — ${data.fetched || ''}</div>`;
  });
}

// ── Obsidian Export ─────────────────────────────────────────
function exportObsidian() {
  const a = document.createElement('a');
  a.href = '/api/obsidian_export';
  a.download = '';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

// ── Voice Memos ─────────────────────────────────────────────
let _mediaRecorder = null;
let _recChunks = [];
let _recBlob = null;
let _recInterval = null;
let _recStart = null;

function toggleRecording() {
  if (_mediaRecorder && _mediaRecorder.state === 'recording') {
    _mediaRecorder.stop();
    return;
  }
  navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
    _recChunks = [];
    _recBlob = null;
    _mediaRecorder = new MediaRecorder(stream);
    _mediaRecorder.ondataavailable = e => { if (e.data.size > 0) _recChunks.push(e.data); };
    _mediaRecorder.onstop = () => {
      stream.getTracks().forEach(t => t.stop());
      _recBlob = new Blob(_recChunks, { type: 'audio/webm' });
      clearInterval(_recInterval);
      const preview = document.getElementById('memo-preview');
      preview.src = URL.createObjectURL(_recBlob);
      preview.style.display = 'block';
      document.getElementById('rec-btn').textContent = '⏺ Record';
      document.getElementById('rec-btn').classList.remove('recording');
      document.getElementById('rec-status').textContent = 'Recorded — name it and save';
      document.getElementById('save-memo-btn').disabled = false;
    };
    _mediaRecorder.start();
    _recStart = Date.now();
    _recInterval = setInterval(() => {
      const s = Math.floor((Date.now() - _recStart) / 1000);
      document.getElementById('rec-timer').textContent =
        String(Math.floor(s/60)).padStart(2,'0') + ':' + String(s%60).padStart(2,'0');
    }, 1000);
    document.getElementById('rec-btn').textContent = '⏹ Stop';
    document.getElementById('rec-btn').classList.add('recording');
    document.getElementById('rec-status').textContent = '● Recording...';
    document.getElementById('save-memo-btn').disabled = true;
  }).catch(err => {
    document.getElementById('rec-status').textContent = 'Mic error: ' + err.message;
  });
}

function saveMemo() {
  if (!_recBlob) return;
  const name = document.getElementById('memo-name').value.trim() || 'memo';
  const form = new FormData();
  form.append('audio', _recBlob, 'recording.webm');
  form.append('name', name);
  document.getElementById('rec-status').textContent = 'Saving...';
  fetch('/api/memos', { method: 'POST', body: form })
    .then(r => r.json())
    .then(d => {
      document.getElementById('rec-status').textContent = d.status === 'saved' ? '✓ Saved: ' + d.name : 'Error saving';
      document.getElementById('save-memo-btn').disabled = true;
      document.getElementById('memo-name').value = '';
      _recBlob = null;
      document.getElementById('memo-preview').style.display = 'none';
      loadMemos();
    });
}

function notepadToLibrary() {
  const content = document.getElementById('notepad').value.trim();
  if (!content) { alert('Notepad is empty.'); return; }
  const title = prompt('Save as note titled:', 'Notepad ' + new Date().toLocaleDateString());
  if (!title) return;
  fetch('/api/notes', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({title: title.trim(), content})
  })
  .then(r => r.json())
  .then(d => {
    document.getElementById('note-status').textContent = `✓ Saved to library as "${d.title}"`;
    setTimeout(() => document.getElementById('note-status').textContent = '', 4000);
    loadNotesList();
  });
}

// ══════════════════════════════════════════════════════════
//  NOTES LIBRARY
// ══════════════════════════════════════════════════════════

let _currentNoteFname = null;

function loadNotesList() {
  const el = document.getElementById('notes-list');
  if (!el) return;
  el.innerHTML = '<div class="loading">Loading...</div>';
  api('/api/notes', data => {
    const notes = data.notes || [];
    if (!notes.length) {
      el.innerHTML = '<div class="no-data" style="padding:16px">No notes yet — click <strong>+ New Note</strong> to start.</div>';
      return;
    }
    el.innerHTML = `<div style="overflow-x:auto">
      <table style="width:100%;border-collapse:collapse;font-size:12px">
        <thead>
          <tr style="font-size:9px;letter-spacing:2px;color:var(--text-dim);border-bottom:1px solid var(--border2)">
            <th style="text-align:left;padding:6px 14px;font-weight:normal">TITLE</th>
            <th style="text-align:right;padding:6px 8px;font-weight:normal">SIZE</th>
            <th style="text-align:left;padding:6px 8px;font-weight:normal">MODIFIED</th>
            <th style="text-align:center;padding:6px 8px;font-weight:normal">ACTIONS</th>
          </tr>
        </thead>
        <tbody>
          ${notes.map((n, i) => `
          <tr style="border-bottom:1px solid var(--border);${i%2===1?'background:rgba(255,255,255,0.02)':''}">
            <td style="padding:6px 14px">
              <a href="#" onclick="notesOpenDoc('${encodeURIComponent(n.fname)}','${n.title.replace(/'/g,"\\'")}');return false"
                 style="color:var(--text-hi);text-decoration:none;font-family:var(--font-m)"
                 onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--text-hi)'">${n.title}</a>
            </td>
            <td style="padding:6px 8px;text-align:right;color:var(--text-dim);white-space:nowrap">${n.size < 1024 ? n.size+'B' : (n.size/1024).toFixed(1)+'KB'}</td>
            <td style="padding:6px 8px;color:var(--text-dim);white-space:nowrap">${n.modified}</td>
            <td style="padding:6px 8px;text-align:center;white-space:nowrap">
              <a href="/api/notes/${encodeURIComponent(n.fname)}/download"
                 style="background:none;border:1px solid var(--border2);color:var(--text-dim);font-size:10px;padding:2px 7px;cursor:pointer;text-decoration:none;border-radius:2px;margin-right:4px">⬇</a>
              <button onclick="notesRename('${encodeURIComponent(n.fname)}','${n.title.replace(/'/g,"\\'")}')"
                style="background:none;border:1px solid var(--border2);color:var(--text-dim);font-size:10px;padding:2px 7px;cursor:pointer;margin-right:4px;border-radius:2px">✎</button>
              <button onclick="notesDelete('${encodeURIComponent(n.fname)}')"
                style="background:none;border:1px solid var(--red2);color:var(--red2);font-size:10px;padding:2px 6px;cursor:pointer;border-radius:2px">✕</button>
            </td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
  });
}

function notesNewDoc() {
  _currentNoteFname = null;
  document.getElementById('notes-title').value = '';
  document.getElementById('notes-body').value = '';
  document.getElementById('notes-save-status').textContent = '';
  document.getElementById('notes-editor-wrap').style.display = 'block';
  document.getElementById('notes-title').focus();
}

function notesOpenDoc(encodedFname, title) {
  const fname = decodeURIComponent(encodedFname);
  fetch('/api/notes/' + encodedFname)
    .then(r => r.json())
    .then(d => {
      _currentNoteFname = d.fname;
      document.getElementById('notes-title').value = title;
      document.getElementById('notes-body').value = d.content || '';
      document.getElementById('notes-save-status').textContent = '';
      document.getElementById('notes-editor-wrap').style.display = 'block';
      document.getElementById('notes-body').focus();
      // scroll editor into view
      document.getElementById('notes-editor-wrap').scrollIntoView({behavior:'smooth',block:'nearest'});
    });
}

function notesCloseEditor() {
  _currentNoteFname = null;
  document.getElementById('notes-editor-wrap').style.display = 'none';
  document.getElementById('notes-title').value = '';
  document.getElementById('notes-body').value = '';
}

function notesSave() {
  const title = document.getElementById('notes-title').value.trim() || 'untitled';
  const content = document.getElementById('notes-body').value;
  const statusEl = document.getElementById('notes-save-status');
  statusEl.textContent = 'Saving...';
  fetch('/api/notes', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({title, content, fname: _currentNoteFname})
  })
  .then(r => r.json())
  .then(d => {
    _currentNoteFname = d.fname;
    statusEl.textContent = `✓ SAVED — ${d.modified}`;
    loadNotesList();
  });
}

function notesDownload() {
  if (!_currentNoteFname) { notesSave(); return; }
  window.location.href = '/api/notes/' + encodeURIComponent(_currentNoteFname) + '/download';
}

function notesRename(encodedFname, currentTitle) {
  // Replace the title cell with an inline input field
  const rows = document.querySelectorAll('#notes-list tr');
  rows.forEach(row => {
    const cell = row.querySelector('td:first-child');
    if (!cell) return;
    const link = cell.querySelector('a');
    if (!link) return;
    // Check if this is the right row by matching encoded fname in the onclick
    const btn = row.querySelector('button[onclick*="notesRename"]');
    if (!btn || !btn.getAttribute('onclick').includes(encodedFname)) return;

    // Swap link for input
    const input = document.createElement('input');
    input.type = 'text';
    input.value = currentTitle;
    input.style.cssText = 'flex:1;width:100%;background:var(--bg2);border:1px solid var(--accent);color:var(--text);font-family:var(--font-m);font-size:11px;padding:3px 8px;border-radius:3px;outline:none';
    cell.innerHTML = '';
    cell.appendChild(input);
    input.focus();
    input.select();

    function submitRename() {
      const newTitle = input.value.trim();
      if (!newTitle || newTitle === currentTitle) { loadNotesList(); return; }
      fetch('/api/notes/' + encodedFname + '/rename', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({title: newTitle})
      })
      .then(r => r.json())
      .then(d => {
        if (d.status === 'renamed' && _currentNoteFname === decodeURIComponent(encodedFname)) {
          _currentNoteFname = d.fname;
          document.getElementById('notes-title').value = newTitle;
        }
        loadNotesList();
      })
      .catch(() => loadNotesList());
    }
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') submitRename();
      if (e.key === 'Escape') loadNotesList();
    });
    input.addEventListener('blur', submitRename);
  });
}

function notesDelete(encodedFname) {
  if (!confirm('Delete this note?')) return;
  fetch('/api/notes/' + encodedFname, {method: 'DELETE'})
    .then(() => {
      if (_currentNoteFname === decodeURIComponent(encodedFname)) notesCloseEditor();
      loadNotesList();
    });
}

function loadMemos() {
  const el = document.getElementById('memo-library');
  if (!el) return;
  api('/api/memos', data => {
    const memos = data.memos || [];
    if (!memos.length) {
      el.innerHTML = '<div class="no-data">No memos recorded yet.</div>';
      return;
    }
    el.innerHTML = `<div style="overflow-x:auto">
      <table style="width:100%;border-collapse:collapse;font-size:12px">
        <thead>
          <tr style="font-size:9px;letter-spacing:2px;color:var(--text-dim);border-bottom:1px solid var(--border2)">
            <th style="text-align:left;padding:6px 14px;font-weight:normal">NAME</th>
            <th style="text-align:right;padding:6px 8px;font-weight:normal">SIZE</th>
            <th style="text-align:left;padding:6px 8px;font-weight:normal">RECORDED</th>
            <th style="text-align:center;padding:6px 8px;font-weight:normal">ACTIONS</th>
          </tr>
        </thead>
        <tbody>
          ${memos.map((m, i) => `
          <tr style="border-bottom:1px solid var(--border);${i%2===1?'background:rgba(255,255,255,0.02)':''}">
            <td style="padding:6px 14px;color:var(--text-hi)">${m.name}</td>
            <td style="padding:6px 8px;text-align:right;color:var(--text-dim)">${(m.size/1024).toFixed(0)}KB</td>
            <td style="padding:6px 8px;color:var(--text-dim)">${m.created}</td>
            <td style="padding:6px 8px;text-align:center">
              <audio controls src="/api/memos/${encodeURIComponent(m.name)}"
                     style="height:24px;vertical-align:middle;max-width:160px"></audio>
              <button onclick="deleteMemo('${m.name}')"
                style="background:none;border:1px solid var(--red2);color:var(--red2);font-size:10px;padding:2px 6px;cursor:pointer;margin-left:4px">✕</button>
            </td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
  });
}

function deleteMemo(name) {
  if (!confirm('Delete "' + name + '"?')) return;
  fetch('/api/memos/' + encodeURIComponent(name), { method: 'DELETE' })
    .then(() => loadMemos());
}

function loadSWPC(force) {
  api(force ? '/api/swpc?force=1' : '/api/swpc', data => {
    const el = document.getElementById('swpc-panel');
    if (!el) return;
    const kp = data.kp ?? 0;
    const kpBar = Math.min(Math.round(kp / 9 * 100), 100);
    const sw = data.solar_wind || {};
    const bz = sw.bz_gsm;
    const bzColor = bz == null ? 'var(--text-dim)' : bz < -10 ? '#f44336' : bz < 0 ? '#ff9800' : '#4caf50';

    // 3-day outlook warning banner
    const outlookBanner = (data.forecast_max_scale && data.forecast_max_scale !== 'G0')
      ? `<div style="padding:8px 14px;background:${(data.forecast_color||'var(--border)')+'22'};border-left:3px solid ${data.forecast_color||'var(--accent)'};margin-bottom:0">
          <div style="font-size:10px;letter-spacing:2px;color:${data.forecast_color||'var(--accent)'};font-family:var(--font-m)">
            ⚠ 3-DAY OUTLOOK: MAX Kp ${data.forecast_max_kp} — NOAA SCALE ${data.forecast_max_scale}
          </div>
          ${data.forecast_rationale ? `<div style="font-size:11px;color:var(--text-dim);margin-top:4px;line-height:1.5">${data.forecast_rationale}</div>` : ''}
          ${data.forecast_issued ? `<div style="font-size:9px;color:var(--text-dim);margin-top:4px;letter-spacing:1px">ISSUED: ${data.forecast_issued}</div>` : ''}
        </div>` : '';

    // NOAA scale badge helper
    const scaleBadge = (label, value, color) =>
      `<div class="swpc-scale-badge" style="border-color:${color}40;background:${color}12">
        <div class="swpc-scale-label">${label}</div>
        <div class="swpc-scale-value" style="color:${color}">${value}</div>
      </div>`;

    const sp = data.storm_prob || {};

    el.innerHTML = `
      ${outlookBanner}

      <!-- Scale badges row -->
      <div class="swpc-scales-row">
        ${scaleBadge('GEOMAGNETIC', `G${Math.min(Math.floor(kp >= 5 ? kp - 4 : 0),5) || (kp >= 4 ? 'Active' : 'Quiet')}`, data.kp_color || '#4caf50')}
        ${scaleBadge('RADIO (R)', data.r_scale || 'R0', data.r_color || '#4caf50')}
        ${scaleBadge('RADIATION (S)', data.s_scale || 'S0', data.s_color || '#4caf50')}
        ${scaleBadge('FLARE CLASS', data.flare_class || '---', data.r_color || '#4caf50')}
        ${data.sunspot_number != null ? scaleBadge('SUNSPOTS', data.sunspot_number, '#c9a84c') : ''}
        ${data.f107 ? scaleBadge('F10.7 FLUX', data.f107 + ' sfu', '#7a9ab5') : ''}
        ${data.ap_index ? scaleBadge('Ap INDEX', data.ap_index, '#7a9ab5') : ''}
      </div>

      <div class="swpc-grid">
        <div class="swpc-main">
          <div style="font-size:9px;letter-spacing:4px;color:var(--text-dim);margin-bottom:6px">PLANETARY Kp INDEX</div>
          <div style="font-family:var(--font-h);font-size:56px;line-height:1;color:${data.kp_color || '#888'}">${kp}</div>
          <div style="font-size:12px;color:${data.kp_color || 'var(--text-dim)'};margin:6px 0;letter-spacing:1px">${data.kp_label || '---'}</div>
          <div style="height:4px;background:var(--border);margin-top:8px">
            <div style="height:100%;width:${kpBar}%;background:${data.kp_color || '#888'};transition:width .5s"></div>
          </div>
          <div style="font-size:9px;color:var(--text-dim);margin-top:4px">Kp ${data.kp_tag || ''} — Scale: 0–9</div>
          ${Object.keys(sp).length ? `
          <div style="margin-top:14px;font-size:9px;letter-spacing:2px;color:var(--text-dim);margin-bottom:6px">STORM PROB — 24HR</div>
          ${[['Active',sp.active,'#ffeb3b'],['G1',sp.g1,'#ff9800'],['G2',sp.g2,'#ff5722'],['G3+',sp.g3plus,'#f44336']].map(([l,v,c])=>`
            <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
              <span style="font-size:9px;color:var(--text-dim);width:30px;letter-spacing:1px">${l}</span>
              <div style="flex:1;height:4px;background:var(--border)">
                <div style="height:100%;width:${v||0}%;background:${c};transition:width .5s"></div>
              </div>
              <span style="font-size:9px;color:${c};width:28px;text-align:right">${v||0}%</span>
            </div>`).join('')}` : ''}
        </div>
        <div class="swpc-details">
          <div style="font-size:9px;letter-spacing:3px;color:var(--text-dim);margin-bottom:8px">SOLAR WIND</div>
          ${row_obs('Speed', sw.speed_kms != null ? sw.speed_kms + ' km/s' : '---')}
          ${row_obs('Density', sw.density != null ? sw.density + ' p/cm³' : '---')}
          ${row_obs('Bt (Total)', sw.bt != null ? sw.bt + ' nT' : '---')}
          <div class="wx-obs-row">
            <span class="wx-obs-label">Bz (GSM)</span>
            <span style="color:${bzColor};font-family:var(--font-m)">
              ${bz != null ? (bz > 0 ? '+' : '') + bz + ' nT' : '---'}
            </span>
          </div>
          ${row_obs('Source', sw.source || '---')}
          ${sw.time ? `<div class="wx-obs-station" style="margin-top:8px">SOLAR WIND: ${sw.time} UTC</div>` : ''}
          ${data.proton_flux != null ? `
          <div style="margin-top:12px;font-size:9px;letter-spacing:3px;color:var(--text-dim);margin-bottom:8px">PROTON EVENT (≥10 MeV)</div>
          ${row_obs('Flux', data.proton_flux + ' pfu')}
          ${row_obs('S-Scale', `<span style="color:${data.s_color||'#4caf50'}">${data.s_scale||'S0'}</span>`)}
          ` : ''}
          ${data.xray_flux != null ? `
          <div style="margin-top:12px;font-size:9px;letter-spacing:3px;color:var(--text-dim);margin-bottom:8px">X-RAY FLUX</div>
          ${row_obs('Class', `<span style="color:${data.r_color||'#4caf50'}">${data.flare_class||'---'}</span>`)}
          ${row_obs('Flux', data.xray_flux.toExponential(2) + ' W/m²')}
          ${data.xray_time ? `<div class="wx-obs-station" style="margin-top:4px">XRAY OBS: ${data.xray_time} UTC</div>` : ''}
          ` : ''}
        </div>
      </div>
      ${data.alerts && data.alerts.length ? `
        <div class="panel-sub-header">SWPC ACTIVE ALERTS (${data.alerts.length})</div>
        <div>
          ${data.alerts.map(a => `
            <div style="padding:8px 14px;border-bottom:1px solid var(--border)">
              <div style="font-size:10px;color:var(--red2);letter-spacing:1px;font-family:var(--font-m)">${a.title}</div>
              <div style="font-size:9px;color:var(--text-dim);margin-top:2px">${a.issued}</div>
            </div>`).join('')}
        </div>` : ''}
      <div class="wx-obs-station">SOURCE: NOAA SWPC — ${data.fetched || ''} &nbsp;<a href="https://www.swpc.noaa.gov" target="_blank" style="color:var(--accent)">↗ SWPC</a></div>
    `;

    // SANS ISC feed (also returned in SWPC endpoint)
    const iscEl = document.getElementById('sans-isc-feed');
    if (iscEl && data.sans_isc && data.sans_isc.length) {
      iscEl.innerHTML = data.sans_isc.map(e => `
        <div style="padding:9px 16px;border-bottom:1px solid var(--border)">
          <a href="${e.link}" target="_blank" style="color:var(--text-hi);font-size:13px;text-decoration:none;font-family:var(--font-h)"
             onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--text-hi)'">${e.title}</a>
          <div style="font-size:10px;color:var(--text-dim);margin-top:3px">${e.published}</div>
          ${e.summary ? `<div style="font-size:11px;color:var(--text-dim);margin-top:4px;line-height:1.5">${e.summary}</div>` : ''}
        </div>`).join('');
    } else if (iscEl) {
      iscEl.innerHTML = '<div class="no-data">SANS ISC feed unavailable — <a href="https://isc.sans.edu" target="_blank" style="color:var(--accent)">Visit isc.sans.edu ↗</a></div>';
    }

    // Krebs on Security
    const krebsEl = document.getElementById('krebs-feed');
    if (krebsEl && data.krebs && data.krebs.length) {
      krebsEl.innerHTML = data.krebs.map(e => `
        <div style="padding:9px 16px;border-bottom:1px solid var(--border)">
          <a href="${e.link}" target="_blank" style="color:var(--text-hi);font-size:13px;text-decoration:none;font-family:var(--font-h)"
             onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--text-hi)'">${e.title}</a>
          <div style="font-size:10px;color:var(--text-dim);margin-top:3px">${e.published}</div>
          ${e.summary ? `<div style="font-size:11px;color:var(--text-dim);margin-top:4px;line-height:1.5">${e.summary}</div>` : ''}
        </div>`).join('');
    } else if (krebsEl) {
      krebsEl.innerHTML = '<div class="no-data">Krebs feed unavailable — <a href="https://krebsonsecurity.com" target="_blank" style="color:var(--accent)">Visit krebsonsecurity.com ↗</a></div>';
    }

    // BleepingComputer
    const bleepEl = document.getElementById('bleeping-feed');
    if (bleepEl) {
      if (data.bleeping && data.bleeping.length) {
        bleepEl.innerHTML = data.bleeping.map(e => `
          <div style="padding:9px 16px;border-bottom:1px solid var(--border)">
            <a href="${e.link}" target="_blank" style="color:var(--text-hi);font-size:13px;text-decoration:none;font-family:var(--font-h)"
               onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--text-hi)'">${e.title}</a>
            <div style="font-size:10px;color:var(--text-dim);margin-top:3px">${e.published}</div>
            ${e.summary ? `<div style="font-size:11px;color:var(--text-dim);margin-top:4px;line-height:1.5">${e.summary}</div>` : ''}
          </div>`).join('');
      } else {
        bleepEl.innerHTML = '<div class="no-data">BleepingComputer feed unavailable</div>';
      }
    }

    // The Hacker News
    const thnEl = document.getElementById('thn-feed');
    if (thnEl) {
      if (data.thn && data.thn.length) {
        thnEl.innerHTML = data.thn.map(e => `
          <div style="padding:9px 16px;border-bottom:1px solid var(--border)">
            <a href="${e.link}" target="_blank" style="color:var(--text-hi);font-size:13px;text-decoration:none;font-family:var(--font-h)"
               onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--text-hi)'">${e.title}</a>
            <div style="font-size:10px;color:var(--text-dim);margin-top:3px">${e.published}</div>
            ${e.summary ? `<div style="font-size:11px;color:var(--text-dim);margin-top:4px;line-height:1.5">${e.summary}</div>` : ''}
          </div>`).join('');
      } else {
        thnEl.innerHTML = '<div class="no-data">The Hacker News feed unavailable</div>';
      }
    }
  });
}

function loadEarthquakes(force) {
  api(force ? '/api/earthquakes?force=1' : '/api/earthquakes', data => {
    document.getElementById('quake-ts').textContent = data.fetched || '';
    const quakes = data.earthquakes || [];
    document.getElementById('quake-list').innerHTML = quakes.length
      ? quakes.map(q => {
          const cls = q.mag >= 7 ? 'severe' : q.mag >= 6 ? 'high' : 'mod';
          return `<div class="quake-item">
            <div class="quake-mag ${cls}">${q.mag}</div>
            <div class="quake-place"><a href="${q.url}" target="_blank">${q.place}</a></div>
            <div class="quake-time">${q.time}</div>
          </div>`;
        }).join('')
      : '<div class="no-data">✓ No significant earthquakes this week</div>';
  });
}

function loadMETAR() {
  api('/api/metar', data => {
    const ts = document.getElementById('metar-ts');
    if (ts) ts.textContent = data.fetched || '';
    const el = document.getElementById('metar-panel');
    if (!el) return;
    const stations = data.stations || [];
    if (!stations.length) { el.innerHTML = '<div class="no-data">METAR unavailable</div>'; return; }

    el.innerHTML = `<div style="overflow-x:auto">` + stations.map(s => {
      const wspd = s.wspd != null ? s.wspd + ' kt' : '---';
      const wdir = s.wdir != null ? deg_to_compass_js(s.wdir) + ' (' + s.wdir + '°)' : '---';
      const gust = s.wgst ? ` G${s.wgst}kt` : '';
      const temp = s.temp != null ? Math.round(s.temp * 9/5 + 32) + '°F' : '---';
      const dewp = s.dewp != null ? Math.round(s.dewp * 9/5 + 32) + '°F' : '---';
      const vis  = s.vis  != null ? s.vis + ' SM' : '---';
      return `
        <div style="padding:10px 16px;border-bottom:1px solid var(--border)">
          <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:4px">
            <span style="font-family:var(--font-h);font-size:16px;color:var(--accent);min-width:60px">${s.id}</span>
            <span style="font-size:10px;color:var(--text-dim)">${s.time}</span>
            <span style="font-size:12px;color:var(--text-hi)">Temp: ${temp}</span>
            <span style="font-size:12px;color:var(--text-hi)">Dewp: ${dewp}</span>
            <span style="font-size:12px;color:var(--text-hi)">Wind: ${wdir} @ ${wspd}${gust}</span>
            <span style="font-size:12px;color:var(--text-hi)">Vis: ${vis}</span>
            ${s.wx ? `<span style="font-size:12px;color:var(--red2)">${s.wx}</span>` : ''}
          </div>
          <div style="font-family:var(--font-m);font-size:10px;color:var(--text-dim);letter-spacing:.5px;background:var(--bg3);padding:5px 10px;border-left:3px solid var(--border2)">${s.raw}</div>
        </div>`;
    }).join('') + `</div>`;
  });
}

function deg_to_compass_js(deg) {
  const dirs = ["N","NNE","NE","ENE","E","ESE","SE","SSE","S","SSW","SW","WSW","W","WNW","NW","NNW"];
  return dirs[Math.round(deg / 22.5) % 16];
}

function windArrow(deg) {
  if (deg == null) return '';
  // Arrow points INTO the wind (meteorological convention) — rotate 180° + bearing
  const rot = (parseFloat(deg) + 180) % 360;
  return `<span style="display:inline-block;transform:rotate(${rot}deg);font-size:16px">↑</span>`;
}

function loadLakeMichigan() {
  api('/api/lake_michigan', data => {
    const ts = document.getElementById('lake-ts');
    if (ts) ts.textContent = data.fetched || '';
    const pw = data.pwaw3 || {};
    const trend = data.pwaw3_trend || [];

    // ── PWAW3 current conditions ──────────────────────────
    const bd = document.getElementById('buoy-data');
    if (Object.keys(pw).length) {
      const wspd = pw.wind_speed_mph != null ? pw.wind_speed_mph + ' mph' : '---';
      const wgst = pw.wind_gust_mph  != null ? pw.wind_gust_mph  + ' mph' : '---';
      const atmp = pw.air_temp_f     != null ? pw.air_temp_f     + '°F'   : '---';
      const pres = pw.pressure_mb    != null ? pw.pressure_mb    + ' mb'  : '---';
      const ptdy = pw.pressure_trend && pw.pressure_trend !== 'MM' ? pw.pressure_trend + ' mb/3hr' : '';
      const dir  = pw.wind_dir || '---';
      const arrow = windArrow(pw.wind_dir_deg);

      bd.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:1px;background:var(--border);margin-bottom:1px">
          <div class="stat-box" style="padding:12px">
            <div class="stat-label">Wind Speed</div>
            <div style="font-size:28px;font-family:var(--font-h);color:var(--text-hi)">${wspd}</div>
            <div class="stat-sub">Gust: ${wgst}</div>
          </div>
          <div class="stat-box" style="padding:12px;text-align:center">
            <div class="stat-label">Wind Direction</div>
            <div style="font-size:28px;color:var(--accent)">${arrow} ${dir}</div>
            <div class="stat-sub">${pw.wind_dir_deg ? pw.wind_dir_deg + '°' : ''}</div>
          </div>
          <div class="stat-box" style="padding:12px">
            <div class="stat-label">Air Temp</div>
            <div style="font-size:22px;font-family:var(--font-h);color:var(--text-hi)">${atmp}</div>
          </div>
          <div class="stat-box" style="padding:12px">
            <div class="stat-label">Pressure</div>
            <div style="font-size:18px;font-family:var(--font-h);color:var(--text-hi)">${pres}</div>
            <div class="stat-sub">${ptdy}</div>
          </div>
        </div>
        <div class="dim" style="font-size:10px;padding:6px 10px;letter-spacing:1px">
          NDBC PWAW3 — PORT WASHINGTON, WI &nbsp;|&nbsp;
          <a href="https://www.ndbc.noaa.gov/station_page.php?station=pwaw3" target="_blank" style="color:var(--accent)">View Full NDBC Station Page ↗</a>
          &nbsp;|&nbsp; <a href="https://www.weather.gov/greatlakes/globs?sort=4&lake=Michigan&kt=f&trends=f&seagull=t&shipsonly=f" target="_blank" style="color:var(--accent)">Great Lakes Obs ↗</a>
        </div>`;

      // Trend table
      const tt = document.getElementById('pwaw3-trend');
      if (tt && trend.length) {
        tt.innerHTML = `<table style="width:100%;border-collapse:collapse;font-size:11px">
          <thead><tr>
            <th style="padding:5px 10px;text-align:left;font-size:9px;letter-spacing:2px;color:var(--accent);border-bottom:1px solid var(--border)">TIME (UTC)</th>
            <th style="padding:5px 10px;text-align:right;font-size:9px;letter-spacing:2px;color:var(--accent);border-bottom:1px solid var(--border)">SPEED</th>
            <th style="padding:5px 10px;text-align:right;font-size:9px;letter-spacing:2px;color:var(--accent);border-bottom:1px solid var(--border)">GUST</th>
            <th style="padding:5px 10px;text-align:center;font-size:9px;letter-spacing:2px;color:var(--accent);border-bottom:1px solid var(--border)">DIR</th>
            <th style="padding:5px 10px;text-align:right;font-size:9px;letter-spacing:2px;color:var(--accent);border-bottom:1px solid var(--border)">AIR °F</th>
          </tr></thead><tbody>` +
          trend.map((r,i) => `<tr style="${i===0?'background:rgba(201,168,76,.05)':''}">
            <td style="padding:5px 10px;color:var(--text-dim)">${r.t}</td>
            <td style="padding:5px 10px;text-align:right;color:var(--text-hi)">${r.wspd != null ? r.wspd + ' mph' : '---'}</td>
            <td style="padding:5px 10px;text-align:right;color:var(--red2)">${r.gust != null ? r.gust + ' mph' : '---'}</td>
            <td style="padding:5px 10px;text-align:center;color:var(--accent)">${r.dir}</td>
            <td style="padding:5px 10px;text-align:right;color:var(--blue2)">${r.atmp != null ? r.atmp + '°' : '---'}</td>
          </tr>`).join('') + '</tbody></table>';
      }
    } else {
      bd.innerHTML = '<div class="no-data">Station data unavailable</div>';
    }

    // ── Marine forecast — structured sections ────────────
    const mf = document.getElementById('marine-forecast');
    const sections = data.marine_sections || [];
    if (sections.length) {
      mf.innerHTML = sections.map(s => {
        // Highlight LMZ645 (our primary zone) with accent border
        const isPrimary = s.header && s.header.includes('645');
        const hdrStyle = isPrimary
          ? 'font-family:var(--font-m);font-size:10px;letter-spacing:2px;padding:6px 14px;background:rgba(201,168,76,.12);color:var(--accent);border-left:3px solid var(--accent)'
          : 'font-family:var(--font-m);font-size:10px;letter-spacing:2px;padding:6px 14px;background:var(--bg3);color:var(--text-dim);border-left:3px solid var(--border2)';
        const bodyStyle = isPrimary
          ? 'font-size:12px;color:var(--text);white-space:pre-wrap;line-height:1.7;padding:10px 14px;background:rgba(201,168,76,.04)'
          : 'font-size:11px;color:var(--text-dim);white-space:pre-wrap;line-height:1.6;padding:10px 14px';
        return `<div style="margin-bottom:2px">
          <div style="${hdrStyle}">${s.header}</div>
          <div style="${bodyStyle}">${s.body}</div>
        </div>`;
      }).join('');
    } else if (data.marine_text) {
      mf.innerHTML = `<pre style="font-size:11px;color:var(--text-dim);white-space:pre-wrap;line-height:1.6;padding:14px">${data.marine_text}</pre>`;
    } else {
      mf.innerHTML = '<div class="no-data">Marine forecast unavailable</div>';
    }

    // ── Area Forecast Discussion (AFD) ───────────────────
    const afdEl = document.getElementById('afd-text');
    if (afdEl) {
      if (data.afd_text) {
        // Split AFD into named sections (headers are lines like ".SHORT TERM...")
        const afdSections = data.afd_text.split(/(?=\n\.[A-Z][^\n]{2,}\.\.\.)/);
        afdEl.innerHTML = afdSections.map(block => {
          const hdrMatch = block.match(/\n(\.[A-Z][^\n]+\.\.\.)/);
          if (hdrMatch) {
            const hdr = hdrMatch[1].trim();
            const body = block.slice(hdrMatch.index + hdrMatch[0].length).trim();
            return `<div style="margin-bottom:10px">
              <div style="font-family:var(--font-m);font-size:10px;letter-spacing:2px;padding:5px 14px;background:var(--bg3);color:var(--accent);border-left:3px solid var(--accent)">${hdr}</div>
              <div style="font-size:11px;color:var(--text-dim);white-space:pre-wrap;line-height:1.6;padding:8px 14px">${body}</div>
            </div>`;
          }
          return `<pre style="font-size:11px;color:var(--text-dim);white-space:pre-wrap;line-height:1.6;padding:8px 14px">${block.trim()}</pre>`;
        }).join('');
      } else {
        afdEl.innerHTML = '<div class="no-data">AFD unavailable</div>';
      }
      const afdTs = document.getElementById('afd-issued');
      if (afdTs && data.afd_issued) afdTs.textContent = `Issued: ${data.afd_issued} UTC`;
    }
  });
}

function refreshRadar() {
  const img = document.getElementById('radar-img');
  if (img) img.src = 'https://radar.weather.gov/ridge/standard/KMKX_loop.gif?t=' + Date.now();
}

// ── Wisconsin 511 / Road Map ─────────────────────────────
let _wi511MapInit = false;
function loadGlerlImages(force) {
  // Cache-buster: YYYY-MM-DD-HH rounded to 6-hour block so browser re-fetches when server cache turns over
  const now = new Date();
  const block = Math.floor(now.getUTCHours() / 6) * 6;
  const pad = v => String(v).padStart(2,'0');
  const key = `${now.getUTCFullYear()}-${pad(now.getUTCMonth()+1)}-${pad(now.getUTCDate())}-${pad(block)}`;
  document.querySelectorAll('.glerl-img').forEach(img => {
    const name = img.dataset.name;
    img.src = `/api/glerl/${name}?d=${key}${force ? '&force=1' : ''}`;
  });
}

function initWi511Map() {
  if (_wi511MapInit) return;
  const el = document.getElementById('wi511-map');
  if (!el || typeof L === 'undefined') return;
  _wi511MapInit = true;

  // Center on SE Wisconsin — Port Washington / Milwaukee area
  const map = L.map('wi511-map', {
    center: [43.45, -87.95],
    zoom: 10,
    zoomControl: true
  });

  // Dark-themed OSM tile layer (CartoDB Dark Matter — embeddable, no key needed)
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
    subdomains: 'abcd',
    maxZoom: 19
  }).addTo(map);

  // Key locations as markers
  const locations = [
    { lat: 43.3989, lng: -87.8936, label: 'Port Washington', icon: '📡' },
    { lat: 43.0389, lng: -87.9065, label: 'Milwaukee (MKE)', icon: '✈' },
    { lat: 43.1122, lng: -87.9073, label: 'Milwaukee/Mequon Area', icon: '🏙' },
    { lat: 43.5247, lng: -87.8412, label: 'Sheboygan County', icon: '🗺' },
  ];

  locations.forEach(loc => {
    L.marker([loc.lat, loc.lng])
      .bindPopup(`<b>${loc.icon} ${loc.label}</b><br><a href="https://511wi.gov/" target="_blank" style="color:#4a9eff">View on 511wi.gov ↗</a>`)
      .addTo(map);
  });

  // Traffic layer toggle button
  // 511wi.gov traffic speed tiles (same source as 511wi.gov/map — no key needed)
  const trafficTileLayer = L.tileLayer(
    'https://tiles.ibi511.com/Geoservice/GetTrafficTile?x={x}&y={y}&z={z}',
    { maxZoom: 19, opacity: 0.85, attribution: '&copy; <a href="https://511wi.gov">511 Wisconsin</a>' }
  );
  let trafficOn = false;
  trafficTileLayer.addTo(map);
  trafficOn = true;

  const trafficBtn = L.control({position: 'topright'});
  trafficBtn.onAdd = function() {
    const div = L.DomUtil.create('div', 'leaflet-bar');
    div.innerHTML = '<a href="#" title="Toggle Traffic Layer" style="font-size:11px;padding:4px 8px;display:block;background:#07111f;color:#44ff88;border:1px solid #1e3a5c;text-decoration:none;white-space:nowrap" id="traffic-toggle">🚗 Traffic On</a>';
    L.DomEvent.on(div.querySelector('a'), 'click', function(e) {
      L.DomEvent.preventDefault(e);
      if (trafficOn) {
        map.removeLayer(trafficTileLayer);
        trafficOn = false;
        this.textContent = '🚗 Traffic Off';
        this.style.color = '#c9a84c';
      } else {
        trafficTileLayer.addTo(map);
        trafficOn = true;
        this.textContent = '🚗 Traffic On';
        this.style.color = '#44ff88';
      }
    });
    return div;
  };
  trafficBtn.addTo(map);

  // Layer switcher: Street vs Satellite
  const layers = {
    'Dark': L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {subdomains:'abcd',maxZoom:19}),
    'Street': L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom:19}),
    'Topo': L.tileLayer('https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png', {maxZoom:17})
  };
  L.control.layers(layers).addTo(map);

  // Fix Leaflet sizing inside hidden tab
  setTimeout(() => map.invalidateSize(), 200);
}

// ══════════════════════════════════════════════════════════
//  COMMS
// ══════════════════════════════════════════════════════════

function loadNotepad() {
  api('/api/notepad', data => {
    document.getElementById('notepad').value = data.content || '';
  });
}

function saveNote() {
  const content = document.getElementById('notepad').value;
  fetch('/api/notepad', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({content})
  }).then(r => r.json()).then(data => {
    const s = document.getElementById('note-status');
    s.textContent = `✓ Saved to server at ${data.ts}`;
    setTimeout(() => s.textContent = '', 3000);
  });
}

function downloadNote() {
  const content = document.getElementById('notepad').value;
  const blob = new Blob([content], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `kevsec-notes-${new Date().toISOString().slice(0,10)}.txt`;
  a.click();
}

// Auto-save every 2 min if comms tab is active
setInterval(() => {
  if (document.getElementById('tab-comms').classList.contains('active')) {
    const c = document.getElementById('notepad').value;
    if (c) fetch('/api/notepad', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:c})});
  }
}, 120000);

function loadReminders() {
  api('/api/reminders', data => {
    const reminders = data.reminders || [];
    const wrap = document.getElementById('reminders-list');
    if (!reminders.length) {
      wrap.innerHTML = '<div class="no-data">No active reminders</div>';
      return;
    }
    wrap.innerHTML = reminders.map(r => `
      <div class="reminder-item">
        <div style="flex:1">
          <div class="rem-text">${r.text}</div>
          ${r.remind_at ? `<div class="rem-time-tag">⏰ ${r.remind_at.replace('T',' ')}</div>` : ''}
        </div>
        <button class="rem-del" onclick="deleteReminder(${r.id})">✕</button>
      </div>`).join('');
  });
}

function addReminder() {
  const text = document.getElementById('rem-text').value.trim();
  const remind_at = document.getElementById('rem-time').value;
  if (!text) return;
  fetch('/api/reminders', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({text, remind_at})
  }).then(r => r.json()).then(() => {
    document.getElementById('rem-text').value = '';
    document.getElementById('rem-time').value = '';
    loadReminders();
  });
}

function deleteReminder(id) {
  fetch('/api/reminders', {
    method:'DELETE', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({id})
  }).then(() => loadReminders());
}

// ══════════════════════════════════════════════════════════
//  NUKE AUTHORITY
// ══════════════════════════════════════════════════════════

let _nukeTimer = null;
let _nukeAudio = null;
let _nukeArmed = false;
let _nukeSeconds = 30;

function _nukeBeep(freq, dur, vol) {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain); gain.connect(ctx.destination);
    osc.frequency.value = freq;
    osc.type = 'square';
    gain.gain.setValueAtTime(vol || 0.15, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + dur);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + dur);
  } catch(e) {}
}

function _nukeAlarm() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const dur = 1.5;
    [0, 0.3, 0.6, 0.9, 1.2].forEach(t => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain); gain.connect(ctx.destination);
      osc.frequency.setValueAtTime(880, ctx.currentTime + t);
      osc.frequency.linearRampToValueAtTime(440, ctx.currentTime + t + 0.25);
      osc.type = 'sawtooth';
      gain.gain.setValueAtTime(0.2, ctx.currentTime + t);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + t + 0.28);
      osc.start(ctx.currentTime + t);
      osc.stop(ctx.currentTime + t + 0.3);
    });
  } catch(e) {}
}

function openNukeModal() {
  _nukeArmed = false;
  _nukeSeconds = 30;
  const modal = document.getElementById('nuke-modal');
  modal.style.display = 'flex';
  document.getElementById('nuke-executing').style.display = 'none';
  document.getElementById('nuke-password').disabled = true;
  document.getElementById('nuke-password').value = '';
  document.getElementById('nuke-confirm').disabled = true;
  document.getElementById('nuke-confirm').checked = false;
  document.getElementById('nuke-execute-btn').disabled = true;
  document.getElementById('nuke-execute-btn').style.color = '#330000';
  document.getElementById('nuke-execute-btn').style.borderColor = '#330000';
  document.getElementById('nuke-execute-btn').style.cursor = 'not-allowed';
  document.getElementById('nuke-pw-error').style.display = 'none';
  document.getElementById('nuke-armed-msg').style.display = 'none';
  document.getElementById('nuke-confirm-label').style.opacity = '0.4';
  document.getElementById('nuke-countdown').textContent = '30';
  document.getElementById('nuke-countdown-bar').style.width = '0%';
  document.getElementById('nuke-countdown-bar').style.transition = 'none';

  _nukeBeep(220, 0.3, 0.1); // opening tone

  setTimeout(() => {
    document.getElementById('nuke-countdown-bar').style.transition = 'width 1s linear';
  }, 50);

  _nukeTimer = setInterval(() => {
    _nukeSeconds--;
    const pct = ((30 - _nukeSeconds) / 30 * 100).toFixed(1);
    document.getElementById('nuke-countdown').textContent = String(_nukeSeconds).padStart(2,'0');
    document.getElementById('nuke-countdown-bar').style.width = pct + '%';

    // Beep pattern: fast in last 5 seconds, every 5 otherwise
    if (_nukeSeconds <= 5) {
      _nukeBeep(660, 0.08, 0.12);
    } else if (_nukeSeconds % 5 === 0) {
      _nukeBeep(440, 0.15, 0.1);
    } else {
      _nukeBeep(330, 0.05, 0.06);
    }

    if (_nukeSeconds <= 0) {
      clearInterval(_nukeTimer);
      _nukeTimer = null;
      _nukeArmed = true;
      _nukeAlarm();
      document.getElementById('nuke-countdown').textContent = '00';
      document.getElementById('nuke-countdown').style.color = '#ff6600';
      document.getElementById('nuke-countdown-bar').style.background = '#ff6600';
      document.getElementById('nuke-armed-msg').style.display = 'block';
      document.getElementById('nuke-password').disabled = false;
      document.getElementById('nuke-confirm').disabled = false;
      document.getElementById('nuke-confirm-label').style.opacity = '1';
      document.getElementById('nuke-password').focus();
    }
  }, 1000);
}

function _nukeStandDown() {
  // Descending stand-down tone
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    [880, 660, 440, 330, 220].forEach((freq, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain); gain.connect(ctx.destination);
      osc.frequency.value = freq;
      osc.type = 'sine';
      gain.gain.setValueAtTime(0.12, ctx.currentTime + i * 0.12);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + i * 0.12 + 0.15);
      osc.start(ctx.currentTime + i * 0.12);
      osc.stop(ctx.currentTime + i * 0.12 + 0.16);
    });
  } catch(e) {}
}

function abortNuke() {
  _nukeStandDown();
  if (_nukeTimer) { clearInterval(_nukeTimer); _nukeTimer = null; }
  // Flash the countdown red briefly, then close
  const cd = document.getElementById('nuke-countdown');
  cd.textContent = 'ABORT';
  cd.style.fontSize = '28px';
  cd.style.color = '#aa3333';
  setTimeout(closeNukeModal, 800);
}

function closeNukeModal() {
  if (_nukeTimer) { clearInterval(_nukeTimer); _nukeTimer = null; }
  document.getElementById('nuke-modal').style.display = 'none';
  document.getElementById('nuke-final-confirm').style.display = 'none';
  document.getElementById('nuke-executing').style.display = 'none';
  _nukeArmed = false;
}

function nukeCheckReady() {
  if (!_nukeArmed) return;
  const pw = document.getElementById('nuke-password').value;
  const checked = document.getElementById('nuke-confirm').checked;
  const btn = document.getElementById('nuke-execute-btn');
  if (pw.length > 0 && checked) {
    btn.disabled = false;
    btn.style.color = '#ff2200';
    btn.style.borderColor = '#cc0000';
    btn.style.cursor = 'pointer';
    btn.style.boxShadow = '0 0 20px #cc000066';
    document.getElementById('nuke-pw-error').style.display = 'none';
  } else {
    btn.disabled = true;
    btn.style.color = '#330000';
    btn.style.borderColor = '#330000';
    btn.style.cursor = 'not-allowed';
    btn.style.boxShadow = 'none';
  }
}

// Step 2 → Step 3: verify password client-readable, reveal final confirm button
function primeNuke() {
  const pw = document.getElementById('nuke-password').value;
  if (!pw || !_nukeArmed || !document.getElementById('nuke-confirm').checked) return;
  _nukeAlarm();
  // Hide auth panel, show final confirmation step
  document.getElementById('nuke-execute-btn').closest('div').closest('div').style.display = 'none';
  document.getElementById('nuke-final-confirm').style.display = 'block';
}

// Step 3 → Fire: send to backend
function executeNuke() {
  const pw = document.getElementById('nuke-password').value;
  if (!pw || !_nukeArmed) return;

  document.getElementById('nuke-final-confirm').style.display = 'none';
  document.getElementById('nuke-executing').style.display = 'block';
  const log = document.getElementById('nuke-status-log');
  log.innerHTML = 'AUTHENTICATING...<br>';

  const csrf = document.querySelector('meta[name="csrf-token"]');
  fetch('/api/nuke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf ? csrf.content : '' },
    body: JSON.stringify({ password: pw })
  }).then(r => r.json()).then(data => {
    if (data.error) {
      log.innerHTML += '✕ ' + data.error + '<br>ABORTING.<br>';
      _nukeBeep(110, 0.5, 0.2);
      setTimeout(() => {
        document.getElementById('nuke-executing').style.display = 'none';
        document.getElementById('nuke-execute-btn').closest('div').closest('div').style.display = 'block';
        document.getElementById('nuke-pw-error').style.display = 'block';
        document.getElementById('nuke-pw-error').textContent = '✕ ' + data.error;
      }, 2000);
      return;
    }
    // Authenticated — sequence is running on server
    _nukeAlarm();
    setTimeout(_nukeAlarm, 1800);
    setTimeout(_nukeAlarm, 3600);
    const phases = [
      'AUTHENTICATION: ACCEPTED',
      'PHASE 1 — STOPPING ALL SERVICES...',
      'PHASE 2 — SHREDDING SSH KEYS & CREDENTIALS (DOD 3-PASS)...',
      'PHASE 3 — WIPING APPLICATION DATA...',
      'PHASE 4 — NWIPE DOD 5220.22-M — /dev/sdb (1.9T DATA DRIVE)...',
      'PHASE 5 — ZEROING /dev/sda ROOT DRIVE...',
      'SYSTEM WILL GO OFFLINE. CONNECTION LOST.'
    ];
    let i = 1;
    const phaseInterval = setInterval(() => {
      if (i < phases.length) {
        log.innerHTML += phases[i] + '<br>';
        _nukeBeep(220, 0.2, 0.15);
        i++;
      } else {
        clearInterval(phaseInterval);
      }
    }, 1400);
  }).catch(() => {
    log.innerHTML += 'CONNECTION LOST — SYSTEM IS OFFLINE.<br>';
  });
}

// Close modal on backdrop click (outside the inner box)
document.getElementById('nuke-modal').addEventListener('click', function(e) {
  if (e.target === this) closeNukeModal();
});

// ── SSH Copy ───────────────────────────────────────────────
function copySSH() {
  navigator.clipboard.writeText('ssh slankey@69.30.236.220').then(() => {
    const el = document.getElementById('ssh-btn-sub2');
    if (el) { el.textContent = '✓ Copied!'; setTimeout(() => el.textContent = 'Click to copy', 2000); }
  });
}

// ══════════════════════════════════════════════════════════
//  GDACS — Global Disaster Alerts
// ══════════════════════════════════════════════════════════
function loadGDACS(force) {
  const el = document.getElementById('gdacs-list');
  const tsEl = document.getElementById('gdacs-ts');
  if (!el) return;
  el.innerHTML = '<div class="loading">Loading GDACS alerts...</div>';
  api(force ? '/api/gdacs?force=1' : '/api/gdacs', data => {
    if (tsEl) tsEl.textContent = data.fetched || '';
    const events = data.events || [];
    if (!events.length) {
      el.innerHTML = '<div class="no-data">✓ No active global disaster alerts</div>';
      return;
    }
    el.innerHTML = events.map(a => {
      const col = a.color || '#888';
      const alertLabel = a.alert || '';
      return `<div style="padding:8px 14px;border-bottom:1px solid var(--border);display:flex;gap:10px;align-items:flex-start">
        <span style="font-size:14px;flex-shrink:0;margin-top:2px">${a.icon || '⚠'}</span>
        <div style="flex:1;min-width:0">
          <a href="${a.link||'#'}" target="_blank" style="color:var(--text-hi);font-size:12px;text-decoration:none;font-family:var(--font-h);line-height:1.4;display:block"
             onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--text-hi)'">${a.title}</a>
          <div style="font-size:10px;color:var(--text-dim);margin-top:3px">${a.type || ''}${a.type && a.country ? ' · ' : ''}${a.country || ''}${a.date ? ' · ' + a.date : ''}</div>
        </div>
        ${alertLabel ? `<span style="flex-shrink:0;font-size:9px;letter-spacing:1px;color:${col};font-family:var(--font-m);padding:2px 6px;border:1px solid ${col}40;border-radius:2px">${alertLabel}</span>` : ''}
      </div>`;
    }).join('');
  });
}

// ══════════════════════════════════════════════════════════
//  Daily Goals
// ══════════════════════════════════════════════════════════
let _goalsRaw = '';

function loadGoals(force) {
  const viewEl = document.getElementById('goals-view');
  if (!viewEl) return;
  api(force ? '/api/goals?force=1' : '/api/goals', data => {
    _goalsRaw = data.raw || '';
    const items = data.items || [];
    if (!items.length) {
      viewEl.innerHTML = '<div class="no-data">No goals defined — click Edit to add some.</div>';
      return;
    }
    const done = items.filter(i => i.done).length;
    viewEl.innerHTML = `
      <div style="font-size:10px;letter-spacing:2px;color:var(--text-dim);margin-bottom:8px;padding:0 14px">${done}/${items.length} COMPLETE</div>
      <div style="height:3px;background:var(--border);margin:0 14px 12px">
        <div style="height:100%;width:${items.length ? Math.round(done/items.length*100) : 0}%;background:var(--accent);transition:width .4s"></div>
      </div>
      ${items.map((item, idx) => `
        <div style="display:flex;align-items:flex-start;gap:10px;padding:7px 14px;border-bottom:1px solid var(--border);cursor:pointer"
             onclick="toggleGoal(${idx})" title="Click to toggle">
          <span style="flex-shrink:0;font-size:14px;color:${item.done ? 'var(--accent)' : 'var(--text-dim)'};margin-top:1px">${item.done ? '✓' : '○'}</span>
          <span style="font-size:12px;color:${item.done ? 'var(--text-dim)' : 'var(--text-hi)'};${item.done ? 'text-decoration:line-through' : ''};line-height:1.5">${item.text}</span>
        </div>`).join('')}`;
  });
}

function toggleGoal(idx) {
  let lines = _goalsRaw.split('\n');
  let itemIdx = 0;
  lines = lines.map(line => {
    if (/^\s*- \[[ x]\]/i.test(line)) {
      if (itemIdx === idx) {
        itemIdx++;
        const isDone = /- \[x\]/i.test(line);
        return isDone ? line.replace(/- \[x\]/i, '- [ ]') : line.replace(/- \[ \]/, '- [x]');
      }
      itemIdx++;
    }
    return line;
  });
  fetch('/api/goals', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: lines.join('\n') })
  }).then(() => loadGoals(true));
}

function toggleGoalsEdit() {
  const viewEl = document.getElementById('goals-view');
  const editWrap = document.getElementById('goals-editor');
  const editEl = document.getElementById('goals-textarea');
  if (!viewEl || !editWrap) return;
  const isEditing = editWrap.style.display !== 'none';
  if (isEditing) {
    editWrap.style.display = 'none';
    viewEl.style.display = '';
  } else {
    if (editEl) editEl.value = _goalsRaw;
    editWrap.style.display = '';
    viewEl.style.display = 'none';
    if (editEl) editEl.focus();
  }
}

function saveGoals() {
  const editEl = document.getElementById('goals-textarea');
  if (!editEl) return;
  fetch('/api/goals', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: editEl.value })
  }).then(r => r.json()).then(() => {
    toggleGoalsEdit();
    loadGoals(true);
  });
}

// ── IP Management ────────────────────────────────────────────────
function _ipFeedback(msg, ok) {
  const el = document.getElementById('banip-feedback');
  if (!el) return;
  el.textContent = msg;
  el.style.color = ok ? 'var(--accent)' : 'var(--red2)';
  setTimeout(() => { el.textContent = ''; }, 5000);
}

function banIP() {
  const ip = (document.getElementById('ban-ip-input') || {}).value.trim();
  const reason = (document.getElementById('ban-reason-input') || {}).value.trim();
  if (!ip) { _ipFeedback('Enter an IP address', false); return; }
  _csrfPost('/api/ban_ip', { ip, reason: reason || 'manual_dashboard_ban' }, data => {
    if (data.error) { _ipFeedback('Error: ' + data.error, false); return; }
    const res = data.results || {};
    const parts = Object.entries(res).map(([k,v]) => k + ':' + (v ? '✓' : '✗')).join(' ');
    _ipFeedback('Banned ' + data.ip + ' — ' + parts, true);
    document.getElementById('ban-ip-input').value = '';
    document.getElementById('ban-reason-input').value = '';
    setTimeout(() => loadFirewallDrops(), 1500);
  });
}

function unbanIP() {
  const ip = (document.getElementById('unban-ip-input') || {}).value.trim();
  if (!ip) { _ipFeedback('Enter an IP address', false); return; }
  _csrfPost('/api/f2b_unban', { ip }, data => {
    if (data.error) { _ipFeedback('Error: ' + data.error, false); return; }
    const count = Object.keys(data.results || {}).length;
    _ipFeedback('Unbanned ' + data.ip + ' from ' + count + ' jail(s)', true);
    document.getElementById('unban-ip-input').value = '';
    setTimeout(() => loadFirewallDrops(), 1500);
  });
}

function runBlacklistUpdate() {
  const outEl = document.getElementById('blacklist-output');
  if (outEl) { outEl.style.display = 'block'; outEl.textContent = 'Running...'; }
  _ipFeedback('Running blacklist update...', true);
  _csrfPost('/api/run_blacklist_update', {}, data => {
    if (data.error) {
      _ipFeedback('Error: ' + data.error, false);
      if (outEl) outEl.textContent = 'Error: ' + data.error;
      return;
    }
    _ipFeedback(data.ok ? 'Blacklist updated' : 'Update failed', data.ok);
    if (outEl) outEl.textContent = data.output || '(no output)';
  });
}

function loadJailSummary() {
  api('/api/firewall_drops', data => {
    const el = document.getElementById('jail-summary');
    if (!el) return;
    const f2bs = data.f2b || [];
    if (!f2bs.length) { el.innerHTML = '<span style="color:var(--text-dim)">No active bans</span>'; return; }
    // Group by jail
    const jails = {};
    f2bs.forEach(d => {
      const j = d.source || 'unknown';
      if (!jails[j]) jails[j] = { count: 0, total: d.total || 0 };
      jails[j].count++;
    });
    el.innerHTML = Object.entries(jails).map(([j, info]) =>
      `<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--border)">
        <span style="color:var(--accent)">${j}</span>
        <span>${info.count} shown${info.total ? ' / ' + info.total + ' total' : ''}</span>
       </div>`
    ).join('');
  });
}

// Helper: POST with CSRF token
function _csrfPost(url, body, cb) {
  const token = document.querySelector('meta[name="csrf-token"]');
  fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token ? token.content : '' },
    body: JSON.stringify(body)
  }).then(r => r.json()).then(cb).catch(e => { console.error(url, e); });
}

// ── Server Health + Network ─────────────────────────────────────
function loadServerHealth(force) {
  api((force ? '/api/network_stats?force=1' : '/api/network_stats'), data => {
    const ts = document.getElementById('health-ts');
    if (ts) ts.textContent = data.ts || '';

    // Network interfaces
    const netEl = document.getElementById('health-net');
    if (netEl) {
      const ifaces = data.interfaces || {};
      const rows = Object.entries(ifaces).map(([name, iface]) =>
        `<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--border)">
          <span style="color:var(--accent);min-width:60px">${name}</span>
          <span>↓ ${_fmtBytes(iface.rx_bytes)}</span>
          <span>↑ ${_fmtBytes(iface.tx_bytes)}</span>
        </div>`
      ).join('');
      netEl.innerHTML = rows || '<span style="color:var(--text-dim)">No interfaces</span>';
    }

    // Top processes
    const procsEl = document.getElementById('health-procs');
    if (procsEl) {
      const procs = data.top_procs || [];
      if (!procs.length) { procsEl.innerHTML = '<tr><td colspan="5" class="no-data">No data</td></tr>'; return; }
      procsEl.innerHTML = procs.map(p =>
        `<tr>
          <td style="color:var(--text-dim)">${p.user}</td>
          <td style="color:var(--text-dim)">${p.pid}</td>
          <td style="color:${parseFloat(p.cpu) > 20 ? 'var(--red2)' : 'var(--text)'}">${p.cpu}%</td>
          <td style="color:${parseFloat(p.mem) > 10 ? 'var(--red2)' : 'var(--text)'}">${p.mem}%</td>
          <td style="color:var(--accent);font-size:10px">${p.cmd}</td>
        </tr>`
      ).join('');
    }
  });

  // Separate call for server stats from /api/server_control GET (existing)
  fetch('/api/network_stats').then(r => r.json()).then(data => {
    const statsEl = document.getElementById('health-stats');
    if (!statsEl) return;
    const ifaces = data.interfaces || {};
    const total_rx = Object.values(ifaces).reduce((a, i) => a + i.rx_bytes, 0);
    const total_tx = Object.values(ifaces).reduce((a, i) => a + i.tx_bytes, 0);
    statsEl.innerHTML = `
      <div class="stat-box"><div class="stat-val">${_fmtBytes(total_rx)}</div><div class="stat-lbl">TOTAL RX</div></div>
      <div class="stat-box"><div class="stat-val">${_fmtBytes(total_tx)}</div><div class="stat-lbl">TOTAL TX</div></div>
      <div class="stat-box"><div class="stat-val">${Object.keys(ifaces).length}</div><div class="stat-lbl">INTERFACES</div></div>
      <div class="stat-box"><div class="stat-val">${(data.top_procs||[]).length}</div><div class="stat-lbl">TOP PROCS</div></div>
    `;
  }).catch(() => {});
}

function _fmtBytes(bytes) {
  if (bytes === undefined || bytes === null) return '—';
  const gb = bytes / 1073741824;
  if (gb >= 1) return gb.toFixed(2) + ' GB';
  const mb = bytes / 1048576;
  if (mb >= 1) return mb.toFixed(1) + ' MB';
  return Math.round(bytes / 1024) + ' KB';
}

// ── DJ Atticus ────────────────────────────────────────────────────────────────
function loadDjStatus() {
  fetch('/api/spotify_status').then(r => r.json()).then(data => {
    const statusEl = document.getElementById('dja-spotify-status');
    const textEl   = document.getElementById('dja-status-text');
    const authBtn  = document.getElementById('dja-auth-btn');
    if (!statusEl) return;
    if (!data.authorized) {
      statusEl.textContent = '⚠ Not authorized — click Authorize Spotify';
      statusEl.style.color = 'var(--warn, #f59e0b)';
      if (textEl) textEl.textContent = 'After authorizing, DJ Atticus will appear in your Spotify device list.';
    } else if (data.expired) {
      statusEl.textContent = '⚠ Token expired — click Refresh Token';
      statusEl.style.color = 'var(--warn, #f59e0b)';
    } else {
      const mins = Math.round(data.expires_in / 60);
      statusEl.textContent = `✅ Authorized — token valid for ${mins}m`;
      statusEl.style.color = 'var(--green, #4ade80)';
      if (authBtn) authBtn.textContent = '🔗 Re-authorize Spotify';
      if (textEl) textEl.textContent = 'DJ Atticus should appear in your Spotify → Connect devices list. Select it to stream.';
    }
    const ts = document.getElementById('dja-ts');
    if (ts) ts.textContent = new Date().toLocaleTimeString();
  }).catch(() => {});
}

function djSpotifyRefresh() {
  const statusEl = document.getElementById('dja-spotify-status');
  if (statusEl) { statusEl.textContent = 'Refreshing...'; statusEl.style.color = 'var(--text-dim)'; }
  _csrfPost('/api/spotify_refresh', {}).then(r => r.json()).then(data => {
    if (data.ok) {
      if (statusEl) { statusEl.textContent = `✅ Token refreshed (valid ${Math.round(data.expires_in/60)}m)`; statusEl.style.color = 'var(--green, #4ade80)'; }
    } else {
      if (statusEl) { statusEl.textContent = `❌ ${data.error}`; statusEl.style.color = 'var(--danger, #f87171)'; }
    }
  }).catch(e => { if (statusEl) statusEl.textContent = '❌ Error: ' + e; });
}
