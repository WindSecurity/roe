// Roe popup. Everything from the page is rendered with textContent only, never innerHTML,
// so a hostile page cannot inject markup into this UI.
const app = document.getElementById('app');
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
const LEVEL = { high: 'High risk', medium: 'Medium risk', low: 'Weak signal' };
const RANK = { high: 0, medium: 1, low: 2 };
const ORG = self.ROE_EDITION === 'org';
const { CATS, REFS, EXPOSURE } = Roe;
let tabId = null;
let filter = 'all';
let settings = null;
let lastData = null;
let automatedHere = false;
const pendingRemoved = new Set();   // ids the person removed; shown as removed before the page confirms
const openState = new Map();         // details key -> open, kept across live re-renders
const toggled = new Set();           // highlight buttons that are on

document.querySelector('.ver').textContent = chrome.runtime.getManifest().version + (ORG ? ' · org' : '');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const fetchReport = () => chrome.runtime.sendMessage({ type: 'roe:get', tabId });
const allFrames = (msg) => Promise.allSettled(Object.keys((lastData && lastData.frames) || { 0: 1 }).map((fid) => chrome.tabs.sendMessage(tabId, msg, { frameId: Number(fid) })));
const SETTINGS = { mode: 'warn', allow: [], ghRaw: true, scanImages: true, scanDownloads: true, downloadScans: [] };

async function load() {
  const forced = Number(new URLSearchParams(location.search).get('tab'));   // popup.html?tab=N opens it for a given tab
  const [tab] = forced ? [await chrome.tabs.get(forced).catch(() => null)] : await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  tabId = tab.id;
  settings = await chrome.storage.local.get(SETTINGS);
  let data = (await fetchReport()) || { frames: {} };
  if (ORG) chrome.runtime.sendMessage({ type: 'roe:automation-tabs' }).then((r) => { automatedHere = !!(r && r.tabs.includes(tabId)); if (lastData) paint(); }).catch(() => {});

  // Tabs that were already open when Roe was installed or reloaded never got the content
  // script. Inject it now (allowed by activeTab because the person just opened the popup).
  if (!data.frames[0]) {
    paintLoading();
    try {
      await chrome.scripting.executeScript({
        target: { tabId, allFrames: true },
        files: ['edition.js', 'detector.js', 'sinks.js', 'surfaces.js', 'exposure.js', 'ai-sites.js', 'content.js', 'guard.js']
      });
    } catch (e) { /* browser pages, the Web Store and PDFs cannot be scripted */ }
    for (let i = 0; i < 10 && !data.frames[0]; i++) {
      await wait(250);
      data = (await fetchReport()) || { frames: {} };
    }
  }
  lastData = data;
  paint();
}

// Live updates: the service worker writes each frame's report to session storage, so the
// popup re-renders the moment the page changes (after a removal, a rescan or a mode switch)
// instead of guessing with timers.
let raf = 0;
chrome.storage.session.onChanged.addListener((changes) => {
  const c = changes['tab:' + tabId];
  if (!c) return;
  lastData = c.newValue || { frames: {} };
  for (const id of [...pendingRemoved]) {
    const f = findById(id);
    if (!f || f.sanitized || f.gone) pendingRemoved.delete(id);
  }
  cancelAnimationFrame(raf);
  raf = requestAnimationFrame(paint);
});
chrome.storage.local.onChanged.addListener(async (changes) => {
  if (!settings) return;
  for (const k of Object.keys(SETTINGS)) if (changes[k]) settings[k] = changes[k].newValue;
  cancelAnimationFrame(raf);
  raf = requestAnimationFrame(paint);
});

function findById(id) {
  for (const rep of Object.values((lastData && lastData.frames) || {})) { const f = rep.findings.find((x) => x.id === id); if (f) return f; }
  return null;
}

const SURFACE_NOTE = {
  email: 'Email bodies are written by strangers and are read by mail agents.',
  github: 'Issues, PRs and READMEs are written by anyone and are read by coding agents.',
  raw: 'Raw files are loaded by agents as-is.',
  chat: 'Chat messages come from other people and bots.',
  tickets: 'Tickets are written by customers and outsiders.',
  docs: 'Shared documents can be edited by others.',
  social: 'Public posts are open to anyone.',
  aichat: 'An AI assistant. What you paste here leaves this browser.',
  file: 'A local file.',
  web: 'Any public page can carry hidden text.'
};

function link(ref) {
  const a = el('a', '', ref.name);
  if (ref.url) { a.href = ref.url; a.target = '_blank'; a.rel = 'noreferrer noopener'; }
  return a;
}

function section(key, title, count, defOpen) {
  const d = el('details', 'sec');
  d.open = openState.has(key) ? openState.get(key) : !!defOpen;
  const s = el('summary');
  s.append(el('span', '', title));
  if (count !== undefined && count !== null) s.append(el('span', 'count', String(count)));
  d.append(s);
  d.addEventListener('toggle', () => openState.set(key, d.open));
  return d;
}

function busy(btn, text) { btn.classList.add('busy'); btn.disabled = true; btn.textContent = text; }

function paintLoading() {
  app.replaceChildren();
  const v = el('div', 'verdict');
  v.append(el('h2', 'loading', 'Scanning this page'), el('p', '', 'Reading text, attributes, comments and images an agent would see.'));
  app.append(v);
}

function paint() {
  if (!lastData || !settings) return;
  const y = document.scrollingElement.scrollTop;
  render(settings, lastData);
  document.scrollingElement.scrollTop = y;
}

function render(settings, data) {
  const frag = document.createDocumentFragment();
  const add = (...n) => frag.append(...n);
  const frames = Object.entries(data.frames);
  const top = data.frames[0];

  if (!top) {
    const v = el('div', 'verdict');
    v.append(el('h2', '', 'Roe has not scanned this tab'),
      el('p', '', 'It cannot run on browser pages, the Web Store or PDFs. For local files, turn on “Allow access to file URLs” for Roe in chrome://extensions. On a normal page, try reloading it.'));
    add(v, dashboardBox(0));
    app.replaceChildren(frag);
    return;
  }

  const host = new URL(top.url).hostname || 'this page';
  const paused = settings.allow.includes(host);
  const surf = top.surface || { id: 'web', label: 'Public web page' };

  const findings = [];
  const sinkList = [];
  for (const [frameId, rep] of frames) {
    for (const f of rep.findings) {
      const x = { ...f, frameId: Number(frameId), frameUrl: Number(frameId) === 0 ? '' : rep.url };
      if (pendingRemoved.has(f.id)) { x.sanitized = true; x.removable = false; x.optimistic = true; }
      findings.push(x);
    }
    sinkList.push(...(rep.sinks || []));
  }
  findings.sort((a, b) => RANK[a.level] - RANK[b.level] || Number(b.hidden) - Number(a.hidden));
  const strong = findings.filter((f) => f.level !== 'low');
  const activeStrong = strong.filter((f) => !f.sanitized && !f.gone);
  const weak = findings.filter((f) => f.level === 'low');
  const removedCount = findings.filter((f) => f.sanitized || f.gone).length;
  const removableHidden = strong.filter((f) => f.hidden && f.removable && !f.sanitized && !f.gone && f.kind !== 'image');
  const exposure = top.exposure || {};
  const expTotal = Object.values(exposure).reduce((n, v) => n + v.n, 0);

  // surface chip
  const chip = el('div', 'surface');
  chip.append(el('span', 'chip', surf.label), el('span', 'host', host));
  if (ORG && automatedHere) chip.append(el('span', 'chip red', 'Automated'));
  add(chip, el('p', 'surfnote', SURFACE_NOTE[surf.id] || SURFACE_NOTE.web));

  // verdict
  const v = el('div', 'verdict ' + (paused ? '' : activeStrong.length ? 'bad' : 'ok'));
  if (paused) {
    v.append(el('h2', '', 'Roe is paused on ' + host), el('p', '', 'Nothing on this site is being scanned or changed.'));
  } else if (activeStrong.length) {
    const anth = activeStrong.filter((f) => f.anthropic).length;
    const nHidden = activeStrong.filter((f) => f.hidden).length;
    v.append(
      el('h2', '', activeStrong.length + (activeStrong.length === 1 ? ' possible attack on an AI agent found' : ' possible attacks on an AI agent found')),
      el('p', '', (nHidden ? nHidden + ' of ' + activeStrong.length + ' are hidden from you but readable by an agent.' : 'They are visible on the page.') +
        (removedCount ? ' ' + removedCount + ' removed from the page.' : '') +
        (anth ? ' ' + anth + ' match attacks Anthropic has written about.' : ''))
    );
  } else {
    v.append(el('h2', '', removedCount ? removedCount + ' hidden item' + (removedCount === 1 ? '' : 's') + ' removed from this page' : 'No attack signals found'),
      el('p', '', removedCount ? 'The text is gone from the page DOM. Roe keeps the evidence below so you can still copy it.' : 'Roe matches known patterns only, so this does not prove the page is safe.'));
  }
  add(v);

  // at-a-glance strip
  if (!paused) {
    const strip = el('div', 'strip');
    const cell = (n, label, tone) => { const c = el('div', 'cell' + (tone && n ? ' ' + tone : '')); c.append(el('b', '', String(n)), el('span', '', label)); return c; };
    strip.append(
      cell(activeStrong.length, 'Active threats', 'bad'),
      cell(activeStrong.filter((f) => f.hidden).length, 'Hidden', 'bad'),
      cell(removedCount, 'Removed'),
      cell(sinkList.length + expTotal, 'Agent exposure', 'warn')
    );
    add(strip);
  }

  // controls
  const controls = el('div', 'controls');
  const seg = el('div', 'seg');
  seg.setAttribute('role', 'group');
  seg.setAttribute('aria-label', 'What Roe does with hidden text');
  [['warn', 'Warn only'], ['sanitize', 'Warn and remove hidden text']].forEach(([mode, label]) => {
    const b = el('button', '', label);
    b.setAttribute('aria-pressed', String(settings.mode === mode));
    b.addEventListener('click', () => {
      if (settings.mode === mode) return;
      seg.querySelectorAll('button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      settings.mode = mode;
      chrome.storage.local.set({ mode });
    });
    seg.append(b);
  });
  const site = el('button', 'link', paused ? 'Resume on this site' : 'Pause on this site');
  site.addEventListener('click', () => {
    const allow = paused ? settings.allow.filter((h) => h !== host) : [...settings.allow, host];
    busy(site, paused ? 'Resuming…' : 'Pausing…');
    chrome.storage.local.set({ allow });
  });
  controls.append(seg, site);
  add(controls);

  if (!paused) {
    const row = el('div', 'controls');
    if (removableHidden.length) {
      const rm = el('button', 'primary', 'Remove ' + removableHidden.length + ' hidden item' + (removableHidden.length === 1 ? '' : 's') + ' now');
      rm.addEventListener('click', async () => {
        const ids = removableHidden.map((f) => f.id);
        ids.forEach((id) => pendingRemoved.add(id));
        paint();                                  // show the result at once
        const res = await allFrames({ type: 'roe:remove', ids: 'hidden' });
        if (!res.some((r) => r.status === 'fulfilled' && r.value && r.value.removed)) {
          ids.forEach((id) => pendingRemoved.delete(id));
          paint(); toast('Could not remove. Reload the page and try again.');
        }
      });
      row.append(rm);
    }
    const rs = el('button', 'link', 'Rescan');
    rs.addEventListener('click', async () => {
      busy(rs, 'Scanning…');
      await allFrames({ type: 'roe:rescan' });
      setTimeout(() => { if (rs.isConnected) { rs.classList.remove('busy'); rs.disabled = false; rs.textContent = 'Rescan'; } }, 1500);
    });
    row.append(rs);
    add(row);

    if (surf.id === 'github') {
      const g = el('div', 'gh');
      const t = el('button', 'link', settings.ghRaw ? 'GitHub raw check: on (turn off)' : 'GitHub raw check: off (turn on)');
      t.addEventListener('click', () => { busy(t, 'Updating…'); chrome.storage.local.set({ ghRaw: !settings.ghRaw }); });
      g.append(t);
      if (top.rawStatus) g.append(el('p', '', top.rawStatus));
      g.append(el('p', '', 'Reads the raw Markdown an agent gets from api.github.com, including HTML comments the page never shows. Only the repo and issue number are sent.'));
      add(g);
    }

    // category filters
    const counts = {};
    strong.forEach((f) => { counts[f.cat] = (counts[f.cat] || 0) + 1; });
    const catKeys = Object.keys(counts);
    if (filter !== 'all' && !counts[filter]) filter = 'all';
    if (catKeys.length > 1) {
      const bar = el('div', 'filters');
      [['all', 'All ' + strong.length], ...catKeys.map((k) => [k, (CATS[k] || k) + ' ' + counts[k]])].forEach(([k, label]) => {
        const b = el('button', '', label);
        b.setAttribute('aria-pressed', String(filter === k));
        b.addEventListener('click', () => { filter = k; paint(); });
        bar.append(b);
      });
      add(bar);
    }

    const shown = strong.filter((f) => filter === 'all' || f.cat === filter);
    const list = el('ul', 'cards');
    shown.forEach((f) => list.append(card(f)));
    add(list);

    if (weak.length) {
      const d = section('weak', 'Weak signals', weak.length);
      const wl = el('ul', 'cards');
      weak.forEach((f) => wl.append(card(f)));
      d.append(wl);
      add(d);
    }

    // evidence on this page: what was found and exactly where
    add(evidenceSection(top, host, strong));

    // what an agent can access on this page
    add(accessSection(top, surf, sinkList, exposure, activeStrong));
  }

  add(dashboardBox(strong.length));

  // files, images and downloads
  const dls = settings.downloadScans || [];
  const flaggedDl = dls.filter((d) => d.findings.some((f) => f.level !== 'low')).length;
  const files = section('files', 'Files, images and downloads', flaggedDl ? flaggedDl + ' flagged' : null, flaggedDl > 0);
  const fbox = el('div', 'gh');
  const open = el('button', 'secondary', 'Scan a file or image…');
  open.addEventListener('click', () => chrome.tabs.create({ url: chrome.runtime.getURL('scan.html') }));
  fbox.append(open);
  const toggle = (key, on, off) => {
    const t = el('button', 'link', settings[key] ? on : off);
    t.addEventListener('click', () => { settings[key] = !settings[key]; t.textContent = settings[key] ? on : off; chrome.storage.local.set({ [key]: settings[key] }); });
    const p = el('p'); p.append(t); return p;
  };
  fbox.append(
    toggle('scanImages', 'Scan images on pages: on (turn off)', 'Scan images on pages: off (turn on)'),
    el('p', '', 'Each displayed image is fetched again without cookies, from the browser cache when it can, and checked for hidden text in its metadata and near-invisible text.'),
    toggle('scanDownloads', 'Scan downloads: on (turn off)', 'Scan downloads: off (turn on)'),
    el('p', '', 'Needs “Allow access to file URLs” for Roe in chrome://extensions. Files stay on this device.')
  );
  if (dls.some((d) => d.error === 'file-access')) fbox.append(el('p', 'notes', 'The last download could not be read. Turn on “Allow access to file URLs” for Roe in chrome://extensions.'));
  if (dls.length) {
    fbox.append(el('p', '', 'Recent downloads'));
    const ul = el('ul');
    dls.slice(0, 5).forEach((d) => {
      const n = d.findings.filter((f) => f.level !== 'low').length;
      const li = el('li');
      const a = el('button', 'link', d.name + (d.error ? ' (not scanned)' : n ? ' (' + n + ' flagged)' : ' (clean)'));
      a.addEventListener('click', () => chrome.tabs.create({ url: chrome.runtime.getURL('scan.html#dl=' + d.id) }));
      li.append(a); ul.append(li);
    });
    fbox.append(ul);
  }
  files.append(fbox);
  add(files);

  // sources behind the rules
  const src = section('sources', 'Sources behind these rules');
  const sl = el('ul', 'sources');
  Object.values(REFS).forEach((r) => {
    const li = el('li');
    li.append(link(r));
    if (r.anthropic) li.append(el('span', 'tag anth', 'Anthropic'));
    li.append(el('div', 'none', r.note));
    sl.append(li);
  });
  src.append(sl);
  add(src);

  add(el('p', 'foot', ORG
    ? 'Roe reads page content and watches for automated control of this browser. A browser-built-in assistant reads pages without a tab of its own, so for it Roe shows what was exposed, not what was read. Removal changes only the page DOM; screenshot-based agents are unaffected.'
    : 'Roe reads page content. It cannot see what your AI agent reads, does or sends, so a path shown here is possible, not proven. Removal changes only the page DOM; screenshot-based agents are unaffected.'));

  app.replaceChildren(frag);
}

function evidenceSection(top, host, strong) {
  const d = section('evidence', 'Evidence on this page', strong.length, strong.length > 0 && strong.length <= 6);
  const box = el('div', 'evidence');
  const page = el('div', 'evpage');
  page.append(el('div', 'evtitle', top.title || host));
  const u = el('div', 'evurl', top.url);
  u.title = top.url;
  page.append(u, el('div', 'evmeta', 'Scanned ' + new Date(top.scannedAt || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })));
  box.append(page);
  if (!strong.length) {
    box.append(el('p', 'none', 'Nothing found on this page yet. Anything Roe finds is listed here with the exact place it was found, and kept in the dashboard’s evidence log.'));
    d.append(box);
    return d;
  }
  const table = el('ol', 'evlist');
  strong.forEach((f) => {
    const li = el('li', f.level + (f.sanitized || f.gone ? ' done' : ''));
    const line = el('div', 'evline');
    line.append(el('span', 'dot'), el('span', 'evcat', CATS[f.cat] || f.cat), el('span', 'evstate', f.sanitized || f.gone ? 'Removed' : f.hidden ? 'Hidden' : 'Visible'));
    li.append(line);
    li.append(el('div', 'evwhere', (f.frameUrl ? 'Frame ' + shortUrl(f.frameUrl) + ' › ' : '') + (f.where || f.technique) + ' · ' + f.technique));
    li.append(el('div', 'evsnip', '“' + f.snippet + '”'));
    table.append(li);
  });
  box.append(table);
  const acts = el('div', 'actions');
  const copy = el('button', '', 'Copy page evidence');
  copy.addEventListener('click', async () => {
    const ev = { page: top.url, title: top.title, scannedAt: new Date(top.scannedAt || Date.now()).toISOString(), surface: top.surface && top.surface.label,
      findings: strong.map((f) => ({ level: f.level, category: f.cat, technique: f.technique, hidden: f.hidden, removed: !!(f.sanitized || f.gone), element: f.where, frame: f.frameUrl || null, rules: f.rules.map((r) => r.id), text: f.snippet })) };
    await navigator.clipboard.writeText(JSON.stringify(ev, null, 2));
    copy.textContent = 'Copied';
  });
  const log = el('button', '', 'Open evidence log');
  log.addEventListener('click', () => openDash('evidence'));
  acts.append(copy, log);
  box.append(acts);
  d.append(box);
  return d;
}

function accessSection(top, surf, sinkList, exposure, active) {
  const expKeys = Object.keys(exposure);
  const n = sinkList.length + expKeys.length;
  const d = section('access', 'What an agent can access here', n || null, false);
  const box = el('div', 'access');
  box.append(el('p', 'none', 'Anything that can read this page, such as an assistant built into the browser or an agent extension, sees everything below.'));
  const rows = el('dl', 'grid');
  const row = (k, vNode) => { const r = el('div'); r.append(el('dt', '', k)); const dd = el('dd'); dd.append(vNode); r.append(dd); rows.append(r); };
  const chips = (items, tone) => {
    const w = el('div', 'chips');
    if (!items.length) w.append(el('span', 'none', 'None found'));
    items.forEach((t) => w.append(el('span', 'pill' + (tone ? ' ' + tone : ''), t)));
    return w;
  };
  row('Content source', el('span', '', surf.label + (['email', 'chat', 'tickets', 'github', 'raw', 'social', 'docs'].includes(surf.id) ? ', written by others' : '')));
  row('Sensitive data', chips(expKeys.map((k) => (EXPOSURE[k] || k) + ' ' + exposure[k].n), 'warn'));
  row('Actions it could take', chips(sinkList.map((s) => s.label), ''));
  row('Instructions aimed at it', chips(active.length ? [active.length + ' active, ' + active.filter((f) => f.hidden).length + ' hidden'] : [], 'bad'));
  if (ORG) row('Automated control', el('span', automatedHere ? 'flag' : '', automatedHere ? 'This tab is being driven by an agent or debugger right now' : 'Not detected in this tab'));
  box.append(rows);
  const samples = expKeys.flatMap((k) => exposure[k].samples.map((s) => (EXPOSURE[k] || k) + ': ' + s)).slice(0, 4);
  if (samples.length) box.append(el('p', 'none mono', 'Masked: ' + samples.join('  ·  ')));
  const b = el('button', 'link', 'See agent access across all sites');
  b.addEventListener('click', () => openDash('access'));
  box.append(b);
  d.append(box);
  return d;
}

function dashboardBox(n) {
  const b = el('button', 'dash');
  const t = el('span', 'dash-t');
  t.append(el('strong', '', 'Open visibility dashboard'), el('span', '', ORG ? 'Evidence, agent access, agent activity and policy' : 'Evidence across every site, and what agents could access'));
  b.append(t, el('span', 'arrow', '→'));
  b.addEventListener('click', () => openDash('overview'));
  return b;
}

async function openDash(view) {
  const url = chrome.runtime.getURL('dashboard.html');
  const [t] = await chrome.tabs.query({ url: url + '*' });
  if (t) { await chrome.tabs.update(t.id, { active: true, url: url + '#' + view }); await chrome.windows.update(t.windowId, { focused: true }); }
  else await chrome.tabs.create({ url: url + '#' + view });
  window.close();
}

const shortUrl = (u) => { try { const x = new URL(u); return x.host + (x.pathname.length > 24 ? x.pathname.slice(0, 24) + '…' : x.pathname); } catch (e) { return u.slice(0, 40); } };

let toastTimer = 0;
function toast(msg) {
  let t = document.getElementById('toast');
  if (!t) { t = el('div', 'toast'); t.id = 'toast'; t.setAttribute('role', 'status'); document.body.append(t); }
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}

function card(f) {
  const removed = f.sanitized || f.gone;
  const li = el('li', 'card ' + f.level + (removed ? ' removed' : '') + (f.optimistic ? ' just' : ''));

  const top = el('div', 'top');
  top.append(el('span', 'level', removed ? 'Removed' : LEVEL[f.level]),
    el('span', 'how', (f.hidden ? 'Hidden: ' : 'Visible: ') + f.technique));
  li.append(top);

  const tags = el('div', 'tags');
  tags.append(el('span', 'tag cat', CATS[f.cat] || f.cat));
  if (f.anthropic) tags.append(el('span', 'tag anth', 'Anthropic-discussed'));
  if (f.kind === 'remote') tags.append(el('span', 'tag', 'Raw, not on page'));
  li.append(tags);

  const split = el('dl', 'split');
  const a = el('div', 'yousee');
  a.append(el('dt', '', 'You see'),
    el('dd', '', removed ? 'Nothing now. Roe removed this from the page.' : f.kind === 'remote' ? 'Nothing. It is in the raw Markdown, not the rendered page.' : f.kind === 'title' ? 'The tab title. It is easy to overlook, and an agent reads it as trusted.' : f.technique === 'file name in link' ? 'Nothing. It is in a link’s file name, which you rarely read.' : f.kind === 'image' ? (/near-invisible/.test(f.technique) ? 'Almost nothing. The text is only a few shades from the background.' : 'Nothing in the picture. It is stored inside the image file.') : f.hidden ? 'Nothing. Your browser does not display it.' : 'This text, in plain view.'));
  const b = el('div', 'agent');
  b.append(el('dt', '', 'An agent reads'), el('dd', '', '“' + f.snippet + '”'));
  split.append(a, b);
  li.append(split);

  li.append(el('p', 'why', f.rules.map((r) => r.label).join('. ') + '.'));
  if (f.where) li.append(el('p', 'loc', 'Found at ' + (f.frameUrl ? shortUrl(f.frameUrl) + ' › ' : '') + f.where));

  const refs = (f.refs || []).map((k) => REFS[k]).filter(Boolean);
  if (refs.length) {
    const p = el('p', 'seen', 'Seen in: ');
    refs.forEach((r, i) => { if (i) p.append(document.createTextNode(' · ')); p.append(link(r)); });
    li.append(p);
  }

  if (f.sinks && f.sinks.length) {
    const t = el('div', 'targets');
    t.append(el('p', '', 'Could be aimed at'));
    const ul = el('ul');
    f.sinks.forEach((s) => {
      const row = el('li');
      row.append(el('span', s.present ? 'here' : 'none', s.label));
      row.append(el('span', 'tag' + (s.present ? ' anth' : ''), s.present ? 'on this page' : 'agent tools only'));
      if (s.present && s.examples.length) row.append(el('div', 'none', s.examples.join(', ')));
      ul.append(row);
    });
    t.append(ul);
    li.append(t);
  }

  const actions = el('div', 'actions');
  if (!removed && ['text', 'text-group', 'attribute', 'template', 'comment', 'image'].includes(f.kind)) {
    const hiddenText = f.hidden && (f.kind === 'text' || f.kind === 'text-group');
    const orig = hiddenText ? 'Reveal and highlight' : 'Highlight on page';
    const hb = el('button', '', toggled.has(f.id) ? 'Clear highlight' : orig);
    hb.addEventListener('click', async () => {
      try {
        if (toggled.has(f.id)) { toggled.delete(f.id); hb.textContent = orig; await chrome.tabs.sendMessage(tabId, { type: 'roe:unhighlight' }, { frameId: f.frameId }); return; }
        toggled.clear(); toggled.add(f.id); hb.textContent = 'Clear highlight';
        const res = await chrome.tabs.sendMessage(tabId, { type: 'roe:highlight', id: f.id }, { frameId: f.frameId });
        if (!(res && res.ok)) { toggled.delete(f.id); hb.textContent = (res && res.reason) || 'Could not highlight'; }
      } catch (e) { toggled.delete(f.id); hb.textContent = 'Could not reach the page. Reload it.'; }
    });
    actions.append(hb);
  } else if (f.kind === 'title' && !removed) {
    actions.append(el('span', 'how', 'Shown on the browser tab'));
  }
  if (f.removable && !removed) {
    const rm = el('button', 'danger', f.kind === 'image' ? 'Remove image from page' : f.kind === 'title' ? 'Replace tab title' : 'Remove from page');
    rm.addEventListener('click', async () => {
      pendingRemoved.add(f.id);
      toggled.delete(f.id);
      paint();                               // the card turns into its removed state immediately
      try {
        const res = await chrome.tabs.sendMessage(tabId, { type: 'roe:remove', ids: [f.id] }, { frameId: f.frameId });
        if (!(res && res.removed)) throw new Error('not removed');
      } catch (e) {
        pendingRemoved.delete(f.id); paint(); toast('Could not remove it. The page may have changed; try Rescan.');
      }
    });
    actions.append(rm);
  }
  const c = el('button', '', 'Copy evidence');
  c.addEventListener('click', async () => {
    const top = lastData.frames[0];
    const ev = { page: top && top.url, frame: f.frameUrl || null, kind: f.kind, category: f.cat, technique: f.technique, hidden: f.hidden, level: f.level, score: f.score, rules: f.rules.map((r) => r.id), sources: f.refs, element: f.where, text: f.snippet };
    await navigator.clipboard.writeText(JSON.stringify(ev, null, 2));
    c.textContent = 'Copied';
    setTimeout(() => { if (c.isConnected) c.textContent = 'Copy evidence'; }, 1400);
  });
  actions.append(c);
  li.append(actions);
  return li;
}

load();
