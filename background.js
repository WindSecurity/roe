// Roe service worker: collects each frame's report per tab, drives the toolbar badge,
// keeps the evidence, agent-access and agent-activity logs behind the visibility dashboard,
// and (opt-in) fetches the raw Markdown an agent would read through the GitHub API.
importScripts('edition.js', 'ai-sites.js');
const ORG = self.ROE_EDITION === 'org';
const tabKey = (id) => 'tab:' + id;
let queue = Promise.resolve();
const enqueue = (fn) => (queue = queue.then(fn, fn));

function updateBadge(tabId, data) {
  let medium = 0, high = 0;
  for (const rep of Object.values(data.frames)) {
    for (const f of rep.findings) {
      if (f.gone) continue;
      if (f.level === 'high') high++;
      else if (f.level === 'medium') medium++;
    }
  }
  const n = high + medium;
  chrome.action.setBadgeText({ tabId, text: n ? String(n) : '' });
  chrome.action.setBadgeBackgroundColor({ tabId, color: high ? '#B00B3A' : '#9A5B00' });
}

// ---------- GitHub raw Markdown ----------
const GH_CACHE = new Map(); // key -> { at, items }
const NAME = /^[A-Za-z0-9_.-]{1,100}$/;
const trim = (s) => (typeof s === 'string' ? s.slice(0, 20000) : '');

async function githubRaw(t) {
  if (!t || !NAME.test(t.owner) || !NAME.test(t.repo) || (t.number && !/^\d{1,9}$/.test(t.number))) return { items: [], error: 'bad target' };
  const key = [t.owner, t.repo, t.kind, t.number || ''].join('/');
  const hit = GH_CACHE.get(key);
  if (hit && Date.now() - hit.at < 5 * 60 * 1000) return { items: hit.items };
  const base = 'https://api.github.com/repos/' + t.owner + '/' + t.repo;
  const opt = { headers: { Accept: 'application/vnd.github+json' }, credentials: 'omit' };
  const items = [];
  try {
    if (t.kind === 'repo') {
      const r = await fetch(base + '/readme', { headers: { Accept: 'application/vnd.github.raw+json' }, credentials: 'omit' });
      if (!r.ok) return { items, error: 'GitHub returned ' + r.status + ' (private repo or rate limit)' };
      items.push({ label: 'README', text: trim(await r.text()) });
    } else {
      const r = await fetch(base + '/issues/' + t.number, opt);
      if (!r.ok) return { items, error: 'GitHub returned ' + r.status + ' (private repo or rate limit)' };
      const j = await r.json();
      items.push({ label: (t.kind === 'pull' ? 'Pull request' : 'Issue') + ' description', text: trim(j.body) });
      const c = await fetch(base + '/issues/' + t.number + '/comments?per_page=50', opt);
      if (c.ok) (await c.json()).forEach((x, i) => items.push({ label: 'Comment ' + (i + 1) + ' by ' + (x.user && x.user.login), text: trim(x.body) }));
    }
  } catch (e) { return { items, error: 'network error' }; }
  GH_CACHE.set(key, { at: Date.now(), items });
  return { items };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return false;
  if (msg.type === 'roe:report' && sender.tab) {
    const { id: tabId } = sender.tab;
    const frameId = sender.frameId;
    enqueue(async () => {
      const key = tabKey(tabId);
      const data = (await chrome.storage.session.get(key))[key] || { frames: {} };
      data.frames[frameId] = msg.report;
      await chrome.storage.session.set({ [key]: data });
      updateBadge(tabId, data);
      try {
        await saveEvidence(sender.tab, frameId, msg.report);
        if (frameId === 0) await saveAccess(sender.tab, msg.report);
      } catch (e) { console.warn('Roe: log write failed', e); }
    });
    return false;
  }
  if (msg.type === 'roe:activity' && sender.tab && ORG) {
    logActivity({ ...msg.event, tabId: sender.tab.id, title: sender.tab.title });
    return false;
  }
  if (msg.type === 'roe:automation-state') {
    sendResponse({ on: !!(sender.tab && automation.has(sender.tab.id)) });
    return false;
  }
  if (msg.type === 'roe:approve' && sender.tab && ORG) {
    requestApproval(msg, sender.tab).then(sendResponse);
    return true;
  }
  if (msg.type === 'roe:get') {
    enqueue(async () => {
      const key = tabKey(msg.tabId);
      sendResponse((await chrome.storage.session.get(key))[key] || { frames: {} });
    });
    return true; // answer asynchronously
  }
  if (msg.type === 'roe:image' && sender.tab) {
    scanImageUrl(msg.url).then(sendResponse);
    return true;
  }
  if (msg.type === 'roe:github' && sender.tab) {
    githubRaw(msg.target).then(sendResponse);
    return true;
  }
  return false;
});

// A new page load starts a fresh report.
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === 'loading') enqueue(() => chrome.storage.session.remove(tabKey(tabId)));
  if (ORG && info.url) onNavigate(tabId, info.url, tab);
  if (ORG && info.status === 'complete') checkAutomation();
});
chrome.tabs.onRemoved.addListener((tabId) => enqueue(() => chrome.storage.session.remove(tabKey(tabId))));

// ---------- offscreen scanner (documents and images need a DOM) ----------
let offPromise = null;
function ensureOffscreen() {
  if (offPromise) return offPromise;
  offPromise = (async () => {
    const ctxs = await chrome.runtime.getContexts({ contextTypes: ['OFFSCREEN_DOCUMENT'] });
    if (!ctxs.length) await chrome.offscreen.createDocument({ url: 'offscreen.html', reasons: ['DOM_PARSER', 'BLOBS'], justification: 'Parse documents and decode images to look for hidden instructions aimed at AI agents.' });
  })().catch((e) => { offPromise = null; throw e; });
  return offPromise;
}
async function offScan(url, name, max) {
  await ensureOffscreen();
  try { return await chrome.runtime.sendMessage({ type: 'roe:off-scan', url, name, max }); }
  catch (e) { offPromise = null; await ensureOffscreen(); return chrome.runtime.sendMessage({ type: 'roe:off-scan', url, name, max }); }
}

// ---------- images on pages ----------
const IMG_CACHE = new Map();
const EXT = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/webp': 'webp', 'image/svg+xml': 'svg' };
function imageName(url) {
  if (url.startsWith('data:')) return 'image.' + (EXT[(/^data:([^;,]+)/.exec(url) || [])[1]] || 'png');
  try { const n = new URL(url).pathname.split('/').pop() || 'image'; return /\.(png|jpe?g|gif|webp|svg)$/i.test(n) ? n : n + '.img'; } catch (e) { return 'image.img'; }
}
async function scanImageUrl(url) {
  if (!/^(https?:|data:image\/)/.test(url)) return { ok: false, error: 'unsupported' };
  if (IMG_CACHE.has(url)) return IMG_CACHE.get(url);
  const res = await offScan(url, imageName(url), 8 * 1024 * 1024).catch((e) => ({ ok: false, error: String(e) }));
  if (IMG_CACHE.size > 200) IMG_CACHE.delete(IMG_CACHE.keys().next().value);
  IMG_CACHE.set(url, res);
  return res;
}

// ---------- downloads ----------
const SKIP_DL = /\.(mp[34]|m4a|mov|avi|mkv|webm|iso|dmg|exe|msi|apk|deb|rpm|torrent|woff2?|ttf|otf)$/i;
const fileUrl = (p) => (p.startsWith('/') ? 'file://' + encodeURI(p) : 'file:///' + encodeURI(p.replace(/\\/g, '/')));
async function scanDownload(item) {
  const name = item.filename.split(/[\\/]/).pop();
  const rec = { id: item.id, name, at: Date.now(), kind: '', findings: [], notes: [], error: '' };
  try {
    const r = await offScan(fileUrl(item.filename), name, 40 * 1024 * 1024);
    if (!r || !r.ok) rec.error = /Failed to fetch|NetworkError/i.test((r && r.error) || '') ? 'file-access' : ((r && r.error) || 'unreadable');
    else { rec.kind = r.res.kind; rec.notes = r.res.notes.slice(0, 6); rec.findings = r.res.findings.slice(0, 25); }
  } catch (e) { rec.error = 'unreadable'; }
  const { downloadScans = [] } = await chrome.storage.local.get('downloadScans');
  await chrome.storage.local.set({ downloadScans: [rec, ...downloadScans.filter((x) => x.id !== rec.id)].slice(0, 25) });
  const strong = rec.findings.filter((f) => f.level !== 'low').length;
  if (strong) {
    chrome.notifications.create('roe-dl-' + rec.id, { type: 'basic', iconUrl: 'icons/128.png', title: 'Roe: instructions aimed at AI agents in a download',
      message: name + ': ' + strong + (strong === 1 ? ' possible attack' : ' possible attacks') + '. Click to see what an agent would read.' });
  }
  return rec;
}
async function onDownloadChanged(delta) {
  if (!delta.state || delta.state.current !== 'complete') return;
  const s = await chrome.storage.local.get({ scanDownloads: true });
  const [item] = await chrome.downloads.search({ id: delta.id });
  if (!s.scanDownloads) { if (ORG && item) await downloadContext(item, null); return; }
  if (!item || !item.filename || SKIP_DL.test(item.filename) || item.fileSize > 40 * 1024 * 1024) return;
  let rec = await scanDownload(item);
  if (rec.error && rec.error !== 'file-access') { await new Promise((r) => setTimeout(r, 1500)); rec = await scanDownload(item); }   // one retry for transient failures
  if (ORG) await downloadContext(item, rec);
}
chrome.downloads.onChanged.addListener((delta) => { onDownloadChanged(delta).catch((e) => console.warn('Roe: download scan failed', e)); });
chrome.notifications.onClicked.addListener((id) => {
  const m = /^roe-dl-(\d+)$/.exec(id);
  if (m) { chrome.tabs.create({ url: chrome.runtime.getURL('scan.html#dl=' + m[1]) }); chrome.notifications.clear(id); }
});

// ---------- evidence log: what was found, and on which page ----------
// One entry per page (URL) per visit window. Rescans of the same page merge into it instead of
// adding a new row each time, so the log reads as "this page carried these attacks".
const MAX_EVIDENCE = 500;
const MAX_FINDINGS_PER_PAGE = 60;
const VISIT_WINDOW = 6 * 60 * 60 * 1000;
const lastWrite = new Map();
const pageUrlOf = (u) => { try { const x = new URL(u); x.hash = ''; return x.href; } catch (e) { return u || ''; } };
const hostOf = (u) => { try { return new URL(u).hostname || (u.startsWith('file:') ? 'local file' : ''); } catch (e) { return ''; } };

async function saveEvidence(tab, frameId, report) {
  const strong = (report.findings || []).filter((f) => f.level === 'high' || f.level === 'medium');
  if (!strong.length) return;
  const now = Date.now();
  const url = pageUrlOf(tab.url || report.url);
  const { evidenceLog = [] } = await chrome.storage.local.get('evidenceLog');
  let i = evidenceLog.findIndex((e) => e.url === url && now - (e.lastSeen || e.timestamp) < VISIT_WINDOW);
  let entry = i >= 0 ? evidenceLog[i] : null;
  let changed = false;
  if (!entry) {
    entry = { id: now + '-' + tab.id, url, host: hostOf(url), pageTitle: tab.title || report.title || 'Untitled', surface: report.surface || { id: 'web', label: 'Public web page' },
      firstSeen: now, lastSeen: now, timestamp: now, automated: false, findings: [] };
    changed = true;
  }
  if (!entry.findings) entry.findings = [];
  for (const f of strong) {
    const had = entry.findings.find((x) => x.id === f.id);
    const removed = !!(f.sanitized || f.gone);
    if (had) { if (removed && !had.removed) { had.removed = true; had.removedAt = now; changed = true; } continue; }
    if (entry.findings.length >= MAX_FINDINGS_PER_PAGE) continue;
    entry.findings.push({
      id: f.id, cat: f.cat, cats: f.cats, level: f.level, score: f.score, technique: f.technique, hidden: f.hidden,
      kind: f.kind, where: f.where || '', frameUrl: frameId === 0 ? '' : pageUrlOf(report.url), snippet: f.snippet,
      rules: f.rules, sinks: f.sinks, refs: f.refs, anthropic: f.anthropic, foundAt: now, removed
    });
    changed = true;
  }
  if (automation.has(tab.id) && !entry.automated) { entry.automated = true; changed = true; }
  if (!changed && now - (lastWrite.get('ev:' + url) || 0) < 60000) return;
  lastWrite.set('ev:' + url, now);
  entry.lastSeen = entry.timestamp = now;
  if (tab.title) entry.pageTitle = tab.title;
  if (i >= 0) evidenceLog.splice(i, 1);
  evidenceLog.unshift(entry);
  await chrome.storage.local.set({ evidenceLog: evidenceLog.slice(0, MAX_EVIDENCE) });
}

// ---------- access log: what an agent reading each page could see and do ----------
const MAX_ACCESS = 400;
async function saveAccess(tab, report) {
  const url = pageUrlOf(tab.url || report.url);
  if (!/^(https?|file):/.test(url) || report.paused) return;
  const now = Date.now();
  const exposure = {};
  for (const [k, v] of Object.entries(report.exposure || {})) exposure[k] = { n: v.n, samples: v.samples || [] };
  const kinds = {};
  const sinkLabels = [];
  for (const s of report.sinks || []) { kinds[s.kind] = (kinds[s.kind] || 0) + 1; if (sinkLabels.length < 8) sinkLabels.push(s.label + (s.detail ? ' (' + s.detail + ')' : '')); }
  const live = (report.findings || []).filter((f) => f.level !== 'low' && !f.gone && !f.sanitized);
  const summary = { high: live.filter((f) => f.level === 'high').length, medium: live.filter((f) => f.level === 'medium').length, hidden: live.filter((f) => f.hidden).length };
  const sig = JSON.stringify([exposure, kinds, summary]);

  const { accessLog = [] } = await chrome.storage.local.get('accessLog');
  const i = accessLog.findIndex((e) => e.url === url);
  const prev = i >= 0 ? accessLog[i] : null;
  const automated = automation.has(tab.id);
  const newVisit = !prev || now - prev.lastSeen > 30 * 60 * 1000;
  if (prev && !newVisit && prev.sig === sig && (!automated || prev.automated) && now - prev.lastSeen < 60000) return;
  const entry = {
    url, host: hostOf(url), title: tab.title || report.title || prev?.title || 'Untitled',
    surface: report.surface ? { id: report.surface.id, label: report.surface.label } : { id: 'web', label: 'Public web page' },
    firstSeen: prev ? prev.firstSeen : now, lastSeen: now, visits: (prev ? prev.visits : 0) + (newVisit ? 1 : 0),
    exposure, sinkKinds: kinds, sinks: sinkLabels, findings: summary, automated: automated || !!(prev && prev.automated),
    aiSite: (self.Roe.aiSiteFor(url) || {}).label || '', sig
  };
  if (i >= 0) accessLog.splice(i, 1);
  accessLog.unshift(entry);
  await chrome.storage.local.set({ accessLog: accessLog.slice(0, MAX_ACCESS) });
}

// ---------- activity log (org): what AI assistants and agents did ----------
const MAX_ACTIVITY = 1000;
const recentAct = new Map();
function logActivity(ev) {
  const now = Date.now();
  const key = [ev.type, ev.tabId, ev.url, ev.label].join('|');
  if (recentAct.get(key) > now - 3000) return Promise.resolve();
  recentAct.set(key, now);
  if (recentAct.size > 500) recentAct.clear();
  return enqueue(async () => {
    const { activityLog = [] } = await chrome.storage.local.get('activityLog');
    activityLog.unshift({ id: now + '-' + Math.random().toString(36).slice(2, 7), at: now, ...ev, host: ev.host || hostOf(ev.url) });
    await chrome.storage.local.set({ activityLog: activityLog.slice(0, MAX_ACTIVITY) });
  });
}

// ---------- policy (org) ----------
let policy = self.Roe.mergePolicy();
async function loadPolicy() {
  const [{ policy: local }, managed] = await Promise.all([
    chrome.storage.local.get('policy'),
    chrome.storage.managed ? chrome.storage.managed.get(null).catch(() => ({})) : {}
  ]);
  policy = self.Roe.mergePolicy(local, managed && managed.policy);
  if (ORG) await applyAiRules();
  return policy;
}
async function applyAiRules() {
  if (!chrome.declarativeNetRequest) return;
  const old = await chrome.declarativeNetRequest.getDynamicRules();
  const add = [];
  self.Roe.AI_SITES.forEach((site, i) => {
    if ((policy.ai || {})[site.id] !== 'block') return;
    const condition = { resourceTypes: ['main_frame', 'sub_frame'] };
    if (site.hosts) condition.requestDomains = site.hosts; else condition.regexFilter = site.regex;
    add.push({ id: 1000 + i, priority: 1, action: { type: 'block' }, condition });
  });
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: old.map((r) => r.id), addRules: add });
}
chrome.storage.onChanged.addListener((c, area) => { if (c.policy || area === 'managed') loadPolicy(); });
loadPolicy();

// AI assistants opened as pages, and pages visited by a tab under automated control.
const lastNav = new Map();
function onNavigate(tabId, url, tab) {
  const site = self.Roe.aiSiteFor(url);
  const now = Date.now();
  if (site) {
    const mode = (policy.ai || {})[site.id] || 'log';
    const k = tabId + '|' + site.id;
    if (mode !== 'allow' && !(lastNav.get(k) > now - 10 * 60 * 1000)) {
      lastNav.set(k, now);
      logActivity({ type: mode === 'block' ? 'ai-blocked' : 'ai-open', label: site.label, url, tabId, title: tab && tab.title });
    }
  }
  if (automation.has(tabId) && /^(https?|file):/.test(url)) logActivity({ type: 'agent-visit', label: hostOf(url), url, tabId, title: tab && tab.title });
}

// ---------- automated control (org) ----------
// Browser agents drive a tab through a debugger session. chrome.debugger.getTargets() tells us
// which tabs have one attached (an agent extension, a CDP automation tool, or DevTools).
const automation = new Map();   // tabId -> since
chrome.storage.session.get('automation').then(({ automation: a }) => { for (const [k, v] of Object.entries(a || {})) automation.set(Number(k), v); });
let checking = null;
function checkAutomation() {
  if (!ORG || !chrome.debugger || !chrome.debugger.getTargets) return Promise.resolve();
  if (checking) return checking;
  checking = (async () => {
    const targets = await chrome.debugger.getTargets();
    const now = new Set(targets.filter((t) => t.attached && t.type === 'page' && typeof t.tabId === 'number').map((t) => t.tabId));
    const byTab = new Map(targets.map((t) => [t.tabId, t]));
    let changed = false;
    for (const id of now) {
      if (automation.has(id)) continue;
      automation.set(id, Date.now()); changed = true;
      const t = byTab.get(id) || {};
      logActivity({ type: 'automation-start', label: 'Automated control started', url: /^(https?|file):/.test(t.url || '') ? t.url : '', title: t.title, tabId: id });
      chrome.tabs.sendMessage(id, { type: 'roe:automation', on: true }).catch(() => {});
    }
    for (const [id, since] of [...automation]) {
      if (now.has(id)) continue;
      automation.delete(id); changed = true;
      const tab = await chrome.tabs.get(id).catch(() => null);
      logActivity({ type: 'automation-end', label: 'Automated control ended', url: tab && /^(https?|file):/.test(tab.url || '') ? tab.url : '', title: tab && tab.title, tabId: id, duration: Date.now() - since });
      chrome.tabs.sendMessage(id, { type: 'roe:automation', on: false }).catch(() => {});
    }
    if (changed) await chrome.storage.session.set({ automation: Object.fromEntries(automation) });
  })().catch(() => {}).finally(() => { checking = null; });
  return checking;
}
if (ORG) {
  chrome.alarms.create('roe-automation', { periodInMinutes: 0.5 });
  chrome.alarms.onAlarm.addListener((a) => { if (a.name === 'roe-automation') checkAutomation(); });
  chrome.tabs.onActivated.addListener(() => checkAutomation());
  chrome.runtime.onMessage.addListener((m) => { if (m && m.type === 'roe:report') checkAutomation(); return false; });
  checkAutomation();
}

// ---------- step-up approval (org) ----------
// The approval is a system notification: outside every web page, so an agent that drives the
// page (by script or by screenshot and clicks) cannot approve its own action.
const approvals = new Map();   // notification id -> { resolve, timer, ev }
async function requestApproval(msg, tab) {
  const id = 'roe-ap-' + Date.now();
  const ev = { label: msg.label, control: msg.control, url: msg.url, host: msg.host, why: msg.why, tabId: tab.id, title: tab.title };
  logActivity({ ...ev, type: 'approval-requested' });
  return new Promise((resolve) => {
    const finish = (approved, reason) => {
      const a = approvals.get(id);
      if (!a) return;
      approvals.delete(id); clearTimeout(a.timer); chrome.notifications.clear(id);
      logActivity({ ...ev, type: approved ? 'approval-granted' : 'approval-denied', reason });
      resolve({ approved, reason });
    };
    approvals.set(id, { finish, timer: setTimeout(() => finish(false, 'not approved in time'), (policy.timeoutSec || 90) * 1000) });
    chrome.notifications.create(id, {
      type: 'basic', iconUrl: 'icons/128.png', requireInteraction: true, priority: 2,
      title: 'Roe: approve an automated action?',
      message: '“' + msg.label + '” on ' + msg.host + (msg.why === 'automated' ? ' (tab under automated control)' : ' (scripted click)'),
      buttons: [{ title: 'Approve' }, { title: 'Deny' }]
    }, () => { if (chrome.runtime.lastError) finish(false, 'could not ask for approval'); });
  });
}
chrome.notifications.onButtonClicked.addListener((id, idx) => { const a = approvals.get(id); if (a) a.finish(idx === 0, idx === 0 ? '' : 'denied'); });
chrome.notifications.onClosed.addListener((id) => { const a = approvals.get(id); if (a) a.finish(false, 'dismissed'); });

// Downloads that land while an AI assistant is open or a tab is under automated control.
async function downloadContext(item, rec) {
  const tabs = await chrome.tabs.query({});
  const ai = tabs.map((t) => self.Roe.aiSiteFor(t.url || '')).filter(Boolean);
  if (!automation.size && !ai.length) return;
  const name = item.filename.split(/[\\/]/).pop();
  const flagged = rec ? rec.findings.filter((f) => f.level !== 'low').length : 0;
  logActivity({ type: 'download', label: name, url: item.finalUrl || item.url, flagged,
    why: automation.size ? 'automated' : 'ai-open', context: automation.size ? 'A tab was under automated control' : ai[0].label + ' was open' });
}

// The popup and dashboard ask for the current automation state.
chrome.runtime.onMessage.addListener((m, sender, sendResponse) => {
  if (m && m.type === 'roe:automation-tabs') { checkAutomation().then(() => sendResponse({ tabs: [...automation.keys()], supported: !!(chrome.debugger && chrome.debugger.getTargets) })); return true; }
  return false;
});
