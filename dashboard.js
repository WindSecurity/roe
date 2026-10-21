// Roe visibility dashboard. Page-derived text is only ever set with textContent.
(() => {
  const ORG = self.ROE_EDITION === 'org';
  const { CATS, REFS, EXPOSURE, AI_SITES } = Roe;
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined && text !== null) n.textContent = text; return n; };
  const svg = (tag, attrs) => { const n = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const k in attrs) n.setAttribute(k, attrs[k]); return n; };
  const DAY = 86400000;

  let data = { evidenceLog: [], accessLog: [], activityLog: [], policy: null, managed: null };
  let view = 'overview';
  const ui = { q: '', level: 'all', cat: 'all', time: 'all', open: new Set(), accessOnly: true, actType: 'all' };

  const VIEWS = [
    { id: 'overview', label: 'Overview', kicker: 'Visibility', title: 'What AI agents could see and do in this browser', lede: 'Attacks found in pages, the data and actions those pages exposed to agents, and what agents did.' },
    { id: 'evidence', label: 'Evidence', kicker: 'Prompt injection', title: 'Evidence log', lede: 'Every instruction aimed at an AI agent that Roe found, grouped by website, with the exact page and element it was found in.' },
    { id: 'access', label: 'Agent access', kicker: 'Exposure', title: 'What an agent could access', lede: 'Each page you open is context for any agent that can read it. This is the sensitive data and the actions each page put in reach.' },
    { id: 'activity', label: 'Agent activity', org: true, kicker: 'Organization', title: 'What agents did', lede: 'AI assistants opened, tabs under automated control, the pages they visited and the sensitive actions they attempted.' },
    { id: 'policy', label: 'Policy', org: true, kicker: 'Organization', title: 'Control', lede: 'Decide which AI sites are allowed, which domains agents may act on, and when a person must approve an agent’s action.' }
  ];

  // ---------- helpers ----------
  const ago = (t) => {
    const d = Date.now() - t;
    if (d < 60000) return 'just now';
    if (d < 3600000) return Math.floor(d / 60000) + ' min ago';
    if (d < DAY) return Math.floor(d / 3600000) + ' h ago';
    if (d < 7 * DAY) return Math.floor(d / DAY) + ' d ago';
    return new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
  };
  const stamp = (t) => new Date(t).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  const hostOf = (u) => { try { const x = new URL(u); return x.protocol === 'file:' ? 'local file' : x.hostname; } catch (e) { return u || ''; } };
  const pathOf = (u) => { try { const x = new URL(u); return (x.pathname + x.search).slice(0, 120) || '/'; } catch (e) { return u; } };
  const plural = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');
  const safeHref = (u) => /^(https?|file):/i.test(u || '') ? u : null;
  function ext(a, text, href) { const l = el('a', a, text); const h = safeHref(href); if (h) { l.href = h; l.target = '_blank'; l.rel = 'noreferrer noopener'; } return l; }
  function btn(text, cls, fn) { const b = el('button', 'btn' + (cls ? ' ' + cls : ''), text); if (fn) b.addEventListener('click', fn); return b; }
  function kpi(n, label, tone, sub) { const c = el('div', 'kpi' + (tone ? ' ' + tone : '')); c.append(el('b', '', String(n)), el('span', 'kl', label)); if (sub) c.append(el('span', 'ks', sub)); return c; }
  function panel(title, extra) { const p = el('section', 'panel'); if (title) { const h = el('div', 'ph'); h.append(el('h2', '', title)); if (extra) h.append(extra); p.append(h); } return p; }
  function empty(title, body) { const e = el('div', 'empty'); e.append(el('span', 'emark'), el('h3', '', title), el('p', '', body)); return e; }
  let tt = 0;
  function toast(msg) { const t = $('toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(tt); tt = setTimeout(() => t.classList.remove('show'), 2400); }
  function confirmDialog(title, body, ok) {
    return new Promise((resolve) => {
      const d = $('confirm');
      $('confirmTitle').textContent = title; $('confirmBody').textContent = body; $('confirmOk').textContent = ok;
      d.returnValue = '';
      d.addEventListener('close', () => resolve(d.returnValue === 'ok'), { once: true });
      d.showModal();
    });
  }
  function download(name, text, type) {
    const a = el('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  const liveFindings = (e) => e.findings || [];
  const policyNow = () => Roe.mergePolicy(data.policy, data.managed);

  // ---------- data ----------
  async function loadData() {
    const s = await chrome.storage.local.get({ evidenceLog: [], accessLog: [], activityLog: [], policy: null });
    let managed = null;
    try { if (chrome.storage.managed) managed = ((await chrome.storage.managed.get(null)) || {}).policy || null; } catch (e) { managed = null; }
    data = { ...s, managed };
    // older (0.5) entries: one row per scan. Fold them into one row per page.
    const seen = new Map();
    const merged = [];
    for (const e of data.evidenceLog) {
      if (!e.lastSeen) { e.lastSeen = e.timestamp; e.firstSeen = e.timestamp; e.host = hostOf(e.url); }
      const k = e.url + '|' + Math.floor(e.firstSeen / (6 * 3600000));
      const prev = seen.get(k);
      if (prev && !e.findings.some((f) => !prev.findings.find((x) => x.id === f.id))) { prev.firstSeen = Math.min(prev.firstSeen, e.firstSeen); continue; }
      seen.set(k, e); merged.push(e);
    }
    data.evidenceLog = merged;
  }
  let pend = 0;
  chrome.storage.onChanged.addListener((c, area) => {
    if (area === 'managed' || c.evidenceLog || c.accessLog || c.activityLog || c.policy) {
      clearTimeout(pend);
      pend = setTimeout(async () => {
        await loadData();
        // do not repaint under someone who is typing or choosing; the next change will catch up
        if (document.activeElement && /INPUT|SELECT|TEXTAREA/.test(document.activeElement.nodeName)) { nav(); return; }
        paint();
      }, 250);
    }
  });

  // ---------- chrome ----------
  function nav() {
    const n = $('nav');
    n.replaceChildren();
    const counts = {
      overview: null,
      evidence: data.evidenceLog.reduce((s, e) => s + liveFindings(e).length, 0),
      access: data.accessLog.filter(exposed).length,
      activity: ORG ? data.activityLog.length : null,
      policy: null
    };
    for (const v of VIEWS) {
      const b = el('button', 'nav-i' + (view === v.id ? ' on' : ''));
      b.append(el('span', '', v.label));
      if (v.org) b.append(el('span', 'org', 'Org'));
      if (counts[v.id]) b.append(el('span', 'n', String(counts[v.id])));
      b.setAttribute('aria-current', view === v.id ? 'page' : 'false');
      b.addEventListener('click', () => { location.hash = v.id; });
      n.append(b);
    }
    $('edition').textContent = ORG ? 'org' : 'open source';
    const f = $('sidefoot');
    f.replaceChildren(el('p', '', 'v' + chrome.runtime.getManifest().version + (ORG ? ' · Roe for Organizations' : ' · open source')),
      el('p', '', 'Everything here is stored on this device. Nothing is uploaded.'));
  }

  function paint() {
    const v = VIEWS.find((x) => x.id === view) || VIEWS[0];
    $('kicker').textContent = v.kicker + (v.org ? ' · Org edition' : '');
    $('title').textContent = v.title;
    $('lede').textContent = v.lede;
    $('topActions').replaceChildren();
    nav();
    const y = scrollY;
    const out = document.createDocumentFragment();
    if (v.org && !ORG) out.append(locked(v));
    else ({ overview, evidence, access, activity, policy })[v.id](out);
    $('view').replaceChildren(out);
    scrollTo(0, y);
    document.title = 'Roe · ' + v.label;
  }

  function locked(v) {
    const p = panel(null);
    p.classList.add('locked');
    p.append(el('span', 'lock-tag', 'Roe for Organizations'),
      el('h2', '', v.id === 'activity' ? 'See what AI agents actually did' : 'Control what AI agents may do'),
      el('p', '', v.id === 'activity'
        ? 'The org edition detects tabs under automated control, logs every page an agent visits and every sensitive action it attempts, and records AI assistant use across the browser. Security teams get visibility even where an assistant cannot be banned outright.'
        : 'The org edition applies policy pushed through Chrome enterprise management: allow, log or block AI sites, set per-domain rules for agent actions, and require a person to approve an agent’s sensitive action from a system notification the agent cannot reach.'));
    const ul = el('ul', 'ticks');
    (v.id === 'activity'
      ? ['Automated control start and end, per tab', 'Pages visited by an agent', 'Sensitive actions attempted, held, approved or denied', 'Downloads during an agent session', 'AI assistant sites opened']
      : ['AI site policy: allow, log or block', 'Domain rules: monitor, require approval, block', 'Out-of-band step-up approval', 'Managed policy from Chrome enterprise management']).forEach((t) => ul.append(el('li', '', t)));
    p.append(ul);
    return p;
  }

  // ---------- overview ----------
  function exposed(a) { return Object.keys(a.exposure || {}).length || Object.keys(a.sinkKinds || {}).length || (a.findings && (a.findings.high + a.findings.medium)); }

  function overview(out) {
    const ev = data.evidenceLog;
    const all = ev.flatMap((e) => liveFindings(e).map((f) => ({ ...f, e })));
    const high = all.filter((f) => f.level === 'high').length;
    const hidden = all.filter((f) => f.hidden).length;
    const removed = all.filter((f) => f.removed).length;
    const sites = new Set(ev.map((e) => e.host || hostOf(e.url)));
    const acc = data.accessLog;
    const withData = acc.filter((a) => Object.keys(a.exposure || {}).length).length;
    const withActs = acc.filter((a) => Object.keys(a.sinkKinds || {}).length).length;

    const k = el('div', 'kpis');
    k.append(
      kpi(all.length, 'Attacks found', all.length ? 'bad' : '', high + ' high risk'),
      kpi(hidden, 'Hidden from the user', hidden ? 'bad' : '', removed + ' removed'),
      kpi(sites.size, 'Websites affected', '', plural(ev.length, 'page')),
      kpi(withData, 'Pages exposing sensitive data', withData ? 'warn' : '', 'of ' + plural(acc.length, 'page') + ' seen'),
      kpi(withActs, 'Pages with agent-reachable actions', '', 'forms, send, pay, delete')
    );
    if (ORG) {
      const act = data.activityLog;
      const auto = act.filter((a) => a.type === 'automation-start').length;
      const held = act.filter((a) => a.type === 'approval-requested' || a.type === 'action-blocked').length;
      k.append(kpi(auto, 'Automated sessions', auto ? 'warn' : '', plural(act.filter((a) => a.type === 'agent-visit').length, 'page') + ' visited'),
        kpi(held, 'Agent actions held', held ? 'bad' : '', act.filter((a) => a.type === 'approval-granted').length + ' approved'));
    }
    out.append(k);

    const row = el('div', 'cols');
    const c = panel('Detections, last 14 days', legend());
    c.append(chart(all));
    row.append(c);

    const ts = panel('Top websites');
    const bySite = new Map();
    for (const f of all) { const h = f.e.host || hostOf(f.e.url); const s = bySite.get(h) || { h, n: 0, hi: 0, last: 0 }; s.n++; if (f.level === 'high') s.hi++; s.last = Math.max(s.last, f.e.lastSeen); bySite.set(h, s); }
    const top = [...bySite.values()].sort((a, b) => b.n - a.n).slice(0, 7);
    if (!top.length) ts.append(empty('No attacks logged yet', 'Pages with instructions aimed at AI agents show up here as you browse.'));
    else {
      const max = top[0].n;
      const ul = el('ul', 'bars');
      top.forEach((s) => {
        const li = el('li');
        const b = el('button', 'barrow');
        b.addEventListener('click', () => { ui.q = s.h; location.hash = 'evidence'; });
        const lab = el('span', 'bl'); lab.append(el('span', 'bh', s.h), el('span', 'bm', ago(s.last)));
        const track = el('span', 'track'); const fill = el('span', 'fill'); fill.style.width = Math.max(4, (s.n / max) * 100) + '%'; const hf = el('span', 'fill hi'); hf.style.width = (s.hi / max) * 100 + '%'; track.append(fill, hf);
        b.append(lab, track, el('span', 'bn', String(s.n)));
        li.append(b); ul.append(li);
      });
      ts.append(ul);
    }
    row.append(ts);
    out.append(row);

    const row2 = el('div', 'cols');
    const rec = panel('Latest evidence', btn('Open evidence log', 'ghost', () => { location.hash = 'evidence'; }));
    const latest = ev.slice(0, 6);
    if (!latest.length) rec.append(empty('Nothing yet', 'Roe logs every page where it finds a medium or high risk instruction aimed at an agent.'));
    else {
      const ul = el('ul', 'feed');
      latest.forEach((e) => {
        const f = liveFindings(e);
        const li = el('li', f.some((x) => x.level === 'high') ? 'high' : 'medium');
        const top = el('div', 'fl');
        top.append(el('span', 'dot'), el('span', 'ft', e.pageTitle || e.host), el('span', 'fm', ago(e.lastSeen)));
        li.append(top, el('div', 'fu', (e.host || hostOf(e.url)) + pathOf(e.url)), el('div', 'fs', plural(f.length, 'finding') + ' · ' + [...new Set(f.map((x) => CATS[x.cat] || x.cat))].slice(0, 3).join(', ')));
        ul.append(li);
      });
      rec.append(ul);
    }
    row2.append(rec);

    const sees = panel('What Roe can and cannot see');
    const ul = el('ul', 'ticks');
    ['Instructions in page text, hidden text, attributes, comments, titles, images, files and downloads',
      'Sensitive data and actions each page puts in front of an agent (counts and masked samples only)',
      ORG ? 'Tabs driven through a debugger session, the pages they visit and the sensitive actions they attempt' : 'In the org edition: tabs under automated control and the actions agents attempt',
      ORG ? 'AI assistant sites opened in a tab, and downloads during an agent session' : 'In the org edition: AI assistant sites opened, and policy and approvals'].forEach((t) => ul.append(el('li', '', t)));
    const no = el('ul', 'ticks no');
    ['What an assistant built into the browser actually read: it has no tab of its own, so Roe shows what each page exposed to it',
      'What an agent sends to its model provider'].forEach((t) => no.append(el('li', '', t)));
    sees.append(ul, no);
    row2.append(sees);
    out.append(row2);
  }

  function legend() {
    const l = el('div', 'legend');
    [['hi', 'High risk'], ['md', 'Medium risk']].forEach(([c, t]) => { const i = el('span', 'li'); i.append(el('span', 'sw ' + c), document.createTextNode(t)); l.append(i); });
    return l;
  }

  function chart(all) {
    const days = 14;
    const start = new Date(); start.setHours(0, 0, 0, 0);
    const t0 = start.getTime() - (days - 1) * DAY;
    const buckets = Array.from({ length: days }, (_, i) => ({ t: t0 + i * DAY, hi: 0, md: 0 }));
    for (const f of all) {
      const t = f.foundAt || f.e.firstSeen || f.e.timestamp;
      const i = Math.floor((t - t0) / DAY);
      if (i >= 0 && i < days) buckets[i][f.level === 'high' ? 'hi' : 'md']++;
    }
    const max = Math.max(4, ...buckets.map((b) => b.hi + b.md));
    const step = Math.ceil(max / 4);
    const top = step * 4;
    const W = 640, H = 210, L = 30, B = 24, T = 8, plotH = H - B - T, bw = (W - L) / days;
    const wrap = el('div', 'chart');
    const s = svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Detections per day for the last 14 days' });
    for (let g = 0; g <= 4; g++) {
      const y = T + plotH - (g * step / top) * plotH;
      s.append(svg('line', { x1: L, x2: W, y1: y, y2: y, class: g ? 'grid' : 'base' }));
      const tx = svg('text', { x: L - 6, y: y + 3, class: 'ax', 'text-anchor': 'end' }); tx.textContent = g * step; s.append(tx);
    }
    const tip = el('div', 'tip');
    buckets.forEach((b, i) => {
      const x = L + i * bw + bw * 0.2, w = bw * 0.6;
      const hH = (b.hi / top) * plotH, mH = (b.md / top) * plotH;
      const gEl = svg('g', { class: 'bar' });
      const baseY = T + plotH;
      if (b.md) gEl.append(svg('rect', { x, width: w, y: baseY - mH, height: Math.max(0, mH - (b.hi ? 1 : 0)), class: 'md', rx: b.hi ? 0 : 2 }));
      if (b.hi) gEl.append(svg('rect', { x, width: w, y: baseY - mH - hH, height: Math.max(0, hH - 1), class: 'hi', rx: 2 }));
      const hit = svg('rect', { x: L + i * bw, width: bw, y: T, height: plotH, class: 'hit' });
      const d = new Date(b.t);
      hit.addEventListener('mouseenter', () => {
        tip.replaceChildren(el('b', '', d.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' })), el('span', '', b.hi + ' high · ' + b.md + ' medium'));
        tip.style.left = ((L + i * bw + bw / 2) / W * 100) + '%';
        tip.classList.add('show');
        gEl.classList.add('on');
      });
      hit.addEventListener('mouseleave', () => { tip.classList.remove('show'); gEl.classList.remove('on'); });
      gEl.append(hit);
      s.append(gEl);
      if (i % 2 === (days - 1) % 2) { const tx = svg('text', { x: L + i * bw + bw / 2, y: H - 6, class: 'ax', 'text-anchor': 'middle' }); tx.textContent = i === days - 1 ? 'Today' : d.getDate() + ' ' + d.toLocaleDateString([], { month: 'short' }); s.append(tx); }
    });
    wrap.append(s, tip);
    return wrap;
  }

  // ---------- evidence ----------
  function filtered() {
    const q = ui.q.trim().toLowerCase();
    const range = { hour: 3600000, day: DAY, week: 7 * DAY, month: 30 * DAY }[ui.time];
    return data.evidenceLog.map((e) => {
      if (range && Date.now() - e.lastSeen > range) return null;
      const pageHit = !q || (e.url + ' ' + (e.pageTitle || '')).toLowerCase().includes(q);
      const fs = liveFindings(e).filter((f) => (ui.level === 'all' || f.level === ui.level) && (ui.cat === 'all' || f.cat === ui.cat || (f.cats || []).includes(ui.cat)) &&
        (pageHit || (f.snippet + ' ' + f.technique + ' ' + (f.where || '')).toLowerCase().includes(q)));
      return fs.length ? { ...e, findings: fs } : null;
    }).filter(Boolean);
  }

  function evidence(out) {
    const ta = $('topActions');
    ta.append(btn('Export JSON', '', () => { download('roe-evidence-' + new Date().toISOString().slice(0, 10) + '.json', JSON.stringify(filtered(), null, 2), 'application/json'); toast('Exported JSON'); }),
      btn('Export CSV', '', exportCSV),
      btn('Clear log', 'danger', async () => { if (await confirmDialog('Clear the evidence log?', 'Every logged page and finding on this device will be deleted. Export first if you need a record.', 'Clear log')) { await chrome.storage.local.set({ evidenceLog: [] }); toast('Evidence log cleared'); } }));

    const bar = el('div', 'toolbar');
    const q = el('input', 'search'); q.type = 'search'; q.placeholder = 'Search site, page, text or element'; q.value = ui.q;
    q.addEventListener('input', () => { ui.q = q.value; renderList(); });
    const sel = (key, opts) => { const s = el('select'); opts.forEach(([v, t]) => { const o = el('option', '', t); o.value = v; s.append(o); }); s.value = ui[key]; s.addEventListener('change', () => { ui[key] = s.value; renderList(); }); return s; };
    bar.append(q,
      sel('level', [['all', 'All levels'], ['high', 'High risk'], ['medium', 'Medium risk']]),
      sel('cat', [['all', 'All categories'], ...Object.entries(CATS)]),
      sel('time', [['all', 'All time'], ['hour', 'Last hour'], ['day', 'Last 24 hours'], ['week', 'Last 7 days'], ['month', 'Last 30 days']]));
    out.append(bar);
    const sum = el('p', 'summary');
    const list = el('div', 'sites');
    out.append(sum, list);

    function renderList() {
      const rows = filtered();
      const nf = rows.reduce((s, e) => s + e.findings.length, 0);
      const bySite = new Map();
      rows.forEach((e) => { const h = e.host || hostOf(e.url); if (!bySite.has(h)) bySite.set(h, []); bySite.get(h).push(e); });
      sum.textContent = plural(nf, 'finding') + ' on ' + plural(rows.length, 'page') + ' across ' + plural(bySite.size, 'website');
      list.replaceChildren();
      if (!rows.length) {
        list.append(data.evidenceLog.length ? empty('No evidence matches these filters', 'Clear the search or widen the time range.') : empty('No evidence logged yet', 'As you browse, Roe logs every page carrying a medium or high risk instruction aimed at an AI agent: what it said, how it was hidden, and exactly where on the page it sat.'));
        return;
      }
      for (const [h, pages] of bySite) {
        const all = pages.flatMap((p) => p.findings);
        const site = el('section', 'site');
        const head = el('div', 'site-h');
        const hi = all.filter((f) => f.level === 'high').length;
        head.append(el('span', 'sev ' + (hi ? 'high' : 'medium')), el('h3', '', h),
          el('span', 'meta', plural(pages.length, 'page') + ' · ' + plural(all.length, 'finding') + (hi ? ' · ' + hi + ' high' : '') + ' · last ' + ago(Math.max(...pages.map((p) => p.lastSeen)))));
        site.append(head);
        for (const p of pages) site.append(pageBlock(p));
        list.append(site);
      }
    }
    renderList();
  }

  function pageBlock(p) {
    const b = el('div', 'page');
    const h = el('div', 'page-h');
    const t = el('div', 'pt');
    t.append(el('div', 'ptitle', p.pageTitle || 'Untitled page'), ext('purl', pathOf(p.url), p.url));
    const m = el('div', 'pm');
    m.append(el('span', 'chip', (p.surface && p.surface.label) || 'Web page'));
    if (p.automated) m.append(el('span', 'chip red', 'Agent was driving this tab'));
    m.append(el('span', 'when', p.firstSeen !== p.lastSeen ? 'First ' + stamp(p.firstSeen) + ' · last ' + ago(p.lastSeen) : stamp(p.lastSeen)));
    h.append(t, m);
    b.append(h);
    const tbl = el('div', 'ftable');
    const hr = el('div', 'fr head');
    ['Risk', 'Category', 'How it reaches the agent', 'Where on the page', ''].forEach((x) => hr.append(el('span', '', x)));
    tbl.append(hr);
    p.findings.forEach((f) => tbl.append(findingRow(p, f)));
    b.append(tbl);
    return b;
  }

  function findingRow(p, f) {
    const key = p.id + '|' + f.id;
    const wrap = el('div', 'fwrap' + (ui.open.has(key) ? ' open' : '') + (f.removed ? ' removed' : ''));
    const r = el('button', 'fr');
    r.setAttribute('aria-expanded', String(ui.open.has(key)));
    const lv = el('span', 'lv ' + f.level, f.level === 'high' ? 'High' : 'Medium');
    r.append(lv, el('span', 'cat', CATS[f.cat] || f.cat),
      el('span', 'tech', (f.hidden ? 'Hidden · ' : 'Visible · ') + f.technique),
      el('span', 'where', (f.frameUrl ? 'iframe ' + hostOf(f.frameUrl) + ' › ' : '') + (f.where || '—')),
      el('span', 'state', f.removed ? 'Removed' : ''));
    const d = el('div', 'fd');
    r.addEventListener('click', () => {
      if (ui.open.has(key)) ui.open.delete(key); else ui.open.add(key);
      wrap.classList.toggle('open'); r.setAttribute('aria-expanded', String(ui.open.has(key)));
    });
    const said = el('div', 'said');
    said.append(el('span', 'lab', 'An agent reads'), el('blockquote', '', f.snippet));
    const facts = el('dl', 'facts');
    const fact = (k, v) => { const x = el('div'); x.append(el('dt', '', k)); const dd = el('dd'); typeof v === 'string' ? dd.textContent = v : dd.append(v); x.append(dd); facts.append(x); };
    fact('Page', ext('', p.url, p.url));
    if (f.frameUrl) fact('Inside frame', ext('', f.frameUrl, f.frameUrl));
    fact('Element', f.where || 'Not tied to one element');
    fact('Found', stamp(f.foundAt || p.firstSeen) + (f.removed ? ' · removed from the page' : ''));
    fact('Matched', (f.rules || []).map((x) => x.label || x.id).join('. ') || '—');
    const sinks = (f.sinks || []);
    if (sinks.length) { const w = el('div', 'chips'); sinks.forEach((s) => w.append(el('span', 'pill' + (s.present ? ' bad' : ''), s.label + (s.present ? ' (on this page)' : '')))); fact('Could be aimed at', w); }
    const refs = (f.refs || []).map((k) => REFS[k]).filter(Boolean);
    if (refs.length) { const w = el('div', 'refs'); refs.forEach((x) => w.append(ext('', x.name, x.url))); fact('Seen in', w); }
    const a = el('div', 'row');
    a.append(btn('Copy as JSON', 'small', async (e) => {
      await navigator.clipboard.writeText(JSON.stringify({ page: p.url, title: p.pageTitle, frame: f.frameUrl || null, element: f.where, found: new Date(f.foundAt || p.firstSeen).toISOString(), level: f.level, category: f.cat, technique: f.technique, hidden: f.hidden, removed: !!f.removed, rules: (f.rules || []).map((x) => x.id), text: f.snippet }, null, 2));
      e.target.textContent = 'Copied';
    }));
    if (safeHref(p.url)) a.append(btn('Open page', 'small ghost', () => chrome.tabs.create({ url: p.url })));
    d.append(said, facts, a);
    wrap.append(r, d);
    return wrap;
  }

  function exportCSV() {
    const rows = [['First seen', 'Last seen', 'Website', 'Page URL', 'Page title', 'Frame URL', 'Element', 'Level', 'Category', 'Technique', 'Hidden', 'Removed', 'Agent text', 'Rules']];
    filtered().forEach((e) => e.findings.forEach((f) => rows.push([new Date(f.foundAt || e.firstSeen).toISOString(), new Date(e.lastSeen).toISOString(), e.host || hostOf(e.url), e.url, e.pageTitle || '', f.frameUrl || '', f.where || '', f.level, CATS[f.cat] || f.cat, f.technique, f.hidden ? 'yes' : 'no', f.removed ? 'yes' : 'no', f.snippet, (f.rules || []).map((r) => r.label || r.id).join('; ')])));
    // Quote every cell, and neutralise cells a spreadsheet would treat as a formula.
    const cell = (v) => { let s = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
    download('roe-evidence-' + new Date().toISOString().slice(0, 10) + '.csv', rows.map((r) => r.map(cell).join(',')).join('\r\n'), 'text/csv');
    toast('Exported CSV');
  }

  // ---------- agent access ----------
  function access(out) {
    const acc = data.accessLog;
    const ta = $('topActions');
    ta.append(btn('Export JSON', '', () => download('roe-agent-access-' + new Date().toISOString().slice(0, 10) + '.json', JSON.stringify(acc.map(({ sig, ...x }) => x), null, 2), 'application/json')),
      btn('Clear', 'danger', async () => { if (await confirmDialog('Clear the agent access log?', 'The record of what each page exposed to agents will be deleted from this device.', 'Clear')) await chrome.storage.local.set({ accessLog: [] }); }));

    const dataPages = acc.filter((a) => Object.keys(a.exposure || {}).length);
    const types = {};
    dataPages.forEach((a) => Object.entries(a.exposure).forEach(([k, v]) => { types[k] = (types[k] || 0) + v.n; }));
    const k = el('div', 'kpis');
    k.append(kpi(acc.length, 'Pages an agent could read', '', plural(new Set(acc.map((a) => a.host)).size, 'website')),
      kpi(dataPages.length, 'Exposed sensitive data', dataPages.length ? 'warn' : '', Object.keys(types).length ? Object.entries(types).sort((a, b) => b[1] - a[1]).slice(0, 2).map(([t, n]) => (EXPOSURE[t] || t).toLowerCase() + ' ' + n).join(', ') : 'none found'),
      kpi(acc.filter((a) => Object.keys(a.sinkKinds || {}).length).length, 'Put actions in reach', '', 'send, pay, delete, sign in'),
      kpi(acc.filter((a) => a.findings && a.findings.high + a.findings.medium).length, 'Also carried attacks', acc.some((a) => a.findings && a.findings.high) ? 'bad' : '', 'injection and data on one page'),
      kpi(acc.filter((a) => ['email', 'chat', 'tickets', 'github', 'raw', 'social', 'docs'].includes(a.surface && a.surface.id)).length, 'Untrusted content sources', '', 'email, chat, tickets, code'));
    if (ORG) k.append(kpi(acc.filter((a) => a.automated).length, 'Visited by an agent', acc.some((a) => a.automated) ? 'bad' : '', 'under automated control'));
    out.append(k);

    if (Object.keys(types).length) {
      const p = panel('Sensitive data within an agent’s reach');
      const ul = el('ul', 'bars');
      const max = Math.max(...Object.values(types));
      Object.entries(types).sort((a, b) => b[1] - a[1]).forEach(([t, n]) => {
        const li = el('li'); const r = el('div', 'barrow static');
        const lab = el('span', 'bl'); lab.append(el('span', 'bh', EXPOSURE[t] || t), el('span', 'bm', plural(dataPages.filter((a) => a.exposure[t]).length, 'page')));
        const track = el('span', 'track'); const f = el('span', 'fill warn'); f.style.width = Math.max(4, n / max * 100) + '%'; track.append(f);
        r.append(lab, track, el('span', 'bn', String(n))); li.append(r); ul.append(li);
      });
      p.append(ul);
      out.append(p);
    }

    const bar = el('div', 'toolbar');
    const q = el('input', 'search'); q.type = 'search'; q.placeholder = 'Search site or page'; q.value = ui.q;
    const only = el('label', 'check'); const cb = el('input'); cb.type = 'checkbox'; cb.checked = ui.accessOnly; only.append(cb, document.createTextNode('Only pages that exposed something'));
    bar.append(q, only);
    out.append(bar);
    const tbl = panel(null);
    tbl.classList.add('flush');
    out.append(tbl);
    const draw = () => {
      const qq = ui.q.trim().toLowerCase();
      const rows = acc.filter((a) => (!ui.accessOnly || exposed(a) || a.automated) && (!qq || (a.url + ' ' + a.title).toLowerCase().includes(qq)));
      tbl.replaceChildren();
      if (!rows.length) { tbl.append(empty(acc.length ? 'Nothing matches' : 'No pages recorded yet', acc.length ? 'Turn off the filter to see every page.' : 'As you browse, Roe records what each page exposes to an agent that reads it.')); return; }
      const t = el('div', 'atable');
      const hr = el('div', 'ar head');
      ['Page', 'Sensitive data', 'Actions in reach', 'Signals', 'Seen'].forEach((x) => hr.append(el('span', '', x)));
      t.append(hr);
      rows.slice(0, 250).forEach((a) => {
        const r = el('div', 'ar' + (a.automated ? ' auto' : ''));
        const pg = el('div', 'apage'); pg.append(el('span', 'ah', a.host), ext('purl', a.title || pathOf(a.url), a.url), el('span', 'chip', a.surface ? a.surface.label : 'Web page'));
        const ex = el('div', 'chips');
        const ek = Object.entries(a.exposure || {});
        if (!ek.length) ex.append(el('span', 'none', '—'));
        ek.forEach(([k2, v]) => { const pill = el('span', 'pill warn', (EXPOSURE[k2] || k2) + ' ' + v.n); if (v.samples && v.samples.length) pill.title = v.samples.join('  '); ex.append(pill); });
        const sk = el('div', 'chips');
        if (!(a.sinks || []).length) sk.append(el('span', 'none', '—'));
        (a.sinks || []).slice(0, 4).forEach((s) => sk.append(el('span', 'pill', s)));
        if ((a.sinks || []).length > 4) sk.append(el('span', 'none', '+' + (a.sinks.length - 4)));
        const sg = el('div', 'chips');
        if (a.findings && a.findings.high + a.findings.medium) sg.append(el('span', 'pill bad', plural(a.findings.high + a.findings.medium, 'attack')));
        if (a.automated) sg.append(el('span', 'pill bad', 'Agent visited'));
        if (a.aiSite) sg.append(el('span', 'pill', 'AI site: ' + a.aiSite));
        if (!sg.children.length) sg.append(el('span', 'none', '—'));
        const seen = el('div', 'aseen'); seen.append(el('span', '', ago(a.lastSeen)), el('span', 'none', plural(a.visits || 1, 'visit')));
        r.append(pg, ex, sk, sg, seen);
        t.append(r);
      });
      tbl.append(t);
      if (rows.length > 250) tbl.append(el('p', 'summary pad', 'Showing the latest 250 of ' + rows.length + ' pages.'));
    };
    q.addEventListener('input', () => { ui.q = q.value; draw(); });
    cb.addEventListener('change', () => { ui.accessOnly = cb.checked; draw(); });
    draw();
    out.append(el('p', 'note', 'Values are never stored. Roe keeps the type, a count and a masked sample (for example “ghp_••••”), so this log is safe to export.'));
  }

  // ---------- agent activity (org) ----------
  const ACT = {
    'ai-open': ['AI assistant opened', ''],
    'ai-blocked': ['AI site blocked by policy', 'bad'],
    'automation-start': ['Automated control started', 'bad'],
    'automation-end': ['Automated control ended', ''],
    'agent-visit': ['Agent visited a page', 'warn'],
    'agent-action': ['Agent action allowed', 'warn'],
    'approval-requested': ['Approval requested', 'warn'],
    'approval-granted': ['Approved by a person', 'ok'],
    'approval-denied': ['Stopped', 'bad'],
    'action-blocked': ['Agent action blocked', 'bad'],
    download: ['Download during agent session', 'warn']
  };
  async function activity(out) {
    const act = data.activityLog;
    const ta = $('topActions');
    ta.append(btn('Export JSON', '', () => download('roe-agent-activity-' + new Date().toISOString().slice(0, 10) + '.json', JSON.stringify(act, null, 2), 'application/json')),
      btn('Clear', 'danger', async () => { if (await confirmDialog('Clear agent activity?', 'The activity record on this device will be deleted.', 'Clear')) await chrome.storage.local.set({ activityLog: [] }); }));

    const status = panel('Automated control right now');
    const st = el('div', 'status');
    status.append(st);
    out.append(status);
    chrome.runtime.sendMessage({ type: 'roe:automation-tabs' }).then(async (r) => {
      st.replaceChildren();
      if (!r || !r.supported) { st.append(el('p', 'none', 'Automation detection is not available in this build.')); return; }
      if (!r.tabs.length) { st.append(el('span', 'state-ok', 'No tab is under automated control'), el('p', 'none', 'Roe checks every 30 seconds and whenever you switch tabs. An agent extension, a CDP automation tool or an open DevTools window all count as a debugger session.')); return; }
      for (const id of r.tabs) {
        const t = await chrome.tabs.get(id).catch(() => null);
        const real = t && safeHref(t.url);
        const row = el('div', 'live');
        row.append(el('span', 'pulse'), el('span', 'lt', real ? t.title || t.url : 'Blank or browser tab'), el('span', 'lu', real ? hostOf(t.url) : 'tab ' + id));
        st.append(row);
      }
    }).catch(() => {});

    const counts = {};
    act.forEach((a) => { counts[a.type] = (counts[a.type] || 0) + 1; });
    const k = el('div', 'kpis');
    k.append(kpi((counts['ai-open'] || 0) + (counts['ai-blocked'] || 0), 'AI assistant visits', '', (counts['ai-blocked'] || 0) + ' blocked'),
      kpi(counts['automation-start'] || 0, 'Automated sessions', counts['automation-start'] ? 'warn' : '', plural(counts['agent-visit'] || 0, 'page') + ' visited'),
      kpi((counts['agent-action'] || 0) + (counts['approval-requested'] || 0) + (counts['action-blocked'] || 0), 'Sensitive actions attempted', '', (counts['approval-granted'] || 0) + ' approved'),
      kpi((counts['approval-denied'] || 0) + (counts['action-blocked'] || 0), 'Actions stopped', (counts['approval-denied'] || counts['action-blocked']) ? 'bad' : '', 'denied, timed out or blocked'),
      kpi(counts.download || 0, 'Downloads in agent sessions', counts.download ? 'warn' : '', act.filter((a) => a.type === 'download' && a.flagged).length + ' flagged'));
    out.append(k);

    const bar = el('div', 'toolbar');
    const s = el('select');
    [['all', 'All activity'], ...Object.entries(ACT).map(([k2, v]) => [k2, v[0]])].forEach(([v, t]) => { const o = el('option', '', t + (v !== 'all' && counts[v] ? ' (' + counts[v] + ')' : '')); o.value = v; s.append(o); });
    s.value = ui.actType;
    bar.append(s);
    out.append(bar);
    const p = panel(null); p.classList.add('flush');
    out.append(p);
    const draw = () => {
      const rows = act.filter((a) => ui.actType === 'all' || a.type === ui.actType);
      p.replaceChildren();
      if (!rows.length) { p.append(empty('No agent activity yet', 'Open an AI assistant, or let an agent drive a tab, and every step shows up here.')); return; }
      const ul = el('ol', 'tl');
      let lastDay = '';
      rows.slice(0, 400).forEach((a) => {
        const day = new Date(a.at).toLocaleDateString([], { weekday: 'long', month: 'short', day: 'numeric' });
        if (day !== lastDay) { ul.append(el('li', 'day', day)); lastDay = day; }
        const [label, tone] = ACT[a.type] || [a.type, ''];
        const li = el('li', 'ev ' + tone);
        const tm = el('span', 'tm', new Date(a.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
        const body = el('div', 'eb');
        const h = el('div', 'eh'); h.append(el('span', 'et', label));
        if (a.label && !['agent-visit', 'automation-start', 'automation-end'].includes(a.type)) h.append(el('span', 'el', '“' + a.label + '”'));
        if (a.control) h.append(el('span', 'chip', a.control));
        if (a.why) h.append(el('span', 'chip' + (a.why === 'automated' ? ' red' : ''), a.why === 'automated' ? 'Tab under automated control' : a.why === 'scripted' ? 'Scripted click' : a.context || a.why));
        if (a.flagged) h.append(el('span', 'chip red', plural(a.flagged, 'attack') + ' in file'));
        body.append(h);
        if (safeHref(a.url)) body.append(ext('eu', (a.host || hostOf(a.url)) + pathOf(a.url), a.url));
        if (a.reason) body.append(el('div', 'none', 'Reason: ' + a.reason));
        if (a.duration) body.append(el('div', 'none', 'Lasted ' + Math.max(1, Math.round(a.duration / 60000)) + ' min'));
        li.append(tm, el('span', 'node'), body);
        ul.append(li);
      });
      p.append(ul);
    };
    s.addEventListener('change', () => { ui.actType = s.value; draw(); });
    draw();
  }

  // ---------- policy (org) ----------
  function policy(out) {
    const pol = policyNow();
    const managed = !!data.managed;
    const save = async (patch) => {
      const next = { ...Roe.DEFAULT_POLICY, ...(data.policy || {}), ...patch };
      data.policy = next;
      await chrome.storage.local.set({ policy: next });
      toast('Policy saved. It applies to open tabs at once.');
    };
    if (managed) {
      const m = el('div', 'banner');
      m.append(el('b', '', 'Managed by your organization.'), document.createTextNode(' Settings pushed through Chrome enterprise management override the ones below and cannot be changed here.'));
      out.append(m);
    }

    // AI sites
    const ai = panel('AI assistant sites');
    ai.append(el('p', 'pdesc', 'Allow a site, log every visit to it, or block it outright. Blocking works on web pages only; an assistant built into the browser itself is controlled through the browser’s own enterprise policies, and Roe still shows what pages exposed to it.'));
    const grid = el('div', 'ptable');
    AI_SITES.forEach((s) => {
      const r = el('div', 'prow');
      r.append(el('span', 'pn', s.label), el('span', 'pu', s.hosts ? s.hosts[0] : 'google.com/search?udm=50'));
      r.append(segmented([['allow', 'Allow'], ['log', 'Log'], ['block', 'Block']], (pol.ai || {})[s.id] || 'log', managed && data.managed.ai && data.managed.ai[s.id], (v) => save({ ai: { ...((data.policy || {}).ai || {}), [s.id]: v } })));
      grid.append(r);
    });
    ai.append(grid);
    out.append(ai);

    // domain rules
    const dom = panel('Domain rules for agent actions');
    dom.append(el('p', 'pdesc', 'What happens when an agent (a scripted click or a tab under automated control) tries a sensitive action on a site: sending, paying, deleting, granting access or submitting credentials. People clicking for themselves are never affected.'));
    const modes = [['monitor', 'Monitor'], ['approve', 'Require approval'], ['block', 'Block']];
    const dl = el('div', 'ptable');
    (pol.domains || []).forEach((d, i) => {
      const r = el('div', 'prow');
      r.append(el('span', 'pn mono', d.host), el('span', 'pu', d.host.includes('.') ? 'and its subdomains' : ''));
      r.append(segmented(modes, d.mode, managed && data.managed.domains, (v) => { const list = [...(data.policy?.domains || [])]; list[i] = { ...list[i], mode: v }; save({ domains: list }); }));
      if (!managed || !data.managed.domains) r.append(btn('Remove', 'small ghost', () => save({ domains: (data.policy?.domains || []).filter((_, j) => j !== i) }).then(paint)));
      dl.append(r);
    });
    if (!(pol.domains || []).length) dl.append(el('p', 'none pad', 'No domain rules. Every site is monitored.'));
    dom.append(dl);
    if (!managed || !data.managed.domains) {
      const add = el('form', 'addrow');
      const inp = el('input', 'search'); inp.placeholder = 'Domain, for example mail.google.com or bank.com'; inp.required = true;
      const ms = el('select'); modes.forEach(([v, t]) => { const o = el('option', '', t); o.value = v; ms.append(o); }); ms.value = 'approve';
      add.append(inp, ms, btn('Add rule', 'primary'));
      add.addEventListener('submit', async (e) => {
        e.preventDefault();
        let h = inp.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/:?#].*$/, '').replace(/^\*\./, '');
        if (!/^[a-z0-9.-]+\.[a-z]{2,}$|^localhost$/.test(h)) { toast('Enter a domain like example.com'); return; }
        const list = (data.policy?.domains || []).filter((d) => d.host !== h);
        await save({ domains: [...list, { host: h, mode: ms.value }] });
        paint();
      });
      dom.append(add);
    }
    out.append(dom);

    // step-up
    const su = panel('Step-up approval');
    su.append(el('p', 'pdesc', 'When an action is held, Roe asks for approval in a system notification rather than on the page, so an agent that drives the page by script or by screenshot cannot approve itself. Like a second factor, the person has to confirm on a separate channel.'));
    const sw = (key, title, desc) => {
      const r = el('label', 'switch');
      const i = el('input'); i.type = 'checkbox'; i.checked = !!pol[key]; i.disabled = managed && key in data.managed;
      i.addEventListener('change', () => save({ [key]: i.checked }));
      const t = el('span', 'st'); t.append(el('b', '', title), el('span', '', desc));
      r.append(i, el('span', 'knob'), t);
      return r;
    };
    su.append(sw('holdAutomated', 'Hold sensitive actions in tabs under automated control', 'Any send, pay, delete or sign-in action in a tab an agent is driving waits for approval.'),
      sw('holdScripted', 'Hold scripted clicks on sensitive controls everywhere', 'Catches agents that click through page scripts instead of a debugger. Sites that click their own buttons from script will also ask.'));
    const tr = el('div', 'prow');
    tr.append(el('span', 'pn', 'Approval expires after'));
    const tsel = el('select'); [[30, '30 seconds'], [60, '1 minute'], [90, '90 seconds'], [180, '3 minutes']].forEach(([v, t]) => { const o = el('option', '', t); o.value = v; tsel.append(o); });
    tsel.value = String(pol.timeoutSec || 90); tsel.disabled = managed && 'timeoutSec' in data.managed;
    tsel.addEventListener('change', () => save({ timeoutSec: Number(tsel.value) }));
    tr.append(el('span', 'pu', 'then the action is stopped'), tsel);
    su.append(tr);
    out.append(su);

    // deployment
    const dep = panel('Deploy to your organization');
    dep.append(el('p', 'pdesc', 'Push the same settings to every managed browser with Chrome enterprise policy for extensions (3rd-party managed storage). The schema ships with the extension as managed_schema.json. A pushed policy looks like this:'));
    const pre = el('pre', 'code');
    pre.textContent = JSON.stringify({ policy: { ai: { gemini: 'block', aimode: 'log', chatgpt: 'log' }, domains: [{ host: 'mail.google.com', mode: 'approve' }, { host: 'bank.example.com', mode: 'block' }], holdAutomated: true, holdScripted: false, timeoutSec: 90 } }, null, 2);
    dep.append(pre, btn('Copy current policy as JSON', '', async () => { const { managed: _m, ...p } = policyNow(); await navigator.clipboard.writeText(JSON.stringify({ policy: p }, null, 2)); toast('Copied'); }));
    out.append(dep);
  }

  function segmented(opts, value, locked, onChange) {
    const g = el('div', 'seg');
    g.setAttribute('role', 'group');
    opts.forEach(([v, t]) => {
      const b = el('button', v === 'block' ? 'blk' : '', t);
      b.type = 'button';
      b.setAttribute('aria-pressed', String(v === value));
      b.disabled = !!locked;
      b.addEventListener('click', () => { if (b.getAttribute('aria-pressed') === 'true') return; g.querySelectorAll('button').forEach((x) => x.setAttribute('aria-pressed', String(x === b))); onChange(v); });
      g.append(b);
    });
    return g;
  }

  // ---------- boot ----------
  const route = () => { const h = location.hash.slice(1); view = VIEWS.some((v) => v.id === h) ? h : 'overview'; scrollTo(0, 0); paint(); };
  window.addEventListener('hashchange', route);
  loadData().then(route);
})();
