// Roe content script: scans the page for text aimed at AI agents, maps it to possible sinks,
// warns (outline / popup) and optionally removes hidden text. It never sends page content anywhere.
(() => {
  if (!self.Roe || !self.Roe.surface || !self.Roe.analyze || !self.Roe.pageSinks || !self.Roe.exposure || !document.documentElement || window.__roeLoaded) return;
  window.__roeLoaded = true;

  const { analyze, behavior, normName, linkFileName, rate, intentSinks, pageSinks, linkSinks, stripInvisible, surface, githubTarget, rawMarkdownHidden, REFS } = Roe;
  const MAX_NODES = 30000;
  const SKIP = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'TITLE']);   // the tab title is checked on its own
  const ATTR_SELECTOR = '[alt],[title],[aria-label],[aria-description],[placeholder],input[type=hidden][value],meta[content]';
  const ATTRS = ['alt', 'title', 'aria-label', 'aria-description', 'placeholder', 'value', 'content'];
  const FLAG = '#B00B3A';
  const SURFACE = surface(location);
  const BLOCK = 'p,div,li,td,th,tr,section,article,blockquote,header,footer,main,pre,h1,h2,h3,h4,h5,h6,dd,dt,body';
  const UNTRUSTED = ['email', 'chat', 'tickets', 'github', 'raw', 'social'].includes(SURFACE.id);

  let settings = { mode: 'warn', allow: [], ghRaw: true, scanImages: true };
  let imgFindings = [];         // findings from images on the page (persist across rescans)
  const imgEls = new Map();     // finding id -> <img>
  const imgSeen = new Set();
  let imgBusy = false, imgCount = 0;
  let remote = [];              // findings from GitHub raw Markdown (persist across rescans)
  let rawStatus = '';
  let rawDone = '';
  let current = new Map();      // finding id -> finding from the latest scan
  let refs = new Map();          // finding id -> { node, el, attr, stripOnly }
  const history = new Map();     // sanitized findings stay listed after the text is gone
  const outlined = new Map();    // element -> [outline, outlineOffset] before Roe touched it
  const revealed = new Map();    // element -> original style attribute
  let timer = 0;
  let lastSinks = [], lastExposure = {};

  // ---------- helpers ----------
  const hash = (s) => { let h = 5381; for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0; return 'f' + (h >>> 0).toString(36); };

  function pathOf(el) {
    const parts = [];
    for (let e = el, d = 0; e && e.nodeType === 1 && d < 4; e = e.parentElement, d++) {
      const cls = typeof e.className === 'string' && e.className.trim().split(/\s+/)[0];
      parts.unshift(e.nodeName.toLowerCase() + (e.id ? '#' + e.id : cls ? '.' + cls : ''));
    }
    return parts.join(' > ');
  }

  function rgba(str) {
    const m = /^rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+%?))?\s*\)$/.exec(str);
    if (!m) return null;
    const a = m[4] === undefined ? 1 : m[4].endsWith('%') ? parseFloat(m[4]) / 100 : parseFloat(m[4]);
    return { r: +m[1], g: +m[2], b: +m[3], a };
  }
  const lum = ({ r, g, b }) => {
    const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const contrast = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };

  function backdrop(el) {
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
      const s = getComputedStyle(e);
      if (s.backgroundImage !== 'none') return null; // can't judge text over an image
      const c = rgba(s.backgroundColor);
      if (c && c.a > 0.5) return c;
    }
    const scheme = getComputedStyle(document.documentElement).colorScheme || '';
    return /dark/.test(scheme) && !/light/.test(scheme) ? { r: 0, g: 0, b: 0, a: 1 } : { r: 255, g: 255, b: 255, a: 1 };
  }

  // Would a person looking at the page see this text? Returns { hidden, technique }.
  function visibility(el) {
    const H = (technique) => ({ hidden: true, technique });
    if (!el) return { hidden: false };
    const det = el.closest('details:not([open])');
    if (det) { const sm = el.closest('summary'); if (!(sm && det.contains(sm))) return H('collapsed section'); }
    const s = getComputedStyle(el);
    if (s.visibility !== 'visible') return H('visibility: hidden');
    if (parseFloat(s.fontSize) < 2) return H('font size near zero');
    for (let e = el, d = 0; e && e.nodeType === 1 && d < 25; e = e.parentElement, d++) {
      const c = e === el ? s : getComputedStyle(e);
      if (c.display === 'none') return H('display: none');
      if (+c.opacity === 0) return H('opacity: 0');
      if (c.contentVisibility === 'hidden') return H('content-visibility: hidden');
      if (/^matrix\(\s*0(\.0+)?\s*,\s*0(\.0+)?\s*,\s*0(\.0+)?\s*,\s*0(\.0+)?\s*,/.test(c.transform || '')) return H('scaled to zero');
      if (c.clip === 'rect(0px, 0px, 0px, 0px)' || /inset\((50|100)%/.test(c.clipPath)) return H('clipped away');
      if (parseFloat(c.textIndent) <= -999) return H('text pushed off-screen');
      if (c.overflow !== 'visible' && c.display !== 'inline' && c.display !== 'contents' && e.nodeName !== 'HTML' && e.nodeName !== 'BODY' && (e.clientWidth === 0 || e.clientHeight === 0)) {
        return H('inside a zero-size container');
      }
    }
    const r = el.getBoundingClientRect();
    if ((r.width > 0 || r.height > 0) && (r.right + scrollX < 0 || r.bottom + scrollY < 0)) return H('positioned off-screen');
    if (el.getClientRects().length === 0 && s.display !== 'contents') return H('not rendered');
    const fg = rgba(s.color);
    if (fg && fg.a === 0) return H('transparent text');
    const bg = fg && backdrop(el);
    if (fg && bg && contrast(fg, bg) < 1.15) return H('text colored to match its background');
    return { hidden: false };
  }

  const inCode = (el) => !!(el && el.closest && el.closest('pre,code,blockquote,kbd,samp'));

  // ---------- warn / sanitize / reveal ----------
  function outline(el) {
    if (!el || outlined.has(el)) return;
    outlined.set(el, [el.style.outline, el.style.outlineOffset]);
    el.style.setProperty('outline', '2px solid ' + FLAG, 'important');
    el.style.setProperty('outline-offset', '2px', 'important');
  }
  function clearOutlines() {
    for (const [el, [o, off]] of outlined) { el.style.outline = o; el.style.outlineOffset = off; }
    outlined.clear();
  }

  function sanitize(f, ref) {
    try {
      if (f.kind === 'comment') ref.node.remove();
      else if (f.kind === 'text') ref.node.nodeValue = ref.stripOnly ? stripInvisible(ref.node.nodeValue) : '';
      else if (f.kind === 'text-group') ref.nodes.forEach((n) => { n.nodeValue = ''; });
      else if (f.kind === 'attribute' && ref.el) ref.el.removeAttribute(ref.attr);
      else if (f.kind === 'template' && ref.el) ref.el.content.textContent = '';
      else if (f.kind === 'image' && ref.el) ref.el.remove();
      else if (f.kind === 'title') document.title = location.hostname || 'page';
      else return false;
      f.sanitized = true;
      f.canReveal = false;
      f.removable = false;
      history.set(f.id, f);
      return true;
    } catch (e) { return false; /* page may have detached the node */ }
  }

  const SHOW = 'display:block!important;visibility:visible!important;opacity:1!important;position:static!important;clip:auto!important;clip-path:none!important;height:auto!important;width:auto!important;max-height:none!important;overflow:visible!important;content-visibility:visible!important;transform:none!important;text-indent:0!important;';
  const MARK = 'font-size:15px!important;color:#fff!important;background:' + FLAG + '!important;padding:6px 8px!important;margin:6px 0!important;border-radius:4px!important;';
  const showEl = (e, mark) => {
    if (!revealed.has(e)) revealed.set(e, e.getAttribute('style'));
    e.style.cssText += ';' + SHOW + (mark ? MARK : '');
  };
  function hideAll() {
    for (const [e, s] of revealed) { if (s === null) e.removeAttribute('style'); else e.setAttribute('style', s); }
    revealed.clear();
  }
  const openDetails = (el) => { for (let d = el.closest('details'); d; d = d.parentElement && d.parentElement.closest('details')) d.open = true; };
  function reveal(id) {
    const ref = refs.get(id);
    if (!ref || !ref.el || !ref.el.isConnected) return false;
    if (revealed.has(ref.el)) return true;
    hideAll();
    openDetails(ref.el);
    showEl(ref.el, true);
    for (let e = ref.el.parentElement, d = 0; e && e !== document.body && d < 10; e = e.parentElement, d++) {
      const c = getComputedStyle(e);
      if (c.display === 'none' || +c.opacity === 0 || c.visibility !== 'visible') showEl(e, false);
    }
    return true;
  }
  function toggleReveal(id) {
    const ref = refs.get(id);
    if (!ref || !ref.el || !ref.el.isConnected) return null;
    if (revealed.has(ref.el)) { hideAll(); return false; }
    reveal(id);
    ref.el.scrollIntoView({ block: 'center' });
    return true;
  }

  // ---------- highlight: scroll to a finding and mark exactly where it is ----------
  // Drawn as an overlay in a shadow root (no page text is changed, and page CSS cannot touch it).
  let hl = null;
  function clearHighlight() {
    if (!hl) return;
    hl.host.remove();
    window.removeEventListener('resize', hl.paint);
    document.removeEventListener('keydown', hl.onKey, true);
    hl = null;
  }
  function draw(getRects, label, fill) {
    clearHighlight();
    const host = document.createElement('div');
    host.id = 'roe-highlight-host';
    host.style.cssText = 'position:absolute;left:0;top:0;width:0;height:0;z-index:2147483647;pointer-events:none;';
    const root = host.attachShadow({ mode: 'open' });
    const paint = () => {
      root.replaceChildren();
      const rects = getRects().slice(0, 40);
      if (!rects.length) return;
      const sx = window.scrollX, sy = window.scrollY;
      for (const r of rects) {
        const box = document.createElement('div');
        box.style.cssText = 'position:absolute;box-sizing:border-box;border-radius:3px;pointer-events:none;outline:2px solid ' + FLAG + ';' + (fill ? 'background:rgba(255,213,74,.5);' : '') +
          'left:' + (r.left + sx - 3) + 'px;top:' + (r.top + sy - 2) + 'px;width:' + (r.width + 6) + 'px;height:' + (r.height + 4) + 'px;';
        root.append(box);
      }
      const r0 = rects[0], tag = document.createElement('div');
      tag.textContent = label + '   \u2715';
      const above = r0.top > 34;
      tag.style.cssText = 'position:absolute;pointer-events:auto;cursor:pointer;white-space:nowrap;background:' + FLAG + ';color:#fff;font:600 12px/1 system-ui,sans-serif;padding:6px 9px;border-radius:4px;box-shadow:0 2px 8px rgba(0,0,0,.35);' +
        'left:' + Math.max(4, r0.left + sx - 3) + 'px;top:' + (above ? r0.top + sy - 34 : r0.bottom + sy + 6) + 'px;';
      tag.title = 'Click or press Esc to clear';
      tag.addEventListener('click', clearHighlight);
      root.append(tag);
    };
    document.documentElement.append(host);
    paint();
    const onKey = (e) => { if (e.key === 'Escape') clearHighlight(); };
    window.addEventListener('resize', paint);
    document.addEventListener('keydown', onKey, true);
    hl = { host, paint, onKey };
    host.dataset.boxes = String(root.children.length ? root.children.length - 1 : 0);
    observer.takeRecords();
  }

  function rangeFor(f, ref) {
    try {
      if (f.kind === 'text' && ref.node && ref.node.isConnected) {
        const r = document.createRange(), v = ref.node.nodeValue;
        const probe = f.snippet.replace(/^Decoded: /, '').slice(0, 28).toLowerCase();
        const i = probe.length >= 10 ? v.toLowerCase().indexOf(probe) : -1;
        if (i >= 0) { r.setStart(ref.node, i); r.setEnd(ref.node, Math.min(v.length, i + Math.max(f.snippet.length, 40))); } else r.selectNodeContents(ref.node);
        return r;
      }
      if (f.kind === 'text-group' && ref.nodes) {
        const live = ref.nodes.filter((n) => n.isConnected);
        if (!live.length) return null;
        const r = document.createRange(), last = live[live.length - 1];
        r.setStart(live[0], 0); r.setEnd(last, last.nodeValue.length);
        return r;
      }
    } catch (e) { /* node changed under us */ }
    return null;
  }

  function highlight(id) {
    const f = current.get(id) || history.get(id), ref = refs.get(id);
    if (!f || (!ref && f.kind !== 'title')) return { ok: false, reason: 'No longer on the page.' };
    if (f.sanitized) return { ok: false, reason: 'Already removed from the page.' };
    if (f.kind === 'title') return { ok: false, reason: 'It is in the tab title, not in the page.' };
    if (f.kind === 'remote') return { ok: false, reason: 'It is in the raw Markdown on GitHub, not the rendered page.' };
    const textual = f.kind === 'text' || f.kind === 'text-group';
    const revealedNow = f.hidden && textual ? reveal(id) : false;
    const range = textual ? rangeFor(f, ref) : null;
    let el = ref.el && ref.el.isConnected ? ref.el : range && range.startContainer.parentElement;
    if (!el) return { ok: false, reason: 'No longer on the page.' };
    el.scrollIntoView({ block: 'center', inline: 'nearest' });
    let target = el;
    if (!textual) { while (target && target !== document.body) { const b = target.getBoundingClientRect(); if (b.width > 1 && b.height > 1) break; target = target.parentElement; } }
    const label = 'Roe: ' + (f.level === 'high' ? 'likely' : 'possible') + ' prompt injection' + (f.hidden && !textual ? ' (hidden in this element)' : '');
    const getRects = () => {
      if (f.kind === 'text-group' && ref.nodes) {      // one box per line of text, not per block
        const out = [];
        for (const n of ref.nodes) { if (!n.isConnected) continue; const r = document.createRange(); r.selectNodeContents(n); for (const b of r.getClientRects()) if (b.width > 1 && b.height > 1) out.push(b); }
        if (out.length) return out;
      }
      if (range) { const rs = [...range.getClientRects()].filter((r) => r.width > 1 && r.height > 1); if (rs.length) return rs; }
      const b = (target || el).getBoundingClientRect();
      return b.width > 1 && b.height > 1 ? [b] : [];
    };
    draw(getRects, label, !(f.hidden && textual));
    return { ok: true, revealed: revealedNow };
  }

  // ---------- scan ----------
  // Build one finding from an analysis. `ctx` carries visibility and surface context.
  function makeFinding(a, ctx, kind, where, sinks) {
    const r = rate(a, { ...ctx, kind, boost: SURFACE.boost, agentFile: SURFACE.agentFile, untrusted: UNTRUSTED });
    if (!r.level) return null;
    const refs = new Set(a.refs);
    // Anthropic's example is hidden white text in an email that steers a mail agent.
    if (r.hidden && SURFACE.id === 'email') refs.add('anthropic_browser');
    const refList = [...refs];
    const f = {
      kind,
      cat: a.cat,
      cats: a.cats,
      refs: refList,
      anthropic: refList.some((k) => REFS[k] && REFS[k].anthropic),
      technique: ctx.technique || 'plain text',
      hidden: r.hidden,
      level: r.level,
      score: Math.round(r.score),
      rules: a.rules.map(({ id, label }) => ({ id, label })),
      sig: a.behSignals || [],
      snippet: a.excerpt,
      where,
      sinks: linkSinks(intentSinks(a.text), sinks),
      sanitized: false,
      removable: kind !== 'remote',
      canReveal: (kind === 'text' || kind === 'text-group') && !!ctx.hidden
    };
    f.id = hash(kind + '|' + f.technique + '|' + f.snippet.slice(0, 80));
    return f;
  }

  function scan() {
    refs = new Map();
    current = new Map();
    const sinks = pageSinks(document);
    const out = [];
    const seen = new Set();
    const expText = [];
    let expLen = 0;

    const record = (a, ctx, ref, kind, where) => {
      const f = makeFinding(a, ctx, kind, where, sinks);
      if (!f || seen.has(f.id)) return null;
      f.canReveal = f.canReveal && !!ref.el;
      seen.add(f.id);
      ref.stripOnly = kind === 'text' && !ctx.hidden && a.smuggled;
      refs.set(f.id, ref);
      current.set(f.id, f);
      out.push(f);
      return f;
    };

    const nodeFinding = new Map();   // text node -> its behaviour finding, so a whole passage can replace line fragments
    const drop = (f) => {
      const i = out.indexOf(f);
      if (i >= 0) out.splice(i, 1);
      refs.delete(f.id); current.delete(f.id); seen.delete(f.id);
    };
    const recordPassage = (a, ctx, ref, where) => {
      const cand = makeFinding(a, ctx, 'text-group', where, sinks);
      if (!cand) return null;
      const inner = [...new Set(ref.nodes.map((x) => nodeFinding.get(x)).filter(Boolean))].filter((f) => f.rules.every((r) => r.id === 'behavior'));
      if (inner.some((f) => (f.sig || []).length >= cand.sig.length)) return null;   // replace a line-level hit only when the passage shows more kinds of control
      inner.forEach(drop);
      return record(a, ctx, ref, 'text-group', where);
    };

    // 1. text nodes and HTML comments
    const CHANNEL = ['email', 'chat', 'aichat'].includes(SURFACE.id);   // compose boxes hold the user's own words
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT, {
      acceptNode(n) {
        if (n.nodeValue.length < 3) return NodeFilter.FILTER_REJECT;
        if (n.nodeType === 3 && n.parentNode) {
          if (SKIP.has(n.parentNode.nodeName)) return NodeFilter.FILTER_REJECT;
          if (CHANNEL && n.parentElement && n.parentElement.closest('[contenteditable="true"],[role="textbox"]')) return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    const visCache = new WeakMap();
    const vis = (el) => { if (!el) return { hidden: false }; let v = visCache.get(el); if (!v) { v = visibility(el); visCache.set(el, v); } return v; };
    let shortChecks = 0;
    const blocks = [];        // runs of text in the same block element, in document order
    let cur = null;
    const hitNodes = new Set();      // nodes that already produced a finding
    const covered = new Set();       // nodes covered by a behaviour finding
    let n, count = 0;
    while ((n = walker.nextNode()) && count++ < MAX_NODES) {
      const el = n.parentElement;
      if (expLen < 400000) { expText.push(n.nodeValue); expLen += n.nodeValue.length; }
      if (n.nodeType === 8) {
        if (n.nodeValue.length < 12) continue;
        const a = analyze(n.nodeValue);
        if (a && record(a, { hidden: true, technique: 'HTML comment' }, { node: n, el }, 'comment', el ? pathOf(el) : '')) hitNodes.add(n);
        continue;
      }
      if (n.nodeValue.length < 12 && ++shortChecks > 4000) continue;
      const v = vis(el);
      if (el && n.nodeValue.trim()) {
        const block = el.closest(BLOCK) || el;
        if (!cur || cur.el !== block || cur.hidden !== v.hidden) { cur = { el: block, hidden: v.hidden, technique: v.technique, nodes: [], text: [], len: 0 }; blocks.push(cur); }
        if (cur.len < 6000) { cur.nodes.push(n); cur.text.push(n.nodeValue); cur.len += n.nodeValue.length; }
      }
      if (n.nodeValue.length < 12) continue;
      const a = analyze(n.nodeValue);
      if (!a) continue;
      const f = record(a, { hidden: v.hidden, technique: v.technique, quoted: inCode(el) }, { node: n, el }, 'text', pathOf(el));
      if (f) { hitNodes.add(n); if (f.rules.some((r) => r.id === 'behavior')) nodeFinding.set(n, f); }
    }

    // 1b. a block whose text is split over several nodes (instructions broken up by tags or <br>)
    for (const b of blocks) {
      if (b.nodes.length < 2) continue;
      const joined = b.text.join(' ');
      if (joined.length < 20) continue;
      if (b.nodes.some((x) => hitNodes.has(x) && !nodeFinding.has(x))) continue;   // another rule already reported part of this block
      const bh = behavior(joined);
      if (!b.hidden && (!bh || bh.score < 40)) continue;     // visible blocks: only a strong behaviour match
      const a = analyze(joined);
      if (!a || (!b.hidden && !a.rules.some((r) => r.id === 'behavior'))) continue;
      recordPassage(a, { hidden: b.hidden, technique: b.hidden ? b.technique + ' (split across tags)' : 'passage', quoted: inCode(b.el) }, { nodes: b.nodes, el: b.el }, pathOf(b.el));
    }

    // 1c. a passage spread over neighbouring blocks (one line or paragraph per element, as in email).
    // Only blocks that share a parent are joined (the lines of one message, one document, one hidden div), so two
    // unrelated paragraphs that happen to sit next to each other are never merged into one finding.
    const usedBlock = new Set();
    let windows = 0;
    const windowPass = (keyOf) => {
      for (let i = 0; i < blocks.length && windows < 800;) {
        if (usedBlock.has(blocks[i])) { i++; continue; }
        const key = keyOf(blocks[i]);
        let text = '', j = i;
        while (j < blocks.length && j - i < 14 && blocks[j].hidden === blocks[i].hidden && keyOf(blocks[j]) === key && !usedBlock.has(blocks[j]) && text.length + blocks[j].len < 4000) { text += blocks[j].text.join(' ') + '\n'; j++; }
        const size = j - i;
        if (size >= 2 && text.length >= 80) {
          windows++;
          const bh = behavior(text);
          if (bh && bh.score >= 40) {          // joining blocks needs stronger evidence than one block
            // Shrink to the smallest run of blocks that keeps the same evidence, so neighbours are not swept in.
            const textOf = (x, y) => blocks.slice(x, y).map((bk) => bk.text.join(' ')).join('\n');
            let lo = i, hi = j;
            while (hi - lo > 2 && (behavior(textOf(lo + 1, hi)) || { raw: 0 }).raw >= bh.raw) lo++;
            while (hi - lo > 2 && (behavior(textOf(lo, hi - 1)) || { raw: 0 }).raw >= bh.raw) hi--;
            // grow back over the rest of a "Label: value" block and a short heading just above it, so a highlight covers the whole request
            const isField = (bk) => /^\s*[\w ./&()-]{2,30}:\s*\S/.test(bk.text[0] || '') && bk.len < 300;
            const isHead = (bk) => bk.len <= 90 && !/[.!?]\s*$/.test(bk.text.join(' '));
            while (hi < j && isField(blocks[hi])) hi++;
            if (lo > i && isHead(blocks[lo - 1])) lo--;
            const a = analyze(textOf(lo, hi));
            if (a && a.rules.some((r) => r.id === 'behavior')) {
              const nodes = blocks.slice(lo, hi).flatMap((bk) => bk.nodes);
              const f = recordPassage(a, { hidden: blocks[lo].hidden, technique: blocks[lo].hidden ? blocks[lo].technique + ' (spread over several blocks)' : 'passage' }, { nodes, el: blocks[lo].el }, pathOf(blocks[lo].el));
              if (f) { for (let k = lo; k < hi; k++) usedBlock.add(blocks[k]); i = j; continue; }
            }
          }
        }
        i += Math.max(1, size >> 1);
      }
    };
    windowPass((bk) => bk.el.parentElement);
    windowPass((bk) => bk.el.parentElement && bk.el.parentElement.parentElement);

    // 2. attributes agents read but people don't see (alt, aria-label, hidden inputs, meta)
    for (const el of document.querySelectorAll(ATTR_SELECTOR)) {
      for (const name of ATTRS) {
        const v = el.getAttribute(name);
        if (!v || v.length < 20) continue;
        if (name === 'value' && !(el.nodeName === 'INPUT' && el.type === 'hidden')) continue;
        if (name === 'content' && el.nodeName !== 'META') continue;
        const a = analyze(v);
        if (a) record(a, { hidden: true, technique: 'attribute: ' + name }, { el, attr: name }, 'attribute', pathOf(el));
      }
    }

    // 3. <template> contents (inert on screen, still in the HTML)
    for (const t of document.querySelectorAll('template')) {
      const txt = t.content && t.content.textContent;
      const a = txt && txt.length >= 12 && analyze(txt);
      if (a) record(a, { hidden: true, technique: 'template content' }, { el: t }, 'template', pathOf(t));
    }

    // 3b. the tab title and the file names inside links: agents read both as trusted metadata, people skim past them
    const tabTitle = document.title;
    if (tabTitle && tabTitle.length >= 12) {
      const a = analyze(tabTitle);
      if (a) record(a, { hidden: true, technique: 'tab title' }, { title: true }, 'title', 'Tab title');
    }
    let linkCount = 0;
    for (const el of document.querySelectorAll('a[href],a[download],iframe[src],embed[src],object[data],source[src],video[src],audio[src]')) {
      if (linkCount++ > 400) break;
      for (const attr of ['download', 'href', 'src', 'data']) {
        const v = el.getAttribute(attr);
        const nm = v ? linkFileName(v) : '';
        if (nm.length < 20) continue;
        const a = analyze(normName(nm));
        if (a && record(a, { hidden: true, technique: 'file name in link' }, { el, attr }, 'attribute', pathOf(el))) break;
      }
    }

    // 4. what the GitHub API would hand an agent (raw Markdown)
    for (const f of remote) if (!seen.has(f.id)) { seen.add(f.id); current.set(f.id, f); out.push(f); }

    // 4b. images on the page (scanned in the background)
    for (const f of imgFindings) {
      const el = imgEls.get(f.id);
      if (!seen.has(f.id) && !f.sanitized && el && el.isConnected) { seen.add(f.id); current.set(f.id, f); refs.set(f.id, { el }); out.push(f); }
    }

    // 5. act on findings (removal mode)
    for (const f of out) {
      const ref = refs.get(f.id);
      if (!ref || f.level === 'low') continue;
      if (f.kind === 'image') { outline(ref.el); continue; }      // images are only ever removed by hand
      if (!f.hidden) { if (f.kind !== 'text-group') outline(ref.el); }   // passages are marked on demand with Highlight instead
      else if (settings.mode === 'sanitize') sanitize(f, ref);
    }
    // 6. sensitive data an agent reading this page would also read (counts and masked samples only)
    lastSinks = sinks;
    try {
      const attrText = [...document.querySelectorAll('input[type=hidden][value],meta[content]')].slice(0, 300).map((e) => e.getAttribute('value') || e.getAttribute('content')).join('\n');
      lastExposure = { ...Roe.exposure(expText.join('\n') + '\n' + attrText), ...Roe.fieldExposure(document) };
    } catch (e) { lastExposure = {}; }
    const list = out.slice();
    for (const [id, f] of history) if (!seen.has(id)) list.push({ ...f, gone: true });
    report(list, sinks, false);
  }

  // Report what we already know without walking the DOM again (used right after a removal,
  // so the popup updates at once; the full rescan follows on the next tick).
  function quickReport() {
    const list = [...current.values()];
    for (const [id, f] of history) if (!current.has(id)) list.push({ ...f, gone: true });
    report(list, lastSinks, false);
  }

  // ---------- manual removal ----------
  // ids: an array of finding ids, or 'hidden' for every hidden, removable finding.
  function removeNow(ids) {
    let removed = 0;
    for (const [id, f] of current) {
      if (f.sanitized || f.kind === 'remote') continue;
      if (ids === 'hidden' && f.kind === 'image') continue;
      if (ids === 'hidden' ? !(f.hidden && f.level !== 'low') : !ids.includes(id)) continue;
      const ref = refs.get(id);
      if (ref && sanitize(f, ref)) removed++;
    }
    observer.takeRecords();
    if (removed) { quickReport(); clearTimeout(timer); timer = setTimeout(run, 120); }
    return removed;
  }

  // ---------- GitHub raw Markdown ----------
  async function checkRaw() {
    const t = githubTarget(location);
    if (!t || !settings.ghRaw || settings.allow.includes(location.hostname)) return;
    const key = location.pathname;
    if (rawDone === key) return;
    rawDone = key;
    let res;
    try { res = await chrome.runtime.sendMessage({ type: 'roe:github', target: t }); } catch (e) { return; }
    remote = [];
    rawStatus = !res ? 'GitHub raw check did not run' : res.error ? 'GitHub raw check: ' + res.error : 'Checked raw Markdown of ' + res.items.length + ' item(s) on GitHub';
    const sinks = [];
    for (const it of (res && res.items) || []) {
      if (!it.text) continue;
      const pieces = rawMarkdownHidden(it.text).map((p) => ({ text: p.text, technique: p.technique, hidden: true }));
      pieces.push({ text: it.text, technique: 'raw Markdown', hidden: false, onlyObfuscation: true });
      for (const p of pieces) {
        const a = analyze(p.text);
        if (!a) continue;
        if (p.onlyObfuscation && !(a.smuggled || a.rules.some((r) => r.id === 'invisible' || r.id === 'vs-smuggle'))) continue;
        const f = makeFinding(a, { hidden: p.hidden, technique: p.technique + ' in ' + it.label }, 'remote', it.label + ' (raw, not shown on the page)', sinks);
        if (f) remote.push(f);
      }
    }
    run();
  }

  // ---------- images ----------
  // Each displayed image is fetched again without cookies (from the browser cache when possible) and checked
  // for metadata text, appended data and near-invisible text. Turn off in the popup.
  async function checkImages() {
    if (imgBusy || !settings.scanImages || settings.allow.includes(location.hostname)) return;
    imgBusy = true;
    try {
      const list = [...document.images].filter((im) => im.complete && im.naturalWidth >= 64 && im.naturalHeight >= 64 && (im.currentSrc || im.src));
      imgCount = document.images.length;
      let sent = 0;
      for (const im of list) {
        const src = im.currentSrc || im.src;
        if (imgSeen.has(src) || !/^(https?:|data:image\/)/.test(src)) continue;
        if (++sent > 12) break;
        imgSeen.add(src);
        let res;
        try { res = await chrome.runtime.sendMessage({ type: 'roe:image', url: src }); } catch (e) { continue; }
        if (!res || !res.ok) continue;
        for (const f of res.res.findings) {
          if (f.level === 'low') continue;
          const pf = { ...f, kind: 'image', where: 'Image on this page: ' + (im.alt ? '\u201C' + im.alt.slice(0, 40) + '\u201D' : src.slice(0, 90)), removable: true, canReveal: false, sanitized: false };
          pf.id = hash('img|' + src + '|' + f.id);
          imgFindings.push(pf); imgEls.set(pf.id, im);
        }
      }
    } finally { imgBusy = false; }
    if (imgFindings.length) run();
  }

  function report(findings, sinks, paused) {
    try {
      chrome.runtime.sendMessage({
        type: 'roe:report',
        report: { url: location.href, title: document.title, isTop: window.top === window, paused, findings, sinks, exposure: paused ? {} : lastExposure, surface: SURFACE, rawStatus, scannedAt: Date.now() }
      });
    } catch (e) { /* extension was reloaded; this tab needs a refresh */ }
  }

  function run() {
    clearTimeout(timer);
    if (settings.allow.includes(location.hostname)) {
      clearOutlines(); hideAll(); report([], [], true);
    } else {
      scan();
    }
    observer.takeRecords(); // ignore the changes Roe itself just made
    if (!settings.allow.includes(location.hostname) && document.images.length !== imgCount) setTimeout(checkImages, 400);
  }

  const observer = new MutationObserver(() => { clearTimeout(timer); timer = setTimeout(run, 1200); });

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg) return;
    if (msg.type === 'roe:reveal') sendResponse({ shown: toggleReveal(msg.id) });
    else if (msg.type === 'roe:highlight') sendResponse(highlight(msg.id));
    else if (msg.type === 'roe:unhighlight') { clearHighlight(); hideAll(); sendResponse({ ok: true }); }
    else if (msg.type === 'roe:remove') sendResponse({ removed: removeNow(msg.ids) });
    else if (msg.type === 'roe:rescan') { run(); sendResponse({ ok: true }); }
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local' || !(changes.mode || changes.allow || changes.ghRaw || changes.scanImages)) return;
    if (changes.mode) settings.mode = changes.mode.newValue;
    if (changes.allow) settings.allow = changes.allow.newValue || [];
    if (changes.scanImages) { settings.scanImages = changes.scanImages.newValue !== false; if (!settings.scanImages) { imgFindings = []; } else { imgSeen.clear(); imgCount = 0; } }
    if (changes.ghRaw) { settings.ghRaw = changes.ghRaw.newValue !== false; rawDone = ''; if (!settings.ghRaw) { remote = []; rawStatus = ''; } }
    run();
    checkRaw();
  });

  chrome.storage.local.get({ mode: 'warn', allow: [], ghRaw: true, scanImages: true }).then((s) => {
    settings = s;
    run();
    checkRaw();
    setTimeout(run, 2500); // catch content rendered late by single-page apps
    observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  });
})();
