// Roe file scanner: finds hidden and plain instructions aimed at AI agents inside files.
// Every handler turns a file into "pieces" of text (with how hidden each one is), and the same
// detector used on web pages scores them. Nothing leaves the browser.
(function () {
  const Roe = (self.Roe = self.Roe || {});
  const { analyze, rate, REFS } = Roe;
  const MAX_DEPTH = 3;
  const dec = (b, enc) => { try { return new TextDecoder(enc || 'utf-8').decode(b); } catch (e) { return new TextDecoder('utf-8').decode(b); } };

  const hash = Roe.hash = (s) => { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0).toString(36); };

  function decodeText(b) {
    if (b[0] === 0xff && b[1] === 0xfe) return dec(b.subarray(2), 'utf-16le');
    if (b[0] === 0xfe && b[1] === 0xff) return dec(b.subarray(2), 'utf-16be');
    if (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) b = b.subarray(3);
    let nul = 0; const n = Math.min(b.length, 2000);
    for (let i = 1; i < n; i += 2) if (b[i] === 0) nul++;
    return nul > n / 4 ? dec(b, 'utf-16le') : dec(b);
  }
  const mostlyText = (b) => { const n = Math.min(b.length, 4000); let bad = 0; for (let i = 0; i < n; i++) { const c = b[i]; if (c < 9 || (c > 13 && c < 32 && c !== 27)) bad++; } return n === 0 || bad / n < 0.02; };

  // Printable runs from binary data (old Office files, unknown formats, metadata blocks).
  Roe.printableRuns = function (b, min) {
    min = min || 30;
    const out = [];
    let cur = '', total = 0;
    const lim = Math.min(b.length, 600000);
    for (let i = 0; i < lim; i++) {
      const c = b[i];
      if ((c >= 32 && c < 127) || c === 9) cur += String.fromCharCode(c);
      else { if (cur.length >= min) { out.push(cur); total += cur.length; } cur = ''; if (total > 200000) break; }
    }
    if (cur.length >= min) out.push(cur);
    cur = '';
    for (let i = 0; i + 1 < lim; i += 2) {      // UTF-16LE runs
      const c = b[i] | (b[i + 1] << 8);
      if (c >= 32 && c < 127) cur += String.fromCharCode(c);
      else { if (cur.length >= min) out.push(cur); cur = ''; }
    }
    if (cur.length >= min) out.push(cur);
    return out;
  };

  function chunks(text) {
    if (text.length <= 5500) return [text];
    const out = [];
    for (let i = 0; i < text.length && out.length < 120; i += 4500) out.push(text.slice(i, i + 5500));
    return out;
  }

  // ---------- findings ----------
  function addPiece(S, text, o) {
    if (!text || text.trim().length < 3 || S.findings.length >= 80) return;
    for (const chunk of chunks(text)) {
      const a = analyze(chunk);
      if (!a) continue;
      const r = rate(a, { hidden: !!o.hidden, kind: o.kind || (o.attr ? 'attribute' : 'file'), boost: 1.1, untrusted: true, agentFile: S.agentFile });
      if (!r.level) continue;
      const where = S.path + (o.where ? ' \u00B7 ' + o.where : '');
      const refs = [...new Set(a.refs)];
      const f = {
        kind: 'file', cat: a.cat, cats: a.cats, refs,
        anthropic: refs.some((k) => REFS[k] && REFS[k].anthropic),
        technique: o.technique || 'plain text', hidden: r.hidden, level: r.level, score: Math.round(r.score),
        rules: a.rules.map(({ id, label }) => ({ id, label })), snippet: a.excerpt, where, sinks: []
      };
      f.id = hash(f.technique + '|' + where + '|' + f.snippet.slice(0, 80));
      if (S.seen.has(f.id)) continue;
      S.seen.add(f.id);
      S.findings.push(f);
    }
  }
  const push = (map, k, v) => { if (!map.has(k)) map.set(k, []); map.get(k).push(v); };
  const flush = (S, map, where, extra) => { for (const [tech, arr] of map) addPiece(S, arr.join('\n'), Object.assign({ hidden: true, technique: tech, where }, extra || {})); };

  // ---------- dispatch ----------
  function sniff(name, b) {
    const ext = (name.split('.').pop() || '').toLowerCase();
    if (b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) return 'pdf';
    if (b[0] === 0x50 && b[1] === 0x4b && (b[2] === 3 || b[2] === 5)) return 'zip';
    if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'png';
    if (b[0] === 0xff && b[1] === 0xd8) return 'jpeg';
    if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return 'gif';
    if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45) return 'webp';
    if (!mostlyText(b) && !/^(txt|md|csv|json|html?|eml|ics|svg|xml)$/.test(ext)) return 'binary';
    if (/^(html?|xhtml|svg|xml|mht|mhtml)$/.test(ext)) return 'html';
    if (/^(md|markdown|mdx)$/.test(ext)) return 'md';
    if (ext === 'eml' || ext === 'msg' && mostlyText(b)) return 'eml';
    if (ext === 'ics' || ext === 'vcf') return 'ics';
    if (/^(json|ipynb|jsonl)$/.test(ext)) return 'json';
    if (ext === 'rtf') return 'rtf';
    const head = dec(b.subarray(0, 600)).toLowerCase();
    if (/<!doctype html|<html[\s>]/.test(head)) return 'html';
    if (/^(from |received:|return-path:|mime-version:|content-type:)/m.test(head) && /^(subject|from|to):/m.test(head)) return 'eml';
    return 'text';
  }

  Roe.isAgentFile = Roe.isAgentFile || ((p) => /(^|\/)(CLAUDE|AGENTS|GEMINI|MEMORY|SKILL)\.md$|(^|\/)\.cursorrules$|(^|\/)\.windsurfrules$|copilot-instructions\.md$|(^|\/)\.cursor\/rules\/|(^|\/)\.claude\/|(^|\/)mcp\.json$|(^|\/)llms?\.txt$/i.test(p));

  Roe.handlers = Roe.handlers || {};
  async function scanInto(S, name, bytes, label) {
    if (S.depth >= MAX_DEPTH) { S.notes.push('Skipped nested file ' + name + ' (too deep).'); return; }
    const sub = await Roe.scanFile({ name, bytes, depth: S.depth + 1, path: S.path + ' \u203A ' + name });
    for (const f of sub.findings) if (!S.seen.has(f.id)) { S.seen.add(f.id); S.findings.push(f); }
    for (const n of sub.notes) S.notes.push(name + ': ' + n);
    S.children.push({ name, kind: sub.kind, flagged: sub.findings.length });
  }

  Roe.scanFile = async function ({ name, bytes, depth, path }) {
    const S = { name, path: path || name, depth: depth || 0, size: bytes.length, findings: [], notes: [], seen: new Set(), children: [], kind: 'File', agentFile: Roe.isAgentFile(path || name), scanInto: (n, b) => scanInto(S, n, b), addPiece: (t, o) => addPiece(S, t, o), addFinding: (f) => { if (!S.seen.has(f.id)) { S.seen.add(f.id); S.findings.push(f); } }, flush: (m, w, e) => flush(S, m, w, e) };
    if (name.length >= 15) addPiece(S, Roe.normName(name), { hidden: false, technique: 'file name', where: 'file name', kind: 'filename' });
    const type = sniff(name, bytes);
    S.type = type;
    try {
      const h = Roe.handlers[type];
      if (h) await h(S, bytes, name);
      else S.notes.push('No reader for this file type (' + type + ').');
    } catch (e) { S.notes.push('Could not fully read this file: ' + (e && e.message || e)); }
    S.findings.sort((a, b) => ({ high: 0, medium: 1, low: 2 }[a.level] - { high: 0, medium: 1, low: 2 }[b.level]) || Number(b.hidden) - Number(a.hidden));
    return { name, size: S.size, kind: S.kind, type, findings: S.findings, notes: S.notes, children: S.children, extra: S.extra || null };
  };

  // ---------- plain formats ----------
  Roe.handlers.text = async (S, b) => { S.kind = S.agentFile ? 'Agent instruction file' : 'Text file'; addPiece(S, decodeText(b), { hidden: false, technique: 'file text' }); };

  Roe.handlers.md = async (S, b) => {
    S.kind = S.agentFile ? 'Agent instruction file (Markdown)' : 'Markdown';
    const t = decodeText(b);
    addPiece(S, t, { hidden: false, technique: 'file text' });
    for (const p of Roe.rawMarkdownHidden(t)) addPiece(S, p.text, { hidden: true, technique: p.technique });
  };

  Roe.handlers.rtf = async (S, b) => {
    S.kind = 'RTF document';
    const t = decodeText(b);
    const hid = []; t.replace(/\{\\v(?![a-z])[^{}]*\}/g, (m) => { hid.push(m.replace(/\\[a-z]+-?\d* ?|[{}]/gi, '')); return ''; });
    addPiece(S, hid.join('\n'), { hidden: true, technique: 'hidden text (RTF \\v)' });
    addPiece(S, t.replace(/\\'[0-9a-f]{2}/gi, '').replace(/\\[a-z]+-?\d* ?|[{}]/gi, ''), { hidden: false, technique: 'document text' });
  };

  Roe.handlers.binary = async (S, b, name) => {
    S.kind = 'Binary file';
    S.notes.push('Unknown or binary format: only embedded text strings were checked.');
    addPiece(S, Roe.printableRuns(b, 30).join('\n'), { hidden: false, technique: 'embedded text strings' });
  };

  Roe.handlers.json = async (S, b, name) => {
    const t = decodeText(b);
    let j;
    try { j = JSON.parse(t); } catch (e) { S.kind = 'JSON (unparseable)'; addPiece(S, t, { hidden: false, technique: 'file text' }); return; }
    if (j && Array.isArray(j.cells)) {
      S.kind = 'Jupyter notebook';
      j.cells.forEach((c, i) => {
        addPiece(S, [].concat(c.source || []).join(''), { hidden: false, technique: 'notebook ' + c.cell_type + ' cell', where: 'cell ' + (i + 1) });
        for (const o of c.outputs || []) addPiece(S, [].concat(o.text || (o.data && o.data['text/plain']) || (o.data && o.data['text/html']) || []).join(''), { hidden: false, technique: 'notebook output', where: 'cell ' + (i + 1) });
      });
      return;
    }
    S.kind = S.agentFile ? 'Agent configuration (JSON)' : 'JSON';
    let n = 0;
    (function walk(v, path) {
      if (n > 3000) return;
      if (typeof v === 'string') { if (v.length >= 12) { n++; addPiece(S, v, { hidden: false, technique: 'JSON field', where: path }); } }
      else if (Array.isArray(v)) v.forEach((x, i) => walk(x, path + '[' + i + ']'));
      else if (v && typeof v === 'object') for (const k of Object.keys(v)) walk(v[k], path ? path + '.' + k : k);
    })(j, '');
  };

  Roe.handlers.ics = async (S, b) => {
    S.kind = 'Calendar / contact file';
    const lines = decodeText(b).replace(/\r?\n[ \t]/g, '').split(/\r?\n/);
    for (const l of lines) {
      const m = /^([A-Z-]+)(?:;[^:]*)?:(.*)$/.exec(l);
      if (m && /^(SUMMARY|DESCRIPTION|LOCATION|COMMENT|X-ALT-DESC|NOTE|TITLE|ORG)$/.test(m[1]))
        addPiece(S, m[2].replace(/\\n/gi, '\n').replace(/\\([,;\\])/g, '$1'), { hidden: false, technique: 'calendar field ' + m[1] });
    }
  };

  // ---------- email ----------
  const qpDecode = (s) => s.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16)));
  const b64 = (s) => { try { const bin = atob(s.replace(/\s+/g, '')); return Uint8Array.from(bin, (c) => c.charCodeAt(0)); } catch (e) { return new Uint8Array(); } };
  function decodeWords(v) {
    return v.replace(/=\?([\w-]+)\?([bq])\?([^?]*)\?=/gi, (m, cs, enc, txt) => {
      try { return enc.toLowerCase() === 'b' ? dec(b64(txt), cs) : dec(Uint8Array.from(qpDecode(txt.replace(/_/g, ' ')), (c) => c.charCodeAt(0)), cs); } catch (e) { return txt; }
    });
  }
  function splitMime(raw) {
    const m = /\r?\n\r?\n/.exec(raw);
    const head = m ? raw.slice(0, m.index) : raw, body = m ? raw.slice(m.index + m[0].length) : '';
    const headers = {};
    for (const line of head.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/)) { const i = line.indexOf(':'); if (i > 0) { const k = line.slice(0, i).toLowerCase(); headers[k] = (headers[k] ? headers[k] + ' ' : '') + line.slice(i + 1).trim(); } }
    return { headers, body };
  }
  const param = (v, k) => { const m = new RegExp(k + '\\*?=\\s*(?:"([^"]*)"|([^;\\s]+))', 'i').exec(v || ''); return m ? (m[1] || m[2]) : ''; };

  async function mimePart(S, raw, depth) {
    const { headers, body } = splitMime(raw);
    const ctype = (headers['content-type'] || 'text/plain').toLowerCase();
    const enc = (headers['content-transfer-encoding'] || '').toLowerCase();
    const boundary = param(headers['content-type'], 'boundary');
    if (/^multipart\//.test(ctype) && boundary && depth < 6) {
      for (const part of body.split('--' + boundary)) { if (part.trim() && !part.startsWith('--')) await mimePart(S, part.replace(/^\r?\n/, ''), depth + 1); }
      return;
    }
    const fname = decodeWords(param(headers['content-disposition'], 'filename') || param(headers['content-type'], 'name'));
    let bytes = enc === 'base64' ? b64(body) : enc === 'quoted-printable' ? Uint8Array.from(qpDecode(body), (c) => c.charCodeAt(0)) : Uint8Array.from(body, (c) => c.charCodeAt(0) & 255);
    const charset = param(headers['content-type'], 'charset') || 'utf-8';
    if (fname || !/^text\/(plain|html)/.test(ctype)) {
      if (bytes.length) { S.notes.push('Attachment found: ' + (fname || ctype)); await scanInto(S, fname || 'attachment', bytes); }
      return;
    }
    const text = dec(bytes, charset);
    if (ctype.startsWith('text/html')) Roe.scanHtml(S, text, 'email body (HTML)');
    else addPiece(S, text, { hidden: false, technique: 'email body (plain text)' });
  }

  Roe.handlers.eml = async (S, b) => {
    S.kind = 'Email message';
    const raw = decodeText(b);
    const { headers } = splitMime(raw);
    for (const k of Object.keys(headers)) {
      if (/^(received|dkim-signature|arc-|authentication-results|message-id|date|content-|mime-version|x-google|x-received|return-path)/.test(k)) continue;
      addPiece(S, decodeWords(headers[k]), { hidden: k !== 'subject', technique: 'email header: ' + k });
    }
    await mimePart(S, raw, 0);
  };

  // ---------- HTML (static: no rendering, so hidden-text tricks are read from inline styles and <style> rules) ----------
  const BLOCK = 'p,div,li,td,th,tr,section,article,blockquote,header,footer,main,pre,h1,h2,h3,h4,h5,h6,dd,dt,body,br';
  const hex = (v) => {
    v = (v || '').trim().toLowerCase().replace(/\s+/g, '').replace(/!important/, '');
    if (!v || v === 'inherit' || v === 'transparent' || v === 'initial') return '';
    if (v === 'white') return '#ffffff'; if (v === 'black') return '#000000';
    let m = /^#([0-9a-f]{3})$/.exec(v); if (m) return '#' + m[1].split('').map((c) => c + c).join('');
    m = /^#([0-9a-f]{6})/.exec(v); if (m) return '#' + m[1];
    m = /^rgba?\((\d+),(\d+),(\d+)/.exec(v); if (m) return '#' + [m[1], m[2], m[3]].map((n) => Math.min(255, +n).toString(16).padStart(2, '0')).join('');
    return '';
  };
  const nearWhite = (h) => !!h && [1, 3, 5].every((i) => parseInt(h.slice(i, i + 2), 16) >= 0xf0);
  const px = (v) => { const m = /^(-?[\d.]+)\s*(px|pt|em|rem|%)?/.exec((v || '').trim()); if (!m) return null; const n = parseFloat(m[1]); return m[2] === 'pt' ? n * 1.33 : m[2] === 'em' || m[2] === 'rem' ? n * 16 : m[2] === '%' ? n * 0.16 : n; };

  function parseDecl(s) { const o = {}; for (const d of (s || '').split(';')) { const i = d.indexOf(':'); if (i > 0) o[d.slice(0, i).trim().toLowerCase()] = d.slice(i + 1).trim().toLowerCase().replace(/\s*!important/, ''); } return o; }

  Roe.scanHtml = function (S, html, label) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    // simple <style> rules (no @media): selector -> declarations
    const rules = [];
    for (const st of doc.querySelectorAll('style')) {
      const css = st.textContent.replace(/\/\*[\s\S]*?\*\//g, '').replace(/@media[^{]*\{([^{}]*\{[^{}]*\})*[^{}]*\}/g, '');
      const re = /([^{}@]+)\{([^{}]*)\}/g; let m;
      while ((m = re.exec(css)) && rules.length < 500) for (const sel of m[1].split(',')) rules.push([sel.trim(), parseDecl(m[2])]);
    }
    const cache = new WeakMap();
    const decls = (el) => {
      let d = cache.get(el); if (d) return d;
      d = {};
      for (const [sel, o] of rules) { try { if (sel && el.matches(sel)) Object.assign(d, o); } catch (e) { /* unsupported selector */ } }
      Object.assign(d, parseDecl(el.getAttribute('style')));
      if (el.getAttribute('bgcolor') && !d['background-color']) d['background-color'] = el.getAttribute('bgcolor');
      if (el.getAttribute('color') && !d.color) d.color = el.getAttribute('color');
      cache.set(el, d); return d;
    };
    const inherited = (el, prop) => { for (let e = el; e && e.nodeType === 1; e = e.parentElement) { const d = decls(e); const v = hex(d[prop] || (prop === 'background-color' ? d.background : '')); if (v) return v; } return ''; };
    const own = (el) => {
      const d = decls(el);
      if (el.hasAttribute('hidden')) return 'hidden attribute';
      if (el.nodeName === 'NOSCRIPT') return 'noscript content';
      if (d.display === 'none') return 'display: none';
      if (d.visibility === 'hidden' || d.visibility === 'collapse') return 'visibility: hidden';
      if (d.opacity !== undefined && parseFloat(d.opacity) <= 0.05) return 'opacity: 0';
      if (/mso-hide\s*:\s*all/.test(el.getAttribute('style') || '') || d['mso-hide'] === 'all') return 'mso-hide: all (hidden in Outlook)';
      const fs = px(d['font-size']); if (fs !== null && fs < 2) return 'tiny font';
      const hh = px(d.height), mh = px(d['max-height']), ww = px(d.width);
      if ((hh === 0 || mh === 0 || ww === 0) && /hidden|clip/.test((d.overflow || '') + (d['overflow-y'] || ''))) return 'zero-size box';
      if (mh === 0) return 'zero-size box';
      const ti = px(d['text-indent']), lf = px(d.left), tp = px(d.top);
      if ((ti !== null && ti <= -500) || (/absolute|fixed/.test(d.position || '') && ((lf !== null && lf <= -500) || (tp !== null && tp <= -500)))) return 'positioned off-screen';
      if (/rect\(\s*0/.test(d.clip || '') || /inset\(\s*(100|50)%/.test(d['clip-path'] || '')) return 'clipped away';
      if (/scale\(\s*0\s*\)/.test(d.transform || '')) return 'scaled to zero';
      const c = hex(d.color);
      if (c) { const bg = inherited(el, 'background-color'); if (bg ? c === bg : nearWhite(c)) return bg ? 'text colored to match its background' : 'white text'; }
      return '';
    };
    const reason = (el) => { for (let e = el; e && e.nodeType === 1; e = e.parentElement) { const r = own(e); if (r) return r; } return ''; };

    const visible = [], hid = new Map();
    let lastBlock = null, line = '';
    const w = doc.createTreeWalker(doc.documentElement, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT);
    let n, count = 0;
    while ((n = w.nextNode()) && count++ < 60000) {
      if (n.nodeType === 8) { if (n.nodeValue.trim().length > 8) push(hid, 'HTML comment', n.nodeValue); continue; }
      const p = n.parentElement;
      if (!p || /^(SCRIPT|STYLE|TEXTAREA|TITLE)$/.test(p.nodeName) || !n.nodeValue.trim()) continue;
      const r = reason(p);
      if (r) { push(hid, 'Hidden: ' + r, n.nodeValue.trim()); continue; }
      const blk = p.closest(BLOCK) || p;
      if (blk !== lastBlock && line) { visible.push(line); line = ''; }
      lastBlock = blk; line += (line ? ' ' : '') + n.nodeValue.trim();
    }
    if (line) visible.push(line);
    addPiece(S, visible.join('\n'), { hidden: false, technique: 'visible text', where: label });
    flush(S, hid, label);

    // things a person never reads but an agent does
    const attrs = new Map();
    for (const el of doc.querySelectorAll('[alt],[title],[aria-label],[placeholder],input[type=hidden][value],meta[content]')) {
      for (const a of ['alt', 'title', 'aria-label', 'placeholder']) { const v = el.getAttribute(a); if (v && v.length > 15) push(attrs, 'attribute: ' + a, v); }
      if (el.nodeName === 'META') { const v = el.getAttribute('content'); if (v && v.length > 15 && !/^width=|^IE=|^text\/html/i.test(v)) push(attrs, 'meta tag', v); }
      if (el.nodeName === 'INPUT') push(attrs, 'hidden form field', el.getAttribute('value'));
    }
    for (const t of doc.querySelectorAll('template')) push(attrs, 'template content', t.content.textContent);
    for (const s of doc.querySelectorAll('script[type="application/ld+json"]')) push(attrs, 'structured data (JSON-LD)', s.textContent);
    const title = doc.querySelector('title'); if (title) addPiece(S, title.textContent, { hidden: false, technique: 'page title', where: label });
    flush(S, attrs, label, { attr: true });
    S.kind = S.kind === 'File' ? 'HTML document' : S.kind;
  };
  Roe.handlers.html = async (S, b, name) => {
    S.kind = /\.svg$/i.test(name) ? 'SVG image' : 'HTML document';
    Roe.scanHtml(S, decodeText(b), 'document');
  };
})();
