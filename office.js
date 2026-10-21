// Roe: Office documents and archives. Reads the XML inside .docx/.pptx/.xlsx/.odt and looks at
// what a person never sees: hidden runs, tiny or white text, speaker notes, hidden slides and
// sheets, comments, tracked deletions, alt text and document properties.
(function () {
  const Roe = (self.Roe = self.Roe || {});
  const H = (Roe.handlers = Roe.handlers || {});
  const dec = (b) => new TextDecoder('utf-8').decode(b);
  const push = (map, k, v) => { if (!map.has(k)) map.set(k, []); map.get(k).push(v); };

  function xml(bytes) {
    const d = new DOMParser().parseFromString(dec(bytes), 'application/xml');
    return d.getElementsByTagName('parsererror').length ? null : d;
  }
  const get = async (zip, name) => { const e = zip.entries.get(name); if (!e) return null; try { return xml(await e.read()); } catch (x) { return null; } };
  const tags = (d, t) => Array.from(d.getElementsByTagName(t));
  const text = (el) => el.textContent || '';
  const IMG = /\.(png|jpe?g|gif|webp)$/i;

  async function props(S, zip) {
    const map = new Map();
    const core = await get(zip, 'docProps/core.xml');
    if (core) for (const el of core.documentElement.children) if (text(el).trim().length > 8) push(map, 'document property: ' + el.nodeName.replace(/^.*:/, ''), text(el));
    const custom = await get(zip, 'docProps/custom.xml');
    if (custom) for (const el of tags(custom, 'vt:lpwstr')) if (text(el).trim().length > 8) push(map, 'custom document property', text(el));
    const meta = await get(zip, 'meta.xml');                          // OpenDocument
    if (meta) for (const t of ['dc:title', 'dc:description', 'dc:subject', 'meta:keyword', 'meta:user-defined']) for (const el of tags(meta, t)) if (text(el).trim().length > 8) push(map, 'document property: ' + t.replace(/^.*:/, ''), text(el));
    S.flush(map, 'properties');
  }

  async function media(S, zip, dir) {
    let n = 0;
    for (const [name, e] of zip.entries) {
      if (!name.startsWith(dir) || !IMG.test(name) || e.size > 6 * 1024 * 1024 || n++ >= 20) continue;
      try { await S.scanInto(name.split('/').pop(), await e.read()); } catch (x) { /* skip unreadable image */ }
    }
  }

  // ---------- Word ----------
  const WHITE = /^(ff|fe|fd)(ff|fe|fd)(ff|fe|fd)$/i;
  function runWhy(r) {
    let rp = null;
    for (const c of r.children) if (c.nodeName === 'w:rPr') rp = c;
    if (!rp) return '';
    const q = (t) => { for (const c of rp.children) if (c.nodeName === t) return c; return null; };
    const on = (el) => el && !/^(0|false|off)$/i.test(el.getAttribute('w:val') || '');
    if (on(q('w:vanish')) || on(q('w:specVanish'))) return 'hidden text (Word "Hidden" font)';
    const sz = q('w:sz'); if (sz) { const v = +sz.getAttribute('w:val'); if (v > 0 && v < 4) return 'tiny font (under 2 pt)'; }
    const col = q('w:color'), shd = q('w:shd');
    if (col && WHITE.test(col.getAttribute('w:val') || '')) {
      const fill = shd && (shd.getAttribute('w:fill') || '');
      if (!fill || /^auto$/i.test(fill) || WHITE.test(fill)) return 'white text';
    }
    return '';
  }
  H.docx = async (S, zip) => {
    S.kind = 'Word document';
    for (const n of zip.entries.keys()) {
      if (!/^word\/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$/.test(n)) continue;
      const d = await get(zip, n); if (!d) continue;
      const label = n.replace(/^word\//, '').replace(/\.xml$/, '');
      const hid = new Map(); const vis = [];
      for (const p of tags(d, 'w:p')) {
        let line = '';
        for (const r of tags(p, 'w:r')) {
          let t = '', del = '';
          for (const c of r.children) { if (c.nodeName === 'w:t') t += text(c); else if (c.nodeName === 'w:tab') t += ' '; else if (c.nodeName === 'w:delText') del += text(c); }
          if (del.trim()) push(hid, 'deleted tracked text still stored in the file', del);
          if (!t) continue;
          const why = runWhy(r);
          if (why) push(hid, why, t); else line += t;
        }
        if (line.trim()) vis.push(line);
      }
      if (n === 'word/comments.xml') S.addPiece(vis.join('\n'), { hidden: true, technique: 'review comment (not in the document body)', where: label });
      else S.addPiece(vis.join('\n'), { hidden: false, technique: 'document text', where: label });
      S.flush(hid, label);
      if (n === 'word/document.xml') {
        const alt = new Map();
        for (const el of [...tags(d, 'wp:docPr'), ...tags(d, 'pic:cNvPr')]) for (const a of ['descr', 'title']) { const v = el.getAttribute(a); if (v && v.length > 15) push(alt, 'image alt text', v); }
        S.flush(alt, label, { attr: true });
      }
    }
    for (const n of zip.entries.keys()) if (/^customXml\/item\d*\.xml$/.test(n)) { const d = await get(zip, n); if (d && text(d.documentElement).trim().length > 15) S.addPiece(text(d.documentElement), { hidden: true, technique: 'custom XML part', where: n }); }
    if (zip.entries.has('word/vbaProject.bin')) S.notes.push('Contains VBA macros (vbaProject.bin).');
    await props(S, zip); await media(S, zip, 'word/media/');
  };

  // ---------- PowerPoint ----------
  H.pptx = async (S, zip) => {
    S.kind = 'PowerPoint presentation';
    const pres = await get(zip, 'ppt/presentation.xml');
    const sz = pres && tags(pres, 'p:sldSz')[0];
    const W = sz ? +sz.getAttribute('cx') : 12192000, Hh = sz ? +sz.getAttribute('cy') : 6858000;
    const names = [...zip.entries.keys()].filter((n) => /^ppt\/(slides\/slide|notesSlides\/notesSlide)\d+\.xml$/.test(n)).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    for (const n of names) {
      const d = await get(zip, n); if (!d) continue;
      const isNotes = n.includes('notesSlides'), label = (isNotes ? 'notes ' : 'slide ') + n.match(/(\d+)\.xml/)[1];
      const hiddenSlide = !isNotes && d.documentElement.getAttribute('show') === '0';
      const hid = new Map(), vis = [];
      for (const p of tags(d, 'a:p')) {
        let line = '';
        for (const r of tags(p, 'a:r')) {
          const t = tags(r, 'a:t').map(text).join('');
          if (!t) continue;
          const rp = tags(r, 'a:rPr')[0];
          const size = rp ? +rp.getAttribute('sz') : 0;
          let off = false;
          for (let e = r.parentNode; e && e.nodeName !== 'p:spTree'; e = e.parentNode) {
            if (e.nodeName === 'p:sp' || e.nodeName === 'p:graphicFrame') {
              const o = tags(e, 'a:off')[0], x = tags(e, 'a:ext')[0];
              if (o && x) { const ox = +o.getAttribute('x'), oy = +o.getAttribute('y'), cx = +x.getAttribute('cx'), cy = +x.getAttribute('cy'); off = ox + cx <= 0 || oy + cy <= 0 || ox >= W || oy >= Hh; }
              break;
            }
          }
          if (isNotes) push(hid, 'speaker notes (not shown on the slide)', t);
          else if (hiddenSlide) push(hid, 'hidden slide', t);
          else if (size > 0 && size < 200) push(hid, 'tiny font (under 2 pt)', t);
          else if (off) push(hid, 'positioned off the slide', t);
          else line += t;
        }
        if (line.trim()) vis.push(line);
      }
      S.addPiece(vis.join('\n'), { hidden: false, technique: 'slide text', where: label });
      S.flush(hid, label);
      const alt = new Map();
      for (const el of tags(d, 'p:cNvPr')) { const v = el.getAttribute('descr'); if (v && v.length > 15) push(alt, 'image alt text', v); }
      S.flush(alt, label, { attr: true });
    }
    for (const n of zip.entries.keys()) if (/^ppt\/comments\/.*\.xml$/.test(n)) { const d = await get(zip, n); if (d) S.addPiece(tags(d, 'p:text').map(text).join('\n'), { hidden: true, technique: 'review comment', where: n }); }
    await props(S, zip); await media(S, zip, 'ppt/media/');
  };

  // ---------- Excel ----------
  const colIndex = (ref) => { let n = 0; for (const ch of /^[A-Z]+/.exec(ref)[0]) n = n * 26 + ch.charCodeAt(0) - 64; return n; };
  H.xlsx = async (S, zip) => {
    S.kind = 'Excel workbook';
    const shared = [];
    const ss = await get(zip, 'xl/sharedStrings.xml');
    if (ss) for (const si of tags(ss, 'si')) shared.push(tags(si, 't').map(text).join(''));
    const wb = await get(zip, 'xl/workbook.xml'), rels = await get(zip, 'xl/_rels/workbook.xml.rels');
    const target = {}; if (rels) for (const r of tags(rels, 'Relationship')) target[r.getAttribute('Id')] = r.getAttribute('Target');
    const sheets = wb ? tags(wb, 'sheet') : [];
    for (const sh of sheets) {
      const name = sh.getAttribute('name'), state = sh.getAttribute('state') || 'visible';
      let t = target[sh.getAttribute('r:id')] || ''; t = t.startsWith('/') ? t.slice(1) : 'xl/' + t;
      const d = await get(zip, t); if (!d) continue;
      const hiddenCols = []; for (const c of tags(d, 'col')) if (c.getAttribute('hidden') === '1') hiddenCols.push([+c.getAttribute('min'), +c.getAttribute('max')]);
      const hid = new Map(), vis = [];
      for (const row of tags(d, 'row')) {
        const rowHidden = row.getAttribute('hidden') === '1';
        const cells = [];
        for (const c of tags(row, 'c')) {
          const ty = c.getAttribute('t'); let v = '';
          if (ty === 's') v = shared[+text(tags(c, 'v')[0] || { textContent: '' })] || '';
          else if (ty === 'inlineStr') v = tags(c, 't').map(text).join('');
          else if (ty === 'str') v = text(tags(c, 'v')[0] || { textContent: '' });
          if (!v) continue;
          const ci = colIndex(c.getAttribute('r') || 'A1');
          const colHidden = hiddenCols.some(([a, b]) => ci >= a && ci <= b);
          if (state !== 'visible') push(hid, 'hidden sheet "' + name + '"' + (state === 'veryHidden' ? ' (very hidden)' : ''), v);
          else if (rowHidden) push(hid, 'hidden row', v);
          else if (colHidden) push(hid, 'hidden column', v);
          else cells.push(v);
        }
        if (cells.length) vis.push(cells.join(' | '));
      }
      S.addPiece(vis.join('\n'), { hidden: false, technique: 'cell text', where: 'sheet ' + name });
      S.flush(hid, 'sheet ' + name);
    }
    for (const n of zip.entries.keys()) {
      if (/^xl\/comments\d*\.xml$/.test(n)) { const d = await get(zip, n); if (d) S.addPiece(tags(d, 'comment').map((c) => tags(c, 't').map(text).join('')).join('\n'), { hidden: true, technique: 'cell comment', where: n }); }
      if (/^xl\/threadedComments\/.*\.xml$/.test(n)) { const d = await get(zip, n); if (d) S.addPiece(tags(d, 'text').map(text).join('\n'), { hidden: true, technique: 'cell comment', where: n }); }
    }
    if (zip.entries.has('xl/vbaProject.bin')) S.notes.push('Contains VBA macros (vbaProject.bin).');
    await props(S, zip); await media(S, zip, 'xl/media/');
  };

  // ---------- OpenDocument ----------
  H.odf = async (S, zip) => {
    S.kind = 'OpenDocument file';
    const d = await get(zip, 'content.xml');
    if (d) {
      const hid = new Map();
      for (const el of d.getElementsByTagName('*')) if (el.getAttribute('text:display') === 'none' || el.getAttribute('text:condition') !== null && el.nodeName === 'text:hidden-paragraph') push(hid, 'hidden text (OpenDocument)', text(el));
      S.addPiece(text(d.documentElement), { hidden: false, technique: 'document text', where: 'content.xml' });
      S.flush(hid, 'content.xml');
    }
    await props(S, zip);
  };

  // ---------- generic archives and dispatch ----------
  H.zip = async (S, bytes, name) => {
    const zip = Roe.unzip(bytes);
    if (!zip) { S.kind = 'Archive'; S.notes.push('Could not read the archive.'); return; }
    zip.notes.forEach((x) => S.notes.push(x));
    const has = (n) => zip.entries.has(n);
    if (has('word/document.xml')) return H.docx(S, zip);
    if (has('ppt/presentation.xml')) return H.pptx(S, zip);
    if (has('xl/workbook.xml')) return H.xlsx(S, zip);
    if (has('mimetype') && has('content.xml')) return H.odf(S, zip);
    S.kind = 'Archive';
    let n = 0;
    for (const [en, e] of zip.entries) {
      if (n >= 80) { S.notes.push('Only the first 80 files in the archive were scanned.'); break; }
      if (e.size > 8 * 1024 * 1024 || /\.(exe|dll|so|dylib|class|jar|woff2?|ttf|otf|mp[34]|mov|avi|mkv|iso)$/i.test(en)) continue;
      n++;
      try { await S.scanInto(en, await e.read()); } catch (x) { S.notes.push(en + ': ' + x.message); }
    }
  };
})();
