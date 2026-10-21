// Roe: PDF reader built on a bundled copy of PDF.js (Apache-2.0, see vendor/LICENSE-pdfjs.txt).
(function () {
  const Roe = (self.Roe = self.Roe || {});
  let lib = null;
  async function pdfjs() {
    if (lib) return lib;
    lib = await import(chrome.runtime.getURL('vendor/pdf.min.mjs'));
    lib.GlobalWorkerOptions.workerSrc = chrome.runtime.getURL('vendor/pdf.worker.min.mjs');
    return lib;
  }
  const push = (map, k, v) => { if (!map.has(k)) map.set(k, []); map.get(k).push(v); };

  Roe.handlers.pdf = async (S, bytes) => {
    S.kind = 'PDF document';
    const P = await pdfjs();
    const task = P.getDocument({ data: bytes.slice(), isEvalSupported: false, disableFontFace: true, verbosity: 0, wasmUrl: chrome.runtime.getURL('vendor/wasm/') });
    const doc = await task.promise;
    try {
      // document properties and XMP metadata
      const props = new Map();
      try {
        const md = await doc.getMetadata();
        for (const [k, v] of Object.entries(md.info || {})) if (typeof v === 'string' && v.length > 8 && !/^(PDFFormatVersion|Producer|CreationDate|ModDate)$/.test(k)) push(props, 'document property: ' + k, v);
        if (md.metadata) for (const [k, v] of md.metadata.getAll ? Object.entries(md.metadata.getAll()) : []) if (typeof v === 'string' && v.length > 8) push(props, 'XMP metadata: ' + k, v);
      } catch (e) { /* no metadata */ }
      S.flush(props, 'properties');

      const pages = Math.min(doc.numPages, 150);
      if (doc.numPages > pages) S.notes.push('Only the first ' + pages + ' of ' + doc.numPages + ' pages were scanned.');
      let chars = 0;
      for (let p = 1; p <= pages && chars < 500000; p++) {
        const page = await doc.getPage(p);
        const view = page.view, where = 'page ' + p;
        // which strings are drawn in white or in the invisible render mode (found through the drawing operators)
        const norm = (x) => x.replace(/\s+/g, ' ').trim();
        const white = new Set(), invisible = new Set();
        try {
          const ops = await page.getOperatorList(), O = P.OPS;
          let fill = [0, 0, 0], mode = 0; const stack = [];
          for (let i = 0; i < ops.fnArray.length; i++) {
            const fn = ops.fnArray[i], a = ops.argsArray[i];
            if (fn === O.save) stack.push([fill, mode]);
            else if (fn === O.restore) { const st = stack.pop(); if (st) [fill, mode] = st; }
            else if (fn === O.setFillRGBColor) fill = typeof a[0] === 'string' ? [1, 3, 5].map((k) => parseInt(a[0].slice(k, k + 2), 16)) : a;
            else if (fn === O.setTextRenderingMode) mode = a[0];
            else if (fn === O.showText || fn === O.showSpacedText) {
              const t = norm((a[0] || []).map((g) => (g && g.unicode) || '').join(''));
              if (t.length < 3) continue;
              if (mode === 3) invisible.add(t);
              else if (fill && fill.length >= 3 && fill[0] >= 240 && fill[1] >= 240 && fill[2] >= 240) white.add(t);
            }
          }
        } catch (e) { /* operator list unavailable */ }
        const inSet = (set, t) => set.has(t) || (t.length >= 12 && set.size <= 200 && [...set].some((w) => w.includes(t)));

        const tc = await page.getTextContent();
        let vis = '';
        const hid = new Map();
        for (const it of tc.items) {
          if (!('str' in it) || !it.str.trim()) { if (it.hasEOL) vis += '\n'; continue; }
          const t = it.transform, size = Math.hypot(t[2], t[3]), ns = norm(it.str);
          if (inSet(invisible, ns)) push(hid, 'invisible text (render mode 3)', it.str);
          else if (inSet(white, ns)) push(hid, 'white text', it.str);
          else if (size > 0 && size < 2) push(hid, 'tiny text (under 2 pt)', it.str);
          else if (t[4] < view[0] - 5 || t[4] > view[2] + 5 || t[5] < view[1] - 5 || t[5] > view[3] + 5) push(hid, 'text placed outside the page', it.str);
          else vis += it.str + (it.hasEOL ? '\n' : ' ');
        }
        chars += vis.length;
        S.addPiece(vis, { hidden: false, technique: 'page text', where });
        S.flush(hid, where);

        // annotations and form fields
        const ann = new Map();
        try {
          for (const a of await page.getAnnotations()) {
            const v = [a.contentsObj && a.contentsObj.str, a.contents, a.alternativeText, typeof a.fieldValue === 'string' ? a.fieldValue : Array.isArray(a.fieldValue) ? a.fieldValue.join(' ') : ''].filter((x) => x && x.length > 12);
            for (const s of v) push(ann, a.fieldType ? 'form field value' : 'PDF annotation', s);
          }
        } catch (e) { /* none */ }
        S.flush(ann, where, { attr: true });
        page.cleanup();
      }

      // embedded files
      try {
        const att = await doc.getAttachments();
        for (const k of Object.keys(att || {})) { S.notes.push('Embedded file: ' + att[k].filename); await S.scanInto(att[k].filename, att[k].content); }
      } catch (e) { /* none */ }
    } finally { try { await doc.destroy(); } catch (e) { /* ignore */ } }
  };
})();
