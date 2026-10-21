// Roe: images. Three layers, from cheapest to most thorough:
//  1. what is stored in the file (text chunks, comments, EXIF, XMP, data appended after the image);
//  2. near-invisible two-tone patterns on flat backgrounds (faint text), with a contrast-boosted preview;
//  3. optional OCR (browser TextDetector, or Tesseract placed in vendor/tesseract/, see README).
(function () {
  const Roe = (self.Roe = self.Roe || {});
  const H = (Roe.handlers = Roe.handlers || {});
  const latin = (b) => { let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return s; };
  const utf8 = (b) => new TextDecoder('utf-8').decode(b);
  const u32be = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  const u32le = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

  function xmp(S, text) {
    const bits = [];
    const body = /<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/.exec(text);
    if (!body) return;
    body[0].replace(/\s([\w:-]+)="([^"]{15,})"/g, (m, k, v) => { if (!/^(xmlns|rdf:about|xmp:CreatorTool|stRef)/.test(k)) bits.push(v); return m; });
    body[0].replace(/<[^>]+>([^<]{15,})<\/[^>]+>/g, (m, v) => { bits.push(v.trim()); return m; });
    S.addPiece(bits.join('\n'), { hidden: true, technique: 'XMP metadata', attr: true });
  }
  const trailing = (S, b, from) => {
    if (b.length - from > 16) S.addPiece(Roe.printableRuns(b.subarray(from), 20).join('\n'), { hidden: true, technique: 'data appended after the end of the image' });
  };

  function png(S, b) {
    let p = 8, end = b.length;
    while (p + 12 <= b.length) {
      const len = u32be(b, p), type = latin(b.subarray(p + 4, p + 8));
      const d = b.subarray(p + 8, p + 8 + len);
      const z = d.indexOf(0);
      if (type === 'tEXt' && z > 0) S.addPiece(utf8(d.subarray(z + 1)), { hidden: true, technique: 'PNG text chunk "' + latin(d.subarray(0, z)) + '"', attr: true });
      else if (type === 'zTXt' && z > 0) S._jobs.push(Roe.inflateZlib(d.subarray(z + 2)).then((x) => S.addPiece(utf8(x), { hidden: true, technique: 'PNG compressed text chunk "' + latin(d.subarray(0, z)) + '"', attr: true })).catch(() => {}));
      else if (type === 'iTXt' && z > 0) {
        const comp = d[z + 1]; let q = z + 3; q = d.indexOf(0, q) + 1; q = d.indexOf(0, q) + 1;
        const tail = d.subarray(q);
        const kw = latin(d.subarray(0, z));
        if (comp) S._jobs.push(Roe.inflateZlib(tail).then((x) => S.addPiece(utf8(x), { hidden: true, technique: 'PNG text chunk "' + kw + '"', attr: true })).catch(() => {}));
        else { const t = utf8(tail); if (kw === 'XML:com.adobe.xmp') xmp(S, t); else S.addPiece(t, { hidden: true, technique: 'PNG text chunk "' + kw + '"', attr: true }); }
      } else if (type === 'eXIf') S.addPiece(Roe.printableRuns(d, 12).join('\n'), { hidden: true, technique: 'EXIF metadata', attr: true });
      p += 12 + len;
      if (type === 'IEND') { end = p; break; }
    }
    trailing(S, b, end);
  }

  function jpeg(S, b) {
    let p = 2;
    while (p + 4 <= b.length) {
      if (b[p] !== 0xff) { p++; continue; }
      const m = b[p + 1];
      if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7) || m === 0xff) { p += m === 0xff ? 1 : 2; continue; }
      if (m === 0xda) break;
      const len = (b[p + 2] << 8) | b[p + 3], seg = b.subarray(p + 4, p + 2 + len);
      if (m === 0xfe) S.addPiece(utf8(seg), { hidden: true, technique: 'JPEG comment', attr: true });
      else if (m === 0xe1) {
        const head = latin(seg.subarray(0, 30));
        if (head.startsWith('Exif')) S.addPiece(Roe.printableRuns(seg, 12).join('\n'), { hidden: true, technique: 'EXIF metadata', attr: true });
        else if (head.startsWith('http://ns.adobe.com/xap')) xmp(S, utf8(seg));
      }
      p += 2 + len;
    }
    let e = b.length - 2; while (e > 2 && !(b[e] === 0xff && b[e + 1] === 0xd9)) e--;
    if (e > 2) trailing(S, b, e + 2);
  }

  function gif(S, b) {
    let p = 13;
    if (b[10] & 0x80) p += 3 * (1 << ((b[10] & 7) + 1));
    const subs = () => { let t = ''; while (p < b.length && b[p]) { t += latin(b.subarray(p + 1, p + 1 + b[p])); p += b[p] + 1; } p++; return t; };
    while (p < b.length) {
      if (b[p] === 0x3b) { trailing(S, b, p + 1); break; }
      if (b[p] === 0x21) { const label = b[p + 1]; p += 2; const t = subs(); if (label === 0xfe) S.addPiece(t, { hidden: true, technique: 'GIF comment', attr: true }); }
      else if (b[p] === 0x2c) { const f = b[p + 9]; p += 10; if (f & 0x80) p += 3 * (1 << ((f & 7) + 1)); p++; subs(); }
      else break;
    }
  }

  function webp(S, b) {
    let p = 12;
    while (p + 8 <= b.length) {
      const type = latin(b.subarray(p, p + 4)), len = u32le(b, p + 4), d = b.subarray(p + 8, p + 8 + len);
      if (type === 'EXIF') S.addPiece(Roe.printableRuns(d, 12).join('\n'), { hidden: true, technique: 'EXIF metadata', attr: true });
      else if (type === 'XMP ') xmp(S, utf8(d));
      p += 8 + len + (len & 1);
    }
  }

  // ---------- pixels ----------
  function makeCanvas(w, h) { return typeof OffscreenCanvas !== 'undefined' ? new OffscreenCanvas(w, h) : Object.assign(document.createElement('canvas'), { width: w, height: h }); }
  const toURL = async (cv) => cv.convertToBlob ? URL.createObjectURL(await cv.convertToBlob()) : cv.toDataURL('image/png');

  // Flat background + a second value a few levels away, in text-sized patches: faint text.
  function faint(img) {
    const { data, width: w, height: h } = img;
    const uniq = new Set();
    for (let i = 0; i < data.length && uniq.size <= 2500; i += 28) uniq.add((data[i] << 16) | (data[i + 1] << 8) | data[i + 2]);
    if (uniq.size > 2500) return null;                  // a photograph: noise would look like faint text
    const T = 16, tiles = [];
    for (let ty = 0; ty + T <= h; ty += T) for (let tx = 0; tx + T <= w; tx += T) {
      const counts = new Map(); let lo = 255, hi = 0, bad = false;
      for (let y = 0; y < T && !bad; y++) for (let x = 0; x < T; x++) {
        const o = ((ty + y) * w + tx + x) * 4, l = (data[o] * 3 + data[o + 1] * 6 + data[o + 2]) / 10 | 0;
        counts.set(l, (counts.get(l) || 0) + 1);
        if (l < lo) lo = l; if (l > hi) hi = l;
        if (counts.size > 5) { bad = true; break; }
      }
      const range = hi - lo;
      if (bad || range < 1 || range > 40) continue;
      const c = [...counts.values()].sort((a, b) => b - a);
      if (c.length >= 2 && c[1] / (T * T) >= 0.04) tiles.push([tx, ty, lo, hi]);
    }
    return tiles.length >= 10 ? tiles : null;
  }

  async function enhanced(img, tiles) {            // reveal faint patches at full contrast
    const { width: w, height: h } = img, out = new ImageData(w, h);
    out.data.fill(255);
    for (const [tx, ty, lo, hi] of tiles) for (let y = 0; y < 16; y++) for (let x = 0; x < 16; x++) {
      const o = ((ty + y) * w + tx + x) * 4, l = (img.data[o] * 3 + img.data[o + 1] * 6 + img.data[o + 2]) / 10, v = Math.max(0, Math.min(255, (l - lo) * 255 / Math.max(1, hi - lo)));
      out.data[o] = out.data[o + 1] = out.data[o + 2] = v;
    }
    const cv = makeCanvas(w, h); cv.getContext('2d').putImageData(out, 0, 0);
    return toURL(cv);
  }

  function localStretch(img) {                      // local contrast boost so OCR can read low-contrast text
    const { width: w, height: h } = img, out = new ImageData(w, h), T = 32;
    for (let ty = 0; ty < h; ty += T) for (let tx = 0; tx < w; tx += T) {
      let lo = 255, hi = 0;
      for (let y = ty; y < Math.min(h, ty + T); y++) for (let x = tx; x < Math.min(w, tx + T); x++) { const l = img.data[(y * w + x) * 4 + 1]; if (l < lo) lo = l; if (l > hi) hi = l; }
      const k = hi - lo >= 2 && hi - lo <= 80 ? 255 / (hi - lo) : 1, base = k === 1 ? 0 : lo;
      for (let y = ty; y < Math.min(h, ty + T); y++) for (let x = tx; x < Math.min(w, tx + T); x++) { const o = (y * w + x) * 4, v = Math.max(0, Math.min(255, (img.data[o + 1] - base) * k)); out.data[o] = out.data[o + 1] = out.data[o + 2] = v; out.data[o + 3] = 255; }
    }
    const cv = makeCanvas(w, h); cv.getContext('2d').putImageData(out, 0, 0); return cv;
  }

  let engine;
  async function ocrEngine() {
    if (engine !== undefined) return engine;
    engine = null;
    if (typeof TextDetector !== 'undefined') { try { const d = new TextDetector(); engine = async (cv) => (await d.detect(cv)).map((x) => x.rawValue).join('\n'); return engine; } catch (e) { /* not supported */ } }
    try {
      const base = chrome.runtime.getURL('vendor/tesseract/');
      if (!(await fetch(base + 'tesseract.min.js', { method: 'HEAD' })).ok) return engine;
      await new Promise((res, rej) => { const s = document.createElement('script'); s.src = base + 'tesseract.min.js'; s.onload = res; s.onerror = rej; document.head.appendChild(s); });
      const worker = await self.Tesseract.createWorker('eng', 1, { workerPath: base + 'worker.min.js', corePath: base, langPath: base, workerBlobURL: false });
      engine = async (cv) => { const blob = cv.convertToBlob ? await cv.convertToBlob() : await new Promise((r) => cv.toBlob(r)); return (await worker.recognize(blob)).data.text; };
    } catch (e) { engine = null; }
    return engine;
  }

  async function pixels(S, b, mime) {
    if (typeof createImageBitmap !== 'function') return;
    let bmp;
    try { bmp = await createImageBitmap(new Blob([b], { type: mime })); } catch (e) { S.notes.push('Could not decode the image pixels.'); return; }
    const k = Math.min(1, 1600 / Math.max(bmp.width, bmp.height)), w = Math.max(1, Math.round(bmp.width * k)), h = Math.max(1, Math.round(bmp.height * k));
    const cv = makeCanvas(w, h), ctx = cv.getContext('2d', { willReadFrequently: true });
    ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, w, h); ctx.drawImage(bmp, 0, 0, w, h);
    const img = ctx.getImageData(0, 0, w, h);
    S.extra = Object.assign(S.extra || {}, { width: bmp.width, height: bmp.height });
    const tiles = faint(img);
    if (tiles) {
      S.extra.enhanced = await enhanced(img, tiles);
      const f = { kind: 'file', cat: 'obfuscation', cats: ['obfuscation'], refs: ['anthropic_browser'], anthropic: true, technique: 'near-invisible patterns in the image', hidden: true, level: 'medium', score: 45,
        rules: [{ id: 'faint-image-text', label: 'Flat background with patches a few shades apart, shaped like text a person would not notice' }],
        snippet: tiles.length + ' patches of near-invisible two-tone detail. Open the contrast-boosted preview to read them.', where: S.path, sinks: [] };
      f.id = Roe.hash('faint|' + S.path);
      S.addFinding(f);
    }
    const ocr = await ocrEngine();
    if (!ocr) { S.notes.push('Text inside the image pixels was not read: no OCR engine is installed (see README).'); return; }
    const plain = await ocr(cv).catch(() => '');
    S.addPiece(plain, { hidden: false, technique: 'text read from the image (OCR)' });
    const boosted = (await ocr(localStretch(img)).catch(() => ''));
    const seen = new Set(plain.split('\n').map((l) => l.trim().toLowerCase()));
    S.addPiece(boosted.split('\n').filter((l) => l.trim() && !seen.has(l.trim().toLowerCase())).join('\n'), { hidden: true, technique: 'faint text found only after a contrast boost (OCR)' });
  }

  async function image(S, b, fmt, mime, kind) {
    S.kind = kind; S._jobs = [];
    if (fmt === 'png') png(S, b); else if (fmt === 'jpeg') jpeg(S, b); else if (fmt === 'gif') gif(S, b); else if (fmt === 'webp') webp(S, b);
    if (fmt !== 'png') xmp(S, latin(b.subarray(0, 200000)));
    await Promise.all(S._jobs);
    await pixels(S, b, mime);
  }
  H.png = (S, b) => image(S, b, 'png', 'image/png', 'PNG image');
  H.jpeg = (S, b) => image(S, b, 'jpeg', 'image/jpeg', 'JPEG image');
  H.gif = (S, b) => image(S, b, 'gif', 'image/gif', 'GIF image');
  H.webp = (S, b) => image(S, b, 'webp', 'image/webp', 'WebP image');
})();
