// Roe: a small, defensive ZIP reader for Office files, archives and email attachments.
// Limits protect against zip bombs: declared and actual sizes are both capped.
(function () {
  const Roe = (self.Roe = self.Roe || {});
  const MAX_ENTRY = 12 * 1024 * 1024, MAX_TOTAL = 48 * 1024 * 1024, MAX_ENTRIES = 600;

  const u16 = (b, o) => b[o] | (b[o + 1] << 8);
  const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

  async function inflate(comp, cap) {
    const stream = new Blob([comp]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    const reader = stream.getReader();
    const parts = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > cap) { await reader.cancel(); throw new Error('entry too large'); }
      parts.push(value);
    }
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  // Returns { entries: Map(name -> { size, read() }), notes: [] } or null if bytes are not a ZIP.
  Roe.unzip = function (bytes) {
    let eocd = -1;
    for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
      if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 5 && bytes[i + 3] === 6) { eocd = i; break; }
    }
    if (eocd < 0) return null;
    const count = u16(bytes, eocd + 10);
    let p = u32(bytes, eocd + 16);
    const entries = new Map();
    const notes = [];
    let declared = 0;
    const dec = new TextDecoder();
    for (let n = 0; n < Math.min(count, MAX_ENTRIES) && p + 46 <= bytes.length; n++) {
      if (u32(bytes, p) !== 0x02014b50) break;
      const method = u16(bytes, p + 10), csize = u32(bytes, p + 20), usize = u32(bytes, p + 24);
      const nlen = u16(bytes, p + 28), elen = u16(bytes, p + 30), clen = u16(bytes, p + 32), off = u32(bytes, p + 42);
      const name = dec.decode(bytes.subarray(p + 46, p + 46 + nlen));
      p += 46 + nlen + elen + clen;
      if (name.endsWith('/')) continue;
      declared += usize;
      if (declared > MAX_TOTAL) { notes.push('Archive is very large; some entries were not read.'); break; }
      entries.set(name, {
        size: usize,
        async read() {
          if (usize > MAX_ENTRY) throw new Error('entry too large');
          if (u32(bytes, off) !== 0x04034b50) throw new Error('bad local header');
          const start = off + 30 + u16(bytes, off + 26) + u16(bytes, off + 28);
          const comp = bytes.subarray(start, start + csize);
          if (method === 0) return comp;
          if (method === 8) return inflate(comp, MAX_ENTRY);
          throw new Error('unsupported compression');
        }
      });
    }
    if (count > MAX_ENTRIES) notes.push('Archive has ' + count + ' entries; only the first ' + MAX_ENTRIES + ' were listed.');
    return { entries, notes };
  };

  Roe.inflateZlib = async function (bytes) {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  };
})();
