// Roe offscreen document: the service worker has no DOM, so documents and images are decoded here.
// Receives { type: 'roe:off-scan', url, name, max }, fetches without cookies, scans, returns findings only.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== 'roe:off-scan') return false;
  (async () => {
    try {
      const max = msg.max || 40 * 1024 * 1024;
      const r = await fetch(msg.url, { credentials: 'omit', cache: 'force-cache', referrerPolicy: 'no-referrer' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      if ((+r.headers.get('content-length') || 0) > max) throw new Error('too large');
      const bytes = new Uint8Array(await r.arrayBuffer());
      if (bytes.length > max) throw new Error('too large');
      const res = await Roe.scanFile({ name: msg.name || 'file', bytes });
      if (res.extra) delete res.extra.enhanced;      // blob URLs do not outlive this document
      sendResponse({ ok: true, res });
    } catch (e) { sendResponse({ ok: false, error: (e && e.message) || String(e) }); }
  })();
  return true;
});
