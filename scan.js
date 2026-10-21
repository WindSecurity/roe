const { CATS, REFS } = Roe;
const results = document.getElementById('results');
const reports = [];
const LEVEL = { high: 'High risk', medium: 'Medium risk', low: 'Weak signal' };

function el(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }
const fmt = (n) => (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB');
function link(ref) { const a = el('a', '', ref.name); if (ref.url) { a.href = ref.url; a.target = '_blank'; a.rel = 'noreferrer noopener'; } return a; }

function card(f) {
  const li = el('li', 'card ' + f.level);
  const top = el('div', 'top');
  top.append(el('span', 'level', LEVEL[f.level]), el('span', 'how', (f.hidden ? 'Hidden: ' : 'Visible: ') + f.technique));
  li.append(top);
  const tags = el('div', 'tags');
  tags.append(el('span', 'tag cat', CATS[f.cat] || f.cat));
  if (f.anthropic) tags.append(el('span', 'tag anth', 'Anthropic-discussed'));
  li.append(tags);
  li.append(el('p', 'surfnote', 'Where: ' + f.where));
  const split = el('dl', 'split');
  const a = el('div', 'yousee'); a.append(el('dt', '', 'You see'), el('dd', '', f.hidden ? 'Nothing. Opening the file normally does not show it.' : 'This text, in plain view.'));
  const b = el('div', 'agent'); b.append(el('dt', '', 'An agent reads'), el('dd', '', '\u201C' + f.snippet + '\u201D'));
  split.append(a, b); li.append(split);
  li.append(el('p', 'why', f.rules.map((r) => r.label).join('. ') + '.'));
  const refs = (f.refs || []).map((k) => REFS[k]).filter(Boolean);
  if (refs.length) { const p = el('p', 'seen', 'Seen in: '); refs.forEach((r, i) => { if (i) p.append(document.createTextNode(' \u00B7 ')); p.append(link(r)); }); li.append(p); }
  return li;
}

function render(box, res, file) {
  box.replaceChildren();
  const strong = res.findings.filter((f) => f.level !== 'low'), weak = res.findings.filter((f) => f.level === 'low');
  box.className = 'file' + (strong.length ? ' bad' : '');
  const head = el('div', 'head');
  head.append(el('span', 'name', res.name), el('span', 'meta', res.kind + ' \u00B7 ' + fmt(res.size)));
  const v = el('strong', '', strong.length ? strong.length + (strong.length === 1 ? ' possible attack on an AI agent' : ' possible attacks on an AI agent') : weak.length ? 'Only weak signals' : 'No attack signals found');
  head.append(v);
  box.append(head);
  const body = el('div', 'body');
  if (file && /^image\//.test(file.type)) {
    const th = el('div', 'thumbs');
    const fig = el('figure'); const im = el('img'); im.src = URL.createObjectURL(file); im.alt = ''; fig.append(im, el('figcaption', '', 'As a person sees it'));
    th.append(fig);
    if (res.extra && res.extra.enhanced) { const f2 = el('figure'); const i2 = el('img'); i2.src = res.extra.enhanced; i2.alt = ''; f2.append(i2, el('figcaption', '', 'Contrast boosted: faint patches revealed')); th.append(f2); }
    body.append(th);
  }
  if (res.notes.length) body.append(el('p', 'notes', res.notes.join(' ')));
  if (res.children && res.children.length) body.append(el('p', 'kids', 'Also scanned inside: ' + res.children.map((c) => c.name + (c.flagged ? ' (' + c.flagged + ' flagged)' : '')).join(', ')));
  const ul = el('ul'); strong.forEach((f) => ul.append(card(f))); body.append(ul);
  if (weak.length) { const d = el('details'); d.append(el('summary', '', 'Weak signals (' + weak.length + ')')); const wl = el('ul'); weak.forEach((f) => wl.append(card(f))); d.append(wl); body.append(d); }
  if (!res.findings.length) body.append(el('p', 'foot', 'Roe matches known patterns and hidden-text tricks. A clean result does not prove a file is safe.'));
  box.append(body);
}

async function handle(files) {
  document.getElementById('copyall').hidden = false;
  for (const file of Array.from(files).slice(0, 60)) {
    const box = el('div', 'file'); box.append(el('div', 'head', 'Scanning ' + file.name + '\u2026')); results.prepend(box);
    if (file.size > 80 * 1024 * 1024) { render(box, { name: file.name, size: file.size, kind: 'File', findings: [], notes: ['Skipped: larger than 80 MB.'] }); continue; }
    const res = await Roe.scanFile({ name: file.webkitRelativePath || file.name, bytes: new Uint8Array(await file.arrayBuffer()) });
    reports.push(res);
    render(box, res, file);
  }
}

const drop = document.getElementById('drop'), pick = document.getElementById('pick'), dir = document.getElementById('pickdir');
drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick.click(); } });
drop.addEventListener('click', (e) => { if (e.target !== pick) { e.preventDefault(); pick.click(); } });
['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', (e) => handle(e.dataTransfer.files));
pick.addEventListener('change', () => handle(pick.files));
dir.addEventListener('change', () => handle(dir.files));
document.getElementById('folder').addEventListener('click', () => dir.click());
document.getElementById('copyall').addEventListener('click', async (e) => {
  await navigator.clipboard.writeText(JSON.stringify(reports.map((r) => ({ file: r.name, kind: r.kind, notes: r.notes, findings: r.findings.map((f) => ({ level: f.level, category: f.cat, technique: f.technique, hidden: f.hidden, where: f.where, sources: f.refs, text: f.snippet })) })), null, 2));
  e.target.textContent = 'Copied';
});

// results of files Roe scanned right after they were downloaded
(async () => {
  const { downloadScans = [] } = await chrome.storage.local.get('downloadScans');
  const want = /^#dl=(\d+)$/.exec(location.hash);
  const show = (rec) => {
    const box = el('div', 'file');
    results.append(box);
    if (rec.error) render(box, { name: rec.name, size: 0, kind: 'Download', findings: [], notes: [rec.error === 'file-access' ? 'Roe could not read this download. Turn on \u201CAllow access to file URLs\u201D for Roe in chrome://extensions.' : 'Roe could not read this download (' + rec.error + ').'] });
    else render(box, { name: rec.name, size: 0, kind: rec.kind, findings: rec.findings, notes: rec.notes, children: [] });
  };
  if (want) { const rec = downloadScans.find((d) => String(d.id) === want[1]); if (rec) show(rec); }
  const rest = downloadScans.filter((d) => !want || String(d.id) !== want[1]);
  if (rest.length) {
    const recent = document.getElementById('recent');
    recent.append(el('h2', '', 'Recent downloads Roe scanned'));
    for (const rec of rest.slice(0, 10)) {
      const d = el('details'); const n = rec.findings.filter((f) => f.level !== 'low').length;
      d.append(el('summary', '', rec.name + (rec.error ? ' (not scanned)' : n ? ' (' + n + ' flagged)' : ' (clean)')));
      const box = el('div', 'file');
      if (rec.error) render(box, { name: rec.name, size: 0, kind: 'Download', findings: [], notes: ['Not scanned: ' + rec.error] });
      else render(box, { name: rec.name, size: 0, kind: rec.kind, findings: rec.findings, notes: rec.notes, children: [] });
      d.append(box); recent.append(d);
    }
  }
})();
