// Roe guard (org edition). Watches clicks and form submits on sensitive controls and, when the
// action is driven by an agent rather than a person, logs it and applies the org policy:
//   monitor  - log only
//   approve  - hold the action until someone approves it in a system notification (out of band,
//              so an agent driving this page cannot approve itself)
//   block    - stop the action
// "Agent-driven" means either a scripted event (isTrusted === false) or any event in a tab Roe
// has seen under automated control (a debugger session, which is how browser agents drive tabs).
(() => {
  if (self.ROE_EDITION !== 'org' || !self.Roe || !self.Roe.domainMode || window.__roeGuard) return;
  window.__roeGuard = true;

  const SEND = /\b(send|forward|reply|post|share|submit|publish|merge|deploy|invite)\b/i;
  const DANGER = /\b(delete|remove|revoke|disable|transfer|pay|confirm|approve|allow|authori[sz]e|grant|buy|purchase|checkout|withdraw|sign out|log ?out)\b/i;
  const RED = '#d13335', NAVY = '#0e2b80', CREAM = '#faecaa';
  const host = location.hostname;

  let policy = Roe.mergePolicy();
  let automated = false;
  let bypassEl = null, bypassForm = null, pending = false;
  const recent = new Map();

  const labelOf = (el) => (el.value && el.nodeName === 'INPUT' ? el.value : el.getAttribute('aria-label') || el.textContent || el.title || '').trim().replace(/\s+/g, ' ').slice(0, 60);
  const riskyForm = (f) => {
    if (!f) return '';
    if (f.querySelector('input[type=password]')) return 'Credentials form';
    if (f.querySelector('input[autocomplete^="cc-"],input[name*="card" i],input[name*="iban" i],input[name*="routing" i]')) return 'Payment form';
    try { if (new URL(f.getAttribute('action') || location.href, location.href).origin !== location.origin) return 'Form to another site'; } catch (e) { /* ignore */ }
    return '';
  };

  function sensitive(target) {
    const el = target && target.closest && target.closest('button,[role=button],input[type=submit],input[type=button],a[href]');
    if (!el) return null;
    const label = labelOf(el);
    if (el.nodeName === 'A') {
      const href = el.getAttribute('href') || '';
      if (/^mailto:/i.test(href)) return { el, label: label || 'Email link', kind: 'Email link' };
      if (el.hasAttribute('download')) return { el, label: label || 'Download', kind: 'Download link' };
      return null;
    }
    if (DANGER.test(label)) return { el, label, kind: 'Sensitive button' };
    if (SEND.test(label)) return { el, label, kind: 'Send button' };
    const form = el.form || el.closest('form');
    const fk = (el.type === 'submit' || el.nodeName === 'BUTTON') && riskyForm(form);
    if (fk) return { el, label: label || 'Submit', kind: fk };
    return null;
  }

  function log(type, s, extra) {
    const key = type + '|' + s.label;
    const now = Date.now();
    if (recent.get(key) > now - 4000) return;
    recent.set(key, now);
    try { chrome.runtime.sendMessage({ type: 'roe:activity', event: { type, label: s.label, control: s.kind, url: location.href, host, ...extra } }); } catch (e) { /* extension reloaded */ }
  }

  // ---------- a small notice in the page, drawn in a closed shadow root ----------
  let toastHost = null, toastTimer = 0;
  function toast(title, body, tone) {
    if (!toastHost) {
      toastHost = document.createElement('div');
      toastHost.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:2147483647;';
      toastHost.attachShadow({ mode: 'open' });
    }
    const root = toastHost.shadowRoot;
    root.replaceChildren();
    const box = document.createElement('div');
    box.style.cssText = 'font:13px/1.45 system-ui,-apple-system,sans-serif;width:320px;max-width:calc(100vw - 32px);background:' + NAVY + ';color:' + CREAM +
      ';border-top:4px solid ' + (tone === 'bad' ? RED : tone === 'ok' ? CREAM : RED) + ';box-shadow:0 8px 28px rgba(9,30,92,.35);padding:12px 14px;opacity:0;transform:translateY(8px);transition:opacity .18s ease,transform .18s ease;';
    const t = document.createElement('div');
    t.style.cssText = 'font-weight:600;margin-bottom:3px;';
    t.textContent = 'Roe: ' + title;
    const b = document.createElement('div');
    b.style.cssText = 'opacity:.85;';
    b.textContent = body;
    box.append(t, b);
    root.append(box);
    if (!toastHost.isConnected) document.documentElement.append(toastHost);
    requestAnimationFrame(() => { box.style.opacity = '1'; box.style.transform = 'none'; });
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { box.style.opacity = '0'; setTimeout(() => toastHost && toastHost.remove(), 200); }, tone === 'wait' ? (policy.timeoutSec || 90) * 1000 : 6000);
  }

  function decide(ev, s, isSubmit) {
    const scripted = !ev.isTrusted;
    if (!scripted && !automated) return;          // a person, in a tab nobody is driving
    const mode = Roe.domainMode(policy, host);
    const why = automated ? 'automated' : 'scripted';
    const hold = mode === 'block' || mode === 'approve' || (automated && policy.holdAutomated) || (scripted && policy.holdScripted);
    if (!hold) { log('agent-action', s, { why, outcome: 'allowed' }); return; }

    ev.preventDefault();
    ev.stopImmediatePropagation();
    if (mode === 'block') {
      log('action-blocked', s, { why });
      toast('blocked an automated action', '“' + s.label + '” on ' + host + ' is blocked by your organization’s policy.', 'bad');
      return;
    }
    if (pending) return;
    pending = true;
    toast('holding an automated action', '“' + s.label + '” on ' + host + ' is waiting for approval. Approve or deny it in the system notification.', 'wait');
    chrome.runtime.sendMessage({ type: 'roe:approve', label: s.label, control: s.kind, url: location.href, host, why }).then((res) => {
      pending = false;
      if (res && res.approved) {
        toast('action approved', '“' + s.label + '” was approved and has been carried out.', 'ok');
        if (isSubmit) { bypassForm = s.form; try { s.form.requestSubmit(); } catch (e) { s.form.submit(); } }
        else { bypassEl = s.el; bypassForm = s.el.form || null; s.el.click(); }
      } else {
        toast('action stopped', '“' + s.label + '” was ' + ((res && res.reason) || 'denied') + '. Nothing was sent.', 'bad');
      }
    }).catch(() => { pending = false; });
  }

  window.addEventListener('click', (ev) => {
    if (bypassEl && ev.target && (ev.target === bypassEl || bypassEl.contains(ev.target))) { bypassEl = null; return; }
    const s = sensitive(ev.target);
    if (s) decide(ev, s, false);
  }, true);

  window.addEventListener('submit', (ev) => {
    const form = ev.target;
    if (bypassForm && form === bypassForm) { bypassForm = null; return; }
    const kind = riskyForm(form);
    if (!kind) return;
    const btn = ev.submitter;
    decide(ev, { el: btn || form, form, label: (btn && labelOf(btn)) || 'Submit form', kind }, true);
  }, true);

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === 'roe:automation') automated = !!msg.on;
  });
  const loadPolicy = async () => {
    const [{ policy: local }, managed] = await Promise.all([
      chrome.storage.local.get('policy'),
      chrome.storage.managed ? chrome.storage.managed.get(null).catch(() => ({})) : {}
    ]);
    policy = Roe.mergePolicy(local, managed && managed.policy);
  };
  chrome.storage.onChanged.addListener((c, area) => { if (c.policy || area === 'managed') loadPolicy(); });
  loadPolicy();
  chrome.runtime.sendMessage({ type: 'roe:automation-state' }).then((r) => { automated = !!(r && r.on); }).catch(() => {});
})();
