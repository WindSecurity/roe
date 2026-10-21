// Roe sink mapper. Two inputs:
//  1. what the suspicious text asks for (intent sinks), inferred from its wording
//  2. which sensitive controls actually exist on this page (page sinks)
// A match means "possible path", never "observed action".
(function () {
  const Roe = (self.Roe = self.Roe || {});

  const INTENT = [
    { id: 'email', label: 'Send or forward email', re: /\b(e-?mail|inbox|gmail|outlook|forward|mailto)\b|[\w.-]+@[\w-]+\.[a-z]{2,}/i },
    { id: 'transfer', label: 'Send data to an outside address', re: /https?:\/\/|\bwebhook\b|\bupload\b|\bexfiltrat\w*/i },
    { id: 'payment', label: 'Payment, payout or bank-detail change', re: /\b(pay|payment|payout|wire|transfer funds|bank account|iban|routing number|invoice|refund|purchase|checkout)\b/i },
    { id: 'credentials', label: 'Credentials, tokens or consent', re: /\b(password|passcode|api[ -]?key|token|secret|cookies?|session|oauth|authori[sz]e|grant access|2fa|otp|ssh)\b/i },
    { id: 'destructive', label: 'Delete data or change permissions', re: /\b(delete|remove|disable|revoke|reset|change (the )?(password|settings|permissions?|owner)|add (a )?user|invite)\b/i },
    { id: 'execute', label: 'Run commands or install software', re: /\b(execute|install|curl|wget|powershell|bash|terminal|pip install|npm install)\b/i },
    { id: 'disclose', label: 'Disclose the AI\u2019s prompt or private context', re: /\b(system prompt|hidden prompt|your instructions|conversation history|previous messages)\b/i }
  ];

  // Which page-level sink kinds make each intent reachable from this page.
  const REACH = {
    email: ['mailto', 'send-button'],
    transfer: ['form-external', 'file-upload', 'send-button'],
    payment: ['payment-field', 'danger-button'],
    credentials: ['password', 'oauth', 'danger-button'],
    destructive: ['danger-button']
  };

  const SEND = /\b(send|forward|reply|post|share|submit)\b/i;
  const DANGER = /\b(delete|remove|revoke|disable|transfer|pay|confirm|approve|allow|authorize|grant)\b/i;
  const OAUTH = /[?&]client_id=|\/oauth2?\/(v\d+(\.\d+)?\/)?authori[sz]e|\/o\/oauth2\/|\/consent\b/i;

  Roe.intentSinks = (text) => INTENT.filter((s) => s.re.test(text)).map(({ id, label }) => ({ id, label }));

  Roe.pageSinks = function (doc) {
    const out = [];
    const counts = {};
    const push = (kind, label, detail) => {
      counts[kind] = (counts[kind] || 0) + 1;
      if (counts[kind] <= 6) out.push({ kind, label, detail: detail || '' });
    };
    const loc = doc.location;

    for (const f of doc.forms) {
      let target;
      try { target = new URL(f.getAttribute('action') || loc.href, loc.href); } catch (e) { continue; }
      if (target.origin !== loc.origin) push('form-external', 'Form that submits to another site', target.host);
      if (f.querySelector('input[type=password]')) push('password', 'Password field', '');
    }
    for (const a of doc.querySelectorAll('a[href^="mailto:" i]')) push('mailto', 'Email link', (a.getAttribute('href') || '').slice(7, 47));
    if (doc.querySelector('input[type=file]')) push('file-upload', 'File upload control', '');
    if (doc.querySelector('input[autocomplete^="cc-"],input[name*="card" i],input[name*="iban" i],input[name*="routing" i]')) {
      push('payment-field', 'Payment or bank field', '');
    }
    if (OAUTH.test(loc.href)) push('oauth', 'This page looks like an OAuth consent screen', loc.host);
    for (const a of doc.querySelectorAll('a[href*="client_id="]')) {
      try { push('oauth', 'Link to an OAuth authorization', new URL(a.href).host); } catch (e) { /* ignore */ }
      if (counts.oauth >= 6) break;
    }
    let seen = 0;
    for (const b of doc.querySelectorAll('button,input[type=submit],input[type=button],[role=button]')) {
      if (++seen > 400) break;
      const label = (b.value || b.textContent || b.getAttribute('aria-label') || '').trim().replace(/\s+/g, ' ').slice(0, 40);
      if (!label) continue;
      if (DANGER.test(label)) push('danger-button', 'Button \u201C' + label + '\u201D', '');
      else if (SEND.test(label)) push('send-button', 'Button \u201C' + label + '\u201D', '');
    }
    return out;
  };

  Roe.linkSinks = function (intents, sinks) {
    return intents.map((i) => {
      const kinds = REACH[i.id] || [];
      const hit = sinks.filter((s) => kinds.includes(s.kind));
      return {
        id: i.id,
        label: i.label,
        present: hit.length > 0,
        examples: hit.slice(0, 2).map((h) => h.label + (h.detail ? ' (' + h.detail + ')' : ''))
      };
    });
  };
})();
