// Roe exposure: what sensitive data on this page an AI agent reading it would also read.
// Only counts and masked samples leave this function; the values themselves are never stored.
(function () {
  const Roe = (self.Roe = self.Roe || {});

  const luhn = (d) => {
    let sum = 0, alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let n = d.charCodeAt(i) - 48;
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  };
  const head = (s, n) => s.slice(0, n) + '••••';

  const TYPES = [
    { id: 'privkey', label: 'Private keys', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/g, mask: () => 'BEGIN PRIVATE KEY' },
    { id: 'cloudkey', label: 'Cloud access keys', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_-]{35}\b/g, mask: (s) => head(s, 4) },
    { id: 'apitoken', label: 'API tokens', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,})/g, mask: (s) => head(s, s.indexOf('_') > 0 && s.indexOf('_') < 11 ? s.indexOf('_') + 1 : 4) },
    { id: 'jwt', label: 'Session tokens (JWT)', re: /\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}/g, mask: () => 'eyJ••••' },
    { id: 'card', label: 'Payment card numbers', re: /\b(?:\d[ -]?){12,18}\d\b/g, check: (s) => { const d = s.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && !/^(\d)\1+$/.test(d) && luhn(d); }, mask: (s) => '•••• ' + s.replace(/\D/g, '').slice(-4) },
    { id: 'email', label: 'Email addresses', re: /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}/g, mask: (s) => { const [u, d] = s.split('@'); return u[0] + '•••@' + d; } }
  ];
  Roe.EXPOSURE = Object.fromEntries(TYPES.map((t) => [t.id, t.label]));
  Roe.EXPOSURE.filledPassword = 'Filled password fields';
  Roe.EXPOSURE.filledField = 'Filled form fields';

  // text -> { [type]: { n, samples } }
  Roe.exposure = function (text) {
    const out = {};
    if (!text) return out;
    for (const t of TYPES) {
      t.re.lastIndex = 0;
      const uniq = new Set();
      let m, guard = 0;
      while ((m = t.re.exec(text)) && guard++ < 2000) {
        if (t.check && !t.check(m[0])) continue;
        uniq.add(m[0]);
      }
      if (uniq.size) out[t.id] = { n: uniq.size, samples: [...uniq].slice(0, 3).map(t.mask) };
    }
    return out;
  };

  // Values typed or autofilled into fields are readable by any agent with DOM access.
  Roe.fieldExposure = function (doc) {
    const out = {};
    let pw = 0, other = 0;
    for (const i of doc.querySelectorAll('input')) {
      if (!i.value || ['hidden', 'submit', 'button', 'checkbox', 'radio', 'range', 'color', 'file', 'image', 'reset'].includes(i.type)) continue;
      if (i.type === 'password') pw++; else other++;
    }
    if (pw) out.filledPassword = { n: pw, samples: [] };
    if (other) out.filledField = { n: other, samples: [] };
    return out;
  };
})();
