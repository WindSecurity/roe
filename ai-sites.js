// AI assistants reachable as web pages. Used for activity logging and, in the org edition,
// for blocking through declarativeNetRequest. Browser-built-in assistants (a side panel, an
// assistant inside the omnibox) have no URL of their own and cannot be matched here.
(function () {
  const Roe = (self.Roe = self.Roe || {});
  Roe.AI_SITES = [
    { id: 'gemini', label: 'Gemini', hosts: ['gemini.google.com'] },
    { id: 'aimode', label: 'Google AI Mode', regex: '^https://www\\.google\\.[a-z.]+/search\\?(.*&)?udm=50(&|$)',
      test: (u) => /^www\.google\.[a-z.]+$/.test(u.hostname) && u.pathname === '/search' && u.searchParams.get('udm') === '50' },
    { id: 'chatgpt', label: 'ChatGPT', hosts: ['chatgpt.com', 'chat.openai.com'] },
    { id: 'claude', label: 'Claude', hosts: ['claude.ai'] },
    { id: 'copilot', label: 'Microsoft Copilot', hosts: ['copilot.microsoft.com'] },
    { id: 'perplexity', label: 'Perplexity', hosts: ['www.perplexity.ai', 'perplexity.ai'] },
    { id: 'deepseek', label: 'DeepSeek', hosts: ['chat.deepseek.com'] },
    { id: 'grok', label: 'Grok', hosts: ['grok.com'] },
    { id: 'metaai', label: 'Meta AI', hosts: ['www.meta.ai', 'meta.ai'] }
  ];
  Roe.aiSiteFor = function (url) {
    let u;
    try { u = new URL(url); } catch (e) { return null; }
    if (!/^https?:$/.test(u.protocol)) return null;
    return Roe.AI_SITES.find((s) => (s.hosts && s.hosts.includes(u.hostname)) || (s.test && s.test(u))) || null;
  };

  Roe.DEFAULT_POLICY = {
    ai: {},                 // site id -> 'allow' | 'log' | 'block'   (missing = 'log')
    domains: [],            // [{ host, mode: 'monitor' | 'approve' | 'block' }]
    holdAutomated: true,    // hold sensitive actions in a tab under automated control
    holdScripted: false,    // hold scripted (non-human) clicks on sensitive controls everywhere
    timeoutSec: 90
  };
  Roe.mergePolicy = (local, managed) => {
    const p = { ...Roe.DEFAULT_POLICY, ...(local || {}) };
    if (managed && Object.keys(managed).length) {
      Object.assign(p, managed, { ai: { ...(p.ai || {}), ...(managed.ai || {}) } });
      p.managed = true;
    }
    return p;
  };
  Roe.domainMode = (policy, host) => {
    const r = (policy.domains || []).filter((d) => host === d.host || host.endsWith('.' + d.host)).sort((a, b) => b.host.length - a.host.length)[0];
    return r ? r.mode : 'monitor';
  };
})();
