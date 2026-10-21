// Roe surfaces: what kind of untrusted endpoint is this page?
// Email, code hosts, chat and tickets carry text written by strangers that agents read as context.
(function () {
  const Roe = (self.Roe = self.Roe || {});

  const AGENT_FILE = /(^|\/)(CLAUDE|AGENTS|GEMINI|MEMORY|SKILL)\.md$|(^|\/)\.cursorrules$|(^|\/)\.windsurfrules$|copilot-instructions\.md$|(^|\/)\.cursor\/rules\/|(^|\/)\.claude\/|(^|\/)mcp\.json$|(^|\/)llms?\.txt$/i;

  const HOSTS = [
    { id: 'aichat', label: 'AI chat app', boost: 0.6, re: /^(claude\.ai|chatgpt\.com|chat\.openai\.com|gemini\.google\.com|grok\.com|copilot\.microsoft\.com|www\.perplexity\.ai|chat\.deepseek\.com)$/ },
    { id: 'email', label: 'Email', boost: 1.15, re: /^(mail\.google\.com|outlook\.(live|office|office365)\.com|mail\.yahoo\.com|mail\.proton\.me|mail\.zoho\.[a-z.]+|app\.fastmail\.com|app\.hey\.com|mail\.aol\.com|www\.icloud\.com)$/ },
    { id: 'github', label: 'GitHub', boost: 1.1, re: /^(github\.com|gist\.github\.com|gitlab\.com|bitbucket\.org)$/ },
    { id: 'raw', label: 'Raw repository file', boost: 1.1, re: /^(raw\.githubusercontent\.com|gist\.githubusercontent\.com)$/ },
    { id: 'chat', label: 'Chat', boost: 1.1, re: /^(app\.slack\.com|discord\.com|teams\.microsoft\.com|web\.whatsapp\.com|web\.telegram\.org)$/ },
    { id: 'tickets', label: 'Tickets and tasks', boost: 1.1, re: /(\.atlassian\.net|linear\.app|\.zendesk\.com|\.freshdesk\.com|intercom\.com|app\.asana\.com|trello\.com)$/ },
    { id: 'docs', label: 'Shared documents', boost: 1.05, re: /^(docs\.google\.com|[a-z0-9-]+\.notion\.(so|site)|www\.notion\.so|[a-z0-9-]+\.sharepoint\.com)$/ },
    { id: 'social', label: 'Public posts and forums', boost: 1.05, re: /^(www\.reddit\.com|old\.reddit\.com|x\.com|twitter\.com|news\.ycombinator\.com|stackoverflow\.com|[a-z.]*stackexchange\.com|www\.linkedin\.com|medium\.com|[a-z0-9-]+\.substack\.com|www\.facebook\.com)$/ }
  ];

  Roe.surface = function (loc) {
    if (loc.protocol === 'file:') return { id: 'file', label: 'Local file', boost: 1, agentFile: AGENT_FILE.test(loc.pathname) };
    const host = loc.hostname;
    const hit = HOSTS.find((h) => h.re.test(host));
    const s = hit ? { id: hit.id, label: hit.label, boost: hit.boost } : { id: 'web', label: 'Public web page', boost: 1 };
    s.host = host;
    s.agentFile = AGENT_FILE.test(loc.pathname);
    if (s.agentFile) { s.boost = 1.2; s.label = 'Agent instruction file (' + s.label + ')'; }
    return s;
  };

  // Which GitHub raw-markdown requests would reveal what an agent reads through the API?
  // Returns { owner, repo, number, kind } or null. Strict, so nothing odd is ever fetched.
  Roe.githubTarget = function (loc) {
    if (loc.hostname !== 'github.com') return null;
    const m = /^\/([A-Za-z0-9_.-]{1,100})\/([A-Za-z0-9_.-]{1,100})(?:\/(issues|pull)\/(\d{1,9}))?(?:[\/?#]|$)/.exec(loc.pathname);
    if (!m) return null;
    const reserved = new Set(['settings', 'orgs', 'marketplace', 'notifications', 'explore', 'topics', 'sponsors', 'login', 'features', 'pricing', 'about']);
    if (reserved.has(m[1])) return null;
    return m[3] ? { owner: m[1], repo: m[2], kind: m[3], number: m[4] } : { owner: m[1], repo: m[2], kind: 'repo' };
  };

  // Pull instruction-like text out of raw Markdown that the rendered page never shows.
  Roe.rawMarkdownHidden = function (md) {
    const out = [];
    const comment = /<!--([\s\S]{0,4000}?)-->/g;
    let m, n = 0;
    while ((m = comment.exec(md)) && n++ < 40) out.push({ text: m[1], technique: 'HTML comment in raw Markdown' });
    const linkComment = /^\s*\[\/\/\]:\s*#\s*[("']([^\n]{12,1000})[)"']\s*$/gm;
    n = 0;
    while ((m = linkComment.exec(md)) && n++ < 40) out.push({ text: m[1], technique: 'Markdown link-comment' });
    return out;
  };
})();
