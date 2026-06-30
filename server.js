const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();

const UPSTREAM = (process.env.UPSTREAM_BASE_URL || 'https://capi.aerolink.lat').replace(/\/+$/, '');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const MAX_RETRIES = parseInt(process.env.MAX_RETRIES || '5');
const CONFIG_PATH = process.env.CONFIG_PATH || path.join(process.env.HOME || '/root', '.aerolink-proxy', 'config.json');
const PORT = parseInt(process.env.PORT || '7860');

// ── Config ─────────────────────────────────────────────────────────────

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
      return migrateConfig(raw);
    }
  } catch {}
  const cfg = { keys: [], proxyKey: '', stats: { total: 0, success: 0, failed: 0, retried: 0 }, settings: { maxRetries: MAX_RETRIES, timeout: 120, enabled: true } };
  saveConfig(cfg);
  return cfg;
}

function migrateConfig(raw) {
  const migrated = { keys: [], proxyKey: raw.proxyKey || raw.proxy_key || '', stats: { total: 0, success: 0, failed: 0, retried: 0 }, settings: { maxRetries: MAX_RETRIES, timeout: 120, enabled: true } };

  const oldStats = raw.stats || {};
  migrated.stats.total = oldStats.total || oldStats.total_requests || 0;
  migrated.stats.success = oldStats.success || oldStats.successful_requests || 0;
  migrated.stats.failed = oldStats.failed || oldStats.failed_requests || 0;
  migrated.stats.retried = oldStats.retried || oldStats.retried_requests || 0;

  const oldSettings = raw.settings || {};
  migrated.settings.maxRetries = oldSettings.maxRetries || oldSettings.max_retries || MAX_RETRIES;
  migrated.settings.timeout = oldSettings.timeout || 120;
  migrated.settings.enabled = oldSettings.enabled !== undefined ? oldSettings.enabled : true;

  for (const k of (raw.keys || [])) {
    migrated.keys.push({
      id: k.id || crypto.randomBytes(6).toString('hex'),
      name: k.name || 'Unnamed',
      key: k.key || k.full_key || '',
      preview: k.preview || k.key_preview || '***',
      enabled: k.enabled !== undefined ? k.enabled : true,
      uses: k.uses || k.total_uses || 0,
      errors: k.errors || k.error_count || 0,
      lastUsed: k.lastUsed || k.last_used || null,
      lastError: k.lastError || k.last_error || null,
      lastErrorTime: k.lastErrorTime || k.last_error_time || null,
    });
  }

  if (migrated.keys.length > 0 || migrated.proxyKey) {
    saveConfig(migrated);
  }

  return migrated;
}

function saveConfig(cfg) {
  fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
  const tmp = CONFIG_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2));
  fs.renameSync(tmp, CONFIG_PATH);
}

let config = loadConfig();

// ── Proxy key ──────────────────────────────────────────────────────────

if (!config.proxyKey) {
  config.proxyKey = crypto.randomBytes(32).toString('hex');
  saveConfig(config);
  console.log('[STARTUP] Generated proxy key');
} else {
  console.log('[STARTUP] Proxy key loaded from config');
}

// ── Rate limiter ───────────────────────────────────────────────────────

const rateBuckets = new Map();
function isRateLimited(key, max, window) {
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket) { bucket = []; rateBuckets.set(key, bucket); }
  while (bucket.length && now - bucket[0] > window) bucket.shift();
  if (bucket.length >= max) return true;
  bucket.push(now);
  return false;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateBuckets) {
    if (!v.length || now - v[v.length - 1] > 600000) rateBuckets.delete(k);
  }
}, 60000);

// ── Blocked paths ──────────────────────────────────────────────────────

const BLOCKED = ['/.env', '/.git', '/wp-', '/phpmy', '/cgi-', '/scripts', '/.ssh', '/actuator', '/debug', '/server-status'];

// Round-robin counter (persists across requests)
let keyIndex = 0;

// ── Auth ───────────────────────────────────────────────────────────────

function verifyProxyKey(req) {
  const auth = req.headers['authorization'] || '';
  if (auth.startsWith('Bearer ')) {
    try { return crypto.timingSafeEqual(Buffer.from(auth.slice(7)), Buffer.from(config.proxyKey)); } catch { return false; }
  }
  const xapi = req.headers['x-api-key'] || '';
  if (xapi) {
    try { return crypto.timingSafeEqual(Buffer.from(xapi), Buffer.from(config.proxyKey)); } catch { return false; }
  }
  return false;
}

function verifyAdmin(req) {
  const cookie = (req.headers.cookie || '').match(/admin_session=([a-f0-9]+)/);
  if (!cookie) return false;
  const expected = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(cookie[1]), Buffer.from(expected)); } catch { return false; }
}

// ── Security middleware ────────────────────────────────────────────────

app.use((req, res, next) => {
  for (const b of BLOCKED) { if (req.path.toLowerCase().startsWith(b)) return res.status(404).end(); }
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('x-frame-options', 'DENY');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('cache-control', 'no-store');
  next();
});

// ── Proxy ──────────────────────────────────────────────────────────────

// Raw body capture — must come before any JSON parsing
app.all('/proxy/*', express.raw({ type: '*/*', limit: '10mb' }), async (req, res) => {
  const ip = req.ip;
  if (isRateLimited('proxy:' + ip, 30, 60000)) return res.status(429).json({ error: 'rate limit' });
  if (!verifyProxyKey(req)) { isRateLimited('proxy_fail:' + ip, 10, 60000); return res.status(401).json({ error: 'unauthorized' }); }
  if (!config.settings.enabled) return res.status(503).json({ error: 'disabled' });

  const subpath = req.path.slice('/proxy/'.length);
  const qs = req.url.split('?')[1] || '';
  const upstreamUrl = `${UPSTREAM}/${subpath}${qs ? '?' + qs : ''}`;

  const allKeys = config.keys.filter(k => k.enabled);
  if (!allKeys.length) return res.status(503).json({ error: 'no keys' });

  const errors = [];

  for (let i = 0; i < allKeys.length; i++) {
    const key = allKeys[keyIndex % allKeys.length];
    keyIndex++;
    config.stats.total++;

    const fwdHeaders = {};
    for (const [k, v] of Object.entries(req.headers)) {
      const lk = k.toLowerCase();
      if (lk === 'host') { fwdHeaders['host'] = 'capi.aerolink.lat'; continue; }
      fwdHeaders[k] = v;
    }

    if (fwdHeaders['authorization']) {
      fwdHeaders['authorization'] = `Bearer ${key.key}`;
    }
    if (fwdHeaders['x-api-key']) {
      fwdHeaders['x-api-key'] = key.key;
    }

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), (config.settings.timeout || 120) * 1000);

      const upstreamRes = await fetch(upstreamUrl, {
        method: req.method,
        headers: fwdHeaders,
        body: ['GET', 'HEAD'].includes(req.method) ? undefined : (req.body || undefined),
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if ([401, 402, 403, 429].includes(upstreamRes.status) || upstreamRes.status >= 500) {
        key.errors = (key.errors || 0) + 1;
        key.lastError = `HTTP ${upstreamRes.status}`;
        key.lastErrorTime = Date.now();
        errors.push(`${key.name}: ${upstreamRes.status}`);
        config.stats.retried++;
        saveConfig(config);
        if (i < allKeys.length - 1) continue;
        config.stats.failed++;
        saveConfig(config);
        return res.status(upstreamRes.status).json({ error: `all ${allKeys.length} keys failed: ${errors.join(', ')}` });
      }

      key.uses = (key.uses || 0) + 1;
      key.lastUsed = Date.now();
      key.lastError = null;
      config.stats.success++;
      saveConfig(config);

      // Forward response headers — strip content-encoding (Node.js fetch auto-decompresses)
      for (const [k, v] of upstreamRes.headers) {
        if (k.toLowerCase() === 'content-encoding') continue;
        res.setHeader(k, v);
      }
      res.status(upstreamRes.status);

      // Stream body
      if (upstreamRes.body) {
        const reader = upstreamRes.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(value);
        }
      }
      return res.end();

    } catch (err) {
      key.errors = (key.errors || 0) + 1;
      key.lastError = err.name === 'AbortError' ? 'timeout' : 'connect error';
      key.lastErrorTime = Date.now();
      errors.push(`${key.name}: ${key.lastError}`);
      config.stats.retried++;
      saveConfig(config);
      if (i < allKeys.length - 1) continue;
      config.stats.failed++;
      saveConfig(config);
      return res.status(502).json({ error: `all ${allKeys.length} keys failed: ${errors.join(', ')}` });
    }
  }
});

// ── Admin ──────────────────────────────────────────────────────────────

app.get('/', (_, res) => res.redirect('/admin'));

app.get('/admin', (req, res) => {
  if (verifyAdmin(req)) return res.redirect('/admin/dashboard');
  res.send(LOGIN_HTML);
});

app.post('/admin/login', express.urlencoded({ extended: false }), (req, res) => {
  const ip = req.ip;
  if (isRateLimited('login:' + ip, 5, 300000)) return res.status(429).send(LOGIN_HTML.replace('{{error}}', 'Too many attempts'));
  if (!ADMIN_PASSWORD || req.body.password !== ADMIN_PASSWORD) {
    isRateLimited('login:' + ip, 5, 300000);
    return res.status(401).send(LOGIN_HTML.replace('{{error}}', 'Invalid password'));
  }
  const session = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest('hex');
  res.setHeader('Set-Cookie', `admin_session=${session}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`);
  res.redirect('/admin/dashboard');
});

app.get('/admin/dashboard', (req, res) => {
  if (!verifyAdmin(req)) return res.redirect('/admin');
  config = loadConfig();
  const keys = config.keys.map(k => `
    <tr>
      <td>${esc(k.name)}</td>
      <td><code>${esc(k.preview || '***')}</code></td>
      <td><span class="${k.enabled !== false ? 'status-enabled' : 'status-disabled'}">${k.enabled !== false ? 'Enabled' : 'Disabled'}</span></td>
      <td>${k.uses || 0}</td>
      <td>${k.errors || 0}</td>
      <td>${k.lastUsed ? new Date(k.lastUsed).toLocaleString() : 'Never'}</td>
      <td title="${esc(k.lastError || '')}">${esc((k.lastError || '-').slice(0, 40))}</td>
      <td>
        <button onclick="toggle('${k.id}')" class="btn-sm">${k.enabled !== false ? 'disable' : 'enable'}</button>
        <button onclick="del('${k.id}')" class="btn-sm btn-danger">delete</button>
      </td>
    </tr>`).join('');

  const s = config.stats || {};
  const st = config.settings || {};
  res.send(DASHBOARD_HTML
    .replace('{{stats}}', `<div class="sc"><div class="label">Keys</div><div class="value blue">${config.keys.filter(k=>k.enabled!==false).length}/${config.keys.length}</div></div>
      <div class="sc"><div class="label">Requests</div><div class="value">${s.total||0}</div></div>
      <div class="sc"><div class="label">Success</div><div class="value green">${s.success||0}</div></div>
      <div class="sc"><div class="label">Failed</div><div class="value red">${s.failed||0}</div></div>
      <div class="sc"><div class="label">Retried</div><div class="value blue">${s.retried||0}</div></div>`)
    .replace('{{keys}}', keys)
    .replace(/{{proxy_key}}/g, config.proxyKey)
    .replace('{{upstream}}', UPSTREAM)
    .replace('{{max_retries}}', st.maxRetries || MAX_RETRIES)
    .replace('{{timeout}}', st.timeout || 120)
    .replace('{{enabled_checked}}', st.enabled !== false ? 'checked' : '')
  );
});

app.post('/admin/api/keys', express.json(), (req, res) => {
  if (!verifyAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
  const { name, key } = req.body;
  if (!key) return res.status(400).json({ error: 'key required' });
  const id = crypto.randomBytes(6).toString('hex');
  config.keys.push({ id, name: name || 'Unnamed', key, preview: key.length > 12 ? key.slice(0, 8) + '...' + key.slice(-4) : '***', enabled: true, uses: 0, errors: 0 });
  saveConfig(config);
  res.json({ ok: true });
});

app.delete('/admin/api/keys/:id', (req, res) => {
  if (!verifyAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
  config.keys = config.keys.filter(k => k.id !== req.params.id);
  saveConfig(config);
  res.json({ ok: true });
});

app.post('/admin/api/keys/:id/toggle', (req, res) => {
  if (!verifyAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
  const k = config.keys.find(k => k.id === req.params.id);
  if (k) k.enabled = !k.enabled;
  saveConfig(config);
  res.json({ ok: true });
});

app.post('/admin/api/settings', express.json(), (req, res) => {
  if (!verifyAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
  Object.assign(config.settings, req.body);
  saveConfig(config);
  res.json({ ok: true });
});

app.post('/admin/api/regen-key', (req, res) => {
  if (!verifyAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
  config.proxyKey = crypto.randomBytes(32).toString('hex');
  saveConfig(config);
  res.json({ ok: true, key: config.proxyKey });
});

app.get('/health', (_, res) => res.json({ status: 'ok' }));

// ── Helpers ────────────────────────────────────────────────────────────

function esc(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

// ── HTML ───────────────────────────────────────────────────────────────

const CSS = `@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
:root{--bg:#09090b;--surface:#18181b;--surface-hover:#27272a;--border:#27272a;--border-hover:#3f3f46;--text:#fafafa;--text-muted:#a1a1aa;--accent:#8b5cf6;--accent-hover:#7c3aed;--green:#22c55e;--red:#ef4444;--blue:#3b82f6;--radius:12px;--shadow:0 4px 6px -1px rgba(0,0,0,.3),0 2px 4px -2px rgba(0,0,0,.2)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;-webkit-font-smoothing:antialiased}
::selection{background:var(--accent);color:#fff}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border-hover);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#52525b}

/* Login */
.login-card{background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:48px;width:100%;max-width:420px;margin:15vh auto;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
.login-card h1{font-size:28px;font-weight:700;margin-bottom:8px;background:linear-gradient(135deg,#fff 0%,#a1a1aa 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sub{color:var(--text-muted);text-align:center;margin-bottom:32px;font-size:14px}
input[type=password],input[type=text],input[type=number]{width:100%;padding:12px 16px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:14px;font-family:inherit;transition:all .2s}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(139,92,246,.15)}
button{width:100%;padding:12px 20px;background:var(--accent);color:#fff;border:none;border-radius:var(--radius);font-size:14px;font-weight:600;cursor:pointer;transition:all .2s;font-family:inherit}
button:hover{background:var(--accent-hover);transform:translateY(-1px);box-shadow:0 4px 12px rgba(139,92,246,.3)}
button:active{transform:translateY(0)}
.err{color:var(--red);text-align:center;margin-bottom:16px;font-size:13px;padding:10px;background:rgba(239,68,68,.1);border-radius:8px}

/* Nav */
.nav{background:rgba(24,24,27,.8);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:1px solid var(--border);padding:0 24px;height:64px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.nav h1{font-size:18px;font-weight:700;display:flex;align-items:center;gap:10px}
.nav h1::before{content:'';width:8px;height:8px;background:var(--green);border-radius:50%;box-shadow:0 0 8px var(--green)}
.nav-status{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text-muted);padding:6px 12px;background:var(--bg);border-radius:20px;border:1px solid var(--border)}
.nav-status::before{content:'';width:6px;height:6px;background:var(--green);border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}

/* Content */
.ct{max-width:1200px;margin:0 auto;padding:32px 24px}

/* Stats Grid */
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:32px}
.sc{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;transition:all .2s;position:relative;overflow:hidden}
.sc:hover{border-color:var(--border-hover);transform:translateY(-2px);box-shadow:var(--shadow)}
.sc::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:0;transition:opacity .2s}
.sc:hover::after{opacity:1}
.sc .label{font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1.5px;font-weight:600}
.sc .value{font-size:32px;font-weight:700;margin-top:8px;font-feature-settings:'tnum'}
.sc .value.green{color:var(--green)}.sc .value.red{color:var(--red)}.sc .value.blue{color:var(--blue)}

/* Sections */
.sec{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:28px;margin-bottom:24px;transition:border-color .2s}
.sec:hover{border-color:var(--border-hover)}
.sec h2{font-size:15px;font-weight:600;margin-bottom:20px;padding-left:14px;border-left:3px solid var(--accent);color:var(--text);display:flex;align-items:center;gap:8px}

/* Table */
table{width:100%;border-collapse:separate;border-spacing:0}
th{text-align:left;padding:12px 16px;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:14px 16px;font-size:13px;border-bottom:1px solid var(--border);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--surface-hover)}
td code{font-family:'JetBrains Mono',monospace;font-size:12px;background:var(--bg);padding:4px 8px;border-radius:6px;color:var(--text-muted)}

/* Buttons */
.btn-sm{padding:6px 12px;border:1px solid var(--border);border-radius:8px;background:transparent;color:var(--text-muted);cursor:pointer;font-size:11px;font-weight:500;margin-right:6px;transition:all .15s;font-family:inherit}
.btn-sm:hover{background:var(--surface-hover);border-color:var(--border-hover);color:var(--text)}
.btn-danger{border-color:rgba(239,68,68,.3);color:var(--red)}
.btn-danger:hover{background:rgba(239,68,68,.1);border-color:var(--red)}

/* Add Form */
.add-form{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;padding:20px;background:var(--bg);border-radius:var(--radius);border:1px dashed var(--border)}
.add-form input{padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:13px;flex:1;min-width:150px}
.add-form button{padding:10px 20px;background:var(--accent);border-radius:10px;width:auto;white-space:nowrap}

/* Proxy Info */
.proxy-info{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-top:16px;font-size:13px}
.proxy-info code{font-family:'JetBrains Mono',monospace;background:var(--surface);padding:4px 10px;border-radius:6px;font-size:12px;color:var(--accent)}
.proxy-info .row{margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.proxy-info .row:last-child{margin-bottom:0}
.proxy-info .lbl{color:var(--text-muted);font-size:12px;font-weight:500;min-width:100px}

/* Code Block */
.cb{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:20px;font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.6;overflow-x:auto;margin-top:12px;color:var(--text-muted)}
.cb b{color:var(--text);font-weight:600}

/* Settings Form */
.sf{display:flex;gap:20px;flex-wrap:wrap;align-items:flex-end}
.sf>div{display:flex;flex-direction:column;gap:6px}
.sf label{font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;font-weight:600}
.sf input[type=number]{padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:13px;width:120px;font-family:'JetBrains Mono',monospace}
.sf button{width:auto;padding:10px 24px;margin-top:auto}

/* Toast */
.toast{position:fixed;bottom:24px;right:24px;background:var(--green);color:#000;padding:14px 24px;border-radius:12px;font-weight:600;font-size:13px;display:none;z-index:999;box-shadow:0 10px 25px rgba(34,197,94,.3);animation:slideUp .3s ease}
@keyframes slideUp{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}

/* Checkbox */
input[type=checkbox]{width:18px;height:18px;accent-color:var(--accent);cursor:pointer}

/* Status badges */
.status-enabled{color:var(--green);font-weight:600;display:inline-flex;align-items:center;gap:6px}
.status-enabled::before{content:'';width:6px;height:6px;background:var(--green);border-radius:50%}
.status-disabled{color:var(--red);font-weight:600;display:inline-flex;align-items:center;gap:6px}
.status-disabled::before{content:'';width:6px;height:6px;background:var(--red);border-radius:50%}

/* Mobile */
@media(max-width:768px){
.nav{padding:0 16px;height:56px}
.nav h1{font-size:16px}
.ct{padding:20px 16px}
.sg{grid-template-columns:repeat(2,1fr);gap:12px}
.sc{padding:18px}
.sc .value{font-size:26px}
.sec{padding:20px;margin-bottom:16px}
.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:0 -20px;padding:0 20px}
table{min-width:700px}
th,td{padding:12px}
.add-form{flex-direction:column;padding:16px}
.add-form input{width:100%;min-width:0}
.add-form button{width:100%}
.sf{flex-direction:column;align-items:stretch;gap:16px}
.sf input[type=number]{width:100%}
.sf button{width:100%}
.proxy-info .row{flex-direction:column;align-items:flex-start;gap:4px}
.proxy-info .lbl{min-width:0}
.cb{font-size:11px;padding:16px}
.login-card{margin:8vh auto;padding:32px 24px;width:calc(100% - 32px)}
.btn-sm{padding:8px 14px;font-size:12px}
}
@media(max-width:480px){
.sg{grid-template-columns:1fr}
.sc .label{font-size:10px}
.sc .value{font-size:24px}
.nav-status span{display:none}
}
`;

const LOGIN_HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Aerolink Proxy</title><style>${CSS}</style></head><body><div class="login-card"><h1>Aerolink Proxy</h1><p class="sub">Admin Dashboard</p><div class="err">{{error}}</div><form method="POST" action="/admin/login"><input type="password" name="password" placeholder="Password" autofocus required><button type="submit">Login</button></form></div></body></html>`;

const DASHBOARD_HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Aerolink Proxy</title><style>${CSS}</style></head><body>
<div class="nav"><h1>Aerolink Proxy</h1><div class="nav-status"><span>Running</span></div></div>
<div class="ct">
<div class="sg">{{stats}}</div>

<div class="sec"><h2>Configuration</h2>
<div class="proxy-info">
<div class="row"><span class="lbl">Upstream:</span> <code>{{upstream}}</code></div>
<div class="row"><span class="lbl">Claude Code URL:</span> <code id="purl"></code> <button class="btn-sm" onclick="copy(document.getElementById('purl').textContent)">Copy</button></div>
<div class="row"><span class="lbl">Proxy Key:</span> <code id="pkey">{{proxy_key}}</code> <button class="btn-sm" onclick="copy(document.getElementById('pkey').textContent)">Copy</button> <button class="btn-sm" onclick="regen()">Regenerate</button></div>
<div class="row"><span class="lbl">Retries:</span> <code>{{max_retries}}</code></div>
<div class="row"><span class="lbl">Timeout:</span> <code>{{timeout}}s</code></div>
</div>
<div class="cb" style="margin-top:12px"><b>Claude Code config (~/.claude/settings.json):</b><br><br>
{ "env": { "ANTHROPIC_BASE_URL": "<span id="curl"></span>", "ANTHROPIC_API_KEY": "<span id="ckey"></span>" } }</div>
</div>

<div class="sec"><h2>Settings</h2>
<div class="sf">
<div><label>Retries</label><input type="number" id="sRetries" value="{{max_retries}}" min="1" max="20"></div>
<div><label>Timeout (s)</label><input type="number" id="sTimeout" value="{{timeout}}" min="10" max="600"></div>
<div><label><input type="checkbox" id="sEnabled" {{enabled_checked}} style="width:20px;height:20px"> Enabled</label></div>
<button onclick="saveSettings()" style="width:auto;padding:8px 16px;background:#6366f1;color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:600">Save</button>
</div></div>

<div class="sec"><h2>API Keys</h2>
<div class="add-form">
<input type="text" id="kName" placeholder="Name" style="width:150px">
<input type="text" id="kValue" placeholder="Paste API key" style="flex:1;min-width:200px">
<button onclick="addKey()">Add Key</button>
</div>
<div class="table-wrap"><table><thead><tr><th>Name</th><th>Key</th><th>Status</th><th>Uses</th><th>Errors</th><th>Last Used</th><th>Last Error</th><th>Actions</th></tr></thead>
<tbody>{{keys}}</tbody></table></div>
</div>
</div>
<div class="toast" id="toast"></div>
<script>
const H=location.origin;
document.getElementById('purl').textContent=H+'/proxy';
document.getElementById('curl').textContent=H+'/proxy';
document.getElementById('ckey').textContent='{{proxy_key}}';
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.style.display='block';setTimeout(()=>t.style.display='none',2500)}
function copy(s){navigator.clipboard.writeText(s);toast('Copied!')}
async function addKey(){const n=document.getElementById('kName').value.trim()||'Unnamed',k=document.getElementById('kValue').value.trim();if(!k)return alert('Enter key');await fetch('/admin/api/keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n,key:k})});location.reload()}
async function del(id){if(!confirm('Delete?'))return;await fetch('/admin/api/keys/'+id,{method:'DELETE'});location.reload()}
async function toggle(id){await fetch('/admin/api/keys/'+id+'/toggle',{method:'POST'});location.reload()}
async function saveSettings(){await fetch('/admin/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({maxRetries:+document.getElementById('sRetries').value,timeout:+document.getElementById('sTimeout').value,enabled:document.getElementById('sEnabled').checked})});toast('Saved!')}
async function regen(){if(!confirm('Regenerate?'))return;const r=await fetch('/admin/api/regen-key',{method:'POST'});const d=await r.json();if(d.ok)location.reload()}
</script></body></html>`;

// ── Start ──────────────────────────────────────────────────────────────

app.listen(PORT, '0.0.0.0', () => console.log(`[STARTUP] Listening on port ${PORT}`));
