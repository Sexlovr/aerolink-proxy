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
  res.removeHeader('x-powered-by');
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
  const upstreamUrl = `${UPSTREAM}/${subpath}${req.url.includes('?') ? '?' + req.url.split('?')[1] : ''}`;

  const maxRetries = config.settings.maxRetries || MAX_RETRIES;
  const errors = [];

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const keys = config.keys.filter(k => k.enabled);
    if (!keys.length) return res.status(503).json({ error: 'no keys' });

    const key = keys[keyIndex % keys.length];
    keyIndex++;
    config.stats.total++;

    // Build headers — raw passthrough, only swap the key value
    const fwdHeaders = {};
    for (const [k, v] of Object.entries(req.headers)) {
      const lk = k.toLowerCase();
      if (lk === 'content-length' || lk === 'transfer-encoding') continue;
      // Set host to upstream
      if (lk === 'host') { fwdHeaders['host'] = 'capi.aerolink.lat'; continue; }
      fwdHeaders[k] = v;
    }

    // Replace BOTH auth headers Claude Code sends
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
        errors.push(`${key.name}: HTTP ${upstreamRes.status}`);
        config.stats.failed++;
        if (attempt < maxRetries - 1) { config.stats.retried++; await new Promise(r => setTimeout(r, 300)); continue; }
        saveConfig(config);
        return res.status(upstreamRes.status).json({ error: 'all keys failed' });
      }

      key.uses = (key.uses || 0) + 1;
      key.lastUsed = Date.now();
      key.lastError = null;
      config.stats.success++;
      saveConfig(config);

      // Forward response headers
      const skipHeaders = new Set(['transfer-encoding', 'connection']);
      for (const [k, v] of upstreamRes.headers) {
        if (!skipHeaders.has(k.toLowerCase())) res.setHeader(k, v);
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
      config.stats.failed++;
      if (attempt < maxRetries - 1) { config.stats.retried++; continue; }
      saveConfig(config);
      return res.status(502).json({ error: 'upstream unreachable' });
    }
  }
  res.status(500).json({ error: 'exhausted' });
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
      <td style="color:${k.enabled !== false ? '#22c55e' : '#ef4444'};font-weight:600">${k.enabled !== false ? 'enabled' : 'disabled'}</td>
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
    .replace('{{stats}}', `<div class="stat-card"><div class="label">Keys</div><div class="value blue">${config.keys.filter(k=>k.enabled!==false).length}/${config.keys.length}</div></div>
      <div class="stat-card"><div class="label">Requests</div><div class="value">${s.total||0}</div></div>
      <div class="stat-card"><div class="label">Success</div><div class="value green">${s.success||0}</div></div>
      <div class="stat-card"><div class="label">Failed</div><div class="value red">${s.failed||0}</div></div>
      <div class="stat-card"><div class="label">Retried</div><div class="value blue">${s.retried||0}</div></div>`)
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

const CSS = `*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,sans-serif;background:#0a0a0a;color:#e5e5e5;min-height:100vh}
.login-card{background:#1a1a2e;border:1px solid #333;border-radius:16px;padding:48px;width:100%;max-width:400px;margin:15vh auto;box-shadow:0 25px 50px rgba(0,0,0,.5)}
h1{font-size:24px;margin-bottom:8px;text-align:center}
.sub{color:#888;text-align:center;margin-bottom:32px;font-size:14px}
input[type=password]{width:100%;padding:12px 16px;background:#0a0a0a;border:1px solid #333;border-radius:8px;color:#fff;font-size:16px;margin-bottom:16px}
input:focus{outline:none;border-color:#6366f1}
button{width:100%;padding:12px;background:#6366f1;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;font-weight:600}
button:hover{background:#5558e6}
.err{color:#ef4444;text-align:center;margin-bottom:16px;font-size:14px}
.nav{background:#111;border-bottom:1px solid #222;padding:16px 24px;display:flex;align-items:center;justify-content:space-between}
.nav h1{font-size:18px}
.ct{max-width:1200px;margin:0 auto;padding:24px}
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;margin-bottom:24px}
.sc{background:#1a1a2e;border:1px solid #222;border-radius:12px;padding:20px}
.sc .label{font-size:12px;color:#888;text-transform:uppercase;letter-spacing:1px}
.sc .value{font-size:28px;font-weight:700;margin-top:4px}
.sc .value.green{color:#22c55e}.sc .value.red{color:#ef4444}.sc .value.blue{color:#6366f1}
.sec{background:#1a1a2e;border:1px solid #222;border-radius:12px;padding:24px;margin-bottom:24px}
.sec h2{font-size:16px;font-weight:600;margin-bottom:16px;padding-left:12px;border-left:3px solid #6366f1}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 12px;font-size:12px;color:#888;text-transform:uppercase;border-bottom:1px solid #333}
td{padding:10px 12px;font-size:13px;border-bottom:1px solid #1a1a2e}
tr:hover{background:#111}
.btn-sm{padding:4px 10px;border:1px solid #333;border-radius:6px;background:transparent;color:#ccc;cursor:pointer;font-size:11px;margin-right:4px}
.btn-sm:hover{background:#222}
.btn-danger{border-color:#ef4444;color:#ef4444}
.add-form{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.add-form input{padding:8px 12px;background:#0a0a0a;border:1px solid #333;border-radius:8px;color:#fff;font-size:13px}
.add-form input:focus{outline:none;border-color:#6366f1}
.add-form button{padding:8px 16px;background:#6366f1;color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:600;font-size:13px;width:auto}
.proxy-info{background:#111;border:1px solid #222;border-radius:8px;padding:16px;margin-top:12px;font-size:13px}
.proxy-info code{background:#0a0a0a;padding:2px 8px;border-radius:4px}
.proxy-info .row{margin-bottom:8px}
.proxy-info .lbl{color:#888;display:inline-block;width:140px}
.cb{background:#0a0a0a;border:1px solid #222;border-radius:8px;padding:16px;font-family:monospace;font-size:13px;overflow-x:auto;margin-top:8px;word-break:break-all}
.sf{display:flex;gap:16px;flex-wrap:wrap;align-items:flex-end}
.sf label{display:block;font-size:12px;color:#888;margin-bottom:4px}
.sf input[type=number]{padding:8px 12px;background:#0a0a0a;border:1px solid #333;border-radius:8px;color:#fff;font-size:13px;width:100px}
.toast{position:fixed;bottom:24px;right:24px;background:#22c55e;color:#000;padding:12px 20px;border-radius:8px;font-weight:600;font-size:14px;display:none;z-index:999}`;

const LOGIN_HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Aerolink Proxy</title><style>${CSS}</style></head><body><div class="login-card"><h1>Aerolink Proxy</h1><p class="sub">Admin Dashboard</p><div class="err">{{error}}</div><form method="POST" action="/admin/login"><input type="password" name="password" placeholder="Password" autofocus required><button type="submit">Login</button></form></div></body></html>`;

const DASHBOARD_HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Aerolink Proxy</title><style>${CSS}</style></head><body>
<div class="nav"><h1>Aerolink Proxy</h1><span style="color:#22c55e">Running</span></div>
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
<table><thead><tr><th>Name</th><th>Key</th><th>Status</th><th>Uses</th><th>Errors</th><th>Last Used</th><th>Last Error</th><th>Actions</th></tr></thead>
<tbody>{{keys}}</tbody></table>
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
