'use strict';
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execFile } = require('child_process');
const { promisify } = require('util');
const { WebSocketServer } = require('ws');
const cookie = require('cookie');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const USERNAME = process.env.PANEL_USERNAME || 'KYAMZ';
const PASSWORD_HASH = process.env.PANEL_PASSWORD_HASH || 'scrypt$3fc273cf4c1896a0f6c0f45d358a61c1$92f3f6bfd89ddd0c16cb2e1add5bfa176becfdc3030c283b527258fefae949a865cb36e265034eadd461f65c3072a8a8d2273cea6246fedc825488a93d893f39';
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, '.data'));
const SERVERS_DIR = path.join(DATA_DIR, 'servers');
const execFileAsync = promisify(execFile);
async function verifyPassword(password, encoded) {
  try {
    const parts = String(encoded).split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
    const salt = Buffer.from(parts[1], 'hex'), expected = Buffer.from(parts[2], 'hex');
    const actual = await new Promise((resolve, reject) => crypto.scrypt(password, salt, expected.length, (err, key) => err ? reject(err) : resolve(key)));
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch { return false; }
}

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('Set SESSION_SECRET (32+ chars) in Railway Variables.');
  process.exit(1);
}
fs.mkdirSync(SERVERS_DIR, { recursive: true });

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
const sessionMiddleware = session({
  name: 'kyamz.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 12 * 60 * 60 * 1000 }
});
app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false }));

const running = new Map();
const sockets = new Map();
const MAX_UPLOAD = 10 * 1024 * 1024;
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_UPLOAD, files: 1 } });

function auth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  return res.status(401).json({ error: 'Sesi tidak valid. Silakan login kembali.' });
}
function safeId(id) {
  return typeof id === 'string' && /^[a-zA-Z0-9_-]{1,48}$/.test(id);
}
function serverDir(id) { if (!safeId(id)) throw new Error('ID server tidak valid'); return path.join(SERVERS_DIR, id); }
function metaPath(id) { return path.join(serverDir(id), 'panel.json'); }
function readMeta(id) { return JSON.parse(fs.readFileSync(metaPath(id), 'utf8')); }
function writeMeta(meta) { fs.writeFileSync(metaPath(meta.id), JSON.stringify(meta, null, 2)); }
function resolveFile(id, rel = '') {
  const root = serverDir(id);
  const normalized = String(rel).replace(/\\/g, '/');
  if (normalized.includes('\0') || normalized.split('/').some(p => p === '..')) throw new Error('Path tidak diizinkan');
  const target = path.resolve(root, normalized);
  if (target !== root && !target.startsWith(root + path.sep)) throw new Error('Path tidak diizinkan');
  return target;
}
function listServers() {
  return fs.readdirSync(SERVERS_DIR, { withFileTypes: true }).filter(x => x.isDirectory()).map(x => {
    try {
      const m = readMeta(x.name), proc = running.get(m.id);
      return { ...m, status: proc && proc.child && proc.child.exitCode === null ? 'running' : 'stopped', pid: proc?.child?.pid || null };
    } catch { return null; }
  }).filter(Boolean);
}
function sendLog(id, text) {
  const set = sockets.get(id); if (!set) return;
  const msg = JSON.stringify({ type: 'log', text: String(text).slice(0, 5000) });
  for (const ws of set) if (ws.readyState === 1) ws.send(msg);
}
function getStats(id) {
  const proc = running.get(id);
  let memoryMB = 0;
  if (proc?.child?.pid) {
    try {
      const stat = fs.readFileSync(`/proc/${proc.child.pid}/status`, 'utf8');
      const m = stat.match(/VmRSS:\s+(\d+)\s+kB/); if (m) memoryMB = Math.round(Number(m[1]) / 1024 * 10) / 10;
    } catch {}
  }
  return { memoryMB, uptime: proc?.startedAt ? Math.floor((Date.now() - proc.startedAt) / 1000) : 0 };
}
function stopServer(id, force = false) {
  const p = running.get(id); if (!p || !p.child) return false;
  p.autoStopping = true;
  try { p.child.kill(force ? 'SIGKILL' : 'SIGTERM'); } catch {}
  if (force) running.delete(id);
  return true;
}
function startServer(id) {
  const meta = readMeta(id);
  const existing = running.get(id);
  if (existing?.child && existing.child.exitCode === null) throw new Error('Server sedang berjalan');
  const cwd = serverDir(id);
  const cmd = String(meta.startup || '').trim();
  if (!cmd) throw new Error('Perintah startup belum diatur');
  const proc = { child: null, startedAt: Date.now(), autoStopping: false, restartCount: 0 };
  // This command is intentionally owner-configurable: only the authenticated personal panel can call it.
  const child = spawn('/bin/sh', ['-lc', cmd], {
    cwd, shell: false, env: { ...process.env, PORT: String(meta.port || process.env.PORT || 3000), PANEL_SERVER_ID: id },
    stdio: ['pipe', 'pipe', 'pipe'], detached: false
  });
  proc.child = child; running.set(id, proc);
  sendLog(id, `[panel] Menjalankan: ${cmd}\n`);
  child.stdout.on('data', b => sendLog(id, b.toString()));
  child.stderr.on('data', b => sendLog(id, b.toString()));
  child.on('error', e => sendLog(id, `[error] ${e.message}\n`));
  child.on('exit', (code, signal) => {
    sendLog(id, `\n[panel] Proses berhenti (code=${code}, signal=${signal || '-'})\n`);
    const latest = running.get(id);
    if (latest === proc) {
      running.delete(id);
      let current; try { current = readMeta(id); } catch { return; }
      if (current.autoRestart && !proc.autoStopping) {
        setTimeout(() => { try { sendLog(id, '[panel] Auto-restart...\n'); startServer(id); } catch (e) { sendLog(id, `[panel] Restart gagal: ${e.message}\n`); } }, 2500).unref();
      }
    }
  });
  return child.pid;
}

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const validPassword = await verifyPassword(String(password || ''), PASSWORD_HASH);
  if (typeof username !== 'string' || typeof password !== 'string' || username !== USERNAME || !validPassword) {
    return res.status(401).json({ error: 'Username atau password salah.' });
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Gagal membuat sesi.' });
    req.session.authenticated = true;
    req.session.save(() => res.json({ ok: true, username: USERNAME }));
  });
});
app.post('/api/logout', auth, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', (req, res) => res.json({ authenticated: !!req.session?.authenticated, username: USERNAME }));
app.use('/api', auth);

app.get('/api/overview', (req, res) => {
  const servers = listServers();
  res.json({ servers, host: { hostname: os.hostname(), cpuCount: os.cpus().length, load: os.loadavg()[0], totalMemoryMB: Math.round(os.totalmem()/1024/1024), freeMemoryMB: Math.round(os.freemem()/1024/1024), node: process.version, python: 'Python 3 (available if installed)' } });
});
app.post('/api/servers', (req, res) => {
  try {
    const name = String(req.body.name || '').trim().slice(0, 60);
    const runtime = req.body.runtime === 'python' ? 'python' : 'node';
    if (!name) return res.status(400).json({ error: 'Nama server wajib diisi.' });
    const id = `${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    const dir = serverDir(id); fs.mkdirSync(dir, { recursive: true });
    const meta = { id, name, runtime, startup: String(req.body.startup || (runtime === 'python' ? 'python3 main.py' : 'node index.js')).slice(0, 300), note: String(req.body.note || '').slice(0, 180), memoryMB: Number(req.body.memoryMB || 512), cpuPercent: Number(req.body.cpuPercent || 10), port: 0, autoRestart: !!req.body.autoRestart, createdAt: new Date().toISOString() };
    writeMeta(meta);
    fs.writeFileSync(path.join(dir, runtime === 'python' ? 'main.py' : 'index.js'), runtime === 'python' ? 'print("Bot berjalan")\n' : 'console.log("Bot berjalan");\n');
    res.json({ ok: true, server: meta });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.get('/api/servers/:id', (req, res) => {
  try { const m = readMeta(req.params.id); res.json({ ...m, status: running.has(m.id) ? 'running' : 'stopped', stats: getStats(m.id) }); }
  catch (e) { res.status(404).json({ error: 'Server tidak ditemukan.' }); }
});
app.patch('/api/servers/:id', (req, res) => {
  try {
    const m = readMeta(req.params.id);
    if (running.has(m.id)) return res.status(409).json({ error: 'Stop server sebelum mengubah pengaturan.' });
    if (req.body.name !== undefined) m.name = String(req.body.name).trim().slice(0, 60) || m.name;
    if (req.body.startup !== undefined) m.startup = String(req.body.startup).slice(0, 300);
    if (req.body.note !== undefined) m.note = String(req.body.note).slice(0, 180);
    if (req.body.memoryMB !== undefined) m.memoryMB = Math.max(128, Math.min(4096, Number(req.body.memoryMB) || 512));
    if (req.body.cpuPercent !== undefined) m.cpuPercent = Math.max(5, Math.min(100, Number(req.body.cpuPercent) || 10));
    if (req.body.autoRestart !== undefined) m.autoRestart = !!req.body.autoRestart;
    writeMeta(m); res.json({ ok: true, server: m });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/servers/:id/start', (req, res) => { try { res.json({ ok: true, pid: startServer(req.params.id) }); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/servers/:id/stop', (req, res) => res.json({ ok: stopServer(req.params.id) }));
app.post('/api/servers/:id/kill', (req, res) => res.json({ ok: stopServer(req.params.id, true) }));
app.post('/api/servers/:id/restart', (req, res) => {
  const id = req.params.id; stopServer(id); setTimeout(() => { try { startServer(id); } catch (e) { sendLog(id, `[panel] Restart gagal: ${e.message}\n`); } }, 900); res.json({ ok: true });
});
app.delete('/api/servers/:id', (req, res) => {
  try { const id = req.params.id; stopServer(id, true); fs.rmSync(serverDir(id), { recursive: true, force: true }); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.get('/api/servers/:id/files', (req, res) => {
  try {
    const dir = resolveFile(req.params.id, req.query.path || '');
    const entries = fs.readdirSync(dir, { withFileTypes: true }).map(d => {
      const full = path.join(dir, d.name); let size = 0; try { size = d.isFile() ? fs.statSync(full).size : 0; } catch {}
      return { name: d.name, type: d.isDirectory() ? 'directory' : 'file', size };
    }).filter(x => x.name !== 'panel.json').sort((a,b) => a.type === b.type ? a.name.localeCompare(b.name) : a.type === 'directory' ? -1 : 1);
    res.json({ path: String(req.query.path || ''), entries });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.get('/api/servers/:id/file', (req, res) => {
  try {
    const file = resolveFile(req.params.id, req.query.path || '');
    if (!fs.statSync(file).isFile()) return res.status(400).json({ error: 'Bukan file.' });
    if (fs.statSync(file).size > 2 * 1024 * 1024) return res.status(413).json({ error: 'File terlalu besar untuk editor (maks 2 MB).' });
    res.json({ content: fs.readFileSync(file, 'utf8') });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/servers/:id/file', (req, res) => {
  try { const file = resolveFile(req.params.id, req.body.path || ''); if (!req.body.path || path.basename(file) === 'panel.json') return res.status(400).json({ error: 'Path file tidak valid.' }); fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, String(req.body.content ?? ''), 'utf8'); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/servers/:id/upload', upload.single('file'), (req, res) => {
  try { if (!req.file) return res.status(400).json({ error: 'Pilih file.' }); const dir = resolveFile(req.params.id, req.body.path || ''); const name = path.basename(req.file.originalname); if (name === 'panel.json') return res.status(400).json({ error: 'Nama file tidak diizinkan.' }); fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(path.join(dir, name), req.file.buffer); res.json({ ok: true, name }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/servers/:id/mkdir', (req, res) => {
  try { const name = String(req.body.name || '').trim(); if (!name || name.includes('/') || name.includes('\\')) return res.status(400).json({ error: 'Nama folder tidak valid.' }); fs.mkdirSync(resolveFile(req.params.id, path.join(req.body.path || '', name)), { recursive: false }); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/servers/:id/touch', (req, res) => {
  try { const name = String(req.body.name || '').trim(); if (!name || name.includes('/') || name.includes('\\') || name === 'panel.json') return res.status(400).json({ error: 'Nama file tidak valid.' }); fs.writeFileSync(resolveFile(req.params.id, path.join(req.body.path || '', name)), ''); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.delete('/api/servers/:id/file', (req, res) => {
  try { const file = resolveFile(req.params.id, req.body.path || ''); if (!req.body.path || path.basename(file) === 'panel.json') return res.status(400).json({ error: 'Path tidak valid.' }); fs.rmSync(file, { recursive: true, force: false }); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/servers/:id/command', (req, res) => {
  const p = running.get(req.params.id); const command = String(req.body.command || '').slice(0, 2000);
  if (!p?.child || p.child.exitCode !== null) return res.status(409).json({ error: 'Server sedang offline.' });
  try { p.child.stdin.write(command + '\n'); res.json({ ok: true }); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.get('/api/servers/:id/stats', (req, res) => { try { res.json(getStats(req.params.id)); } catch { res.status(404).json({ error: 'Tidak ditemukan.' }); } });

const server = app.listen(PORT, '0.0.0.0', () => console.log(`KYAMZ Panel listening on ${PORT}`));
const wss = new WebSocketServer({ noServer: true });
server.on('upgrade', (request, socket, head) => {
  const pathname = new URL(request.url, 'http://localhost').pathname;
  const match = pathname.match(/^\/ws\/servers\/([a-zA-Z0-9_-]{1,48})$/);
  if (!match) return socket.destroy();
  const cookies = cookie.parse(request.headers.cookie || '');
  const sid = cookies['kyamz.sid'];
  if (!sid) return socket.destroy();
  sessionMiddleware(request, { headersSent: false, statusCode: 200, getHeader: () => undefined, setHeader: () => {}, end: () => {}, writeHead: () => {} }, () => {
    // express-session attaches the loaded session; cookie parser/session middleware validates it.
    if (!request.session?.authenticated) return socket.destroy();
    wss.handleUpgrade(request, socket, head, ws => {
      const id = match[1]; let set = sockets.get(id); if (!set) sockets.set(id, set = new Set()); set.add(ws);
      ws.send(JSON.stringify({ type: 'log', text: `[panel] Console tersambung.\n` }));
      ws.on('close', () => { set.delete(ws); if (!set.size) sockets.delete(id); });
    });
  });
});
