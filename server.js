const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Server } = require('socket.io');
const cors = require('cors');
const { AccessToken } = require('livekit-server-sdk');
require('dotenv').config();

const app = express();
app.use(cors());
const jsonParser = express.json({ limit: '2mb' });
app.use((req, res, next) => (req.path === '/api/admin/restore' ? next() : jsonParser(req, res, next))); // восстановление копии читает «сырое» тело без лимита 2 МБ

const MAX_FILE = 10 * 1024 * 1024;
const TEXT_MAX = 4000;
const SESSION_TTL = 30 * 24 * 60 * 60 * 1000;

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' },
  maxHttpBufferSize: 2e6,
});

// Папка с данными. Можно вынести на постоянный диск: DATA_DIR=/var/data/nmessenger в .env
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
// Сколько последних сообщений хранить в каждом чате (по умолчанию 5000)
const HISTORY_KEEP = Math.min(50000, Math.max(200, parseInt(process.env.HISTORY_KEEP || '5000', 10) || 5000));
const zlib = require('zlib');
const DATA_FILE = path.join(DATA_DIR, 'store.json');
const FILES_DIR = path.join(DATA_DIR, 'files');

/* ===================== Владельцы и верификация ===================== */
// Аккаунты из OWNER_USERNAMES всегда верифицированы (синяя галочка), могут выдавать галочку другим и модерировать.
const OWNERS = new Set(String(process.env.OWNER_USERNAMES || process.env.OWNER_USERNAME || 'newrizer').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean));

/* ===================== Защита экземпляра (активация владельцем) ===================== */
// tools/build.js подставляет сюда хеш ключа владельца; в режиме разработки берётся OWNER_KEY_HASH из .env.
const BAKED_OWNER_KEY_HASH = '__NM_OWNER_KEY_HASH__';
const OWNER_KEY_HASH = (BAKED_OWNER_KEY_HASH.startsWith('__') ? String(process.env.OWNER_KEY_HASH || '') : BAKED_OWNER_KEY_HASH).trim();
const LOCK_FILE = path.join(DATA_DIR, '.instance.lock');
let instanceLocked = false;
function machineFingerprint() {
  const os = require('os');
  let user = '';
  try { user = os.userInfo().username; } catch { }
  const cpu = ((os.cpus() || [])[0] || {}).model || '';
  return crypto.createHash('sha256').update([os.hostname(), os.platform(), os.arch(), user, cpu].join('|')).digest('hex');
}
function lockValue() { return crypto.createHmac('sha256', OWNER_KEY_HASH).update(machineFingerprint()).digest('hex'); }
function verifyOwnerKey(k) {
  const [algo, salt, hash] = OWNER_KEY_HASH.split('$');
  if (algo !== 'scrypt' || !salt || !hash) return false;
  try {
    const check = crypto.scryptSync(String(k || ''), salt, 32);
    const buf = Buffer.from(hash, 'hex');
    return buf.length === check.length && crypto.timingSafeEqual(buf, check);
  } catch { return false; }
}
function checkInstance() {
  if (!OWNER_KEY_HASH) { console.warn('⚠️  Защита от копирования выключена: задайте OWNER_KEY_HASH в .env (команда: npm run owner-key)'); return; }
  try { if (fs.readFileSync(LOCK_FILE, 'utf8').trim() === lockValue()) return; } catch { }
  instanceLocked = true;
  console.warn('🔒 Экземпляр не активирован на этом компьютере. Откройте сайт и введите ключ владельца.');
}
const ACTIVATE_PAGE = `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NMessenger — активация</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f1012;color:#e7e9ee;font:15px/1.4 -apple-system,Segoe UI,Roboto,sans-serif}
.card{width:360px;max-width:92vw;background:#17181c;border:1px solid #2a2d34;border-radius:18px;padding:28px 26px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.logo{width:56px;height:56px;border-radius:16px;background:linear-gradient(135deg,#2f7cf6,#7c5cff);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:26px;margin:0 auto 14px}
h1{font-size:18px;margin:0 0 6px;text-align:center}p{color:#9aa0ad;font-size:13px;text-align:center;margin:0 0 18px}
input{width:100%;box-sizing:border-box;background:#212328;border:1px solid #2f3340;color:#fff;border-radius:12px;padding:12px 14px;font-size:15px;outline:0}input:focus{border-color:#2f7cf6}
button{width:100%;margin-top:12px;background:#2f7cf6;color:#fff;border:0;border-radius:12px;padding:12px;font-size:15px;font-weight:600;cursor:pointer}button:disabled{opacity:.6}
.err{color:#ff6b6b;font-size:13px;min-height:18px;margin-top:10px;text-align:center}</style></head><body>
<form class="card" id="f"><div class="logo">N</div><h1>Активация экземпляра</h1><p>Этот сервер NMessenger запущен на новом компьютере. Введите ключ владельца, чтобы продолжить.</p>
<input type="password" id="k" placeholder="Ключ владельца" autofocus autocomplete="off" maxlength="200"><button id="b">Активировать</button><div class="err" id="e"></div></form>
<script>document.getElementById('f').onsubmit=async function(ev){ev.preventDefault();var b=document.getElementById('b'),e=document.getElementById('e');b.disabled=true;e.textContent='';
try{var r=await fetch('/api/activate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:document.getElementById('k').value})});var j=await r.json();if(r.ok&&j.ok){location.replace('/');return}e.textContent=j.error||'Ошибка'}catch(x){e.textContent='Нет связи с сервером'}b.disabled=false}</script></body></html>`;
const activateTries = new Map();
app.post('/api/activate', (req, res) => {
  const ip = req.ip || '';
  const t = activateTries.get(ip) || { n: 0, until: 0 };
  if (t.until > Date.now()) return res.status(429).json({ error: 'Слишком много попыток. Подождите 15 минут.' });
  if (!OWNER_KEY_HASH) return res.json({ ok: true });
  if (!verifyOwnerKey(req.body?.key)) {
    t.n += 1;
    if (t.n >= 5) { t.n = 0; t.until = Date.now() + 15 * 60 * 1000; }
    activateTries.set(ip, t);
    return res.status(401).json({ error: 'Неверный ключ владельца' });
  }
  activateTries.delete(ip);
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(LOCK_FILE, lockValue());
  } catch (e) { return res.status(500).json({ error: 'Не удалось записать файл активации: ' + e.message }); }
  instanceLocked = false;
  console.log('✅ Экземпляр активирован владельцем');
  res.json({ ok: true });
});
app.use((req, res, next) => {
  if (!instanceLocked) return next();
  if (req.path === '/ping' || req.path === '/api/activate') return next();
  if (req.path.startsWith('/api/') || req.path.startsWith('/files/')) return res.status(423).json({ error: 'Экземпляр не активирован' });
  res.status(423).type('html').send(ACTIVATE_PAGE);
});
io.use((socket, next) => (instanceLocked ? next(new Error('locked')) : next()));

function normalizeStore(parsed) {
  return {
    accounts: parsed.accounts || {},
    conversations: parsed.conversations || {},
    sessions: parsed.sessions || {},
    files: parsed.files || {},
    reports: parsed.reports || [],
  };
}
function readStoreFile(fp) {
  let raw = fs.readFileSync(fp);
  if (fp.endsWith('.gz')) raw = zlib.gunzipSync(raw);
  const parsed = JSON.parse(raw.toString('utf8'));
  if (!parsed || typeof parsed !== 'object' || !parsed.accounts) throw new Error('bad store');
  return parsed;
}
function listBackups() {
  try {
    return fs.readdirSync(BACKUP_DIR).filter((f) => /^store-.*\.json(\.gz)?$/.test(f)).sort().map((f) => path.join(BACKUP_DIR, f));
  } catch { return []; }
}
function loadStore() {
  // 1) основной файл, 2) store.json.bak, 3) последняя резервная копия — данные не теряются даже при битом файле
  const candidates = [DATA_FILE, DATA_FILE + '.bak', ...listBackups().reverse()];
  let mainBroken = false;
  for (const fp of candidates) {
    if (!fs.existsSync(fp)) continue;
    try {
      const parsed = readStoreFile(fp);
      if (fp !== DATA_FILE) console.warn('⚠️  store.json повреждён или отсутствует — данные восстановлены из', path.basename(fp));
      return normalizeStore(parsed);
    } catch (e) {
      if (fp === DATA_FILE) {
        mainBroken = true;
        try { fs.copyFileSync(DATA_FILE, DATA_FILE.replace(/\.json$/, '') + '.corrupt-' + Date.now() + '.json'); } catch { }
        console.error('❌ store.json не читается (' + e.message + '), копия сохранена как store.corrupt-*.json');
      }
    }
  }
  if (mainBroken) console.error('❌ Не удалось восстановить данные ни из одной копии — старт с пустой базой');
  return { accounts: {}, conversations: {}, sessions: {}, files: {}, reports: [] };
}

const store = loadStore();
const accounts = new Map(Object.entries(store.accounts));
const convMap = new Map(Object.entries(store.conversations));
const sessions = new Map(Object.entries(store.sessions));
const filesMeta = new Map(Object.entries(store.files));
const reports = store.reports || [];
const usersBySocket = new Map();
const socketsByName = new Map();
const loginTries = new Map();

function snapshotStore({ withSessions = true } = {}) {
  const conversations = {};
  for (const [id, c] of convMap) {
    conversations[id] = { ...c, messages: (c.messages || []).slice(-HISTORY_KEEP) };
  }
  const acc = {};
  for (const [k, v] of accounts) acc[k] = v;
  const now = Date.now();
  const sess = {};
  if (withSessions) for (const [t, s] of sessions) {
    if (s.exp > now) sess[t] = s;
    else sessions.delete(t);
  }
  const files = {};
  for (const [k, v] of filesMeta) files[k] = v;
  return { accounts: acc, conversations, sessions: sess, files, reports };
}
let persistTimer = null;
let dirty = false;
function persistNow() {
  // Атомарная запись: сначала во временный файл, потом переименование. Старый файл остаётся как store.json.bak.
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = DATA_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(snapshotStore()));
    if (fs.existsSync(DATA_FILE)) { try { fs.copyFileSync(DATA_FILE, DATA_FILE + '.bak'); } catch { } }
    fs.renameSync(tmp, DATA_FILE);
    dirty = false;
  } catch (err) {
    console.error('persist error:', err.message);
  }
}
function persist() {
  dirty = true;
  clearTimeout(persistTimer);
  persistTimer = setTimeout(persistNow, 200);
}
const BACKUP_KEEP = Math.max(3, parseInt(process.env.BACKUP_KEEP || '20', 10) || 20);
function makeBackup(reason = 'auto') {
  try {
    if (!accounts.size) return null;
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16);
    const fp = path.join(BACKUP_DIR, `store-${stamp}-${reason}.json.gz`);
    fs.writeFileSync(fp, zlib.gzipSync(JSON.stringify(snapshotStore({ withSessions: false }))));
    const all = listBackups();
    for (const old of all.slice(0, Math.max(0, all.length - BACKUP_KEEP))) { try { fs.unlinkSync(old); } catch { } }
    return fp;
  } catch (e) { console.error('backup error:', e.message); return null; }
}
// Резервная копия при старте и каждые 6 часов (data/backups, хранится BACKUP_KEEP последних)
setTimeout(() => makeBackup('start'), 3000);
setInterval(() => makeBackup('auto'), 6 * 60 * 60 * 1000).unref();
function flushAndExit(sig) {
  try { clearTimeout(persistTimer); if (dirty) persistNow(); } catch { }
  console.log(`\n💾 Данные сохранены (${sig}). Папка: ${DATA_DIR}`);
  process.exit(0);
}
process.on('SIGINT', () => flushAndExit('SIGINT'));
process.on('SIGTERM', () => flushAndExit('SIGTERM'));
process.on('uncaughtException', (e) => { console.error('uncaughtException:', e); try { persistNow(); } catch { } });

function livekitEnabled() {
  return !!(
    process.env.LIVEKIT_API_KEY &&
    process.env.LIVEKIT_API_SECRET &&
    process.env.LIVEKIT_URL
  );
}

function norm(name) {
  return String(name || '').trim();
}
function key(name) {
  return norm(name).toLowerCase();
}
function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}
function dmId(a, b) {
  const [x, y] = [key(a), key(b)].sort();
  return `dm:${x}:${y}`;
}
function secretId(a, b) {
  const [x, y] = [key(a), key(b)].sort();
  return `secret:${x}:${y}`;
}
function favId(username) {
  return 'fav:' + key(username);
}
function timeLabel(ts) {
  return new Date(ts || Date.now()).toLocaleTimeString('ru-RU', {
    hour: '2-digit',
    minute: '2-digit',
  });
}
function validUsername(name) {
  return (
    name &&
    name.length >= 2 &&
    name.length <= 24 &&
    /^[\p{L}\p{N}._-]+$/u.test(name)
  );
}
function slug(s) {
  const v = String(s || '')
    .toLowerCase()
    .replace(/\s+/g, '_')
    .replace(/[^\p{L}\p{N}._-]/gu, '')
    .slice(0, 24);
  return v || uid();
}
function hashPassword(password, salt) {
  const s = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, s, 32).toString('hex');
  return { hash, salt: s };
}
function verifyPassword(password, hash, salt) {
  try {
    const check = crypto.scryptSync(password, salt, 32);
    const buf = Buffer.from(hash, 'hex');
    if (buf.length !== check.length) return false;
    return crypto.timingSafeEqual(buf, check);
  } catch {
    return false;
  }
}
function tooManyTries(id) {
  const rec = loginTries.get(id) || { n: 0, t: 0 };
  if (Date.now() - rec.t > 5 * 60 * 1000) {
    loginTries.set(id, { n: 1, t: Date.now() });
    return false;
  }
  rec.n += 1;
  rec.t = Date.now();
  loginTries.set(id, rec);
  return rec.n > 8;
}
function defaultSettings() {
  return {
    lastSeen: 'all',
    readReceipts: true,
    callsFrom: 'all',
    msgsFrom: 'all',
    theme: 'dark',
    sound: true,
    soundVolume: 0.7,
    enterToSend: true,
    fontSize: 15,
  };
}
function settingsOf(acc) {
  return { ...defaultSettings(), ...(acc.settings || {}) };
}
function createSession(username, meta = {}) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, {
    id: uid(),
    username,
    exp: Date.now() + SESSION_TTL,
    createdAt: Date.now(),
    ua: String(meta.ua || '').slice(0, 180),
    ip: String(meta.ip || '').slice(0, 64),
  });
  persist();
  return token;
}
function sessionUser(token) {
  if (!token) return null;
  const s = sessions.get(token);
  if (!s || s.exp < Date.now()) {
    if (s) sessions.delete(token);
    return null;
  }
  const acc = accounts.get(key(s.username)) || null;
  if (acc && acc.banned) { sessions.delete(token); return null; }
  return acc;
}
function bearerAcc(req) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  return sessionUser(token);
}
function isOnline(username) {
  const set = socketsByName.get(key(username));
  return !!(set && set.size);
}
function blockedSet(acc) {
  return new Set((acc.blocked || []).map(key));
}
function isBlocked(a, b) {
  const A = accounts.get(key(a));
  const B = accounts.get(key(b));
  if (A && blockedSet(A).has(key(b))) return true;
  if (B && blockedSet(B).has(key(a))) return true;
  return false;
}
function publicAccount(acc, viewer) {
  if (!acc) return null;
  const st = settingsOf(acc);
  const hideSeen = st.lastSeen === 'none' && (!viewer || key(viewer) !== key(acc.username));
  return {
    username: acc.username,
    displayName: acc.displayName || acc.username,
    about: acc.about || '',
    avatar: acc.avatar || '',
    pubKey: acc.pubKey || null,
    isBot: !!acc.isBot,
    verified: isVerified(acc.username),
    owner: isOwnerUser(acc.username),
    banned: !!acc.banned,
    commands: acc.isBot ? acc.botCommands || [] : undefined,
    online: acc.isBot ? true : isOnline(acc.username),
    lastSeen: hideSeen ? null : acc.lastSeen || null,
    lastSeenHidden: hideSeen,
  };
}
function listUsers(viewer) {
  return Array.from(accounts.values()).map((a) => publicAccount(a, viewer));
}
function pubKeys() {
  const out = {};
  for (const acc of accounts.values()) {
    if (acc.pubKey) out[key(acc.username)] = acc.pubKey;
  }
  return out;
}
function emitToUser(username, event, data) {
  const set = socketsByName.get(key(username));
  if (!set) return;
  for (const s of set) s.emit(event, data);
}
function emitToConv(conv, event, data, except) {
  for (const p of conv.participants) {
    if (except && key(p) === key(except)) continue;
    emitToUser(p, event, data);
  }
}
function addSocket(username, socket) {
  const k = key(username);
  if (!socketsByName.has(k)) socketsByName.set(k, new Set());
  socketsByName.get(k).add(socket);
}
function removeSocket(username, socket) {
  const k = key(username);
  const set = socketsByName.get(k);
  if (!set) return;
  set.delete(socket);
  if (!set.size) socketsByName.delete(k);
}
function me(socket) {
  return usersBySocket.get(socket.id) || null;
}

function emptyConv(extra) {
  return {
    messages: [],
    lastMessage: null,
    unread: {},
    readAt: {},
    flags: {},
    hidden: {},
    createdAt: Date.now(),
    ...extra,
  };
}

function getOrCreateDM(a, b) {
  const id = dmId(a, b);
  if (!convMap.has(id)) {
    convMap.set(id, emptyConv({ id, type: 'dm', name: null, participants: [a, b] }));
    persist();
  }
  const conv = convMap.get(id);
  if (conv.hidden) {
    delete conv.hidden[key(a)];
    delete conv.hidden[key(b)];
  }
  return conv;
}

function getOrCreateSecret(a, b) {
  const id = secretId(a, b);
  if (!convMap.has(id)) {
    convMap.set(
      id,
      emptyConv({ id, type: 'secret', name: null, participants: [a, b], e2e: true })
    );
    persist();
  }
  const conv = convMap.get(id);
  if (conv.hidden) {
    delete conv.hidden[key(a)];
    delete conv.hidden[key(b)];
  }
  return conv;
}

function ensureFav(username) {
  const id = favId(username);
  if (!convMap.has(id)) {
    convMap.set(
      id,
      emptyConv({
        id,
        type: 'fav',
        name: 'Избранное',
        participants: [username],
      })
    );
    persist();
  }
  return convMap.get(id);
}

function handleTaken(h, exceptId) {
  const k = key(h);
  if (!k) return true;
  if (accounts.has(k)) return true;
  for (const c of convMap.values()) {
    if (c.handle && key(c.handle) === k && c.id !== exceptId) return true;
  }
  return false;
}

function findByHandle(h) {
  const k = key(h);
  const acc = accounts.get(k);
  if (acc) return { kind: 'user', acc };
  for (const c of convMap.values()) {
    if (c.handle && key(c.handle) === k) return { kind: c.type === 'channel' ? 'channel' : 'group', conv: c };
  }
  return null;
}

function convForClient(conv, username) {
  const k = key(username);
  const other =
    conv.type === 'dm' || conv.type === 'secret'
      ? conv.participants.find((p) => key(p) !== k)
      : null;
  const flags = (conv.flags && conv.flags[k]) || {};
  let name = conv.name;
  if (conv.type === 'fav') name = 'Избранное';
  else if (conv.type === 'dm' || conv.type === 'secret') name = other;
  const last = conv.lastMessage ? { ...conv.lastMessage } : null;
  if (last && conv.type === 'secret') {
    last.text = '🔒 Секретное сообщение';
  }
  const owner = conv.owner || (conv.type === 'group' || conv.type === 'channel' ? conv.participants[0] : null);
  const admins = conv.admins || (owner ? [owner] : []);
  const canPost =
    conv.type !== 'channel' ||
    admins.some((a) => key(a) === k) ||
    (owner && key(owner) === k);
  return {
    id: conv.id,
    type: conv.type,
    name,
    handle: conv.handle || null,
    participants: conv.participants,
    lastMessage: last,
    unread: conv.unread[k] || 0,
    createdAt: conv.createdAt,
    pinned: !!flags.pin || conv.type === 'fav',
    muted: !!flags.mute,
    readAt: conv.readAt || {},
    e2e: conv.type === 'secret',
    owner: owner || null,
    admins,
    canPost,
    subscribers: conv.participants.length,
  };
}

function conversationsFor(username) {
  const k = key(username);
  const list = [];
  for (const conv of convMap.values()) {
    if (!conv.participants.some((p) => key(p) === k)) continue;
    if (conv.hidden && conv.hidden[k]) continue;
    list.push(convForClient(conv, username));
  }
  list.sort((a, b) => {
    if (a.type === 'fav' && b.type !== 'fav') return -1;
    if (b.type === 'fav' && a.type !== 'fav') return 1;
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
    const ta = a.lastMessage ? a.lastMessage.ts : a.createdAt || 0;
    const tb = b.lastMessage ? b.lastMessage.ts : b.createdAt || 0;
    return tb - ta;
  });
  return list;
}

function sanitizeReply(reply, conv) {
  if (!reply || !reply.id) return null;
  const src = (conv.messages || []).find((m) => m.id === reply.id);
  if (!src || src.deleted) return null;
  return {
    id: src.id,
    from: src.from,
    text: String(src.text || '').slice(0, 140),
    type: src.type,
  };
}

function botsOf(username) {
  return Array.from(accounts.values())
    .filter((a) => a.isBot && key(a.botOwner) === key(username))
    .map((a) => ({
      username: a.username,
      displayName: a.displayName,
      token: a.botToken,
      about: a.about || '',
    }));
}
function findBotByToken(token) {
  const t = String(token || '');
  for (const a of accounts.values()) {
    if (a.isBot && a.botToken === t) return a;
  }
  return null;
}
function pushMessage(conv, msg) {
  conv.messages.push(msg);
  if (conv.messages.length > HISTORY_KEEP) conv.messages.splice(0, conv.messages.length - HISTORY_KEEP);
  conv.hidden = conv.hidden || {};
  conv.unread = conv.unread || {};
  const fromK = key(msg.from);
  for (const p of conv.participants) {
    const pk = key(p);
    delete conv.hidden[pk];
    if (pk !== fromK) conv.unread[pk] = (conv.unread[pk] || 0) + 1;
  }
  persist();
  for (const p of conv.participants) {
    emitToUser(p, 'receive_message', msg);
    emitToUser(p, 'conversation_upsert', convForClient(conv, p));
  }
}

function fileRef(id) {
  const rec = filesMeta.get(id);
  if (!rec) return null;
  return {
    id: rec.id,
    name: rec.name,
    size: rec.size,
    mime: rec.mime,
    url: '/files/' + rec.id,
  };
}


/* ===================== NMessenger additions: helpers ===================== */
const NAME_MAX = 48;
const ABOUT_MAX = 140;
function convOwner(conv) {
  return conv.owner || (conv.type === 'group' || conv.type === 'channel' ? conv.participants[0] : null);
}
function isConvOwner(conv, user) {
  const o = convOwner(conv);
  return !!o && key(o) === key(user);
}
function isConvAdmin(conv, user) {
  return isConvOwner(conv, user) || (conv.admins || []).some((a) => key(a) === key(user));
}
function broadcastConv(conv) {
  for (const p of conv.participants) emitToUser(p, 'conversation_upsert', convForClient(conv, p));
}
function isOwnerUser(u) { return OWNERS.has(key(u)); }
function isVerified(u) { if (isOwnerUser(u)) return true; const a = accounts.get(key(u)); return !!(a && a.verified); }
function isMod(u) { const a = accounts.get(key(u)); return !!a && !a.isBot && !a.banned && isVerified(u); }
function kickUser(username, reason) {
  for (const [t, sx] of sessions) if (key(sx.username) === key(username)) sessions.delete(t);
  const set = socketsByName.get(key(username));
  if (set) for (const sk of Array.from(set)) { try { sk.emit('auth_error', reason); sk.disconnect(true); } catch { } }
}
function deleteMsg(conv, msg) {
  msg.deleted = true; msg.text = ''; msg.file = null; msg.ciphertext = null; msg.replyTo = null; if (msg.poll) msg.poll = null;
  if (conv.lastMessage && conv.messages[conv.messages.length - 1] && conv.messages[conv.messages.length - 1].id === msg.id) conv.lastMessage.text = 'Сообщение удалено';
  persist();
  emitToConv(conv, 'message_updated', msg);
  for (const p of conv.participants) emitToUser(p, 'conversation_upsert', convForClient(conv, p));
}
function removeConversationForAll(conv, reason) {
  for (const p of conv.participants) emitToUser(p, 'conversation_removed', { id: conv.id, reason });
  convMap.delete(conv.id);
  persist();
}
function modSnapshot() {
  const users = Array.from(accounts.values()).filter((a) => !a.system).map((a) => ({ ...publicAccount(a, null), createdAt: a.createdAt || 0, banReason: a.banReason || '', botOwner: a.botOwner || null }));
  const convs = Array.from(convMap.values()).filter((c) => c.type === 'group' || c.type === 'channel').map((c) => ({ id: c.id, type: c.type, name: c.name, handle: c.handle || '', owner: convOwner(c), members: c.participants.length, messages: (c.messages || []).length, createdAt: c.createdAt || 0 }));
  const reps = reports.slice(-100).reverse().map((r) => ({ ...r, fromName: displayOf(r.from), targetName: r.target ? displayOf(r.target) : '' }));
  return { users, convs, reports: reps, stats: storeStats() };
}

/* ===================== Bot API: очередь обновлений для внешних ботов (Python SDK) ===================== */
const botUpdates = new Map();
function botQueue(b) {
  const k = key(b);
  let q = botUpdates.get(k);
  if (!q) { q = { seq: 0, items: [], waiters: [] }; botUpdates.set(k, q); }
  return q;
}
function tgMessage(conv, msg) {
  const fromAcc = accounts.get(key(msg.from));
  const out = {
    message_id: msg.id,
    date: Math.floor((msg.ts || Date.now()) / 1000),
    chat: { id: conv.id, type: conv.type === 'dm' ? 'private' : conv.type, title: conv.name || null, handle: conv.handle || null },
    from: { username: msg.from, first_name: fromAcc ? fromAcc.displayName || fromAcc.username : msg.from, is_bot: !!(fromAcc && fromAcc.isBot) },
    type: msg.type,
    text: msg.text || '',
  };
  if (msg.file) out.file = { id: msg.file.id, name: msg.file.name, size: msg.file.size, mime: msg.file.mime, url: msg.file.url };
  if (msg.type === 'poll' && msg.poll) out.poll = msg.poll;
  if (msg.replyTo) out.reply_to_message = { message_id: msg.replyTo.id, text: msg.replyTo.text || '', from: msg.replyTo.from || null };
  return out;
}
/* ===================== Опросы (как в Telegram) ===================== */
const POLL_Q_MAX = 255, POLL_OPT_MAX = 100, POLL_OPTS_MAX = 10, POLL_EXPL_MAX = 200, POLL_MAX_PERIOD = 7 * 24 * 3600;
function buildPoll(raw) {
  if (!raw || typeof raw !== 'object') return { error: 'Нет данных опроса' };
  const question = String(raw.question || '').trim().slice(0, POLL_Q_MAX);
  if (!question) return { error: 'Введите вопрос' };
  const seen = new Set();
  const options = (Array.isArray(raw.options) ? raw.options : []).map((o) => String(typeof o === 'object' && o ? o.text : o || '').trim().slice(0, POLL_OPT_MAX)).filter((t) => { if (!t || seen.has(t.toLowerCase())) return false; seen.add(t.toLowerCase()); return true; }).slice(0, POLL_OPTS_MAX);
  if (options.length < 2) return { error: 'Нужно минимум 2 разных варианта' };
  const quiz = !!raw.quiz;
  const multiple = !quiz && !!raw.multiple;
  let correct = quiz ? parseInt(raw.correct, 10) : -1;
  if (quiz && !(correct >= 0 && correct < options.length)) return { error: 'Выберите правильный ответ викторины' };
  const explanation = quiz ? String(raw.explanation || '').trim().slice(0, POLL_EXPL_MAX) : '';
  let period = parseInt(raw.closesIn, 10) || 0;
  period = Math.min(POLL_MAX_PERIOD, Math.max(0, period));
  return { poll: { question, options: options.map((text) => ({ text })), anonymous: raw.anonymous !== false, multiple, quiz, correct, explanation, closed: false, closesAt: period ? Date.now() + period * 1000 : 0, votes: {} } };
}
function pollIsClosed(p) { return !!(p.closed || (p.closesAt && Date.now() >= p.closesAt)); }
function pollView(p, forUser) {
  // Что видит конкретный пользователь: счётчики, свои голоса; для публичных опросов — кто голосовал. Сырые голоса не отдаём.
  const votes = p.votes || {};
  const counts = p.options.map(() => 0);
  let total = 0;
  for (const arr of Object.values(votes)) { if (!arr || !arr.length) continue; total++; for (const i of arr) if (counts[i] !== undefined) counts[i]++; }
  const my = (forUser && votes[key(forUser)]) || [];
  const closed = pollIsClosed(p);
  const out = { question: p.question, options: p.options.map((o) => ({ text: o.text })), anonymous: !!p.anonymous, multiple: !!p.multiple, quiz: !!p.quiz, closed, closesAt: p.closesAt || 0, counts, total, myVotes: my };
  if (!p.anonymous) { const voters = {}; for (const [u, arr] of Object.entries(votes)) for (const i of arr || []) (voters[i] = voters[i] || []).push(u); out.voters = voters; }
  if (p.quiz && (my.length || closed)) { out.correct = p.correct; out.explanation = p.explanation || ''; }
  return out;
}
function shapeMsgFor(msg, forUser) {
  if (!msg || msg.type !== 'poll' || !msg.poll) return msg;
  return { ...msg, poll: pollView(msg.poll, forUser) };
}
function shapeOut(event, data, forUser) {
  if (!data || typeof data !== 'object') return data;
  if (event === 'receive_message' || event === 'message_updated') return shapeMsgFor(data, forUser);
  if ((event === 'history' || event === 'history_more') && Array.isArray(data.messages)) {
    const conv = convMap.get(data.conversationId);
    const total = conv ? (conv.messages || []).length : data.messages.length;
    return { total, hasMore: event === 'history' ? total > data.messages.length : data.hasMore, ...data, messages: data.messages.map((m) => shapeMsgFor(m, forUser)) };
  }
  return data;
}
function dispatchToBots(conv, msg) {
  if (!msg || msg.type === 'system' || msg.type === 'secret' || msg.type === 'call') return;
  const fromAcc = accounts.get(key(msg.from));
  if (fromAcc && fromAcc.isBot) return;
  for (const p of conv.participants) {
    const a = accounts.get(key(p));
    if (!a || !a.isBot || a.system) continue;
    const q = botQueue(p);
    q.seq += 1;
    q.items.push({ update_id: q.seq, message: tgMessage(conv, shapeMsgFor(msg, p)) });
    if (q.items.length > 1000) q.items.splice(0, q.items.length - 1000);
    for (const w of q.waiters.splice(0)) { try { w(); } catch { } }
  }
}
function botChat(bot, chatId) {
  let conv = convMap.get(String(chatId || '').trim());
  if (!conv) {
    const user = accounts.get(key(String(chatId || '')));
    if (user && !user.isBot) conv = getOrCreateDM(bot.username, user.username);
  }
  if (!conv) return { error: 'Чат не найден', code: 404 };
  if (!conv.participants.some((p) => key(p) === key(bot.username))) return { error: 'Бот не добавлен в этот чат', code: 403 };
  if (conv.type === 'channel' && !isConvAdmin(conv, bot.username)) return { error: 'Бот не админ канала', code: 403 };
  return { conv };
}
function storeFile(buf, name, mime, owner) {
  let orig = String(name || 'file');
  try { orig = decodeURIComponent(orig); } catch { }
  orig = path.basename(orig).replace(/[^\w.\p{L}\p{N} ()_-]+/gu, '_').slice(0, 120) || 'file';
  mime = String(mime || 'application/octet-stream').slice(0, 80);
  const id = uid() + path.extname(orig).slice(0, 10);
  if (!fs.existsSync(FILES_DIR)) fs.mkdirSync(FILES_DIR, { recursive: true });
  fs.writeFileSync(path.join(FILES_DIR, id), buf);
  const rec = { id, name: orig, size: buf.length, mime, owner, ts: Date.now() };
  filesMeta.set(id, rec);
  persist();
  return rec;
}

/* ===================== AI-помощник: внешний LLM (OpenAI-совместимый) или встроенный корректор ===================== */
const AI = { url: String(process.env.AI_API_URL || 'https://api.openai.com/v1').replace(/\/+$/, ''), key: String(process.env.AI_API_KEY || ''), model: String(process.env.AI_MODEL || 'gpt-4o-mini') };
function aiInfo() { return { llm: !!AI.key, model: AI.key ? AI.model : null, actions: AI.key ? ['fix', 'shorter', 'polite', 'formal', 'translate', 'emoji'] : ['fix'] }; }
const AI_PROMPTS = {
  fix: 'Ты корректор. Исправь орфографические, пунктуационные и грамматические ошибки в тексте пользователя. Сохрани смысл, стиль, язык, переносы строк, эмодзи, ссылки, @упоминания и форматирование. Верни только исправленный текст без пояснений и кавычек.',
  shorter: 'Сократи текст пользователя примерно вдвое, сохранив смысл, язык и тон. Верни только результат.',
  polite: 'Перепиши текст пользователя вежливо и дружелюбно, сохранив смысл и язык. Верни только результат.',
  formal: 'Перепиши текст пользователя в деловом стиле, сохранив смысл и язык. Верни только результат.',
  translate: 'Переведи текст пользователя: если он на русском — на английский, иначе — на русский. Верни только перевод.',
  emoji: 'Добавь в текст пользователя несколько уместных эмодзи, не меняя слов. Верни только результат.',
};
async function askLLM(system, user) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 30000);
  try {
    const r = await fetch(AI.url + '/chat/completions', {
      method: 'POST', signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + AI.key },
      body: JSON.stringify({ model: AI.model, temperature: 0.2, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] }),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((j.error && j.error.message) || 'HTTP ' + r.status);
    const out = j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content;
    if (typeof out !== 'string' || !out.trim()) throw new Error('пустой ответ модели');
    return out.trim();
  } finally { clearTimeout(t); }
}
const TYPOS = {
  // русские опечатки и просторечия
  'щас': 'сейчас', 'ща': 'сейчас', 'счас': 'сейчас', 'ваще': 'вообще', 'вобще': 'вообще', 'вопще': 'вообще', 'кароче': 'короче', 'седня': 'сегодня', 'сёдня': 'сегодня', 'ниче': 'ничего', 'ничё': 'ничего', 'ничо': 'ничего', 'тока': 'только', 'токо': 'только', 'када': 'когда', 'тада': 'тогда', 'чё': 'что', 'че': 'что', 'чо': 'что', 'шо': 'что', 'ево': 'его', 'сево': 'сего', 'тя': 'тебя', 'тебе': 'тебе',
  'пожалуста': 'пожалуйста', 'пожалуйсто': 'пожалуйста', 'пожалуйста': 'пожалуйста', 'пожалста': 'пожалуйста', 'пж': 'пожалуйста', 'пжл': 'пожалуйста', 'пжлст': 'пожалуйста', 'плз': 'пожалуйста', 'спс': 'спасибо', 'спосибо': 'спасибо', 'спасиба': 'спасибо', 'спасибки': 'спасибо', 'здраствуйте': 'здравствуйте', 'здравствуйте': 'здравствуйте', 'здрасте': 'здравствуйте', 'здрасьте': 'здравствуйте', 'здраствуй': 'здравствуй', 'прив': 'привет', 'превет': 'привет', 'привет': 'привет', 'здарова': 'здорово', 'дарова': 'здорово', 'досвидания': 'до свидания', 'досвидание': 'до свидания', 'извени': 'извини', 'извените': 'извините', 'извиняюсь': 'извините',
  'незнаю': 'не знаю', 'немогу': 'не могу', 'нехочу': 'не хочу', 'небуду': 'не буду', 'непомню': 'не помню', 'непонял': 'не понял', 'непоняла': 'не поняла', 'неполучается': 'не получается', 'неполучилось': 'не получилось', 'нету': 'нет', 'неа': 'нет', 'ага': 'да',
  'чтото': 'что-то', 'ктото': 'кто-то', 'гдето': 'где-то', 'какойто': 'какой-то', 'какаято': 'какая-то', 'какието': 'какие-то', 'когдато': 'когда-то', 'кудато': 'куда-то', 'почемуто': 'почему-то', 'изза': 'из-за', 'изпод': 'из-под', 'потомучто': 'потому что', 'потомушто': 'потому что', 'всётаки': 'всё-таки', 'всетаки': 'всё-таки', 'вобщем': 'в общем', 'вообщем': 'в общем', 'вкраце': 'вкратце', 'вобщемто': 'в общем-то', 'ксожалению': 'к сожалению', 'наверно': 'наверное', 'наврятли': 'навряд ли', 'врятли': 'вряд ли', 'врядли': 'вряд ли', 'нискем': 'ни с кем', 'ниочем': 'ни о чём', 'ниочём': 'ни о чём',
  'зделать': 'сделать', 'зделал': 'сделал', 'зделала': 'сделала', 'зделаю': 'сделаю', 'зделай': 'сделай', 'сдесь': 'здесь', 'здать': 'сдать', 'расказать': 'рассказать', 'расказ': 'рассказ', 'расказал': 'рассказал', 'росказ': 'рассказ', 'програма': 'программа', 'програмы': 'программы', 'програму': 'программу', 'програмист': 'программист', 'колличество': 'количество', 'коллекция': 'коллекция', 'агенство': 'агентство', 'будующий': 'будущий', 'будующего': 'будущего', 'следущий': 'следующий', 'следущего': 'следующего', 'ихний': 'их', 'ихние': 'их', 'ихняя': 'их', 'евоный': 'его', 'ейный': 'её', 'ложить': 'класть', 'ложи': 'клади', 'координально': 'кардинально', 'прецендент': 'прецедент', 'инциндент': 'инцидент', 'черезчур': 'чересчур', 'симпотичный': 'симпатичный', 'симпотичная': 'симпатичная', 'щитать': 'считать', 'щитаю': 'считаю', 'щитаешь': 'считаешь', 'сматреть': 'смотреть', 'сматри': 'смотри', 'придти': 'прийти', 'прийдти': 'прийти', 'прийду': 'приду', 'прийдёт': 'придёт', 'прийдет': 'придёт', 'ездиет': 'ездит', 'едит': 'едет', 'хотит': 'хочет', 'хочут': 'хотят', 'ложится': 'ложится', 'экспрессо': 'эспрессо', 'ньюанс': 'нюанс', 'девченка': 'девчонка', 'девчёнка': 'девчонка', 'мущина': 'мужчина', 'мущины': 'мужчины', 'вкустно': 'вкусно', 'сдесь': 'здесь', 'зделка': 'сделка', 'бесплатно': 'бесплатно', 'безплатно': 'бесплатно', 'безполезно': 'бесполезно', 'расчитать': 'рассчитать', 'расчитывать': 'рассчитывать', 'росписаться': 'расписаться', 'росписание': 'расписание', 'зарание': 'заранее', 'зараннее': 'заранее', 'исскуство': 'искусство', 'искуство': 'искусство', 'военый': 'военный', 'обажаю': 'обожаю', 'обещяю': 'обещаю', 'обещяние': 'обещание', 'вообщето': 'вообще-то', 'сдесь': 'здесь', 'офицально': 'официально', 'офицальный': 'официальный', 'аккаунт': 'аккаунт', 'акаунт': 'аккаунт', 'акаунта': 'аккаунта', 'месенджер': 'мессенджер', 'мессенжер': 'мессенджер', 'месседж': 'сообщение', 'сылка': 'ссылка', 'сылку': 'ссылку', 'сылки': 'ссылки', 'скинь': 'скинь', 'зарегестрироваться': 'зарегистрироваться', 'зарегестрировался': 'зарегистрировался', 'регестрация': 'регистрация', 'пороль': 'пароль', 'пороля': 'пароля', 'учавствовать': 'участвовать', 'учавствую': 'участвую', 'чуствовать': 'чувствовать', 'чуствую': 'чувствую', 'растояние': 'расстояние', 'скачять': 'скачать', 'устонавливать': 'устанавливать', 'устоновить': 'установить', 'скрин': 'скрин', 'сфоткай': 'сфотографируй',
  'хочеш': 'хочешь', 'можеш': 'можешь', 'делаеш': 'делаешь', 'знаеш': 'знаешь', 'будеш': 'будешь', 'идеш': 'идёшь', 'идёш': 'идёшь', 'пишеш': 'пишешь', 'скажеш': 'скажешь', 'сможеш': 'сможешь', 'придеш': 'придёшь', 'придёш': 'придёшь', 'видиш': 'видишь', 'говориш': 'говоришь', 'смотриш': 'смотришь', 'сидиш': 'сидишь', 'спиш': 'спишь',
  'ться': 'ться', 'тся': 'тся',
  // английские
  'teh': 'the', 'recieve': 'receive', 'recieved': 'received', 'seperate': 'separate', 'definately': 'definitely', 'definetly': 'definitely', 'occured': 'occurred', 'untill': 'until', 'wich': 'which', 'becuase': 'because', 'becasue': 'because', 'becouse': 'because', 'alot': 'a lot', 'dont': "don't", 'cant': "can't", 'wont': "won't", 'im': "I'm", 'ive': "I've", 'thier': 'their', 'freind': 'friend', 'tommorow': 'tomorrow', 'tomorow': 'tomorrow', 'adress': 'address', 'begining': 'beginning', 'beleive': 'believe', 'calender': 'calendar', 'collegue': 'colleague', 'enviroment': 'environment', 'goverment': 'government', 'grammer': 'grammar', 'happend': 'happened', 'immediatly': 'immediately', 'independant': 'independent', 'neccessary': 'necessary', 'necesary': 'necessary', 'occassion': 'occasion', 'peice': 'piece', 'realy': 'really', 'recomend': 'recommend', 'succesful': 'successful', 'suprise': 'surprise', 'truely': 'truly', 'wierd': 'weird', 'writting': 'writing', 'youre': "you're", 'theyre': "they're", 'doesnt': "doesn't", 'didnt': "didn't", 'isnt': "isn't", 'wasnt': "wasn't", 'thats': "that's", 'whats': "what's", 'pls': 'please', 'plz': 'please', 'thx': 'thanks', 'u': 'you', 'ur': 'your', 'b4': 'before', 'tonite': 'tonight', 'accomodate': 'accommodate', 'acheive': 'achieve', 'arguement': 'argument', 'basicly': 'basically', 'buisness': 'business', 'comming': 'coming', 'excelent': 'excellent', 'existance': 'existence', 'familar': 'familiar', 'finaly': 'finally', 'foriegn': 'foreign', 'gaurd': 'guard', 'knowlege': 'knowledge', 'liason': 'liaison', 'lisence': 'license', 'mispell': 'misspell', 'noticable': 'noticeable', 'ocassion': 'occasion', 'persue': 'pursue', 'posession': 'possession', 'prefered': 'preferred', 'privelege': 'privilege', 'publically': 'publicly', 'reccomend': 'recommend', 'refered': 'referred', 'relevent': 'relevant', 'religous': 'religious', 'rythm': 'rhythm', 'sieze': 'seize', 'similiar': 'similar', 'sincerly': 'sincerely', 'speach': 'speech', 'sucess': 'success', 'tendancy': 'tendency', 'therefor': 'therefore', 'tounge': 'tongue', 'unfortunatly': 'unfortunately', 'usefull': 'useful', 'vaccuum': 'vacuum', 'vegtable': 'vegetable', 'wether': 'whether', 'wuz': 'was', 'gud': 'good', 'nite': 'night',
};
for (const k of Object.keys(TYPOS)) if (TYPOS[k] === k) delete TYPOS[k];
const REPEAT_OK = new Set(['очень', 'давно', 'быстро', 'тихо', 'далеко', 'чуть', 'еле', 'вот', 'ну', 'да', 'нет', 'так', 'много', 'мало', 'только', 'уже', 'ещё', 'еще', 'сильно', 'долго', 'вряд', 'едва', 'ха', 'хах', 'бла', 'тук', 'кап', 'ой', 'ай', 'no', 'very', 'so', 'really', 'bye', 'ha', 'la']);
const SOFT_EXC = new Set(['клавиш', 'афиш', 'ниш', 'депеш', 'финиш', 'фетиш', 'гашиш', 'кишмиш', 'дервиш', 'мякиш', 'шиш', 'кеш', 'флеш', 'меш', 'фарш', 'марш', 'гуляш', 'шалаш', 'ералаш', 'багаж', 'тираж', 'малыш', 'камыш', 'ландыш', 'латыш', 'крепыш', 'голыш', 'барыш', 'детёныш', 'детеныш', 'мышь', 'плешь']);
const ABBR = /(?:^|[\s(])(?:т|е|д|п|г|гг|ул|пр|просп|пер|д|кв|см|стр|рис|тел|им|др|проч|напр|руб|коп|тыс|млн|млрд|обл|р|с|ст|ч|мин|сек|сут|шт|экз|доп|букв|англ|рус|лат|т\.е|т\.д|т\.п|т\.к|т\.н|и\.т\.д|и\.т\.п|и\.о|Mr|Mrs|Ms|Dr|St|vs|etc|e\.g|i\.e|no|No|approx)\.$/i;
function matchCase(w, rep) {
  if (w.length > 1 && w === w.toUpperCase() && /\p{L}/u.test(w)) return rep.toUpperCase();
  if (w[0] === w[0].toUpperCase() && w[0] !== w[0].toLowerCase()) return rep[0].toUpperCase() + rep.slice(1);
  return rep;
}
function basicFix(input) {
  const prot = [];
  let text = String(input).replace(/```[\s\S]*?```|`[^`\n]*`|https?:\/\/\S+|www\.\S+|[\w.+-]+@[\w-]+\.[\w.-]+|@[\w.]+|#[\p{L}\p{N}_]+|\|\|[\s\S]*?\|\||\b\d+[.,:]\d+\b/gu, (m) => { prot.push(m); return '\u0001' + (prot.length - 1) + '\u0002'; });
  const isLatinText = (text.match(/\b[a-zA-Z]{2,}\b/g) || []).length >= 3;
  // 1. пробелы
  text = text.replace(/[ \t]+$/gm, '').replace(/[ \t]{2,}/g, ' ').replace(/\n{3,}/g, '\n\n');
  // 2. пунктуация: нет пробела перед , . ! ? ; : — есть пробел после
  text = text.replace(/ +([,.!?;:…])/g, '$1');
  text = text.replace(/([,;:])(?=[^\s\d\n\u0001,;:.!?)"»\]])/g, '$1 ');
  text = text.replace(/([.!?…]+)(?=[\p{L}])/gu, (m, p, off, str) => {
    const before = str.slice(Math.max(0, off - 12), off);
    if (ABBR.test(before + p)) return m;
    if (/\d$/.test(before)) return m;
    return m + ' ';
  });
  text = text.replace(/,{2,}/g, ',').replace(/(?<![.!?])\.{2}(?!\.)/g, '.').replace(/\?{3,}/g, '??').replace(/!{4,}/g, '!!!');
  // 3. повторы слов
  text = text.replace(/(?<![\p{L}\p{N}-])(\p{L}{2,})(?:[ \t]+\1(?![\p{L}\p{N}-]))+/giu, (m, w) => (REPEAT_OK.has(w.toLowerCase()) ? m : w));
  // 4. словарь опечаток + мягкий знак в глаголах 2-го лица
  text = text.replace(/\p{L}[\p{L}'’-]*/gu, (w) => {
    const lw = w.toLowerCase();
    if (lw === 'i' && isLatinText) return 'I';
    if (TYPOS[lw]) return matchCase(w, TYPOS[lw]);
    if (w.length >= 5 && /[еёи]ш$/u.test(lw) && /^[а-яё-]+$/i.test(lw) && !SOFT_EXC.has(lw) && /[аеёиоуыэюя][^аеёиоуыэюя]*[еёи]ш$/u.test(lw)) return w + 'ь';
    return w;
  });
  // 5. частицы через дефис
  text = text.replace(/(?<![\p{L}\p{N}-])(кто|что|какой|какая|какое|какие|какого|какому|каким|где|куда|откуда|когда|почему|зачем|как|чей|чья|чьё|чьи|сколько|кем|чем|кого|чего|кому|чему|каком|отчего)[ ]+(то|либо|нибудь)(?![\p{L}\p{N}-])/giu, '$1-$2');
  text = text.replace(/(?<![\p{L}\p{N}-])кое[ ]+(кто|что|как|где|куда|какой|какие|когда|чего|кому)(?![\p{L}\p{N}-])/giu, 'кое-$1');
  // 6. заглавные буквы в начале текста, строки и предложения
  text = text.replace(/(^|\n[ \t]*|[.!?…]+[ \t]+)(\p{Ll})/gmu, (m, a, b, off, str) => {
    if (/[.!?…]/.test(a)) { const before = str.slice(Math.max(0, off - 12), off + a.trimEnd().length); if (ABBR.test(before)) return m; }
    return a + b.toUpperCase();
  });
  // 7. точка в конце длинного сообщения, если предложения уже есть
  if (text.length >= 60 && /[.!?]/.test(text) && /[\p{L}\p{N}]$/u.test(text.trimEnd())) text = text.trimEnd() + '.';
  text = text.replace(/\u0001(\d+)\u0002/g, (m, i) => prot[+i]);
  const a = String(input).split(/\s+/), b = text.split(/\s+/);
  let changes = Math.abs(a.length - b.length);
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) changes++;
  return { text, changes };
}
const aiRate = new Map();
function aiAllowed(user) {
  const now = Date.now();
  const r = aiRate.get(key(user)) || { n: 0, t: now };
  if (now - r.t > 60000) { r.n = 0; r.t = now; }
  r.n += 1;
  aiRate.set(key(user), r);
  return r.n <= 30;
}

function displayOf(username) {
  const a = accounts.get(key(username));
  return a ? a.displayName || a.username : String(username);
}
function sysMessage(conv, text) {
  const sys = { id: uid(), conversationId: conv.id, from: 'system', type: 'system', text, ts: Date.now(), time: timeLabel() };
  conv.messages.push(sys);
  if (conv.messages.length > HISTORY_KEEP) conv.messages.splice(0, conv.messages.length - HISTORY_KEEP);
  conv.lastMessage = { text: sys.text, ts: sys.ts, from: 'system', time: sys.time };
  persist();
  for (const p of conv.participants) emitToUser(p, 'receive_message', sys);
  return sys;
}
function sendAsBot(conv, botUsername, text) {
  const ts = Date.now();
  const msg = { id: uid(), conversationId: conv.id, from: botUsername, type: 'text', text: String(text).slice(0, TEXT_MAX), ts, time: timeLabel(ts), reactions: {}, edited: false, deleted: false };
  conv.lastMessage = { text: msg.text, ts, from: botUsername, time: msg.time };
  pushMessage(conv, msg);
  return msg;
}
function createBotAccount(owner, username, displayName) {
  username = norm(username);
  displayName = norm(displayName) || username;
  if (!validUsername(username) || !/bot$/i.test(username) || username.length < 5) {
    return { error: 'Username бота: 5–24 символа (латиница, цифры, . _ -), должен оканчиваться на «bot»' };
  }
  if (accounts.has(key(username)) || handleTaken(username)) return { error: 'Такой username уже занят' };
  const token = 'nmbot:' + crypto.randomBytes(18).toString('hex');
  const dummy = hashPassword(crypto.randomBytes(16).toString('hex'));
  const acc = {
    username, displayName: displayName.slice(0, 32), about: 'Бот', avatar: '', pubKey: null, isBot: true, botOwner: owner, botToken: token,
    passHash: dummy.hash, salt: dummy.salt, createdAt: Date.now(), lastSeen: Date.now(), settings: defaultSettings(), blocked: [],
  };
  accounts.set(key(username), acc);
  persist();
  io.emit('users_update', listUsers());
  emitToUser(owner, 'bots_ok', botsOf(owner));
  return { acc };
}

/* ===================== BotFather (системный бот) ===================== */
const BOTFATHER = 'botfather';
const bfState = new Map();
function ensureSystemBots() {
  if (accounts.has(BOTFATHER)) return;
  const dummy = hashPassword(crypto.randomBytes(16).toString('hex'));
  accounts.set(BOTFATHER, {
    username: 'BotFather', displayName: 'BotFather', about: 'Создаю ботов и выдаю API-ключи. Напишите /help', avatar: '', pubKey: null,
    isBot: true, system: true, botOwner: 'system', botToken: 'nmbot:' + crypto.randomBytes(18).toString('hex'),
    passHash: dummy.hash, salt: dummy.salt, createdAt: Date.now(), lastSeen: Date.now(), settings: defaultSettings(), blocked: [],
  });
  persist();
}
const BF_HELP = `Я BotFather — создаю ботов для NMessenger и выдаю им API-ключи.

**Команды:**
/newbot — создать нового бота
/setcommands — список команд бота (подсказки при вводе «/»)
/mybots — мои боты
/token — показать API-ключ
/revoke — выпустить новый ключ (старый перестанет работать)
/setname — изменить имя бота
/setabout — изменить описание
/setuserpic — сменить аватар (пришлите фото)
/deletebot — удалить бота
/cancel — отменить текущее действие`;
function bfApiHelp(acc) {
  return `**API-ключ** @${acc.username} — никому не показывайте:
\`${acc.botToken}\`

**Бот на Python за минуту** (сторонние библиотеки не нужны):
1. Скачайте {ORIGIN}/sdk/nmessenger_bot.py в папку с ботом
2. Создайте bot.py:
\`\`\`
from nmessenger_bot import Bot

bot = Bot("${acc.botToken}", "{ORIGIN}")

@bot.command("start")
def start(m):
    m.reply("Привет! Я работаю 🎉")

@bot.message()
def echo(m):
    m.reply("Вы написали: " + m.text)

bot.run()
\`\`\`
3. Запустите: \`python bot.py\` — и напишите боту @${acc.username}
Полный пример с командами, файлами и кнопкой /help: {ORIGIN}/sdk/example_bot.py

**Отправить сообщение:**
\`\`\`
curl -X POST {ORIGIN}/api/bot/${acc.botToken}/sendMessage \\
  -H "Content-Type: application/json" \\
  -d '{"chat_id":"ID_чата_или_username","text":"Привет!"}'
\`\`\`
**Информация о боте:** \`GET {ORIGIN}/api/bot/${acc.botToken}/me\`

chat_id — ID чата из его информации (например group:abc123) или username пользователя. В группу или канал бота добавляют через информацию о чате → «Добавить бота».`;
}
function botFatherHandle(username, conv, msg) {
  const uk = key(username);
  const reply = (t) => sendAsBot(conv, 'BotFather', t);
  const text = String(msg.text || '').trim();
  const lower = text.toLowerCase();
  const st = bfState.get(uk);
  const myBots = () => Array.from(accounts.values()).filter((a) => a.isBot && key(a.botOwner) === uk);
  const findMine = (name) => { const n = key(String(name || '').replace(/^@/, '')); return myBots().find((b) => key(b.username) === n) || null; };
  const botsChanged = () => { persist(); io.emit('users_update', listUsers()); emitToUser(username, 'bots_ok', botsOf(username)); };
  function runCmd(c, b, tail) {
    tail = String(tail || '').trim();
    switch (c) {
      case '/token': return reply(bfApiHelp(b));
      case '/revoke': b.botToken = 'nmbot:' + crypto.randomBytes(18).toString('hex'); botsChanged(); return reply(`Новый ключ для @${b.username} выпущен, старый больше не работает.\n\n` + bfApiHelp(b));
      case '/setname':
        if (tail) { if (tail.length > 32) return reply('Имя: до 32 символов.'); b.displayName = tail; botsChanged(); return reply(`Имя обновлено: **${tail}**`); }
        bfState.set(uk, { step: 'setname_value', bot: b.username }); return reply(`Пришлите новое имя для @${b.username} (до 32 символов).`);
      case '/setabout':
        if (tail) { if (tail.length > ABOUT_MAX) return reply(`Описание: до ${ABOUT_MAX} символов.`); b.about = tail; botsChanged(); return reply('Описание обновлено.'); }
        bfState.set(uk, { step: 'setabout_value', bot: b.username }); return reply(`Пришлите описание для @${b.username} (до ${ABOUT_MAX} символов).`);
      case '/setcommands': {
        if (tail) { const cmds = tail.split(/\n|;/).map((l) => l.match(/^\s*\/?([a-z0-9_]{1,32})\s*[-—:]\s*(.{1,80})$/i)).filter(Boolean).map((m) => ({ command: m[1].toLowerCase(), description: m[2].trim() })); if (cmds.length) { b.botCommands = cmds.slice(0, 50); botsChanged(); return reply(`Сохранено команд: ${cmds.length}.`); } }
        bfState.set(uk, { step: 'setcommands_value', bot: b.username }); return reply(`Пришлите список команд для @${b.username}, каждая с новой строки в формате \`команда - описание\`:\n\`\`\`\nstart - Запустить бота\nhelp - Помощь\n\`\`\`\nЧтобы очистить — напишите «нет».`);
      }
      case '/setuserpic': bfState.set(uk, { step: 'userpic', bot: b.username }); return reply(`Пришлите фото — оно станет аватаром @${b.username}.`);
      case '/deletebot': bfState.set(uk, { step: 'delete_confirm', bot: b.username }); return reply(`Удалить @${b.username}? Это необратимо: бот исчезнет из всех чатов, а ключ перестанет работать.\n\nДля подтверждения пришлите: **Да, удалить**`);
    }
    return reply('Не знаю такой команды. Список: /help');
  }
  if (lower === '/cancel') { bfState.delete(uk); return reply(st ? 'Действие отменено.' : 'Нечего отменять.'); }
  if (st && !text.startsWith('/')) {
    switch (st.step) {
      case 'newbot_name': {
        if (msg.type !== 'text' || !text) return reply('Пришлите имя бота текстом.');
        if (text.length > 32) return reply('Слишком длинно — до 32 символов. Попробуйте ещё раз.');
        bfState.set(uk, { step: 'newbot_username', name: text });
        const hint = slug(text).replace(/[^a-z0-9_]/g, '').replace(/bot$/, '').slice(0, 16) || 'my';
        return reply(`Хорошо. Теперь username бота — латиница, цифры и «_», 5–24 символа, обязательно оканчивается на **bot**. Например: \`${hint}_bot\``);
      }
      case 'newbot_username': {
        const r = createBotAccount(username, text.replace(/^@/, ''), st.name);
        if (r.error) return reply(r.error + '\nПопробуйте другой username или /cancel.');
        bfState.delete(uk);
        return reply(`Готово! Бот **${r.acc.displayName}** создан: @${r.acc.username}\n\n` + bfApiHelp(r.acc));
      }
      case 'pick': {
        const b = findMine(text);
        if (!b) return reply('Такого бота у вас нет. Пришлите @username из /mybots или /cancel.');
        bfState.delete(uk);
        return runCmd(st.cmd, b, st.rest || '');
      }
      case 'setname_value': {
        const b = findMine(st.bot); bfState.delete(uk);
        if (!b) return reply('Бот не найден.');
        if (!text || text.length > 32) return reply('Имя: 1–32 символа. Попробуйте /setname ещё раз.');
        b.displayName = text; botsChanged(); return reply(`Имя обновлено: **${text}**`);
      }
      case 'setcommands_value': {
        const b = findMine(st.bot); bfState.delete(uk);
        if (!b) return reply('Бот не найден.');
        if (lower === 'нет' || lower === 'очистить' || lower === 'clear') { b.botCommands = []; botsChanged(); return reply('Команды очищены.'); }
        const cmds = text.split(/\n/).map((l) => l.match(/^\/?([a-z0-9_]{1,32})\s*[-—:]\s*(.{1,80})$/i)).filter(Boolean).map((m) => ({ command: m[1].toLowerCase(), description: m[2].trim() }));
        if (!cmds.length) return reply('Не понял формат. Каждая строка: `команда - описание`, например:\n```\nstart - Запустить бота\nhelp - Помощь\n```');
        b.botCommands = cmds.slice(0, 50); botsChanged();
        return reply(`Сохранено команд: ${b.botCommands.length}. Теперь при вводе «/» в чате с @${b.username} появятся подсказки.`);
      }
      case 'setabout_value': {
        const b = findMine(st.bot); bfState.delete(uk);
        if (!b) return reply('Бот не найден.');
        if (text.length > ABOUT_MAX) return reply(`Описание: до ${ABOUT_MAX} символов. Попробуйте /setabout ещё раз.`);
        b.about = text; botsChanged(); return reply('Описание обновлено.');
      }
      case 'userpic': {
        const b = findMine(st.bot); bfState.delete(uk);
        if (!b) return reply('Бот не найден.');
        if (msg.type !== 'image' || !msg.file || !msg.file.url) return reply('Нужно прислать именно фото. Попробуйте /setuserpic ещё раз.');
        b.avatar = msg.file.url; botsChanged(); return reply('Аватар обновлён.');
      }
      case 'delete_confirm': {
        const b = findMine(st.bot); bfState.delete(uk);
        if (!b) return reply('Бот не найден.');
        if (lower !== 'да, удалить') return reply('Удаление отменено.');
        accounts.delete(key(b.username)); botsChanged();
        return reply(`Бот @${b.username} удалён.`);
      }
    }
  }
  if (st && text.startsWith('/')) bfState.delete(uk);
  if (!text.startsWith('/')) return reply('Я понимаю только команды. Список: /help');
  const parts = text.split(/\s+/);
  const c = parts[0].toLowerCase();
  const rest = parts.slice(1).join(' ');
  if (c === '/start' || c === '/help') return reply((c === '/start' ? `Привет, ${displayOf(username)}! ` : '') + BF_HELP);
  if (c === '/newbot') { bfState.set(uk, { step: 'newbot_name' }); return reply('Отлично, создаём нового бота. Как его назовём? Пришлите имя (до 32 символов).'); }
  if (c === '/mybots') {
    const bots = myBots();
    if (!bots.length) return reply('У вас пока нет ботов. Создайте первого: /newbot');
    return reply('**Ваши боты:**\n' + bots.map((b) => `• ${b.displayName} — @${b.username}`).join('\n') + `\n\nУправление: /token, /revoke, /setname, /setabout, /setuserpic, /setcommands, /deletebot — можно сразу с @username, например \`/token @${bots[0].username}\``);
  }
  if (['/token', '/revoke', '/setname', '/setabout', '/setuserpic', '/deletebot', '/setcommands'].includes(c)) {
    const bots = myBots();
    if (!bots.length) return reply('У вас пока нет ботов. Создайте: /newbot');
    let b = null;
    let tail = rest;
    const m = rest.match(/^@?(\S+)\s*([\s\S]*)$/);
    if (m && findMine(m[1])) { b = findMine(m[1]); tail = m[2]; }
    else if (bots.length === 1) b = bots[0];
    if (!b) { bfState.set(uk, { step: 'pick', cmd: c, rest }); return reply('Какой бот? Пришлите @username:\n' + bots.map((x) => '• @' + x.username).join('\n')); }
    return runCmd(c, b, tail);
  }
  return reply('Не знаю такой команды. Список: /help');
}

/* ===================== Вход по QR-коду ===================== */
const qrLogins = new Map();
function qrCleanup() {
  const now = Date.now();
  for (const [id, q] of qrLogins) if (now - q.createdAt > 3 * 60 * 1000) qrLogins.delete(id);
}

function attachUser(socket, acc) {
  const username = acc.username;
  usersBySocket.set(socket.id, username);
  addSocket(username, socket);
  acc.lastSeen = Date.now();
  ensureFav(username);
  persist();
  socket.emit('auth_ok', {
    user: publicAccount(acc, username),
    users: listUsers(username),
    conversations: conversationsFor(username),
    livekit: livekitEnabled(),
    settings: settingsOf(acc),
    blocked: acc.blocked || [],
    pubKeys: pubKeys(),
    textMax: TEXT_MAX,
    folders: acc.folders || [],
    bots: botsOf(username),
    ai: aiInfo(),
    isMod: isMod(username),
    isOwner: isOwnerUser(username),
  });
  io.emit('users_update', listUsers());
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/ping', (req, res) => res.send('Server is alive!'));
app.get('/livekit-status', (req, res) => res.json({ enabled: livekitEnabled() }));
// Клиентская библиотека LiveKit раздаётся локально (зафиксированная версия из package.json) — без зависимости от CDN
const LK_CLIENT_FILE = (() => {
  try { const p = require.resolve('livekit-client'); const f = p.endsWith('.umd.js') ? p : path.join(path.dirname(p), 'livekit-client.umd.js'); return fs.existsSync(f) ? f : null; } catch { return null; }
})();
app.get('/vendor/livekit-client.umd.js', (req, res) => {
  if (!LK_CLIENT_FILE) return res.status(404).end();
  res.set('Cache-Control', 'public, max-age=86400');
  res.sendFile(LK_CLIENT_FILE);
});

app.post('/get-livekit-token', async (req, res) => {
  try {
    if (!livekitEnabled()) {
      return res.status(503).json({ error: 'LiveKit не настроен' });
    }
    const acc = bearerAcc(req);
    if (!acc) return res.status(401).json({ error: 'Нужна авторизация' });
    const { roomName, participantName } = req.body || {};
    if (!roomName || !participantName) {
      return res.status(400).json({ error: 'Нужно имя комнаты и пользователя' });
    }
    const at = new AccessToken(
      process.env.LIVEKIT_API_KEY,
      process.env.LIVEKIT_API_SECRET,
      { identity: participantName, ttl: '10h' }
    );
    at.addGrant({
      roomJoin: true,
      room: roomName,
      canPublish: true,
      canSubscribe: true,
    });
    res.json({ token: await at.toJwt(), url: process.env.LIVEKIT_URL });
  } catch (error) {
    console.error('Ошибка токена:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/register', (req, res) => {
  const username = norm(req.body?.username);
  const password = String(req.body?.password || '');
  const displayName = norm(req.body?.displayName) || username;
  if (!validUsername(username)) {
    return res.status(400).json({ error: 'Логин: 2–24 символа, буквы, цифры, . _ -' });
  }
  if (password.length < 6 || password.length > 72) {
    return res.status(400).json({ error: 'Пароль: от 6 до 72 символов' });
  }
  if (displayName.length > 32) {
    return res.status(400).json({ error: 'Имя слишком длинное' });
  }
  if (accounts.has(key(username))) {
    return res.status(409).json({ error: 'Такой логин уже занят' });
  }
  // Имя владельца (OWNER_USERNAMES) может зарегистрировать только тот, кто знает ключ владельца (если ключ настроен)
  if (OWNERS.has(key(username)) && OWNER_KEY_HASH && !verifyOwnerKey(req.body?.ownerKey)) {
    return res.status(403).json({ error: 'Это имя закреплено за владельцем сервера. Введите ключ владельца', needOwnerKey: true });
  }
  const { hash, salt } = hashPassword(password);
  const acc = {
    username,
    displayName,
    about: '',
    avatar: '',
    pubKey: null,
    passHash: hash,
    salt,
    createdAt: Date.now(),
    lastSeen: Date.now(),
    settings: defaultSettings(),
    blocked: [],
  };
  accounts.set(key(username), acc);
  const token = createSession(username, {
    ua: req.headers['user-agent'],
    ip: req.ip,
  });
  persist();
  res.json({ token, user: publicAccount(acc, username) });
});

app.post('/api/login', (req, res) => {
  const username = norm(req.body?.username);
  const password = String(req.body?.password || '');
  const id = key(username) + '|' + (req.ip || '');
  if (tooManyTries(id)) {
    return res.status(429).json({ error: 'Слишком много попыток. Подождите 5 минут.' });
  }
  const acc = accounts.get(key(username));
  if (!acc || acc.isBot || !verifyPassword(password, acc.passHash, acc.salt)) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  if (acc.banned) return res.status(403).json({ error: 'Аккаунт заблокирован администрацией' + (acc.banReason ? ': ' + acc.banReason : '') });
  loginTries.delete(id);
  const token = createSession(username, {
    ua: req.headers['user-agent'],
    ip: req.ip,
  });
  acc.lastSeen = Date.now();
  persist();
  res.json({ token, user: publicAccount(acc, username) });
});

app.post('/api/logout', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (token) sessions.delete(token);
  persist();
  res.json({ ok: true });
});

/* ---- Резервные копии (только владелец) ---- */
function dirSize(dir) { let n = 0; try { for (const f of fs.readdirSync(dir)) { try { const st = fs.statSync(path.join(dir, f)); if (st.isFile()) n += st.size; } catch { } } } catch { } return n; }
function storeStats() {
  let messages = 0; for (const c of convMap.values()) messages += (c.messages || []).length;
  let storeSize = 0; try { storeSize = fs.statSync(DATA_FILE).size; } catch { }
  return { accounts: Array.from(accounts.values()).filter((a) => !a.system && !a.isBot).length, bots: Array.from(accounts.values()).filter((a) => a.isBot && !a.system).length, convs: convMap.size, messages, files: filesMeta.size, filesSize: dirSize(FILES_DIR), storeSize, dataDir: DATA_DIR, backups: listBackups().map((f) => path.basename(f)).slice(-5).reverse(), historyKeep: HISTORY_KEEP };
}
app.get('/api/admin/backup', (req, res) => {
  const acc = bearerAcc(req) || sessionUser(String(req.query.token || ''));
  if (!acc || !isOwnerUser(acc.username)) return res.status(403).json({ error: 'Только владелец' });
  const withFiles = req.query.files !== '0';
  const name = 'nmessenger-backup-' + new Date().toISOString().slice(0, 10) + (withFiles ? '' : '-nofiles') + '.json';
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
  const snap = snapshotStore({ withSessions: false });
  res.write('{"nm_backup":1,"version":3,"exportedAt":' + Date.now() + ',"store":' + JSON.stringify({ accounts: snap.accounts, conversations: snap.conversations, files: snap.files, reports: snap.reports }) + ',"blobs":{');
  let first = true;
  if (withFiles) for (const id of filesMeta.keys()) {
    const fp = path.join(FILES_DIR, id);
    if (!fs.existsSync(fp)) continue;
    try { res.write((first ? '' : ',') + JSON.stringify(id) + ':"' + fs.readFileSync(fp).toString('base64') + '"'); first = false; } catch { }
  }
  res.end('}}');
});
app.post('/api/admin/restore', express.raw({ type: '*/*', limit: '2gb' }), (req, res) => {
  const acc = bearerAcc(req);
  if (!acc || !isOwnerUser(acc.username)) return res.status(403).json({ error: 'Только владелец' });
  let data;
  try { data = Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString('utf8')) : (typeof req.body === 'string' ? JSON.parse(req.body) : req.body); } catch { return res.status(400).json({ error: 'Файл не похож на резервную копию NMessenger' }); }
  if (!data || data.nm_backup !== 1 || !data.store || !data.store.accounts) return res.status(400).json({ error: 'Файл не похож на резервную копию NMessenger' });
  makeBackup('before-restore');
  const st = normalizeStore(data.store);
  accounts.clear(); for (const [k, v] of Object.entries(st.accounts)) accounts.set(k, v);
  convMap.clear(); for (const [k, v] of Object.entries(st.conversations)) convMap.set(k, { ...v, messages: v.messages || [] });
  filesMeta.clear(); for (const [k, v] of Object.entries(st.files)) filesMeta.set(k, v);
  reports.splice(0, reports.length, ...(st.reports || []));
  let blobs = 0;
  if (data.blobs && typeof data.blobs === 'object') {
    if (!fs.existsSync(FILES_DIR)) fs.mkdirSync(FILES_DIR, { recursive: true });
    for (const [id, b64] of Object.entries(data.blobs)) { if (!/^[\w.-]+$/.test(id) || !filesMeta.has(id)) continue; try { fs.writeFileSync(path.join(FILES_DIR, id), Buffer.from(String(b64), 'base64')); blobs++; } catch { } }
  }
  ensureSystemBots();
  persistNow();
  io.emit('force_reload', { reason: 'restore' });
  res.json({ ok: true, accounts: accounts.size, conversations: convMap.size, files: blobs });
});

app.get('/api/sessions', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const acc = sessionUser(token);
  if (!acc) return res.status(401).json({ error: 'Нужна авторизация' });
  const list = [];
  for (const [t, s] of sessions) {
    if (key(s.username) !== key(acc.username)) continue;
    if (s.exp < Date.now()) continue;
    list.push({
      id: s.id,
      createdAt: s.createdAt,
      exp: s.exp,
      ua: s.ua || '',
      ip: s.ip || '',
      current: t === token,
    });
  }
  list.sort((a, b) => b.createdAt - a.createdAt);
  res.json({ sessions: list });
});

app.delete('/api/sessions/:id', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const acc = sessionUser(token);
  if (!acc) return res.status(401).json({ error: 'Нужна авторизация' });
  for (const [t, s] of sessions) {
    if (s.id === req.params.id && key(s.username) === key(acc.username)) {
      if (t === token) return res.status(400).json({ error: 'Нельзя удалить текущую сессию' });
      sessions.delete(t);
      persist();
      return res.json({ ok: true });
    }
  }
  res.status(404).json({ error: 'Сессия не найдена' });
});

app.get('/api/bot/:token/me', (req, res) => {
  const bot = findBotByToken(req.params.token);
  if (!bot) return res.status(401).json({ error: 'Неверный ключ' });
  res.json({
    ok: true,
    id: bot.username,
    username: bot.username,
    first_name: bot.displayName,
    is_bot: true,
  });
});

app.post('/api/bot/:token/sendMessage', (req, res) => {
  const bot = findBotByToken(req.params.token);
  if (!bot) return res.status(401).json({ error: 'Неверный ключ' });
  const chatId = String(req.body?.chat_id || '').trim();
  let text = String(req.body?.text || '').trim();
  if (!chatId || !text) return res.status(400).json({ error: 'Нужны chat_id и text' });
  if (text.length > TEXT_MAX) text = text.slice(0, TEXT_MAX);
  const bc = botChat(bot, chatId);
  if (bc.error) return res.status(bc.code).json({ error: bc.error });
  const conv = bc.conv;
  const ts = Date.now();
  const msg = {
    id: uid(),
    conversationId: conv.id,
    from: bot.username,
    type: 'text',
    text,
    ts,
    time: timeLabel(ts),
    replyTo: req.body?.reply_to_message_id ? sanitizeReply({ id: String(req.body.reply_to_message_id) }, conv) : null,
    reactions: {},
    edited: false,
    deleted: false,
  };
  conv.lastMessage = { text, ts, from: bot.username, time: msg.time };
  pushMessage(conv, msg);
  res.json({ ok: true, result: tgMessage(conv, msg), message_id: msg.id, chat_id: conv.id });
});

app.post('/api/bot/:token/sendPoll', (req, res) => {
  const bot = findBotByToken(req.params.token);
  if (!bot) return res.status(401).json({ error: 'Неверный ключ' });
  const b = req.body || {};
  const bc = botChat(bot, b.chat_id);
  if (bc.error) return res.status(bc.code).json({ error: bc.error });
  const built = buildPoll({ question: b.question, options: b.options, anonymous: b.is_anonymous !== false, multiple: !!b.allows_multiple_answers, quiz: b.type === 'quiz', correct: b.correct_option_id, explanation: b.explanation, closesIn: b.open_period });
  if (built.error) return res.status(400).json({ error: built.error });
  const conv = bc.conv; const ts = Date.now();
  const msg = { id: uid(), conversationId: conv.id, from: bot.username, type: 'poll', text: built.poll.question, poll: built.poll, ts, time: timeLabel(ts), replyTo: b.reply_to_message_id ? sanitizeReply({ id: String(b.reply_to_message_id) }, conv) : null, reactions: {}, edited: false, deleted: false };
  conv.lastMessage = { text: '📊 ' + built.poll.question, ts, from: bot.username, time: msg.time };
  pushMessage(conv, msg);
  res.json({ ok: true, result: tgMessage(conv, shapeMsgFor(msg, bot.username)), message_id: msg.id, chat_id: conv.id });
});
app.post('/api/bot/:token/stopPoll', (req, res) => {
  const bot = findBotByToken(req.params.token);
  if (!bot) return res.status(401).json({ error: 'Неверный ключ' });
  const bc = botChat(bot, req.body?.chat_id);
  if (bc.error) return res.status(bc.code).json({ error: bc.error });
  const msg = bc.conv.messages.find((m) => m.id === String(req.body?.message_id || ''));
  if (!msg || msg.type !== 'poll' || key(msg.from) !== key(bot.username)) return res.status(404).json({ error: 'Опрос не найден' });
  msg.poll.closed = true; persist(); emitToConv(bc.conv, 'message_updated', msg);
  res.json({ ok: true, result: pollView(msg.poll, bot.username) });
});

/* ---- Bot API для внешних ботов (Python SDK: /sdk/nmessenger_bot.py) ---- */
app.get('/api/bot/:token/getUpdates', async (req, res) => {
  const bot = findBotByToken(req.params.token);
  if (!bot) return res.status(401).json({ error: 'Неверный ключ' });
  const offset = Math.max(0, parseInt(req.query.offset || '0', 10) || 0);
  const timeout = Math.min(30, Math.max(0, parseInt(req.query.timeout || '0', 10) || 0));
  const q = botQueue(bot.username);
  q.items = q.items.filter((u) => u.update_id >= offset);
  const pick = () => q.items.filter((u) => u.update_id >= offset).slice(0, 100);
  let list = pick();
  if (!list.length && timeout > 0) {
    await new Promise((resolve) => {
      let done = false;
      const finish = () => { if (done) return; done = true; clearTimeout(t); const i = q.waiters.indexOf(finish); if (i >= 0) q.waiters.splice(i, 1); resolve(); };
      const t = setTimeout(finish, timeout * 1000);
      q.waiters.push(finish);
      req.on('close', finish);
    });
    list = pick();
  }
  res.json({ ok: true, result: list });
});
app.post('/api/bot/:token/setMyCommands', (req, res) => {
  const bot = findBotByToken(req.params.token);
  if (!bot) return res.status(401).json({ error: 'Неверный ключ' });
  const list = Array.isArray(req.body?.commands) ? req.body.commands : [];
  bot.botCommands = list.slice(0, 50).map((c) => ({ command: String(c.command || '').replace(/^\//, '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 32), description: String(c.description || '').slice(0, 80) })).filter((c) => c.command);
  persist();
  io.emit('users_update', listUsers());
  res.json({ ok: true, result: bot.botCommands });
});
app.get('/api/bot/:token/getMyCommands', (req, res) => {
  const bot = findBotByToken(req.params.token);
  if (!bot) return res.status(401).json({ error: 'Неверный ключ' });
  res.json({ ok: true, result: bot.botCommands || [] });
});
app.get('/api/bot/:token/getChat', (req, res) => {
  const bot = findBotByToken(req.params.token);
  if (!bot) return res.status(401).json({ error: 'Неверный ключ' });
  const bc = botChat(bot, req.query.chat_id);
  if (bc.error) return res.status(bc.code).json({ error: bc.error });
  const c = bc.conv;
  res.json({ ok: true, result: { id: c.id, type: c.type === 'dm' ? 'private' : c.type, title: c.name || null, handle: c.handle || null, members_count: c.participants.length, members: c.participants, owner: convOwner(c), admins: c.admins || [] } });
});
app.post('/api/bot/:token/sendChatAction', (req, res) => {
  const bot = findBotByToken(req.params.token);
  if (!bot) return res.status(401).json({ error: 'Неверный ключ' });
  const bc = botChat(bot, req.body?.chat_id);
  if (bc.error) return res.status(bc.code).json({ error: bc.error });
  emitToConv(bc.conv, 'typing', { conversationId: bc.conv.id, user: bot.username }, bot.username);
  res.json({ ok: true });
});
app.post('/api/bot/:token/deleteMessage', (req, res) => {
  const bot = findBotByToken(req.params.token);
  if (!bot) return res.status(401).json({ error: 'Неверный ключ' });
  const bc = botChat(bot, req.body?.chat_id);
  if (bc.error) return res.status(bc.code).json({ error: bc.error });
  const msg = bc.conv.messages.find((m) => m.id === String(req.body?.message_id || ''));
  if (!msg || msg.deleted) return res.status(404).json({ error: 'Сообщение не найдено' });
  if (key(msg.from) !== key(bot.username)) return res.status(403).json({ error: 'Можно удалять только свои сообщения' });
  deleteMsg(bc.conv, msg);
  res.json({ ok: true });
});
app.post('/api/bot/:token/editMessageText', (req, res) => {
  const bot = findBotByToken(req.params.token);
  if (!bot) return res.status(401).json({ error: 'Неверный ключ' });
  const bc = botChat(bot, req.body?.chat_id);
  if (bc.error) return res.status(bc.code).json({ error: bc.error });
  const msg = bc.conv.messages.find((m) => m.id === String(req.body?.message_id || ''));
  const text = String(req.body?.text || '').trim().slice(0, TEXT_MAX);
  if (!msg || msg.deleted || msg.type !== 'text') return res.status(404).json({ error: 'Сообщение не найдено' });
  if (key(msg.from) !== key(bot.username)) return res.status(403).json({ error: 'Можно менять только свои сообщения' });
  if (!text) return res.status(400).json({ error: 'Нужен text' });
  msg.text = text; msg.edited = true;
  if (bc.conv.messages[bc.conv.messages.length - 1].id === msg.id) bc.conv.lastMessage.text = text;
  persist();
  emitToConv(bc.conv, 'message_updated', msg);
  res.json({ ok: true, result: tgMessage(bc.conv, msg) });
});
const sendBotFile = (kind) => [express.raw({ type: '*/*', limit: MAX_FILE + 2048 }), (req, res) => {
  const bot = findBotByToken(req.params.token);
  if (!bot) return res.status(401).json({ error: 'Неверный ключ' });
  const bc = botChat(bot, req.query.chat_id || req.headers['x-chat-id']);
  if (bc.error) return res.status(bc.code).json({ error: bc.error });
  const buf = req.body;
  if (!Buffer.isBuffer(buf) || !buf.length) return res.status(400).json({ error: 'Пустой файл: отправьте содержимое файла телом запроса' });
  if (buf.length > MAX_FILE) return res.status(400).json({ error: 'Максимум 10 МБ' });
  const rec = storeFile(buf, req.headers['x-filename'] || (kind === 'image' ? 'photo.jpg' : 'file'), req.headers['x-mime'] || (kind === 'image' ? 'image/jpeg' : 'application/octet-stream'), bot.username);
  let caption = '';
  try { caption = decodeURIComponent(String(req.headers['x-caption'] || req.query.caption || '')).slice(0, TEXT_MAX); } catch { }
  const conv = bc.conv;
  const ts = Date.now();
  const file = fileRef(rec.id);
  const msg = { id: uid(), conversationId: conv.id, from: bot.username, type: kind, text: caption || (kind === 'image' ? 'Изображение' : file.name), file, ts, time: timeLabel(ts), replyTo: null, reactions: {}, edited: false, deleted: false };
  conv.lastMessage = { text: kind === 'image' ? '📷 Изображение' : '📎 ' + file.name, ts, from: bot.username, time: msg.time };
  pushMessage(conv, msg);
  res.json({ ok: true, result: tgMessage(conv, msg), message_id: msg.id, chat_id: conv.id });
}];
app.post('/api/bot/:token/sendDocument', ...sendBotFile('file'));
app.post('/api/bot/:token/sendPhoto', ...sendBotFile('image'));
app.get('/sdk/:name', (req, res) => {
  const name = String(req.params.name || '');
  if (!/^[\w.-]+\.py$/.test(name)) return res.status(404).end();
  const f = path.join(__dirname, 'sdk', name);
  if (!fs.existsSync(f)) return res.status(404).end();
  res.type('text/x-python; charset=utf-8');
  res.set('Content-Disposition', 'inline; filename="' + name + '"');
  res.send(fs.readFileSync(f, 'utf8'));
});

/* ---- AI-помощник ---- */
app.get('/api/ai/info', (req, res) => res.json(aiInfo()));
app.post('/api/ai', async (req, res) => {
  const acc = bearerAcc(req);
  if (!acc) return res.status(401).json({ error: 'Нужна авторизация' });
  if (!aiAllowed(acc.username)) return res.status(429).json({ error: 'Слишком часто. Подождите минуту.' });
  const action = String(req.body?.action || 'fix');
  let text = String(req.body?.text || '');
  if (!text.trim()) return res.status(400).json({ error: 'Пустой текст' });
  if (text.length > TEXT_MAX) text = text.slice(0, TEXT_MAX);
  if (AI.key) {
    try { return res.json({ ok: true, text: await askLLM(AI_PROMPTS[action] || AI_PROMPTS.fix, text), engine: 'llm' }); }
    catch (e) { if (action !== 'fix') return res.status(502).json({ error: 'ИИ недоступен: ' + e.message }); console.warn('AI fallback:', e.message); }
  }
  if (action !== 'fix') return res.status(400).json({ error: 'Эта функция требует ключ нейросети (AI_API_KEY в .env). Без ключа доступно «Исправить ошибки».' });
  const r = basicFix(text);
  res.json({ ok: true, text: r.text, engine: 'basic', changes: r.changes });
});

app.post(
  '/api/upload',
  express.raw({ type: '*/*', limit: MAX_FILE + 2048 }),
  (req, res) => {
    const acc = bearerAcc(req);
    if (!acc) return res.status(401).json({ error: 'Нужна авторизация' });
    const buf = req.body;
    if (!Buffer.isBuffer(buf) || !buf.length) {
      return res.status(400).json({ error: 'Пустой файл' });
    }
    if (buf.length > MAX_FILE) {
      return res.status(400).json({ error: 'Максимум 10 МБ' });
    }
    let orig = String(req.headers['x-filename'] || 'file');
    try {
      orig = decodeURIComponent(orig);
    } catch {}
    orig = path.basename(orig).replace(/[^\w.\p{L}\p{N} ()_-]+/gu, '_').slice(0, 120) || 'file';
    const mime = String(req.headers['x-mime'] || 'application/octet-stream').slice(0, 80);
    const ext = path.extname(orig).slice(0, 10);
    const id = uid() + ext;
    if (!fs.existsSync(FILES_DIR)) fs.mkdirSync(FILES_DIR, { recursive: true });
    fs.writeFileSync(path.join(FILES_DIR, id), buf);
    const rec = {
      id,
      name: orig,
      size: buf.length,
      mime,
      owner: acc.username,
      ts: Date.now(),
    };
    filesMeta.set(id, rec);
    persist();
    res.json({ id, name: orig, size: buf.length, mime, url: '/files/' + id });
  }
);

app.post('/api/qr/new', (req, res) => {
  qrCleanup();
  if (qrLogins.size > 500) return res.status(429).json({ error: 'Слишком много запросов' });
  const id = uid() + crypto.randomBytes(6).toString('hex');
  const secret = crypto.randomBytes(16).toString('hex');
  qrLogins.set(id, { secret, createdAt: Date.now(), token: null, username: null, ua: req.headers['user-agent'], ip: req.ip });
  res.json({ id, secret, ttl: 180000 });
});
app.get('/api/qr/status/:id', (req, res) => {
  qrCleanup();
  const q = qrLogins.get(req.params.id);
  if (!q || q.secret !== String(req.query.secret || '')) return res.status(404).json({ error: 'expired' });
  if (!q.token) return res.json({ status: 'pending' });
  qrLogins.delete(req.params.id);
  const acc = accounts.get(key(q.username));
  res.json({ status: 'approved', token: q.token, user: publicAccount(acc, acc.username) });
});
app.post('/api/qr/approve', (req, res) => {
  const acc = bearerAcc(req);
  if (!acc) return res.status(401).json({ error: 'Не авторизован' });
  qrCleanup();
  const q = qrLogins.get(String(req.body?.id || ''));
  if (!q) return res.status(404).json({ error: 'QR-код устарел. Обновите страницу входа и отсканируйте снова.' });
  if (q.token) return res.status(409).json({ error: 'Этот код уже использован' });
  q.username = acc.username;
  q.token = createSession(acc.username, { ua: 'QR · ' + String(q.ua || ''), ip: q.ip });
  res.json({ ok: true, user: publicAccount(acc, acc.username) });
});

app.get('/files/:id', (req, res) => {
  const id = String(req.params.id || '');
  if (!/^[a-z0-9._-]+$/i.test(id)) return res.status(400).end();
  const rec = filesMeta.get(id);
  const fp = path.join(FILES_DIR, id);
  if (!rec || !fs.existsSync(fp)) return res.status(404).end();
  res.setHeader('Content-Type', rec.mime || 'application/octet-stream');
  res.setHeader(
    'Content-Disposition',
    `inline; filename*=UTF-8''${encodeURIComponent(rec.name)}`
  );
  fs.createReadStream(fp).pipe(res);
});

io.on('connection', (socket) => {
  console.log('✅ Подключился:', socket.id);
  // Персонализация исходящих данных (опросы: свои голоса, скрытие голосов в анонимных опросах)
  const rawEmit = socket.emit.bind(socket);
  socket.emit = (event, data, ...rest) => rawEmit(event, shapeOut(event, data, me(socket)), ...rest);

  socket.on('auth', (token) => {
    const sess = sessions.get(String(token || ''));
    const bannedAcc = sess && accounts.get(key(sess.username));
    if (bannedAcc && bannedAcc.banned) { socket.emit('auth_error', 'Аккаунт заблокирован администрацией' + (bannedAcc.banReason ? ': ' + bannedAcc.banReason : '')); return; }
    const acc = sessionUser(String(token || ''));
    if (!acc) {
      socket.emit('auth_error', 'Сессия истекла. Войдите снова.');
      return;
    }
    attachUser(socket, acc);
  });

  socket.on('set_pubkey', (jwk) => {
    const username = me(socket);
    if (!username || !jwk || typeof jwk !== 'object') return;
    const acc = accounts.get(key(username));
    if (!acc) return;
    acc.pubKey = jwk;
    persist();
    io.emit('users_update', listUsers());
    io.emit('pubkeys_update', pubKeys());
  });

  socket.on('get_history', (conversationId) => {
    const username = me(socket);
    if (!username) return;
    const conv = convMap.get(conversationId);
    if (!conv || !conv.participants.some((p) => key(p) === key(username))) return;
    const acc = accounts.get(key(username));
    conv.unread[key(username)] = 0;
    conv.readAt = conv.readAt || {};
    if (settingsOf(acc).readReceipts) conv.readAt[key(username)] = Date.now();
    persist();
    socket.emit('history', {
      conversationId,
      messages: conv.messages.slice(-300),
    });
    for (const p of conv.participants) {
      emitToUser(p, 'conversation_upsert', convForClient(conv, p));
    }
  });

  socket.on('open_dm', (target) => {
    const username = me(socket);
    if (!username) return;
    target = norm(target);
    if (!target || key(target) === key(username)) return;
    const acc = accounts.get(key(target));
    if (!acc) return;
    if (isBlocked(username, acc.username)) {
      socket.emit('action_error', 'Пользователь заблокирован');
      return;
    }
    const conv = getOrCreateDM(username, acc.username);
    socket.emit('conversation_upsert', convForClient(conv, username));
    socket.emit('history', {
      conversationId: conv.id,
      messages: conv.messages.slice(-300),
    });
    emitToUser(acc.username, 'conversation_upsert', convForClient(conv, acc.username));
  });

  socket.on('open_secret', (target) => {
    const username = me(socket);
    if (!username) return;
    target = norm(target);
    const acc = accounts.get(key(target));
    if (!acc || key(target) === key(username)) return;
    if (isBlocked(username, acc.username)) {
      socket.emit('action_error', 'Пользователь заблокирован');
      return;
    }
    const conv = getOrCreateSecret(username, acc.username);
    socket.emit('conversation_upsert', convForClient(conv, username));
    socket.emit('history', {
      conversationId: conv.id,
      messages: conv.messages.slice(-300),
    });
    emitToUser(acc.username, 'conversation_upsert', convForClient(conv, acc.username));
  });

  socket.on('open_handle', (handle) => {
    const username = me(socket);
    if (!username) return;
    const found = findByHandle(handle);
    if (!found) {
      socket.emit('action_error', 'Не найдено: @' + handle);
      return;
    }
    if (found.kind === 'user') {
      if (key(found.acc.username) === key(username)) {
        const fav = ensureFav(username);
        socket.emit('conversation_upsert', convForClient(fav, username));
        socket.emit('history', { conversationId: fav.id, messages: fav.messages.slice(-300) });
        return;
      }
      socket.emit('open_dm_proxy');
      const acc = found.acc;
      if (isBlocked(username, acc.username)) {
        socket.emit('action_error', 'Пользователь заблокирован');
        return;
      }
      const conv = getOrCreateDM(username, acc.username);
      socket.emit('conversation_upsert', convForClient(conv, username));
      socket.emit('history', { conversationId: conv.id, messages: conv.messages.slice(-300) });
    } else {
      const conv = found.conv;
      if (!conv.participants.some((p) => key(p) === key(username))) {
        if (conv.type === 'channel') {
          conv.participants.push(username);
          persist();
        } else {
          socket.emit('action_error', 'Вы не состоите в @' + handle);
          return;
        }
      }
      socket.emit('conversation_upsert', convForClient(conv, username));
      socket.emit('history', { conversationId: conv.id, messages: conv.messages.slice(-300) });
    }
  });

  socket.on('open_fav', () => {
    const username = me(socket);
    if (!username) return;
    const conv = ensureFav(username);
    socket.emit('conversation_upsert', convForClient(conv, username));
    socket.emit('history', { conversationId: conv.id, messages: conv.messages.slice(-300) });
  });

  socket.on('create_group', ({ name, members, handle }) => {
    const username = me(socket);
    if (!username) return;
    name = norm(name);
    if (!name || name.length > 48) return;
    const parts = new Set([username]);
    for (const m of members || []) {
      const acc = accounts.get(key(m));
      if (acc) parts.add(acc.username);
    }
    if (parts.size < 2) return;
    let h = slug(handle || name);
    if (handleTaken(h)) h = (h + '_' + uid()).slice(0, 24);
    const conv = emptyConv({
      id: 'group:' + uid(),
      type: 'group',
      name,
      handle: h,
      owner: username,
      admins: [username],
      participants: Array.from(parts),
    });
    const sys = {
      id: uid(),
      conversationId: conv.id,
      from: 'system',
      type: 'system',
      text: `${username} создал группу «${name}» · @${h}`,
      ts: Date.now(),
      time: timeLabel(),
    };
    conv.messages.push(sys);
    conv.lastMessage = { text: sys.text, ts: sys.ts, from: 'system', time: sys.time };
    convMap.set(conv.id, conv);
    persist();
    for (const p of conv.participants) {
      emitToUser(p, 'conversation_upsert', convForClient(conv, p));
    }
    socket.emit('history', { conversationId: conv.id, messages: conv.messages });
  });

  socket.on('create_channel', ({ name, handle }) => {
    const username = me(socket);
    if (!username) return;
    name = norm(name);
    if (!name || name.length > 48) return;
    let h = slug(handle || name);
    if (handleTaken(h)) h = (h + '_' + uid()).slice(0, 24);
    const conv = emptyConv({
      id: 'channel:' + uid(),
      type: 'channel',
      name,
      handle: h,
      owner: username,
      admins: [username],
      participants: [username],
    });
    const sys = {
      id: uid(),
      conversationId: conv.id,
      from: 'system',
      type: 'system',
      text: `Канал «${name}» · @${h}`,
      ts: Date.now(),
      time: timeLabel(),
    };
    conv.messages.push(sys);
    conv.lastMessage = { text: sys.text, ts: sys.ts, from: 'system', time: sys.time };
    convMap.set(conv.id, conv);
    persist();
    socket.emit('conversation_upsert', convForClient(conv, username));
    socket.emit('history', { conversationId: conv.id, messages: conv.messages });
  });

  socket.on('create_bot', ({ username, displayName }) => {
    const owner = me(socket);
    if (!owner) return;
    username = norm(username);
    displayName = norm(displayName) || username;
    if (!validUsername(username) || !/bot$/i.test(username)) {
      socket.emit('action_error', 'Юзернейм бота: 2–24 символа и оканчивается на bot');
      return;
    }
    if (accounts.has(key(username)) || handleTaken(username)) {
      socket.emit('action_error', 'Такой логин уже занят');
      return;
    }
    const token = 'nmbot:' + crypto.randomBytes(18).toString('hex');
    const dummy = hashPassword(crypto.randomBytes(16).toString('hex'));
    const acc = {
      username,
      displayName: displayName.slice(0, 32),
      about: 'Бот',
      avatar: '',
      pubKey: null,
      isBot: true,
      botOwner: owner,
      botToken: token,
      passHash: dummy.hash,
      salt: dummy.salt,
      createdAt: Date.now(),
      lastSeen: Date.now(),
      settings: defaultSettings(),
      blocked: [],
    };
    accounts.set(key(username), acc);
    persist();
    io.emit('users_update', listUsers());
    socket.emit('bots_ok', botsOf(owner));
    socket.emit('bot_created', { username, displayName: acc.displayName, token });
  });

  socket.on('regen_bot', (botUser) => {
    const owner = me(socket);
    if (!owner) return;
    const acc = accounts.get(key(botUser));
    if (!acc || !acc.isBot || key(acc.botOwner) !== key(owner)) return;
    acc.botToken = 'nmbot:' + crypto.randomBytes(18).toString('hex');
    persist();
    socket.emit('bots_ok', botsOf(owner));
    socket.emit('bot_created', { username: acc.username, displayName: acc.displayName, token: acc.botToken });
  });

  socket.on('delete_bot', (botUser) => {
    const owner = me(socket);
    if (!owner) return;
    const acc = accounts.get(key(botUser));
    if (!acc || !acc.isBot || key(acc.botOwner) !== key(owner)) return;
    accounts.delete(key(botUser));
    persist();
    io.emit('users_update', listUsers());
    socket.emit('bots_ok', botsOf(owner));
  });

  socket.on('add_bot', ({ conversationId, bot }) => {
    const username = me(socket);
    if (!username) return;
    const conv = convMap.get(conversationId);
    const b = accounts.get(key(bot));
    if (!conv || !b || !b.isBot) return;
    if (conv.type !== 'group' && conv.type !== 'channel') return;
    const owner = conv.owner || conv.participants[0];
    if (key(owner) !== key(username) && !(conv.admins || []).some((a) => key(a) === key(username))) return;
    if (!conv.participants.some((p) => key(p) === key(b.username))) conv.participants.push(b.username);
    if (conv.type === 'channel') {
      conv.admins = conv.admins || [];
      if (!conv.admins.some((a) => key(a) === key(b.username))) conv.admins.push(b.username);
    }
    persist();
    for (const p of conv.participants) {
      emitToUser(p, 'conversation_upsert', convForClient(conv, p));
    }
  });

  socket.on('save_folders', (folders) => {
    const username = me(socket);
    if (!username || !Array.isArray(folders)) return;
    const acc = accounts.get(key(username));
    if (!acc) return;
    acc.folders = folders.slice(0, 24).map((f) => ({
      id: String(f.id || uid()).slice(0, 32),
      name: String(f.name || 'Папка').slice(0, 24),
      chats: Array.isArray(f.chats) ? f.chats.slice(0, 200).map(String) : [],
    }));
    persist();
    socket.emit('folders_ok', acc.folders);
  });

  socket.on('send_message', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv || !conv.participants.some((p) => key(p) === key(username))) return;
    if (conv.type === 'channel') {
      const owner = conv.owner || conv.participants[0];
      const admins = conv.admins || [owner];
      if (!admins.some((a) => key(a) === key(username))) {
        socket.emit('action_error', 'Писать в канал могут только админы');
        return;
      }
    }

    if (conv.type === 'dm' || conv.type === 'secret') {
      const other = conv.participants.find((p) => key(p) !== key(username));
      if (other && isBlocked(username, other)) {
        socket.emit('action_error', 'Пользователь заблокирован');
        return;
      }
    }

    const ts = Date.now();
    let msg;

    if (conv.type === 'secret') {
      if (!data.ciphertext || !data.iv) return;
      msg = {
        id: uid(),
        conversationId: conv.id,
        from: username,
        type: 'secret',
        e2e: true,
        ciphertext: String(data.ciphertext).slice(0, 2e6),
        iv: String(data.iv).slice(0, 64),
        text: '',
        ts,
        time: timeLabel(ts),
        replyTo: data.replyTo ? { id: data.replyTo.id } : null,
        reactions: {},
        edited: false,
        deleted: false,
      };
      conv.lastMessage = {
        text: '🔒 Секретное сообщение',
        ts,
        from: username,
        time: msg.time,
      };
    } else if (data.type === 'poll') {
      const built = buildPoll(data.poll);
      if (built.error) { socket.emit('action_error', built.error); return; }
      msg = { id: uid(), conversationId: conv.id, from: username, type: 'poll', text: built.poll.question, poll: built.poll, ts, time: timeLabel(ts), replyTo: sanitizeReply(data.replyTo, conv), reactions: {}, edited: false, deleted: false };
      conv.lastMessage = { text: '📊 ' + built.poll.question, ts, from: username, time: msg.time };
    } else {
      const allowed = ['text', 'image', 'file'];
      const type = allowed.includes(data.type) ? data.type : 'text';
      let text = typeof data.text === 'string' ? data.text.trim() : '';
      if (text.length > TEXT_MAX) text = text.slice(0, TEXT_MAX);
      let file = null;
      if ((type === 'image' || type === 'file') && data.file && data.file.id) {
        file = fileRef(data.file.id);
        if (!file) return;
        if (type === 'file' && !text) text = file.name;
        if (type === 'image' && !text) text = 'Изображение';
      } else if (type === 'text') {
        if (!text) return;
      } else {
        return;
      }
      msg = {
        id: uid(),
        conversationId: conv.id,
        from: username,
        type,
        text,
        file,
        ts,
        time: timeLabel(ts),
        replyTo: sanitizeReply(data.replyTo, conv),
        reactions: {},
        edited: false,
        deleted: false,
      };
      conv.lastMessage = {
        text: type === 'image' ? '📷 Изображение' : type === 'file' ? '📎 ' + (file?.name || 'Файл') : text,
        ts,
        from: username,
        time: msg.time,
      };
    }

    conv.messages.push(msg);
    if (conv.messages.length > HISTORY_KEEP) conv.messages.splice(0, conv.messages.length - HISTORY_KEEP);
    conv.hidden = conv.hidden || {};
    conv.unread = conv.unread || {};
    for (const p of conv.participants) {
      const pk = key(p);
      delete conv.hidden[pk];
      if (pk !== key(username)) conv.unread[pk] = (conv.unread[pk] || 0) + 1;
    }
    persist();
    for (const p of conv.participants) {
      emitToUser(p, 'receive_message', msg);
      emitToUser(p, 'conversation_upsert', convForClient(conv, p));
    }
    if (conv.type === 'dm' && key(username) !== BOTFATHER && conv.participants.some((p) => key(p) === BOTFATHER)) {
      try { botFatherHandle(username, conv, msg); } catch (e) { console.error('BotFather:', e); }
    }
    dispatchToBots(conv, msg);
  });

  socket.on('get_history_before', (data) => {
    // Подгрузка старых сообщений при прокрутке вверх
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv || !conv.participants.some((p) => key(p) === key(username))) return;
    const limit = Math.min(200, Math.max(20, parseInt(data.limit, 10) || 100));
    const idx = conv.messages.findIndex((m) => m.id === data.before);
    if (idx <= 0) return socket.emit('history_more', { conversationId: conv.id, messages: [], hasMore: false });
    const start = Math.max(0, idx - limit);
    socket.emit('history_more', { conversationId: conv.id, messages: conv.messages.slice(start, idx), hasMore: start > 0 });
  });
  socket.on('poll_vote', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv || !conv.participants.some((p) => key(p) === key(username))) return;
    const msg = conv.messages.find((m) => m.id === data.id);
    if (!msg || msg.deleted || msg.type !== 'poll' || !msg.poll) return;
    const p = msg.poll;
    if (pollIsClosed(p)) return socket.emit('action_error', 'Опрос уже завершён');
    const n = p.options.length;
    let opts = (Array.isArray(data.options) ? data.options : [data.options]).map((x) => parseInt(x, 10)).filter((x) => x >= 0 && x < n);
    opts = Array.from(new Set(opts));
    const k = key(username);
    if (p.quiz) {
      if (p.votes[k] && p.votes[k].length) return socket.emit('action_error', 'В викторине ответ нельзя изменить');
      if (opts.length !== 1) return;
    } else if (!p.multiple && opts.length > 1) opts = opts.slice(0, 1);
    if (!opts.length) delete p.votes[k]; else p.votes[k] = opts;
    persist();
    emitToConv(conv, 'message_updated', msg);
  });
  socket.on('poll_close', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv || !conv.participants.some((p) => key(p) === key(username))) return;
    const msg = conv.messages.find((m) => m.id === data.id);
    if (!msg || msg.deleted || msg.type !== 'poll' || !msg.poll) return;
    const own = key(msg.from) === key(username);
    if (!own && !((conv.type === 'group' || conv.type === 'channel') && isConvAdmin(conv, username)) && !isMod(username)) return socket.emit('action_error', 'Закрыть опрос может автор или админ');
    if (pollIsClosed(msg.poll)) return;
    msg.poll.closed = true;
    persist();
    emitToConv(conv, 'message_updated', msg);
  });

  socket.on('star_message', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const srcConv = convMap.get(data.conversationId);
    if (!srcConv) return;
    const src = (srcConv.messages || []).find((m) => m.id === data.id);
    if (!src || src.deleted) return;
    const fav = ensureFav(username);
    const copy = {
      ...src,
      id: uid(),
      conversationId: fav.id,
      starredFrom: srcConv.id,
      ts: Date.now(),
      time: timeLabel(),
    };
    fav.messages.push(copy);
    fav.lastMessage = {
      text: copy.type === 'secret' ? '🔒' : copy.text || 'Вложение',
      ts: copy.ts,
      from: username,
      time: copy.time,
    };
    persist();
    emitToUser(username, 'receive_message', copy);
    emitToUser(username, 'conversation_upsert', convForClient(fav, username));
  });

  socket.on('edit_message', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv) return;
    const msg = conv.messages.find((m) => m.id === data.id);
    if (!msg || key(msg.from) !== key(username) || msg.deleted) return;
    if (conv.type === 'secret') {
      if (!data.ciphertext || !data.iv) return;
      msg.ciphertext = String(data.ciphertext).slice(0, 2e6);
      msg.iv = String(data.iv).slice(0, 64);
      msg.edited = true;
    } else {
      if (msg.type !== 'text') return;
      const text = typeof data.text === 'string' ? data.text.trim() : '';
      if (!text || text.length > TEXT_MAX) return;
      msg.text = text;
      msg.edited = true;
      if (conv.lastMessage && conv.messages[conv.messages.length - 1].id === msg.id) {
        conv.lastMessage.text = text;
      }
    }
    persist();
    emitToConv(conv, 'message_updated', msg);
    for (const p of conv.participants) {
      emitToUser(p, 'conversation_upsert', convForClient(conv, p));
    }
  });

  socket.on('delete_message', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv) return;
    const msg = conv.messages.find((m) => m.id === data.id);
    if (!msg || msg.deleted) return;
    const own = key(msg.from) === key(username);
    const member = conv.participants.some((p) => key(p) === key(username));
    // своё сообщение, админ группы/канала или модератор (верифицированный аккаунт)
    if (!own && !(member && (conv.type === 'group' || conv.type === 'channel') && isConvAdmin(conv, username)) && !isMod(username)) return;
    deleteMsg(conv, msg);
  });

  /* ---- Модерация (верифицированные аккаунты) ---- */
  socket.on('mod_list', () => {
    const username = me(socket);
    if (!username || !isMod(username)) return;
    socket.emit('mod_list_ok', modSnapshot());
  });
  socket.on('mod_ban_user', (data) => {
    const username = me(socket);
    if (!username || !isMod(username) || !data) return;
    const target = accounts.get(key(String(data.user || '')));
    if (!target || target.system) return socket.emit('action_error', 'Пользователь не найден');
    if (isOwnerUser(target.username)) return socket.emit('action_error', 'Владельца нельзя заблокировать');
    if (isVerified(target.username) && !isOwnerUser(username)) return socket.emit('action_error', 'Верифицированного пользователя может заблокировать только владелец');
    target.banned = !!data.ban;
    target.banReason = data.ban ? String(data.reason || '').slice(0, 120) : '';
    if (target.banned) kickUser(target.username, 'Аккаунт заблокирован администрацией' + (target.banReason ? ': ' + target.banReason : ''));
    persist();
    io.emit('users_update', listUsers());
    socket.emit('mod_ok', { type: data.ban ? 'ban' : 'unban', user: target.username });
  });
  socket.on('mod_set_verified', (data) => {
    const username = me(socket);
    if (!username || !isOwnerUser(username) || !data) return;
    const target = accounts.get(key(String(data.user || '')));
    if (!target || target.system) return socket.emit('action_error', 'Пользователь не найден');
    if (isOwnerUser(target.username)) return socket.emit('action_error', 'У владельца галочка всегда');
    target.verified = !!data.verified;
    persist();
    io.emit('users_update', listUsers());
    socket.emit('mod_ok', { type: data.verified ? 'verify' : 'unverify', user: target.username });
  });
  socket.on('mod_delete_conversation', (data) => {
    const username = me(socket);
    if (!username || !isMod(username) || !data) return;
    const conv = convMap.get(String(data.conversationId || ''));
    if (!conv || (conv.type !== 'group' && conv.type !== 'channel')) return socket.emit('action_error', 'Можно удалять только группы и каналы');
    const o = convOwner(conv);
    if (o && isOwnerUser(o) && !isOwnerUser(username)) return socket.emit('action_error', 'Чат владельца может удалить только владелец');
    removeConversationForAll(conv, 'moderation');
    socket.emit('mod_ok', { type: 'delete_conversation', conversationId: conv.id, name: conv.name });
  });
  socket.on('mod_dismiss_report', (data) => {
    const username = me(socket);
    if (!username || !isMod(username) || !data) return;
    const i = reports.findIndex((r) => r.id === data.id);
    if (i >= 0) { reports.splice(i, 1); persist(); }
    socket.emit('mod_list_ok', modSnapshot());
  });

  socket.on('react', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv) return;
    const msg = conv.messages.find((m) => m.id === data.id);
    if (!msg || msg.deleted) return;
    const emoji = String(data.emoji || '').slice(0, 8);
    if (!emoji) return;
    msg.reactions = msg.reactions || {};
    const arr = new Set(msg.reactions[emoji] || []);
    if (arr.has(username)) arr.delete(username);
    else arr.add(username);
    if (arr.size) msg.reactions[emoji] = Array.from(arr);
    else delete msg.reactions[emoji];
    persist();
    emitToConv(conv, 'message_updated', msg);
  });

  socket.on('typing', (conversationId) => {
    const username = me(socket);
    if (!username) return;
    const conv = convMap.get(conversationId);
    if (!conv) return;
    emitToConv(conv, 'typing', { conversationId, user: username }, username);
  });

  socket.on('mark_read', (conversationId) => {
    const username = me(socket);
    if (!username) return;
    const conv = convMap.get(conversationId);
    if (!conv) return;
    const acc = accounts.get(key(username));
    conv.unread[key(username)] = 0;
    conv.readAt = conv.readAt || {};
    if (settingsOf(acc).readReceipts) conv.readAt[key(username)] = Date.now();
    persist();
    for (const p of conv.participants) {
      emitToUser(p, 'conversation_upsert', convForClient(conv, p));
    }
  });

  socket.on('set_conv_flag', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.id);
    if (!conv || !conv.participants.some((p) => key(p) === key(username))) return;
    const k = key(username);
    conv.flags = conv.flags || {};
    conv.flags[k] = conv.flags[k] || {};
    if (typeof data.pin === 'boolean') conv.flags[k].pin = data.pin;
    if (typeof data.mute === 'boolean') conv.flags[k].mute = data.mute;
    persist();
    socket.emit('conversation_upsert', convForClient(conv, username));
  });

  socket.on('hide_conversation', (conversationId) => {
    const username = me(socket);
    if (!username) return;
    const conv = convMap.get(conversationId);
    if (!conv || !conv.participants.some((p) => key(p) === key(username))) return;
    if (conv.type === 'fav') return;
    conv.hidden = conv.hidden || {};
    conv.hidden[key(username)] = true;
    persist();
    socket.emit('conversation_removed', conversationId);
  });

  socket.on('leave_group', (conversationId) => {
    const username = me(socket);
    if (!username) return;
    const conv = convMap.get(conversationId);
    if (!conv || (conv.type !== 'group' && conv.type !== 'channel')) return;
    const before = conv.participants.length;
    conv.participants = conv.participants.filter((p) => key(p) !== key(username));
    if (conv.participants.length === before) return;
    if (conv.owner || conv.admins) {
      conv.admins = (conv.admins || []).filter((a) => key(a) !== key(username));
      if (conv.owner && key(conv.owner) === key(username)) {
        conv.owner = conv.admins.find((a) => conv.participants.some((p) => key(p) === key(a))) || conv.participants[0] || null;
      }
      if (conv.owner && !conv.admins.some((a) => key(a) === key(conv.owner))) conv.admins.unshift(conv.owner);
    }
    const sys = {
      id: uid(),
      conversationId: conv.id,
      from: 'system',
      type: 'system',
      text: `${username} вышел из группы`,
      ts: Date.now(),
      time: timeLabel(),
    };
    conv.messages.push(sys);
    conv.lastMessage = { text: sys.text, ts: sys.ts, from: 'system', time: sys.time };
    persist();
    socket.emit('conversation_removed', conversationId);
    for (const p of conv.participants) {
      emitToUser(p, 'receive_message', sys);
      emitToUser(p, 'conversation_upsert', convForClient(conv, p));
    }
  });

  socket.on('clear_history', (conversationId) => {
    const username = me(socket);
    if (!username) return;
    const conv = convMap.get(conversationId);
    if (!conv || !conv.participants.some((p) => key(p) === key(username))) return;
    conv.messages = [];
    conv.lastMessage = null;
    conv.unread = {};
    persist();
    for (const p of conv.participants) {
      emitToUser(p, 'history', { conversationId, messages: [] });
      emitToUser(p, 'conversation_upsert', convForClient(conv, p));
    }
  });

  socket.on('update_profile', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const acc = accounts.get(key(username));
    if (!acc) return;
    if (typeof data.displayName === 'string') {
      const dn = norm(data.displayName);
      if (dn && dn.length <= 32) acc.displayName = dn;
    }
    if (typeof data.about === 'string') acc.about = norm(data.about).slice(0, 140);
    if (typeof data.avatar === 'string') {
      if (!data.avatar) acc.avatar = '';
      else if (data.avatar.startsWith('/files/')) acc.avatar = data.avatar;
    }
    persist();
    socket.emit('profile_ok', publicAccount(acc, username));
    io.emit('users_update', listUsers());
  });

  socket.on('update_settings', (data) => {
    const username = me(socket);
    if (!username || !data || typeof data !== 'object') return;
    const acc = accounts.get(key(username));
    if (!acc) return;
    const cur = settingsOf(acc);
    const next = { ...cur };
    if (['all', 'none'].includes(data.lastSeen)) next.lastSeen = data.lastSeen;
    if (typeof data.readReceipts === 'boolean') next.readReceipts = data.readReceipts;
    if (['all', 'contacts', 'none'].includes(data.callsFrom)) next.callsFrom = data.callsFrom;
    if (['all', 'none'].includes(data.msgsFrom)) next.msgsFrom = data.msgsFrom;
    if (['dark', 'midnight', 'light'].includes(data.theme)) next.theme = data.theme;
    if (typeof data.sound === 'boolean') next.sound = data.sound;
    if (typeof data.soundVolume === 'number') {
      next.soundVolume = Math.min(1, Math.max(0, data.soundVolume));
    }
    if (typeof data.enterToSend === 'boolean') next.enterToSend = data.enterToSend;
    if (typeof data.fontSize === 'number') {
      next.fontSize = Math.min(20, Math.max(13, Math.round(data.fontSize)));
    }
    acc.settings = next;
    persist();
    socket.emit('settings_ok', next);
    io.emit('users_update', listUsers());
  });

  socket.on('change_password', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const acc = accounts.get(key(username));
    if (!acc) return;
    const oldP = String(data.oldPassword || '');
    const newP = String(data.newPassword || '');
    if (!verifyPassword(oldP, acc.passHash, acc.salt)) {
      socket.emit('password_error', 'Старый пароль неверный');
      return;
    }
    if (newP.length < 6 || newP.length > 72) {
      socket.emit('password_error', 'Новый пароль: от 6 символов');
      return;
    }
    const { hash, salt } = hashPassword(newP);
    acc.passHash = hash;
    acc.salt = salt;
    persist();
    socket.emit('password_ok');
  });

  socket.on('block_user', (target) => {
    const username = me(socket);
    if (!username) return;
    target = norm(target);
    if (!target || key(target) === key(username)) return;
    const acc = accounts.get(key(username));
    const other = accounts.get(key(target));
    if (!acc || !other) return;
    acc.blocked = acc.blocked || [];
    if (!acc.blocked.some((x) => key(x) === key(other.username))) {
      acc.blocked.push(other.username);
    }
    persist();
    socket.emit('blocked_ok', acc.blocked);
  });

  socket.on('unblock_user', (target) => {
    const username = me(socket);
    if (!username) return;
    const acc = accounts.get(key(username));
    if (!acc) return;
    acc.blocked = (acc.blocked || []).filter((x) => key(x) !== key(target));
    persist();
    socket.emit('blocked_ok', acc.blocked);
  });

  socket.on('report', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const reason = String(data.reason || 'other').slice(0, 40);
    const text = String(data.text || '').slice(0, 500);
    reports.push({
      id: uid(),
      from: username,
      target: String(data.target || '').slice(0, 48),
      conversationId: data.conversationId || null,
      messageId: data.messageId || null,
      reason,
      text,
      ts: Date.now(),
    });
    if (reports.length > 2000) reports.splice(0, reports.length - 2000);
    persist();
    socket.emit('report_ok');
  });

  socket.on('call_log', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv || !conv.participants.some((p) => key(p) === key(username))) return;
    const status = ['missed', 'declined', 'cancelled', 'answered'].includes(data.status)
      ? data.status
      : 'cancelled';
    const video = !!data.video;
    const duration = Math.max(0, Math.min(86400, Number(data.duration) || 0));
    const labels = {
      missed: video ? 'Пропущенный видеозвонок' : 'Пропущенный звонок',
      declined: video ? 'Отклонённый видеозвонок' : 'Отклонённый звонок',
      cancelled: video ? 'Отменённый видеозвонок' : 'Отменённый звонок',
      answered: video ? 'Видеозвонок' : 'Звонок',
    };
    let text = labels[status];
    if (status === 'answered' && duration) {
      const m = Math.floor(duration / 60);
      const s = duration % 60;
      text += ` · ${m}:${String(s).padStart(2, '0')}`;
    }
    const ts = Date.now();
    const msg = {
      id: uid(),
      conversationId: conv.id,
      from: username,
      type: 'call',
      text,
      call: { status, video, duration },
      ts,
      time: timeLabel(ts),
      reactions: {},
      edited: false,
      deleted: false,
    };
    conv.messages.push(msg);
    conv.lastMessage = { text, ts, from: username, time: msg.time };
    persist();
    for (const p of conv.participants) {
      emitToUser(p, 'receive_message', msg);
      emitToUser(p, 'conversation_upsert', convForClient(conv, p));
    }
  });

  socket.on('call_invite', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    if (isBlocked(username, data.to)) {
      socket.emit('action_error', 'Пользователь заблокирован');
      return;
    }
    const other = accounts.get(key(data.to));
    if (other && settingsOf(other).callsFrom === 'none') {
      socket.emit('action_error', 'Пользователь не принимает звонки');
      return;
    }
    emitToUser(data.to, 'incoming_call', {
      from: username,
      room: data.room,
      video: !!data.video,
      conversationId: data.conversationId,
      mode: data.mode || 'webrtc',
    });
  });
  socket.on('call_accept', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    emitToUser(data.to, 'call_accepted', { from: username, room: data.room });
  });
  socket.on('call_reject', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    emitToUser(data.to, 'call_rejected', { from: username });
  });
  socket.on('call_end', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    emitToUser(data.to, 'call_ended', { from: username });
  });
  socket.on('webrtc_signal', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    emitToUser(data.to, 'webrtc_signal', { from: username, signal: data.signal });
  });

  /* ===== NMessenger additions: участники, права, ссылки ===== */
  socket.on('add_members', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv || (conv.type !== 'group' && conv.type !== 'channel')) return;
    if (!conv.participants.some((p) => key(p) === key(username))) return;
    if (conv.type === 'channel' && !isConvAdmin(conv, username)) { socket.emit('action_error', 'Добавлять подписчиков могут только админы'); return; }
    const added = [];
    for (const m of (Array.isArray(data.members) ? data.members : []).slice(0, 50)) {
      const acc = accounts.get(key(m));
      if (!acc || acc.isBot) continue;
      if (conv.participants.some((p) => key(p) === key(acc.username))) continue;
      if (isBlocked(username, acc.username)) continue;
      conv.participants.push(acc.username);
      added.push(acc.username);
    }
    if (!added.length) return;
    sysMessage(conv, `${displayOf(username)} добавил(а) ${added.map(displayOf).join(', ')}`);
    broadcastConv(conv);
  });

  socket.on('remove_member', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv || (conv.type !== 'group' && conv.type !== 'channel')) return;
    if (!isConvAdmin(conv, username)) { socket.emit('action_error', 'Недостаточно прав'); return; }
    const target = conv.participants.find((p) => key(p) === key(data.user));
    if (!target || key(target) === key(username)) return;
    if (isConvOwner(conv, target)) { socket.emit('action_error', 'Владельца исключить нельзя'); return; }
    if (isConvAdmin(conv, target) && !isConvOwner(conv, username)) { socket.emit('action_error', 'Исключить админа может только владелец'); return; }
    conv.participants = conv.participants.filter((p) => key(p) !== key(target));
    conv.admins = (conv.admins || []).filter((a) => key(a) !== key(target));
    if (conv.unread) delete conv.unread[key(target)];
    const tAcc = accounts.get(key(target));
    sysMessage(conv, tAcc && tAcc.isBot ? `${displayOf(username)} удалил(а) бота ${displayOf(target)}` : `${displayOf(username)} исключил(а) ${displayOf(target)}`);
    emitToUser(target, 'conversation_removed', conv.id);
    broadcastConv(conv);
  });

  socket.on('set_admin', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv || (conv.type !== 'group' && conv.type !== 'channel')) return;
    if (!isConvOwner(conv, username)) { socket.emit('action_error', 'Назначать админов может только владелец'); return; }
    const target = conv.participants.find((p) => key(p) === key(data.user));
    if (!target || isConvOwner(conv, target)) return;
    const owner = convOwner(conv);
    conv.owner = owner;
    conv.admins = (conv.admins || [owner]).filter((a) => key(a) !== key(target));
    if (!conv.admins.some((a) => key(a) === key(owner))) conv.admins.unshift(owner);
    if (data.admin) conv.admins.push(target);
    sysMessage(conv, data.admin ? `${displayOf(target)} теперь администратор` : `${displayOf(target)} больше не администратор`);
    broadcastConv(conv);
  });

  socket.on('update_conversation', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv || (conv.type !== 'group' && conv.type !== 'channel')) return;
    if (!isConvAdmin(conv, username)) { socket.emit('action_error', 'Недостаточно прав'); return; }
    const n = norm(data.name);
    if (!n || n.length > NAME_MAX) { socket.emit('action_error', `Название: 1–${NAME_MAX} символов`); return; }
    if (n === conv.name) return;
    conv.name = n;
    sysMessage(conv, `${displayOf(username)} изменил(а) название на «${n}»`);
    broadcastConv(conv);
  });

  socket.on('join_handle', (handle) => {
    const username = me(socket);
    if (!username) return;
    const h = String(handle || '').replace(/^@/, '').trim();
    const found = findByHandle(h);
    if (!found) { socket.emit('action_error', 'Не найдено: @' + h); return; }
    if (found.kind === 'user') {
      const acc = found.acc;
      if (key(acc.username) === key(username)) {
        const fav = ensureFav(username);
        socket.emit('conversation_upsert', convForClient(fav, username));
        socket.emit('history', { conversationId: fav.id, messages: fav.messages.slice(-300) });
        return;
      }
      socket.emit('open_dm_proxy');
      if (isBlocked(username, acc.username)) { socket.emit('action_error', 'Пользователь заблокирован'); return; }
      const conv = getOrCreateDM(username, acc.username);
      socket.emit('conversation_upsert', convForClient(conv, username));
      socket.emit('history', { conversationId: conv.id, messages: conv.messages.slice(-300) });
      return;
    }
    const conv = found.conv;
    if (!conv.participants.some((p) => key(p) === key(username))) {
      conv.participants.push(username);
      if (conv.type === 'group') sysMessage(conv, `${displayOf(username)} присоединился(ась) по ссылке`);
      else persist();
      broadcastConv(conv);
    }
    socket.emit('conversation_upsert', convForClient(conv, username));
    socket.emit('history', { conversationId: conv.id, messages: conv.messages.slice(-300) });
  });

  socket.on('disconnect', () => {
    const username = usersBySocket.get(socket.id);
    if (username) {
      usersBySocket.delete(socket.id);
      removeSocket(username, socket);
      const acc = accounts.get(key(username));
      if (acc && !isOnline(username)) {
        acc.lastSeen = Date.now();
        persist();
      }
      io.emit('users_update', listUsers());
    }
    console.log('❌ Отключился:', socket.id);
  });
});

ensureSystemBots();
checkInstance();

const PORT = process.env.PORT || 10000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`💾 Данные: ${DATA_DIR} (история: ${HISTORY_KEEP} сообщений на чат, бэкапы: ${BACKUP_DIR})`);
  console.log(`🚀 Server started on port ${PORT}`);
  console.log(`   NMessenger © ${Array.from(OWNERS).join(', ')} — владельцы/модераторы: ${Array.from(OWNERS).map((o) => '@' + o).join(', ')}${AI.key ? ' · AI: ' + AI.model : ' · AI: встроенный корректор (AI_API_KEY не задан)'}`);
});
