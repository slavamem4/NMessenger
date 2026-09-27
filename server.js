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
app.use(express.json({ limit: '2mb' }));

const MAX_FILE = 10 * 1024 * 1024;
const TEXT_MAX = 4000;
const SESSION_TTL = 30 * 24 * 60 * 60 * 1000;

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' },
  maxHttpBufferSize: 2e6,
});

const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'store.json');
const FILES_DIR = path.join(DATA_DIR, 'files');

function loadStore() {
  try {
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    return {
      accounts: parsed.accounts || {},
      conversations: parsed.conversations || {},
      sessions: parsed.sessions || {},
      files: parsed.files || {},
      reports: parsed.reports || [],
    };
  } catch {
    return { accounts: {}, conversations: {}, sessions: {}, files: {}, reports: [] };
  }
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

let persistTimer = null;
function persist() {
  clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    try {
      if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
      const conversations = {};
      for (const [id, c] of convMap) {
        conversations[id] = { ...c, messages: (c.messages || []).slice(-500) };
      }
      const acc = {};
      for (const [k, v] of accounts) acc[k] = v;
      const now = Date.now();
      const sess = {};
      for (const [t, s] of sessions) {
        if (s.exp > now) sess[t] = s;
        else sessions.delete(t);
      }
      const files = {};
      for (const [k, v] of filesMeta) files[k] = v;
      fs.writeFileSync(
        DATA_FILE,
        JSON.stringify({ accounts: acc, conversations, sessions: sess, files, reports })
      );
    } catch (err) {
      console.error('persist error:', err.message);
    }
  }, 200);
}

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
  return accounts.get(key(s.username)) || null;
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
  if (conv.messages.length > 500) conv.messages.splice(0, conv.messages.length - 500);
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
  });
  io.emit('users_update', listUsers());
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/ping', (req, res) => res.send('Server is alive!'));
app.get('/livekit-status', (req, res) => res.json({ enabled: livekitEnabled() }));

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
  let conv = convMap.get(chatId);
  if (!conv) {
    const user = accounts.get(key(chatId));
    if (user && !user.isBot) conv = getOrCreateDM(bot.username, user.username);
  }
  if (!conv) return res.status(404).json({ error: 'Чат не найден' });
  if (!conv.participants.some((p) => key(p) === key(bot.username))) {
    return res.status(403).json({ error: 'Бот не добавлен в этот чат' });
  }
  if (conv.type === 'channel') {
    const admins = conv.admins || [conv.owner];
    if (!admins.some((a) => key(a) === key(bot.username))) {
      return res.status(403).json({ error: 'Бот не админ канала' });
    }
  }
  const ts = Date.now();
  const msg = {
    id: uid(),
    conversationId: conv.id,
    from: bot.username,
    type: 'text',
    text,
    ts,
    time: timeLabel(ts),
    reactions: {},
    edited: false,
    deleted: false,
  };
  conv.lastMessage = { text, ts, from: bot.username, time: msg.time };
  pushMessage(conv, msg);
  res.json({ ok: true, message_id: msg.id, chat_id: conv.id });
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

  socket.on('auth', (token) => {
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
    if (conv.messages.length > 500) conv.messages.splice(0, conv.messages.length - 500);
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
    if (!msg || key(msg.from) !== key(username) || msg.deleted) return;
    msg.deleted = true;
    msg.text = '';
    msg.file = null;
    msg.ciphertext = null;
    msg.replyTo = null;
    if (conv.lastMessage && conv.messages[conv.messages.length - 1].id === msg.id) {
      conv.lastMessage.text = 'Сообщение удалено';
    }
    persist();
    emitToConv(conv, 'message_updated', msg);
    for (const p of conv.participants) {
      emitToUser(p, 'conversation_upsert', convForClient(conv, p));
    }
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

const PORT = process.env.PORT || 10000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server started on port ${PORT}`);
});
