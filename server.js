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

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' },
  maxHttpBufferSize: 2e6,
});

const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'store.json');
const SESSION_TTL = 30 * 24 * 60 * 60 * 1000;

function loadStore() {
  try {
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    return {
      accounts: parsed.accounts || {},
      conversations: parsed.conversations || {},
      sessions: parsed.sessions || {},
    };
  } catch {
    return { accounts: {}, conversations: {}, sessions: {} };
  }
}

const store = loadStore();
const accounts = new Map(Object.entries(store.accounts));
const convMap = new Map(Object.entries(store.conversations));
const sessions = new Map(Object.entries(store.sessions));
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
      fs.writeFileSync(
        DATA_FILE,
        JSON.stringify({ accounts: acc, conversations, sessions: sess })
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
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const sess = token && sessions.get(token);
    if (!sess || sess.exp < Date.now()) {
      return res.status(401).json({ error: 'Нужна авторизация' });
    }
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
function createSession(username) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { username, exp: Date.now() + SESSION_TTL });
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
function isOnline(username) {
  const set = socketsByName.get(key(username));
  return !!(set && set.size);
}
function publicAccount(acc) {
  if (!acc) return null;
  return {
    username: acc.username,
    displayName: acc.displayName || acc.username,
    about: acc.about || '',
    online: isOnline(acc.username),
    lastSeen: acc.lastSeen || null,
  };
}
function listUsers() {
  return Array.from(accounts.values()).map(publicAccount);
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

function getOrCreateDM(a, b) {
  const id = dmId(a, b);
  if (!convMap.has(id)) {
    convMap.set(id, {
      id,
      type: 'dm',
      name: null,
      participants: [a, b],
      messages: [],
      lastMessage: null,
      unread: {},
      readAt: {},
      flags: {},
      hidden: {},
      createdAt: Date.now(),
    });
    persist();
  }
  const conv = convMap.get(id);
  if (conv.hidden) {
    delete conv.hidden[key(a)];
    delete conv.hidden[key(b)];
  }
  return conv;
}

function convForClient(conv, username) {
  const k = key(username);
  const other =
    conv.type === 'dm' ? conv.participants.find((p) => key(p) !== k) : null;
  const flags = (conv.flags && conv.flags[k]) || {};
  return {
    id: conv.id,
    type: conv.type,
    name: conv.type === 'group' ? conv.name : other,
    participants: conv.participants,
    lastMessage: conv.lastMessage,
    unread: conv.unread[k] || 0,
    createdAt: conv.createdAt,
    pinned: !!flags.pin,
    muted: !!flags.mute,
    readAt: conv.readAt || {},
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
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
    const ta = a.lastMessage ? a.lastMessage.ts : a.createdAt || 0;
    const tb = b.lastMessage ? b.lastMessage.ts : b.createdAt || 0;
    return tb - ta;
  });
  return list;
}

function sanitizeImage(data) {
  if (typeof data !== 'string') return null;
  if (!/^data:image\/(png|jpe?g|gif|webp);base64,/.test(data)) return null;
  if (data.length > 1.6e6) return null;
  return data;
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

function attachUser(socket, acc) {
  const username = acc.username;
  usersBySocket.set(socket.id, username);
  addSocket(username, socket);
  acc.lastSeen = Date.now();
  persist();
  socket.emit('auth_ok', {
    user: publicAccount(acc),
    users: listUsers(),
    conversations: conversationsFor(username),
    livekit: livekitEnabled(),
  });
  io.emit('users_update', listUsers());
}

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
    passHash: hash,
    salt,
    createdAt: Date.now(),
    lastSeen: Date.now(),
  };
  accounts.set(key(username), acc);
  const token = createSession(username);
  persist();
  res.json({ token, user: publicAccount(acc) });
});

app.post('/api/login', (req, res) => {
  const username = norm(req.body?.username);
  const password = String(req.body?.password || '');
  const id = key(username) + '|' + (req.ip || '');
  if (tooManyTries(id)) {
    return res.status(429).json({ error: 'Слишком много попыток. Подождите 5 минут.' });
  }
  const acc = accounts.get(key(username));
  if (!acc || !verifyPassword(password, acc.passHash, acc.salt)) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  loginTries.delete(id);
  const token = createSession(username);
  acc.lastSeen = Date.now();
  persist();
  res.json({ token, user: publicAccount(acc) });
});

app.post('/api/logout', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (token) sessions.delete(token);
  persist();
  res.json({ ok: true });
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

  socket.on('get_history', (conversationId) => {
    const username = me(socket);
    if (!username) return;
    const conv = convMap.get(conversationId);
    if (!conv || !conv.participants.some((p) => key(p) === key(username))) return;
    conv.unread[key(username)] = 0;
    conv.readAt = conv.readAt || {};
    conv.readAt[key(username)] = Date.now();
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
    const conv = getOrCreateDM(username, acc.username);
    socket.emit('conversation_upsert', convForClient(conv, username));
    socket.emit('history', {
      conversationId: conv.id,
      messages: conv.messages.slice(-300),
    });
    emitToUser(acc.username, 'conversation_upsert', convForClient(conv, acc.username));
  });

  socket.on('create_group', ({ name, members }) => {
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
    const conv = {
      id: 'group:' + uid(),
      type: 'group',
      name,
      participants: Array.from(parts),
      messages: [],
      lastMessage: null,
      unread: {},
      readAt: {},
      flags: {},
      hidden: {},
      createdAt: Date.now(),
    };
    const sys = {
      id: uid(),
      conversationId: conv.id,
      from: 'system',
      type: 'system',
      text: `${username} создал группу «${name}»`,
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

  socket.on('send_message', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv || !conv.participants.some((p) => key(p) === key(username))) return;

    const type = data.type === 'image' ? 'image' : 'text';
    let text = typeof data.text === 'string' ? data.text.trim() : '';
    let image = null;
    if (type === 'image') {
      image = sanitizeImage(data.image);
      if (!image) return;
      text = text || 'Изображение';
    } else if (!text || text.length > 4000) {
      return;
    }

    const ts = Date.now();
    const msg = {
      id: uid(),
      conversationId: conv.id,
      from: username,
      type,
      text,
      image,
      ts,
      time: timeLabel(ts),
      replyTo: sanitizeReply(data.replyTo, conv),
      reactions: {},
      edited: false,
      deleted: false,
    };
    conv.messages.push(msg);
    if (conv.messages.length > 500) conv.messages.splice(0, conv.messages.length - 500);
    conv.lastMessage = {
      text: type === 'image' ? '📷 Изображение' : text,
      ts,
      from: username,
      time: msg.time,
    };
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

  socket.on('edit_message', (data) => {
    const username = me(socket);
    if (!username || !data) return;
    const conv = convMap.get(data.conversationId);
    if (!conv) return;
    const msg = conv.messages.find((m) => m.id === data.id);
    if (!msg || key(msg.from) !== key(username) || msg.deleted || msg.type !== 'text') return;
    const text = typeof data.text === 'string' ? data.text.trim() : '';
    if (!text || text.length > 4000) return;
    msg.text = text;
    msg.edited = true;
    if (conv.lastMessage && conv.messages[conv.messages.length - 1].id === msg.id) {
      conv.lastMessage.text = text;
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
    msg.image = null;
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
    conv.unread[key(username)] = 0;
    conv.readAt = conv.readAt || {};
    conv.readAt[key(username)] = Date.now();
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
    conv.hidden = conv.hidden || {};
    conv.hidden[key(username)] = true;
    persist();
    socket.emit('conversation_removed', conversationId);
  });

  socket.on('leave_group', (conversationId) => {
    const username = me(socket);
    if (!username) return;
    const conv = convMap.get(conversationId);
    if (!conv || conv.type !== 'group') return;
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
    if (typeof data.about === 'string') {
      acc.about = norm(data.about).slice(0, 140);
    }
    persist();
    socket.emit('profile_ok', publicAccount(acc));
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

  socket.on('call_invite', (data) => {
    const username = me(socket);
    if (!username || !data) return;
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
