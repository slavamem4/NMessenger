const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
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

function loadStore() {
  try {
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    return {
      knownUsers: parsed.knownUsers || {},
      conversations: parsed.conversations || {},
    };
  } catch {
    return { knownUsers: {}, conversations: {} };
  }
}

const store = loadStore();
const knownUsers = new Map(Object.entries(store.knownUsers));
const convMap = new Map(Object.entries(store.conversations));
const usersBySocket = new Map();
const socketsByName = new Map();

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
      const known = {};
      for (const [k, v] of knownUsers) known[k] = v;
      fs.writeFileSync(DATA_FILE, JSON.stringify({ knownUsers: known, conversations }));
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

app.get('/ping', (req, res) => {
  res.send('Server is alive!');
});

app.get('/livekit-status', (req, res) => {
  res.json({ enabled: livekitEnabled() });
});

app.post('/get-livekit-token', async (req, res) => {
  try {
    if (!livekitEnabled()) {
      return res.status(503).json({ error: 'LiveKit не настроен' });
    }
    const { roomName, participantName } = req.body;
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
    const token = await at.toJwt();
    res.json({ token, url: process.env.LIVEKIT_URL });
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
function publicUser(u) {
  return {
    username: u.username,
    online: socketsByName.has(key(u.username)),
    lastSeen: u.lastSeen || null,
  };
}
function listUsers() {
  return Array.from(knownUsers.values()).map(publicUser);
}
function emitToUser(username, event, data) {
  const sock = socketsByName.get(key(username));
  if (sock) sock.emit(event, data);
}
function emitToConv(conv, event, data, except) {
  for (const p of conv.participants) {
    if (except && key(p) === key(except)) continue;
    emitToUser(p, event, data);
  }
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
      createdAt: Date.now(),
    });
    persist();
  }
  return convMap.get(id);
}

function convForClient(conv, username) {
  const k = key(username);
  const other =
    conv.type === 'dm' ? conv.participants.find((p) => key(p) !== k) : null;
  return {
    id: conv.id,
    type: conv.type,
    name: conv.type === 'group' ? conv.name : other,
    participants: conv.participants,
    lastMessage: conv.lastMessage,
    unread: conv.unread[k] || 0,
    createdAt: conv.createdAt,
  };
}

function conversationsFor(username) {
  const k = key(username);
  const list = [];
  for (const conv of convMap.values()) {
    if (conv.participants.some((p) => key(p) === k)) {
      list.push(convForClient(conv, username));
    }
  }
  list.sort((a, b) => {
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

io.on('connection', (socket) => {
  console.log('✅ Подключился:', socket.id);

  socket.on('user_join', (username) => {
    username = norm(username);
    if (!username || username.length < 2 || username.length > 24) {
      socket.emit('join_error', 'Имя: 2–24 символа');
      return;
    }
    if (!/^[\p{L}\p{N} _.-]+$/u.test(username)) {
      socket.emit('join_error', 'Недопустимые символы в имени');
      return;
    }

    const k = key(username);
    const existing = socketsByName.get(k);
    if (existing && existing.id !== socket.id) {
      existing.emit('kicked', 'Вы вошли с другого устройства');
      existing.disconnect(true);
    }

    usersBySocket.set(socket.id, username);
    socketsByName.set(k, socket);
    knownUsers.set(k, { username, lastSeen: Date.now() });
    persist();

    socket.emit('join_ok', {
      username,
      users: listUsers(),
      conversations: conversationsFor(username),
      livekit: livekitEnabled(),
    });
    io.emit('users_update', listUsers());
  });

  socket.on('get_history', (conversationId) => {
    const username = usersBySocket.get(socket.id);
    if (!username) return;
    const conv = convMap.get(conversationId);
    if (!conv || !conv.participants.some((p) => key(p) === key(username))) return;
    conv.unread[key(username)] = 0;
    persist();
    socket.emit('history', {
      conversationId,
      messages: conv.messages.slice(-300),
    });
    socket.emit('conversation_upsert', convForClient(conv, username));
  });

  socket.on('open_dm', (target) => {
    const username = usersBySocket.get(socket.id);
    if (!username) return;
    target = norm(target);
    if (!target || key(target) === key(username)) return;
    const known = knownUsers.get(key(target));
    const display = known ? known.username : target;
    const conv = getOrCreateDM(username, display);
    socket.emit('conversation_upsert', convForClient(conv, username));
    socket.emit('history', {
      conversationId: conv.id,
      messages: conv.messages.slice(-300),
    });
    emitToUser(display, 'conversation_upsert', convForClient(conv, display));
  });

  socket.on('create_group', ({ name, members }) => {
    const username = usersBySocket.get(socket.id);
    if (!username) return;
    name = norm(name);
    if (!name || name.length > 48) return;
    const parts = new Set([username]);
    for (const m of members || []) {
      const km = key(m);
      if (knownUsers.has(km)) parts.add(knownUsers.get(km).username);
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
    const username = usersBySocket.get(socket.id);
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
    };
    conv.messages.push(msg);
    if (conv.messages.length > 500) conv.messages.splice(0, conv.messages.length - 500);
    conv.lastMessage = {
      text: type === 'image' ? '📷 Изображение' : text,
      ts,
      from: username,
      time: msg.time,
    };
    for (const p of conv.participants) {
      const pk = key(p);
      if (pk !== key(username)) conv.unread[pk] = (conv.unread[pk] || 0) + 1;
    }
    persist();
    for (const p of conv.participants) {
      emitToUser(p, 'receive_message', msg);
      emitToUser(p, 'conversation_upsert', convForClient(conv, p));
    }
  });

  socket.on('typing', (conversationId) => {
    const username = usersBySocket.get(socket.id);
    if (!username) return;
    const conv = convMap.get(conversationId);
    if (!conv) return;
    emitToConv(conv, 'typing', { conversationId, user: username }, username);
  });

  socket.on('mark_read', (conversationId) => {
    const username = usersBySocket.get(socket.id);
    if (!username) return;
    const conv = convMap.get(conversationId);
    if (!conv) return;
    conv.unread[key(username)] = 0;
    persist();
    socket.emit('conversation_upsert', convForClient(conv, username));
  });

  socket.on('delete_conversation', (conversationId) => {
    const username = usersBySocket.get(socket.id);
    if (!username) return;
    const conv = convMap.get(conversationId);
    if (!conv || !conv.participants.some((p) => key(p) === key(username))) return;
    convMap.delete(conversationId);
    persist();
    for (const p of conv.participants) {
      emitToUser(p, 'conversation_removed', conversationId);
    }
  });

  socket.on('clear_history', (conversationId) => {
    const username = usersBySocket.get(socket.id);
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

  socket.on('call_invite', (data) => {
    const username = usersBySocket.get(socket.id);
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
    const username = usersBySocket.get(socket.id);
    if (!username || !data) return;
    emitToUser(data.to, 'call_accepted', { from: username, room: data.room });
  });

  socket.on('call_reject', (data) => {
    const username = usersBySocket.get(socket.id);
    if (!username || !data) return;
    emitToUser(data.to, 'call_rejected', { from: username });
  });

  socket.on('call_end', (data) => {
    const username = usersBySocket.get(socket.id);
    if (!username || !data) return;
    emitToUser(data.to, 'call_ended', { from: username });
  });

  socket.on('webrtc_signal', (data) => {
    const username = usersBySocket.get(socket.id);
    if (!username || !data) return;
    emitToUser(data.to, 'webrtc_signal', { from: username, signal: data.signal });
  });

  socket.on('disconnect', () => {
    const username = usersBySocket.get(socket.id);
    if (username) {
      usersBySocket.delete(socket.id);
      const k = key(username);
      if (socketsByName.get(k)?.id === socket.id) socketsByName.delete(k);
      if (knownUsers.has(k)) {
        knownUsers.get(k).lastSeen = Date.now();
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
