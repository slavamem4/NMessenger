const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');
const cors = require('cors');
const { AccessToken } = require('livekit-server-sdk');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

// Отдаем index.html из КОРНЯ проекта
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Роут для проверки (чтобы Render не засыпал)
app.get('/ping', (req, res) => {
  res.send('Server is alive!');
});

// Генерация токена для звонков LiveKit
app.post('/get-livekit-token', async (req, res) => {
  try {
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
      canSubscribe: true 
    });
    
    const token = await at.toJwt();
    res.json({ token, url: process.env.LIVEKIT_URL });
  } catch (error) {
    console.error('Ошибка токена:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Хранилище пользователей
const onlineUsers = new Map();

// Чат Socket.io
io.on('connection', (socket) => {
  console.log('✅ Пользователь подключился:', socket.id);

  socket.on('user_join', (username) => {
    onlineUsers.set(socket.id, username);
    io.emit('users_update', Array.from(onlineUsers.values()));
    io.emit('system_message', `👋 ${username} зашел в чат`);
  });

  socket.on('send_message', (data) => {
    io.emit('receive_message', {
      user: data.user,
      text: data.text,
      time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
    });
  });

  socket.on('call_started', (data) => {
    socket.broadcast.emit('incoming_call', {
      from: data.from,
      room: data.room
    });
  });

  socket.on('disconnect', () => {
    const username = onlineUsers.get(socket.id);
    if (username) {
      onlineUsers.delete(socket.id);
      io.emit('users_update', Array.from(onlineUsers.values()));
      io.emit('system_message', `👋 ${username} вышел`);
    }
    console.log('❌ Пользователь отключился:', socket.id);
  });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log(`🚀 Server started on port ${PORT}`);
});
