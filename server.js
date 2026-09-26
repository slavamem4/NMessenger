const express = require('express');
const http = require('http');
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

// Ответ для проверки работоспособности (ping)
app.get('/ping', (req, res) => {
  res.send('Server is alive!');
});

// Создание токена для звонков LiveKit
app.post('/get-livekit-token', async (req, res) => {
  try {
    const { roomName, participantName } = req.body;
    
    if (!roomName || !participantName) {
      return res.status(400).json({ error: 'Нужно имя комнаты и пользователя' });
    }

    const at = new AccessToken(
      process.env.LIVEKIT_API_KEY,
      process.env.LIVEKIT_API_SECRET,
      { identity: participantName }
    );

    at.addGrant({ roomJoin: true, room: roomName, canPublish: true, canSubscribe: true });
    const token = await at.toJwt();

    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Простой чат
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  socket.on('message', (data) => {
    io.emit('message', data);
  });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
