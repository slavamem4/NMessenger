'use strict';
// Модуль входа NLauncher для NMessenger.
// Сервер NLauncher уже подтвердил почту кодом из письма и подписывает её общим секретом
// NLAUNCHER_SSO_SECRET. Модуль проверяет подпись и выдаёт обычную сессию NMessenger:
// второго кода и пароля не нужно.
//
// Подключение: положить файл рядом с server.js и добавить одну строку перед app.post('/api/register', ...):
// require('./nlauncher-sso')(app, { accounts, deletedAccounts, createSession, publicAccount, hashPassword, defaultSettings, validUsername, normEmail, key, persist, isOwnerUser, slug, ipBanned, noteIp });

const crypto = require('crypto');

const WINDOW_MS = 60_000;
const GMAIL_RE = /^[a-z0-9](?:[a-z0-9.+_-]{0,62}[a-z0-9])?@gmail\.com$/;

function gmailBox(email) {
  const [local, domain] = String(email).split('@');
  if (domain !== 'gmail.com' && domain !== 'googlemail.com') return null;
  return local.split('+')[0].replace(/\./g, '') + '@gmail.com';
}

function signature(secret, b) {
  return crypto
    .createHmac('sha256', secret)
    .update(['nlauncher-sso:v1', b.ts, b.nonce, b.email, b.name, b.ip || ''].join('\n'))
    .digest('hex');
}

module.exports = function nlauncherSso(app, deps) {
  const secret = String(process.env.NLAUNCHER_SSO_SECRET || '');
  const {
    accounts, deletedAccounts, createSession, publicAccount, hashPassword, defaultSettings,
    validUsername, normEmail, key, persist, isOwnerUser, slug, ipBanned, noteIp,
  } = deps;
  const nonces = new Map();

  setInterval(() => {
    const now = Date.now();
    for (const [n, exp] of nonces) if (exp < now) nonces.delete(n);
  }, WINDOW_MS).unref();

  function usernameFor(email) {
    const base = (slug(email.split('@')[0].split('+')[0]) || 'player').replace(/^[._-]+|[._-]+$/g, '').slice(0, 20) || 'player';
    const free = (n) => validUsername(n) && !accounts.has(key(n)) && !deletedAccounts.has(key(n)) && !isOwnerUser(n);
    const first = base.length >= 2 ? base : base + '_gg';
    if (free(first)) return first;
    for (let i = 2; i < 1000; i++) if (free(first.slice(0, 20) + i)) return first.slice(0, 20) + i;
    for (;;) {
      const n = 'player_' + crypto.randomBytes(4).toString('hex');
      if (free(n)) return n;
    }
  }

  function findAccount(email) {
    const box = gmailBox(email);
    let best = null;
    for (const acc of accounts.values()) {
      if (!acc || acc.isBot || acc.system || !acc.email) continue;
      const e = normEmail(acc.email);
      if (e !== email && (!box || gmailBox(e) !== box)) continue;
      // одна почта может быть привязана к нескольким аккаунтам: берём тот, которым пользовались последним
      if (!best || (acc.lastSeen || 0) > (best.lastSeen || 0)) best = acc;
    }
    return best;
  }

  app.post('/api/sso/nlauncher', (req, res) => {
    if (secret.length < 32) return res.status(404).json({ error: 'not configured' });
    // перебор не имеет смысла: подпись HMAC-SHA256 с секретом от 32 символов
    const b = req.body || {};
    const ok =
      typeof b.sig === 'string' && /^[0-9a-f]{64}$/.test(b.sig) &&
      Number.isSafeInteger(b.ts) && Math.abs(Date.now() - b.ts) <= WINDOW_MS &&
      typeof b.nonce === 'string' && /^[0-9a-f]{32}$/.test(b.nonce) &&
      typeof b.email === 'string' && typeof b.name === 'string' && b.name.length <= 64 &&
      (b.ip === undefined || (typeof b.ip === 'string' && b.ip.length <= 64)) &&
      crypto.timingSafeEqual(Buffer.from(signature(secret, b)), Buffer.from(b.sig));
    if (!ok) return res.status(401).json({ error: 'Неверная подпись NLauncher' });
    if (nonces.has(b.nonce)) return res.status(409).json({ error: 'Повтор запроса' });
    nonces.set(b.nonce, Date.now() + 2 * WINDOW_MS);

    const email = normEmail(b.email);
    if (!GMAIL_RE.test(email)) return res.status(400).json({ error: 'Поддерживается только Gmail' });
    const ip = String(b.ip || '');
    if (ip && ipBanned(ip)) return res.status(403).json({ error: 'Доступ с вашего IP-адреса заблокирован' });

    let acc = findAccount(email);
    let created = false;
    if (acc && acc.banned) {
      return res.status(403).json({ error: 'Аккаунт заблокирован администрацией' + (acc.banReason ? ': ' + acc.banReason : '') });
    }
    if (!acc) {
      const username = usernameFor(email);
      // пароль случайный: войти по паролю можно после «Забыли пароль?» с кодом на эту же почту
      const { hash, salt } = hashPassword(crypto.randomBytes(24).toString('base64url'));
      const display = String(b.name).trim().slice(0, 32) || username;
      acc = {
        username,
        displayName: display,
        about: '',
        avatar: '',
        pubKey: null,
        passHash: hash,
        salt,
        createdAt: Date.now(),
        lastSeen: Date.now(),
        settings: defaultSettings(),
        blocked: [],
        email,
        emailAt: Date.now(),
        email2fa: false,
        via: 'nlauncher',
      };
      accounts.set(key(username), acc);
      created = true;
      console.log('NLauncher SSO: новый аккаунт @' + username);
    }
    if (ip) noteIp(acc, ip);
    acc.lastSeen = Date.now();
    const token = createSession(acc.username, { ua: 'NLauncher', ip });
    persist();
    res.json({ token, user: publicAccount(acc, acc.username), created });
  });
};

module.exports.signature = signature;
