#!/usr/bin/env node
/* Генерирует OWNER_KEY_HASH для .env (или для npm run build).
   Использование:  npm run owner-key            — спросит ключ интерактивно
                   npm run owner-key -- "ключ"  — без вопросов */
const crypto = require('crypto');
const readline = require('readline');

function hashKey(key) {
  const salt = crypto.randomBytes(16).toString('hex');
  return 'scrypt$' + salt + '$' + crypto.scryptSync(String(key), salt, 32).toString('hex');
}

function out(key) {
  if (!key || key.length < 8) { console.error('Ключ владельца должен быть не короче 8 символов.'); process.exit(1); }
  const h = hashKey(key);
  console.log('\nДобавьте строку в .env (или передайте в сборку: npm run build):\n');
  console.log('OWNER_KEY_HASH=' + h + '\n');
  console.log('Сам ключ никуда не записывается — запомните его. Его спросят при первом запуске сервера на новом компьютере.');
}

const arg = process.argv.slice(2).join(' ').trim();
if (arg) out(arg);
else {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question('Придумайте ключ владельца (мин. 8 символов): ', (a) => { rl.close(); out(a.trim()); });
}
module.exports = { hashKey };
