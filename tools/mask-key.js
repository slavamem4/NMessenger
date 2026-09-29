#!/usr/bin/env node
// Маскировка встроенного ключа нейросети, чтобы он не лежал в репозитории открытым текстом
// и не срабатывал на secret-scanning (GitHub push protection и т. п.).
//
//   node tools/mask-key.js gsk_xxxxxxxx            → печатает замаскированную строку
//   node tools/mask-key.js gsk_xxxxxxxx --write    → сразу подставляет её в server.js (AI_BUILTIN.key)
//   node tools/mask-key.js --check                 → показывает, какой ключ сейчас вшит (первые/последние символы)
//
// ВАЖНО: это не шифрование и не защита — любой, у кого есть код, восстановит ключ.
// Смысл только в том, чтобы ключ не попадал в индексы сканеров и не утекал при случайном просмотре.
// Свой ключ безопаснее задавать через .env (AI_API_KEY) — он имеет приоритет над встроенным.
const fs = require('fs');
const path = require('path');

const SALT = 'NMessenger·newrizer';
const mask = (s) => Buffer.from(Buffer.from(String(s), 'utf8').map((b, i) => b ^ SALT.charCodeAt(i % SALT.length))).toString('base64');
const unmask = (m) => Buffer.from(Buffer.from(String(m), 'base64').map((b, i) => b ^ SALT.charCodeAt(i % SALT.length))).toString('utf8');

const args = process.argv.slice(2);
const serverPath = path.join(__dirname, '..', 'server.js');
const RE = /(key:\s*unmaskKey\(')([^']*)('\))/;

if (args.includes('--check')) {
  const src = fs.readFileSync(serverPath, 'utf8');
  const m = src.match(RE);
  if (!m) { console.log('В server.js не найден unmaskKey(...) — ключ не вшит'); process.exit(1); }
  const k = unmask(m[2]);
  console.log(k ? `Вшитый ключ: ${k.slice(0, 6)}…${k.slice(-4)} (${k.length} символов)` : 'Вшитый ключ пустой — работает только AI_API_KEY из .env');
  process.exit(0);
}

const key = args.find((a) => !a.startsWith('--')) || '';
if (!key) {
  console.log('Использование: node tools/mask-key.js <ключ> [--write]   |   node tools/mask-key.js --check');
  process.exit(1);
}
const masked = mask(key);
if (unmask(masked) !== key) { console.error('Ошибка маскировки'); process.exit(1); }
if (args.includes('--write')) {
  const src = fs.readFileSync(serverPath, 'utf8');
  if (!RE.test(src)) { console.error('В server.js не найдено место для ключа (key: unmaskKey(\'…\'))'); process.exit(1); }
  fs.writeFileSync(serverPath, src.replace(RE, `$1${masked}$3`));
  console.log(`Готово: ключ ${key.slice(0, 6)}…${key.slice(-4)} вшит в server.js в замаскированном виде. Перезапустите сервер.`);
} else {
  console.log(masked);
  console.log(`\nВставьте в server.js:  key: unmaskKey('${masked}')\nили выполните с флагом --write, чтобы подставить автоматически.`);
}
