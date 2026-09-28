#!/usr/bin/env node
/* Сборка защищённого релиза в папку release/:
     - server.js  → обфусцированный (javascript-obfuscator), с «вшитым» хешем ключа владельца
     - index.html → JS минифицирован и переименованы переменные (terser), комментарии удалены
     - sdk/, package.json (только runtime-зависимости), .env.example, README
   Использование:
     npm run build -- --key "ключ владельца"        (хеш посчитается сам)
     npm run build                                  (возьмёт OWNER_KEY_HASH из .env)
   Дальше на сервере: cd release && npm install --omit=dev && node server.js */
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
const out = path.join(root, 'release');
require('dotenv').config({ path: path.join(root, '.env') });

const args = process.argv.slice(2);
const keyIdx = args.indexOf('--key');
let ownerHash = process.env.OWNER_KEY_HASH || '';
if (keyIdx >= 0 && args[keyIdx + 1]) ownerHash = require('./owner-key.js').hashKey(args[keyIdx + 1]);
if (!ownerHash) {
  console.error('Нужен ключ владельца: npm run build -- --key "ваш ключ"  (или OWNER_KEY_HASH в .env; создать: npm run owner-key)');
  process.exit(1);
}

let JavaScriptObfuscator, terser;
try { JavaScriptObfuscator = require('javascript-obfuscator'); terser = require('terser'); }
catch { console.error('Установите dev-зависимости: npm install'); process.exit(1); }

(async () => {
  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(path.join(out, 'sdk'), { recursive: true });

  // ---- server.js ----
  let server = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
  if (!server.includes("'__NM_OWNER_KEY_HASH__'")) throw new Error('В server.js нет метки __NM_OWNER_KEY_HASH__');
  server = server.replace("'__NM_OWNER_KEY_HASH__'", () => JSON.stringify(ownerHash));
  process.stdout.write('Обфускация server.js… ');
  const obf = JavaScriptObfuscator.obfuscate(server, {
    compact: true,
    target: 'node',
    identifierNamesGenerator: 'hexadecimal',
    renameGlobals: false,
    stringArray: true,
    stringArrayEncoding: ['base64'],
    stringArrayThreshold: 0.8,
    stringArrayRotate: true,
    stringArrayShuffle: true,
    splitStrings: true,
    splitStringsChunkLength: 12,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.35,
    deadCodeInjection: false,
    numbersToExpressions: true,
    simplify: true,
    transformObjectKeys: false,
    unicodeEscapeSequence: false,
    selfDefending: false,
    debugProtection: false,
    disableConsoleOutput: false,
  }).getObfuscatedCode();
  fs.writeFileSync(path.join(out, 'server.js'), '/* NMessenger — защищённая сборка. Копирование и распространение запрещены. */\n' + obf);
  console.log('ok (' + Math.round(obf.length / 1024) + ' KB)');

  // ---- index.html ----
  process.stdout.write('Минификация index.html… ');
  let html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  const m = html.match(/<script>([\s\S]*)<\/script>/);
  if (!m) throw new Error('В index.html не найден <script>');
  const min = await terser.minify(m[1], {
    compress: { passes: 2, drop_debugger: true, pure_getters: false, unsafe: false },
    mangle: { toplevel: false, keep_classnames: true, keep_fnames: false },
    format: { comments: false, ascii_only: false },
  });
  if (min.error) throw min.error;
  const at = html.indexOf(m[0]); const stripC = (x) => x.replace(/<!--[\s\S]*?-->/g, '');
  html = stripC(html.slice(0, at)) + '<script>' + min.code + '</script>' + stripC(html.slice(at + m[0].length));
  html = html.replace(/<style>([\s\S]*?)<\/style>/, (mm, css) => '<style>' + css.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\s*\n\s*/g, '\n').trim() + '</style>');
  html = html.replace('<head>', '<head>\n<!-- NMessenger © владелец сервера. Копирование запрещено. -->');
  fs.writeFileSync(path.join(out, 'index.html'), html);
  console.log('ok (' + Math.round(html.length / 1024) + ' KB)');

  // ---- прочее ----
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  fs.writeFileSync(path.join(out, 'package.json'), JSON.stringify({ name: pkg.name, version: pkg.version, private: true, scripts: { start: 'node server.js' }, dependencies: pkg.dependencies }, null, 2));
  for (const f of fs.readdirSync(path.join(root, 'sdk'))) { const fp = path.join(root, 'sdk', f); if (fs.statSync(fp).isFile() && !f.endsWith('.pyc')) fs.copyFileSync(fp, path.join(out, 'sdk', f)); }
  if (fs.existsSync(path.join(root, '.env.example'))) fs.copyFileSync(path.join(root, '.env.example'), path.join(out, '.env.example'));
  fs.writeFileSync(path.join(out, 'README.txt'), [
    'NMessenger — защищённая сборка',
    '',
    'Запуск:  npm install --omit=dev  и затем  node server.js',
    'Настройки — в файле .env (см. .env.example). OWNER_KEY_HASH уже вшит в сборку, в .env он не нужен.',
    'При первом запуске на новом компьютере сервер попросит ключ владельца в браузере.',
    'Имя владельца (OWNER_USERNAMES) при регистрации тоже требует этот ключ.',
    '',
    'ОБНОВЛЕНИЕ: замените server.js, index.html и папку sdk новыми. Папку data (или DATA_DIR) не трогайте —',
    'там аккаунты, чаты, боты, каналы, файлы и автокопии (data/backups). Перед обновлением можно скачать',
    'полную копию: Настройки → Модерация → «Данные и резервные копии» (только владелец).',
    '',
    'Исходный код в эту папку не входит — храните его отдельно и не выкладывайте на общий сервер.',
  ].join('\n'));
  console.log('Готово: ' + out);
})().catch((e) => { console.error('Ошибка сборки:', e.message); process.exit(1); });
