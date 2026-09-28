# -*- coding: utf-8 -*-
"""
nmessenger_bot — мини-SDK для ботов NMessenger (Python 3.8+, только стандартная библиотека).

Быстрый старт:

    from nmessenger_bot import Bot

    bot = Bot("nmbot:ВАШ_КЛЮЧ", "http://localhost:10000")

    @bot.command("start")
    def start(m):
        m.reply("Привет! Я работаю.")

    @bot.message()                      # любое текстовое сообщение
    def echo(m):
        m.reply("Вы написали: " + m.text)

    bot.run()                           # long polling, Ctrl+C для выхода

Ключ бота выдаёт @BotFather в самом мессенджере (/newbot).
Бот получает сообщения из личных чатов с ним и из групп/каналов, куда его добавили.
"""
import json
import mimetypes
import os
import sys
import time
import threading
import urllib.error
import urllib.parse
import urllib.request

__all__ = ["Bot", "Message", "Chat", "User", "ApiError"]
__version__ = "1.2.0"


class ApiError(Exception):
    """Ошибка Bot API (сервер вернул error)."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class User(object):
    def __init__(self, d):
        d = d or {}
        self.username = d.get("username", "")
        self.first_name = d.get("first_name") or self.username
        self.is_bot = bool(d.get("is_bot"))

    @property
    def mention(self):
        return "@" + self.username if self.username else self.first_name

    def __repr__(self):
        return "User(@%s)" % self.username


class Chat(object):
    def __init__(self, d):
        d = d or {}
        self.id = d.get("id", "")
        self.type = d.get("type", "private")   # private | group | channel
        self.title = d.get("title")
        self.handle = d.get("handle")

    @property
    def is_private(self):
        return self.type == "private"

    def __repr__(self):
        return "Chat(%s, %s)" % (self.id, self.type)


class Message(object):
    """Входящее сообщение. Удобные поля: text, chat, from_user, command, args, file."""

    def __init__(self, bot, d):
        self._bot = bot
        self.raw = d
        self.message_id = d.get("message_id")
        self.date = d.get("date", 0)
        self.type = d.get("type", "text")       # text | image | file
        self.text = d.get("text") or ""
        self.chat = Chat(d.get("chat"))
        self.from_user = User(d.get("from"))
        self.file = d.get("file")               # {id, name, size, mime, url} или None
        self.poll = d.get("poll")               # для type == "poll": {question, options, counts, total, quiz, ...}
        r = d.get("reply_to_message")
        self.reply_to = r  # {message_id, text, from} или None
        self.command = None
        self.args = ""
        if self.text.startswith("/"):
            parts = self.text.split(None, 1)
            cmd = parts[0][1:]
            if "@" in cmd:
                cmd = cmd.split("@", 1)[0]
            self.command = cmd.lower()
            self.args = parts[1].strip() if len(parts) > 1 else ""

    @property
    def chat_id(self):
        return self.chat.id

    @property
    def file_url(self):
        if not self.file:
            return None
        url = self.file.get("url") or ""
        return url if url.startswith("http") else self._bot.base_url + url

    def reply(self, text, quote=True):
        """Ответить в тот же чат (по умолчанию — цитируя сообщение)."""
        return self._bot.send_message(self.chat.id, text, reply_to=self.message_id if quote else None)

    def answer(self, text):
        """Ответить без цитаты."""
        return self._bot.send_message(self.chat.id, text)

    def reply_document(self, path, caption=None):
        return self._bot.send_document(self.chat.id, path, caption)

    def reply_photo(self, path, caption=None):
        return self._bot.send_photo(self.chat.id, path, caption)

    def download(self, to_path=None):
        """Скачать присланный файл. Возвращает путь к сохранённому файлу."""
        if not self.file:
            raise ApiError("В сообщении нет файла")
        to_path = to_path or self.file.get("name") or "file"
        req = urllib.request.Request(self.file_url, headers={"User-Agent": "nmessenger-bot/" + __version__})
        with urllib.request.urlopen(req, timeout=60) as r, open(to_path, "wb") as f:
            f.write(r.read())
        return to_path

    def __repr__(self):
        return "Message(%s, %r)" % (self.from_user.mention, self.text[:40])


class Bot(object):
    def __init__(self, token, base_url="http://localhost:10000", timeout=35):
        if not token or not str(token).startswith("nmbot:"):
            raise ValueError("Нужен ключ бота вида nmbot:... (выдаёт @BotFather командой /newbot)")
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._handlers = []          # [(predicate, func)]
        self._commands = {}          # name -> func
        self._descriptions = []      # [(name, description)]
        self._offset = 0
        self._running = False
        self.me = None
        self.log = lambda *a: print("[bot]", *a, file=sys.stderr)

    # ---------- HTTP ----------
    def _url(self, method, params=None):
        u = "%s/api/bot/%s/%s" % (self.base_url, self.token, method)
        if params:
            u += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        return u

    def _call(self, method, data=None, params=None, raw=None, headers=None, timeout=None):
        hdrs = {"User-Agent": "nmessenger-bot/" + __version__}
        if raw is not None:
            body = raw
            hdrs["Content-Type"] = "application/octet-stream"
        elif data is not None:
            body = json.dumps(data).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        else:
            body = None
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(self._url(method, params), data=body, headers=hdrs, method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                payload = r.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read().decode("utf-8")).get("error") or str(e)
            except Exception:
                msg = str(e)
            raise ApiError(msg, e.code)
        except urllib.error.URLError as e:
            raise ApiError("Нет связи с сервером %s: %s" % (self.base_url, e.reason))
        try:
            j = json.loads(payload)
        except ValueError:
            raise ApiError("Некорректный ответ сервера")
        if isinstance(j, dict) and j.get("error"):
            raise ApiError(j["error"])
        return j

    # ---------- методы API ----------
    def get_me(self):
        self.me = self._call("me")
        return self.me

    def send_message(self, chat_id, text, reply_to=None):
        """chat_id — ID чата (например group:abc123) или username пользователя для личного сообщения."""
        text = str(text)
        out = None
        for i in range(0, max(1, len(text)), 4000):   # длинные тексты режем на части
            out = self._call("sendMessage", {"chat_id": chat_id, "text": text[i:i + 4000], "reply_to_message_id": reply_to if i == 0 else None})
        return out

    def send_document(self, chat_id, path, caption=None, filename=None, mime=None):
        return self._send_file("sendDocument", chat_id, path, caption, filename, mime)

    def send_photo(self, chat_id, path, caption=None, filename=None, mime=None):
        return self._send_file("sendPhoto", chat_id, path, caption, filename, mime)

    def _send_file(self, method, chat_id, path, caption, filename, mime):
        if hasattr(path, "read"):
            data = path.read()
            name = filename or getattr(path, "name", "file")
        else:
            with open(path, "rb") as f:
                data = f.read()
            name = filename or os.path.basename(path)
        if len(data) > 10 * 1024 * 1024:
            raise ApiError("Файл больше 10 МБ")
        mime = mime or mimetypes.guess_type(name)[0] or "application/octet-stream"
        headers = {"x-filename": urllib.parse.quote(name), "x-mime": mime}
        if caption:
            headers["x-caption"] = urllib.parse.quote(str(caption))
        return self._call(method, raw=data, params={"chat_id": chat_id}, headers=headers, timeout=120)

    def send_poll(self, chat_id, question, options, anonymous=True, multiple=False, quiz=False,
                  correct_option=None, explanation=None, open_period=0, reply_to=None):
        """Опрос как в Telegram. options — список строк (2–10). quiz=True + correct_option=индекс — викторина.
        open_period — через сколько секунд закрыть (0 — никогда, максимум 7 дней)."""
        return self._call("sendPoll", {
            "chat_id": chat_id, "question": question, "options": list(options),
            "is_anonymous": bool(anonymous), "allows_multiple_answers": bool(multiple),
            "type": "quiz" if quiz else "regular", "correct_option_id": correct_option,
            "explanation": explanation, "open_period": int(open_period or 0), "reply_to_message_id": reply_to,
        })

    def stop_poll(self, chat_id, message_id):
        """Завершить свой опрос (результаты остаются видны)."""
        return self._call("stopPoll", {"chat_id": chat_id, "message_id": message_id})

    def edit_message(self, chat_id, message_id, text):
        return self._call("editMessageText", {"chat_id": chat_id, "message_id": message_id, "text": str(text)})

    def delete_message(self, chat_id, message_id):
        return self._call("deleteMessage", {"chat_id": chat_id, "message_id": message_id})

    def send_typing(self, chat_id):
        return self._call("sendChatAction", {"chat_id": chat_id, "action": "typing"})

    def get_chat(self, chat_id):
        return self._call("getChat", params={"chat_id": chat_id}).get("result")

    def set_commands(self, commands):
        """commands: [("start", "Запустить бота"), ("help", "Помощь")] или [{"command":..., "description":...}]"""
        lst = []
        for c in commands:
            if isinstance(c, dict):
                lst.append({"command": c.get("command"), "description": c.get("description", "")})
            else:
                lst.append({"command": c[0], "description": c[1] if len(c) > 1 else ""})
        return self._call("setMyCommands", {"commands": lst}).get("result")

    def get_updates(self, offset=0, timeout=25):
        j = self._call("getUpdates", params={"offset": offset, "timeout": timeout}, timeout=timeout + 10)
        return j.get("result", [])

    # ---------- декораторы ----------
    def command(self, name, description=None):
        """@bot.command("start", "Запустить бота") — обработчик команды /start."""
        def deco(func):
            for n in ([name] if isinstance(name, str) else name):
                n = n.lstrip("/").lower()
                self._commands[n] = func
                if description:
                    self._descriptions.append((n, description))
            return func
        return deco

    def message(self, filter_func=None, content_types=("text",)):
        """@bot.message() — любое сообщение (текст по умолчанию); можно передать фильтр: lambda m: "привет" in m.text.lower()"""
        def deco(func):
            def pred(m):
                if content_types and m.type not in content_types:
                    return False
                if m.command and m.command in self._commands:
                    return False
                return bool(filter_func(m)) if filter_func else True
            self._handlers.append((pred, func))
            return func
        return deco

    def file_message(self):
        """@bot.file_message() — сообщения с файлами и фото."""
        return self.message(content_types=("image", "file"))

    # ---------- цикл ----------
    def process_update(self, upd):
        msg = upd.get("message")
        if not msg:
            return
        m = Message(self, msg)
        try:
            if m.command and m.command in self._commands:
                self._commands[m.command](m)
                return
            for pred, func in self._handlers:
                if pred(m):
                    func(m)
                    return
        except ApiError as e:
            self.log("Ошибка API в обработчике:", e)
        except Exception:
            import traceback
            traceback.print_exc()

    def run(self, poll_timeout=25, skip_pending=False, threaded=False):
        """Запустить long polling. skip_pending=True — пропустить сообщения, накопившиеся, пока бот был выключен."""
        try:
            me = self.get_me()
            self.log("Запущен @%s (%s) — %s" % (me.get("username"), me.get("first_name"), self.base_url))
        except ApiError as e:
            self.log("Не удалось подключиться:", e)
            raise
        if self._descriptions:
            try:
                self.set_commands(self._descriptions)
            except ApiError as e:
                self.log("set_commands:", e)
        if skip_pending:
            pend = self.get_updates(0, 0)
            if pend:
                self._offset = pend[-1]["update_id"] + 1
        self._running = True
        backoff = 1
        while self._running:
            try:
                updates = self.get_updates(self._offset, poll_timeout)
                backoff = 1
            except ApiError as e:
                self.log("getUpdates:", e, "— повтор через %ss" % backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue
            except KeyboardInterrupt:
                break
            for upd in updates:
                self._offset = max(self._offset, upd["update_id"] + 1)
                if threaded:
                    threading.Thread(target=self.process_update, args=(upd,), daemon=True).start()
                else:
                    self.process_update(upd)
        self.log("Остановлен")

    def stop(self):
        self._running = False


if __name__ == "__main__":
    print("Это библиотека. Пример использования: см. example_bot.py или строку документации модуля.")
