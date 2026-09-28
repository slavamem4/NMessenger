# -*- coding: utf-8 -*-
"""
Пример бота для NMessenger на Python.

1. Получите ключ у @BotFather в мессенджере: /newbot
2. Положите рядом nmessenger_bot.py (скачивается с вашего сервера: /sdk/nmessenger_bot.py)
3. Впишите ключ и адрес сервера ниже (или задайте переменные окружения NM_BOT_TOKEN и NM_URL)
4. Запустите:  python example_bot.py
"""
import os
import random
import datetime

from nmessenger_bot import Bot

TOKEN = os.environ.get("NM_BOT_TOKEN", "nmbot:ВСТАВЬТЕ_КЛЮЧ_ОТ_BOTFATHER")
SERVER = os.environ.get("NM_URL", "http://localhost:10000")

bot = Bot(TOKEN, SERVER)


@bot.command("start", "Запустить бота")
def start(m):
    m.reply("Привет, %s! Я бот на Python 🐍\nНапишите /help, чтобы увидеть, что я умею." % m.from_user.first_name)


@bot.command("help", "Список команд")
def help_cmd(m):
    m.answer(
        "**Команды:**\n"
        "/time — текущее время\n"
        "/roll — бросить кубик\n"
        "/echo текст — повторить текст\n"
        "/chat — информация о чате\n"
        "/file — прислать файл\n"
        "А ещё я отвечаю на любое сообщение и умею принимать файлы."
    )


@bot.command("time", "Текущее время")
def time_cmd(m):
    m.reply("Сейчас " + datetime.datetime.now().strftime("%H:%M:%S, %d.%m.%Y"))


@bot.command("roll", "Бросить кубик")
def roll(m):
    m.reply("🎲 Выпало: %d" % random.randint(1, 6))


@bot.command("echo", "Повторить текст")
def echo_cmd(m):
    m.reply(m.args or "Напишите так: /echo привет")


@bot.command("chat", "Информация о чате")
def chat_info(m):
    info = bot.get_chat(m.chat_id)
    m.answer("Чат `%s`, тип: %s, участников: %s" % (info["id"], info["type"], info["members_count"]))


@bot.command("file", "Прислать файл")
def send_file(m):
    path = "hello.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write("Файл от бота NMessenger. Время: %s\n" % datetime.datetime.now())
    m.reply_document(path, caption="Держите файл 📎")


@bot.file_message()
def got_file(m):
    f = m.file
    m.reply("Получил %s «%s» (%d КБ). Скачать можно тут: %s" % ("фото" if m.type == "image" else "файл", f["name"], f["size"] // 1024, m.file_url))


@bot.message(lambda m: "привет" in m.text.lower())
def hello(m):
    m.reply("И вам привет, %s 👋" % m.from_user.first_name)


@bot.message()
def any_text(m):
    # В группах бот видит все сообщения; отвечаем только в личке, чтобы не спамить
    if m.chat.is_private:
        bot.send_typing(m.chat_id)
        m.answer("Вы написали: «%s». Попробуйте /help" % m.text)


if __name__ == "__main__":
    bot.run()
