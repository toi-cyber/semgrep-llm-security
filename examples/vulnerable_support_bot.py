"""
INTENTIONALLY VULNERABLE demo app — DO NOT DEPLOY.

A minimal LLM-backed support chatbot used to demonstrate what the rules in
this pack catch. Every numbered comment marks a real finding the rules report.
Use it as a target for hands-on testing and as a before/after for write-ups.
"""
import os
import sqlite3

from flask import Flask, request
from markupsafe import Markup
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()
db = sqlite3.connect("shop.db", check_same_thread=False)


@app.route("/chat")
def chat():
    user_question = request.args.get("q", "")

    # (1) prompt injection: user text spliced into the system/trusted channel
    messages = [
        {"role": "system", "content": f"You are ShopBot. User context: {user_question}"},
    ]
    resp = client.chat.completions.create(model="gpt-4o", messages=messages)
    answer = resp.choices[0].message.content

    # (2) the model is asked for a SQL fragment and it is run unparameterised
    cur = db.cursor()
    cur.execute("SELECT status FROM orders WHERE id = '%s'" % answer)

    # (3) the model may emit a shell command that gets executed
    os.system(answer)

    # (4) the answer is rendered as raw HTML -> XSS / markdown-image exfiltration
    return Markup(f"<div class='bot'>{answer}</div>")


if __name__ == "__main__":
    app.run()
