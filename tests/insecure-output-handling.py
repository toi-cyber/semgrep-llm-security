# Test fixtures for rules/insecure-output-handling.yaml
# Run: semgrep --test --config rules/ tests/
import os
import subprocess  # noqa: F401
import pickle
import requests
from openai import OpenAI

client = OpenAI()


# --- code execution ---------------------------------------------------------
def code_exec_eval():
    resp = client.chat.completions.create(model="gpt-4o", messages=[])
    answer = resp.choices[0].message.content
    # ruleid: llm-output-to-code-execution
    eval(answer)


def code_exec_os_system():
    resp = client.chat.completions.create(model="gpt-4o", messages=[])
    # ruleid: llm-output-to-code-execution
    os.system(resp.choices[0].message.content)


def code_exec_pickle():
    resp = client.messages.create(model="claude", messages=[])
    # ruleid: llm-output-to-code-execution
    pickle.loads(resp.content)


def code_exec_safe_not_from_llm():
    user = input()
    # ok: llm-output-to-code-execution
    eval(user)


# --- SQL --------------------------------------------------------------------
def sql_concat(cur):
    resp = client.chat.completions.create(model="gpt-4o", messages=[])
    name = resp.choices[0].message.content
    # ruleid: llm-output-to-sql-query
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)


def sql_parameterised(cur):
    resp = client.chat.completions.create(model="gpt-4o", messages=[])
    name = resp.choices[0].message.content
    # ok: llm-output-to-sql-query
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))


# --- HTML / XSS -------------------------------------------------------------
def html_markup():
    from markupsafe import Markup
    resp = client.chat.completions.create(model="gpt-4o", messages=[])
    # ruleid: llm-output-rendered-as-html
    return Markup(resp.choices[0].message.content)


def html_streamlit_unsafe():
    import streamlit as st
    resp = client.chat.completions.create(model="gpt-4o", messages=[])
    # ruleid: llm-output-rendered-as-html
    st.markdown(resp.choices[0].message.content, unsafe_allow_html=True)


def html_streamlit_safe():
    import streamlit as st
    resp = client.chat.completions.create(model="gpt-4o", messages=[])
    # ok: llm-output-rendered-as-html
    st.markdown(resp.choices[0].message.content)


# --- SSRF -------------------------------------------------------------------
def ssrf_fetch():
    resp = client.chat.completions.create(model="gpt-4o", messages=[])
    url = resp.choices[0].message.content
    # ruleid: llm-output-to-server-side-request
    requests.get(url)
