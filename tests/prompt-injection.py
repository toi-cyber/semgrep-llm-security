# Test fixtures for rules/prompt-injection.yaml


def build_messages_bad(user_question):
    # ruleid: user-input-in-system-prompt
    return [{"role": "system", "content": f"You are a support bot. Context: {user_question}"}]


def build_messages_bad_format(doc_text):
    # ruleid: user-input-in-system-prompt
    return [{"role": "system", "content": "Knowledge base:\n{}".format(doc_text)}]


def build_messages_ok(user_question):
    # ok: user-input-in-system-prompt
    return [
        {"role": "system", "content": "You are a support bot. Answer only from the knowledge base."},
        {"role": "user", "content": user_question},
    ]
