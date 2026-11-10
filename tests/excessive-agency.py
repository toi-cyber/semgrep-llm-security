# Test fixtures for rules/excessive-agency.yaml
from langchain_experimental.tools import PythonREPLTool
from langchain.agents import load_tools
from langchain_experimental.sql import SQLDatabaseChain


def dangerous_tools(llm, db):
    # ruleid: langchain-dangerous-tool-enabled
    repl = PythonREPLTool()

    # ruleid: langchain-dangerous-tool-enabled
    tools = load_tools(["serpapi", "terminal"], llm=llm)

    # ok: langchain-dangerous-tool-enabled
    safe_tools = load_tools(["serpapi", "llm-math"], llm=llm)

    # ruleid: langchain-allow-dangerous-flag
    chain = SQLDatabaseChain.from_llm(llm, db, allow_dangerous_code=True)

    # ok: langchain-allow-dangerous-flag
    safe_chain = SQLDatabaseChain.from_llm(llm, db)

    return repl, tools, safe_tools, chain, safe_chain
