import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from langgraph.graph import StateGraph, START, END
from app.rag.engine import SecurityKnowledgeBase
from langchain_openai import ChatOpenAI
from app.agents.state import AgentState
from typing import Literal
from langgraph.prebuilt import ToolNode
from langchain_core.tools import tool
from app.agents.codex_tool import codex_generate_fix, codex_analyze_vulnerability, codex_create_pr_description
from app.agents.code_fix_agents import corgea_fix_vulnerability, github_copilot_suggest_fix

# Initialize Components
llm = ChatOpenAI(model="gpt-4o")
kb = SecurityKnowledgeBase()

# Define Tools
@tool
def query_security_rag(query: str) -> str:
    """Consult the internal Security RAG for policies and playbooks. Provide detailed clear information."""
    docs = kb.query(query)
    return "\n".join([d.page_content for d in docs])

# Single consolidated tools list
tools = [
    query_security_rag,
    codex_generate_fix,
    codex_analyze_vulnerability,
    codex_create_pr_description,
    corgea_fix_vulnerability,
    github_copilot_suggest_fix,
]
tool_node = ToolNode(tools)
llm_with_tools = llm.bind_tools(tools)

# Define Node Logic
def call_model(state: AgentState):
    """The brain: decides whether to use a tool or answer the user."""
    system_prompt = """You are a Security Orchestrator with access to these tools:
    1. query_security_rag - Search company security policies (SOC2/HIPAA/PCI-DSS)
    2. codex_generate_fix - Generate secure code fixes using GPT-4
    3. codex_analyze_vulnerability - Analyze vulnerability severity and impact
    4. corgea_fix_vulnerability - Use Corgea for automated third-party remediation
    5. github_copilot_suggest_fix - Get a second opinion on code fixes using Copilot style
    6. codex_create_pr_description - Create GitHub PR descriptions

    Workflow:
    - Use query_security_rag to check compliance requirements
    - Use codex_analyze_vulnerability to assess risk
    - Decide on the best fix strategy:
        - Use corgea_fix_vulnerability for automated remediation if applicable
        - Use codex_generate_fix for custom secure code generation
        - Use github_copilot_suggest_fix for alternative suggestions
    - Use codex_create_pr_description to format PR

    Always provide:
    - A clear risk assessment
    - Specific code fixes with before/after comparison
    - PR title starting with [SECURITY]
    - Compliance impact analysis
    """
    messages = [{"role": "system", "content": system_prompt}] + state["messages"]
    response = llm_with_tools.invoke(messages)
    return {"messages": [response]}

def should_continue(state: AgentState) -> Literal["tools", "__end__"]:
    """Check if the LLM wants to use a tool or stop."""
    last_message = state["messages"][-1]
    if last_message.tool_calls:
        return "tools"
    return END

# Build the Graph
builder = StateGraph(AgentState)
builder.add_node("agent", call_model)
builder.add_node("tools", tool_node)
builder.add_edge(START, "agent")
builder.add_conditional_edges("agent", should_continue)
builder.add_edge("tools", "agent")

orchestrator = builder.compile()

# Test
if __name__ == "__main__":
    from langchain_core.messages import HumanMessage
    inputs = {"messages": [HumanMessage(content="Check our SOC2 policy for password rotation")]}
    for output in orchestrator.stream(inputs):
        print(output)
