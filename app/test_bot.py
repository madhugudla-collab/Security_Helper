import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.agents.orchestrator import orchestrator
from langchain_core.messages import HumanMessage

inputs = {"messages": [HumanMessage(content=" List all mitigation controls for  Prompt Injection please explain?")]}
for output in orchestrator.stream(inputs):
    for key, value in output.items():
        print(f"Node '{key}' is finished!")
        if "messages" in value:
            print(f"Bot says: {value['messages'][-1].content}")



from app.agents.orchestrator import orchestrator
from langchain_core.messages import HumanMessage

inputs = {"messages": [HumanMessage(content="What is the most complex Security finding in Gen AI LLM and MCP and Treditional Appsec Give me the example thrat vector for each complex security issue.")]}
for output in orchestrator.stream(inputs):
    for key, value in output.items():
        print(f"Node '{key}' is finished!")
        if "messages" in value:
            print(f"Bot says: {value['messages'][-1].content}")