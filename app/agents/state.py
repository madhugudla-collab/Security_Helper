from typing import Annotated, Optional, Sequence, TypedDict
from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class AgentState(TypedDict):
    """State for the security orchestrator agent graph."""
    # Full chat history tracked by LangGraph
    messages: Annotated[Sequence[BaseMessage], add_messages]
    # Optional security context (repo info, scan results, etc.)
    security_context: Optional[str]
