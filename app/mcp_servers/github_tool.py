import os
from langchain_mcp_adapters.client import MultiServerMCPClient

async def get_github_tools():
    """Connects to the GitHub MCP server and returns available tools."""
    client = MultiServerMCPClient({
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": os.getenv("GITHUB_TOKEN")}
        }
    })
    return await client.get_tools()
