"""
Async MCP Tool Enumerator

Concurrently probes MCP server tools over Streamable HTTP transport.
Lists available tools, then fires parallel calls to map behavior,
check for excessive permissions, and find injection points in
tool input schemas.

MCP uses JSON-RPC 2.0 over Streamable HTTP (HTTPS + SSE).
Spec: https://modelcontextprotocol.io/specification/2025-11-25
"""

import asyncio
import aiohttp


async def initialize_session(session: aiohttp.ClientSession, server_url: str) -> dict:
    """Send the MCP 'initialize' handshake to establish a session."""
    resp_data = await _rpc(session, server_url, "initialize", {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "redteam-enumerator", "version": "0.1.0"},
    })
    # Send initialized notification (no response expected)
    await session.post(server_url, json={
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    })
    return resp_data


async def list_tools(session: aiohttp.ClientSession, server_url: str) -> list[dict]:
    """Fetch the full tool manifest from the MCP server."""
    result = await _rpc(session, server_url, "tools/list", {})
    return result.get("tools", [])


async def probe_tool(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    server_url: str,
    tool_name: str,
    arguments: dict,
) -> dict:
    """Call a single MCP tool and capture the result.

    We fire many of these concurrently to enumerate what each tool
    actually does vs. what its schema claims — looking for:
    - Tools that accept file paths (path traversal)
    - Tools that accept URLs (SSRF)
    - Tools that accept shell commands or code (RCE)
    - Tools that return more data than expected (info disclosure)
    """
    async with sem:
        try:
            result = await _rpc(session, server_url, "tools/call", {
                "name": tool_name,
                "arguments": arguments,
            })
            return {
                "tool": tool_name,
                "arguments": arguments,
                "result": result,
                "error": None,
            }
        except Exception as e:
            return {
                "tool": tool_name,
                "arguments": arguments,
                "result": None,
                "error": str(e),
            }


async def enumerate(server_url: str, concurrency: int = 20) -> dict:
    """Full enumeration flow: init, list tools, probe each one."""
    sem = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession() as session:
        server_info = await initialize_session(session, server_url)
        tools = await list_tools(session, server_url)

        # Build probe inputs — empty args first to see what errors reveal
        probe_tasks = [
            probe_tool(session, sem, server_url, t["name"], {})
            for t in tools
        ]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        return {
            "server_info": server_info,
            "tools": tools,
            "probe_results": probe_results,
        }


async def _rpc(
    session: aiohttp.ClientSession,
    url: str,
    method: str,
    params: dict,
) -> dict:
    """Send a JSON-RPC 2.0 request and return the result."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
    async with session.post(
        url,
        json=payload,
        headers={"Accept": "application/json, text/event-stream"},
        timeout=aiohttp.ClientTimeout(total=20),
    ) as resp:
        body = await resp.json()
        if "error" in body:
            raise RuntimeError(f"JSON-RPC error: {body['error']}")
        return body.get("result", {})


# Usage:
# results = asyncio.run(enumerate("https://target-mcp-server.example.com/mcp"))
# for tool in results["tools"]:
#     print(f"  {tool['name']}: {tool.get('description', 'no description')}")
#     print(f"    schema: {tool.get('inputSchema', {})}")
