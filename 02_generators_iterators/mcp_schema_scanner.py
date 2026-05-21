"""
MCP Tool Schema Scanner

Takes a JSON file containing a tools/list response from a single MCP server
and lazily scans each tool's inputSchema for risky parameter patterns.

Usage:
    python mcp_schema_scanner.py tools_manifest.json
"""

import json
import sys
from pathlib import Path

# Each risk type maps to keywords that indicate a dangerous parameter.
# If a tool's inputSchema has a property name or description containing
# any of these keywords, it gets flagged for manual review.
RISKY_PATTERNS = {
    "path_traversal": ["path", "file", "filename", "filepath", "directory", "dir", "folder"],
    "ssrf": ["url", "uri", "endpoint", "host", "address", "href", "link"],
    "rce": ["command", "cmd", "exec", "shell", "code", "script", "program", "binary"],
    "sqli": ["query", "sql", "statement", "expression"],
}


def stream_tools(manifest_path: Path):
    """Yield one tool definition at a time from a tools/list JSON response."""
    # Load the manifest once, then yield each tool individually.
    # The generator pattern here means the consumer only ever holds
    # one tool definition in its processing pipeline at a time.
    with manifest_path.open("r") as f:
        data = json.load(f)

    # Handle both {"tools": [...]} wrapper format and bare list format
    tools = data.get("tools", data) if isinstance(data, dict) else data
    for tool in tools:
        yield tool


def flag_risky_tools(tools):
    """Filter generator that yields tools with risky inputSchema properties.

    This is the second stage of the pipeline. It consumes the stream_tools
    generator and only yields tools that match a risky pattern. Tools with
    clean schemas are silently skipped, so the consumer never sees them.
    """
    for tool in tools:
        # Every MCP tool has an inputSchema following JSON Schema format.
        # The properties dict maps parameter names to their type definitions.
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})

        # Check each parameter against our risk patterns.
        # We check both the property name and its description because
        # some schemas use generic names like "input" but describe
        # the parameter as "file path to read" in the description.
        for prop_name, prop_def in properties.items():
            prop_desc = prop_def.get("description", "").lower()
            prop_name_lower = prop_name.lower()

            for risk_type, keywords in RISKY_PATTERNS.items():
                for keyword in keywords:
                    if keyword in prop_name_lower or keyword in prop_desc:
                        # Yield a finding dict rather than printing directly.
                        # This keeps the generator pure and lets the consumer
                        # decide what to do with each finding.
                        yield {
                            "tool": tool.get("name", "unknown"),
                            "description": tool.get("description", ""),
                            "risky_property": prop_name,
                            "risk_type": risk_type,
                            "matched_keyword": keyword,
                        }


def main():
    if len(sys.argv) != 2:
        print("Usage: python mcp_schema_scanner.py <manifest.json>")
        sys.exit(1)

    manifest_path = Path(sys.argv[1])
    if not manifest_path.exists():
        print(f"File not found: {manifest_path}")
        sys.exit(1)

    # Build the generator pipeline: stream tools -> filter risky ones.
    # Nothing executes until we iterate in the for loop below.
    tools = stream_tools(manifest_path)
    findings = flag_risky_tools(tools)

    # This is the only place where the pipeline actually runs.
    # Each iteration pulls one finding through both generators.
    count = 0
    for finding in findings:
        count += 1
        print(f"[{finding['risk_type']}] {finding['tool']}")
        print(f"  property: {finding['risky_property']}")
        print(f"  keyword match: {finding['matched_keyword']}")
        print(f"  tool description: {finding['description']}")
        print()

    if count == 0:
        print("No risky tool schemas found.")
    else:
        print(f"Total findings: {count}")


if __name__ == "__main__":
    main()
