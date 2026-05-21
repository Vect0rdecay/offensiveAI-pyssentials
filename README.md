# offensiveAI-pyssentials

## Summary

Python concepts for offensive security engineers working against AI systems, LLM APIs, agentic stacks, and AI protocols like MCP, A2A, AG-UI, A2P, and UCP.

Ten Python concepts taught through the lens of attacking AI infrastructure. Each concept is its own directory containing three files:

- **README.md** - An explainer that teaches the Python concept alongside the AI concept it applies to. Covers how the two fit together, walks through the code, and calls out antipatterns. Includes links to real sources (protocol specs, library docs, OWASP references, research).
- **core_example.py** - The original code snippet demonstrating the Python pattern applied to an offensive AI use case. Short, focused, and annotated.
- **A standalone tool script** - A separate, self-contained script that builds on the concept in a practical direction against AI infrastructure.

The core examples are code snippets meant to illustrate Python patterns. They are not runnable as-is and need additional logic to execute. The standalone tools are closer to functional but will almost all need modification to work against your specific targets and situation.

## Topics

| # | Concept |
|---|---------|
| 01 | Async I/O and Concurrency (`asyncio`, `aiohttp`) |
| 02 | Generators, Iterators and Lazy Pipelines |
| 03 | Context Managers and Resource Hygiene |
| 04 | Decorators and Higher-Order Functions |
| 05 | Type Hints, Dataclasses and Pydantic |
| 06 | `subprocess`, `shlex` and Safe Command Execution |
| 07 | Bytes, Encoding and Crypto Primitives |
| 08 | HTTP Clients, Sessions and Request Crafting (`httpx` / `requests`) |
| 09 | Parsing, Regex and Structured Data (HTML/JSON/YAML) |
| 10 | Packaging, Imports and Dynamic Code Loading |

## Intended Audience

Offensive security engineers who want to sharpen their Python skills specifically for AI and ML attack surfaces. Each concept assumes you know basic Python but want to understand how these patterns apply to red-teaming LLM applications, probing agentic stacks, and testing AI protocols.
