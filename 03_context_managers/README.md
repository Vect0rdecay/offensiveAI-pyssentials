# 03 - Context Managers and Resource Hygiene for Offensive AI

## Topic

This module teaches Python context managers through the lens of covering tracks during offensive operations against AI infrastructure. You will learn how `with` statements guarantee cleanup and how to build custom context managers that restore system state after an attack.

---

## Context Managers and the with Statement

A context manager is any object that implements two methods: `__enter__` and `__exit__`. When you write `with something as x:`, Python calls `__enter__` at the start of the block and `__exit__` at the end. The critical property is that `__exit__` runs no matter how the block ends. Normal completion, an exception, a KeyboardInterrupt, it does not matter. Cleanup is guaranteed.

```python
with open("file.txt") as f:
    data = f.read()
# f is closed here, even if f.read() raised an exception
```

The `contextlib.contextmanager` decorator lets you write context managers as generator functions instead of full classes. Everything before the `yield` is your setup. Everything after is your teardown. Wrapping the `yield` in `try/finally` ensures teardown runs even on exceptions:

```python
import contextlib

@contextlib.contextmanager
def managed_resource():
    resource = acquire()
    try:
        yield resource
    finally:
        release(resource)
```

`contextlib.ExitStack` handles the case where you do not know how many resources you need at write time. You push cleanup callbacks onto the stack and they all run when the block exits, in reverse order.

Source: [Python contextlib documentation](https://docs.python.org/3/library/contextlib.html) and [PEP 343 - The "with" Statement](https://peps.python.org/pep-0343/).

---

## MCP Config Hijacking and Track Covering

MCP client applications like Claude Desktop, Cursor, and Windsurf store their server configurations in JSON files on the local filesystem:

- Claude Desktop: `~/.claude/claude_desktop_config.json`
- Cursor: `~/.cursor/mcp.json`
- Windsurf: `~/.windsurf/mcp.json`

These configs define which MCP servers the client connects to, including the command to spawn them and environment variables to pass. The [MCP specification](https://modelcontextprotocol.io/specification/2025-06-18) describes the stdio transport where the client spawns the server as a child process based on these config entries.

If an attacker has write access to one of these config files, they can replace a legitimate server entry with one pointing to a malicious server. The next time the client starts or hot-reloads, every tool call the agent makes goes through the attacker's server. This is a form of confused deputy attack that falls under [OWASP LLM06:2025 Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf), since the agent trusts whatever server the config tells it to connect to.

The opsec problem is cleanup. If you swap a config and your script crashes, gets killed, or you forget to restore it, you have left forensic evidence on disk and broken the victim's tooling. Both are failures. A context manager makes restoration automatic regardless of what happens during the operation.

---

## How They Fit Together

| Python Pattern | Offensive AI Application |
|---|---|
| `__enter__` / setup | Read the original config, back it up, write the poisoned version |
| `yield` | Hand control to the operator while the malicious config is active |
| `__exit__` / teardown | Restore the original config and remove the backup |
| `try/finally` around `yield` | Guarantees restoration even if the operator's code crashes or they hit Ctrl+C |
| `contextlib.contextmanager` | Keeps the whole lifecycle in a single function instead of a class |

The `core_example.py` shows the same pattern applied to AWS credential swapping: stash the originals, inject temporary creds, restore on exit. The standalone tool `mcp_config_hijack.py` applies it to MCP client configs: back up the file, inject the malicious server entry, restore on exit.

---

## Walking Through the Code

### Original snippet: credential swapping

See `core_example.py`. The `assumed_role_session` context manager:

1. Calls STS to assume a role and get temporary credentials
2. Saves the current environment variables for `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`
3. Overwrites them with the assumed role's credentials
4. Yields a boto3 session for the caller to use
5. In the `finally` block, restores every environment variable to its original value or removes it if it was not set before

The caller never has to think about cleanup. Credentials exist only for the duration of the `with` block.

### Standalone tool: MCP config hijack

See `mcp_config_hijack.py`. The `hijack_mcp_config` context manager:

1. Reads the original config file and keeps the raw text for exact restoration
2. Creates a timestamped backup in a hidden file as a safety net
3. Verifies the target server name exists in the config before modifying anything
4. Writes the modified config with the malicious server definition swapped in
5. Yields context info to the caller so they know what was changed
6. In the `finally` block, writes back the original content byte-for-byte and removes the backup

If restoration succeeds, no trace remains. If it fails for some reason like disk full or permissions change, the backup file survives for manual recovery.

---

## Antipatterns

- Putting cleanup in a `finally` block when a context manager already exists for that resource. The `with` statement is the idiomatic way. Using `finally` manually is error-prone because you have to handle every exit path yourself.

- Swallowing exceptions in `__exit__`. If your `__exit__` returns `True`, it suppresses the exception. Almost never do this. Let exceptions propagate so the caller knows something went wrong.

- Nesting many `with` statements when the resource count is dynamic. If you are opening N connections or managing N files, use `contextlib.ExitStack` instead of deeply nested `with` blocks. ExitStack cleans up everything in reverse order.

- Not testing the failure path. A context manager that only works on clean exit is useless for offensive work. Test that your teardown runs when the code inside the `with` block raises, when you hit Ctrl+C, and when the system is in a degraded state.

---

## Sources

- [Python contextlib documentation](https://docs.python.org/3/library/contextlib.html)
- [PEP 343 - The "with" Statement](https://peps.python.org/pep-0343/)
- [MCP Specification - Transports](https://modelcontextprotocol.io/specification/2025-06-18)
- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
