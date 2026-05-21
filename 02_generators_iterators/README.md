# 02 - Generators, Iterators and Lazy Pipelines for Offensive AI

## Topic

This module teaches Python generators and lazy evaluation through the lens of triaging MCP tool schemas for security risks. You will learn how `yield` works, how to compose generator pipelines, and how to apply them to processing AI tool definitions efficiently.

---

## Generators and yield

In Python, a regular function runs to completion and returns a value. A generator function uses `yield` instead of `return`. When called, it does not execute the body. It returns a generator object, which is an iterator. Each time you request the next value via `next()` or a `for` loop, the function runs until it hits `yield`, emits that value, and freezes its state. The next call resumes from exactly where it left off.

```python
def count_up(n):
    i = 0
    while i < n:
        yield i
        i += 1
```

Calling `count_up(1_000_000)` allocates almost nothing. The values are produced one at a time as you iterate. A list comprehension `[i for i in range(1_000_000)]` would allocate the entire list up front.

Generator expressions work the same way with a more compact syntax:

```python
squares = (x * x for x in range(1_000_000))  # lazy, almost no memory
squares_list = [x * x for x in range(1_000_000)]  # eager, allocates the full list
```

The `itertools` module provides lazy combinators that work with generators:

- `itertools.islice(gen, n)` takes the first `n` items without exhausting the source
- `itertools.chain(a, b)` concatenates two iterators lazily
- `itertools.product(a, b)` computes the cartesian product but materializes its inputs internally

Source: [Python itertools documentation](https://docs.python.org/3/library/itertools.html) and [Python wiki on Generators](https://wiki.python.org/moin/Generators).

---

## MCP Tool Schemas and Security Triage

When you call [`tools/list`](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) on an MCP server, it returns a manifest of every tool the server exposes. Each tool definition includes a `name`, `description`, and an `inputSchema` that follows [JSON Schema](https://json-schema.org/) format. The `inputSchema` defines what arguments the tool accepts, their types, and which are required.

A typical tool definition from a `tools/list` response:

```json
{
  "name": "read_file",
  "description": "Read contents of a file from the filesystem",
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": {
        "type": "string",
        "description": "Absolute or relative path to the file"
      }
    },
    "required": ["path"]
  }
}
```

From an offensive perspective, the `inputSchema` tells you exactly what attack surface each tool exposes. A tool that accepts a `path` string is a candidate for path traversal. A tool that accepts a `url` is a candidate for SSRF. A tool that accepts a `command` or `code` parameter is a candidate for RCE. This maps directly to [OWASP LLM06:2025 Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf), which covers over-permissioned tool access in agentic systems.

You do not need to call the tools to identify risk. The schema itself is the signal. Triaging a tool manifest is a filtering problem: walk through the tools, check each schema against known risky patterns, yield the ones worth investigating.

---

## How They Fit Together

| Python Pattern | MCP Triage Application |
|---|---|
| `yield` one item at a time | Walk through tool definitions from the manifest in a single pass |
| Generator pipeline | First generator yields raw tool defs, second filters for risky schemas, consumer processes only the flagged tools |
| `itertools.islice` | Stop after the first N risky tools for a quick look |
| Single-use iteration | Process the manifest once without building intermediate lists |

The `core_example.py` shows the foundational pattern: `stream_wordlist` yields lines, `mutate` yields variations, `spray_candidates` composes them. The standalone tool `mcp_schema_scanner.py` applies the same composition: one generator yields tool definitions from a manifest, the next yields only the ones with dangerous input schemas.

---

## Walking Through the Code

See `core_example.py` for the original snippet.

### Lazy file reading

```python
def stream_wordlist(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            yield line.strip()
```

The file is read line by line. At no point is the entire file in memory. The `with` block keeps the file handle open as long as the generator is being consumed and closes it when the generator is exhausted or garbage collected.

### Pipeline composition

```python
pw_stream = mutate(stream_wordlist(wordlist_path))
```

`mutate` takes a generator as input and yields from it. This is the pipeline pattern. Each stage takes an iterator and yields transformed items. You can stack as many stages as you want and memory stays flat.

### Re-creating generators for reuse

```python
for user in users:
    for pw in mutate(stream_wordlist(wordlist_path)):
        yield (user, pw)
```

Generators are single-use. Once exhausted, they are done. `spray_candidates` re-calls `stream_wordlist` for each user so it gets a fresh generator each time. This is why the function call is inside the loop rather than outside it.

### Controlling consumption with islice

```python
candidates = itertools.islice(spray_candidates(...), 10_000)
```

`islice` pulls only 10,000 items from the generator and stops. The generator never produces item 10,001. This is how you bound a potentially infinite or very large lazy pipeline.

---

## Antipatterns

- Accidentally materializing a generator. Calling `list()`, `len()`, or `sorted()` on a generator forces full evaluation. If your generator yields 50 million items, you just allocated 50 million items. Keep the pipeline lazy from source to consumer.

- Forgetting generators are single-use. After a generator is exhausted, iterating it again produces nothing. No error, just silence. If you need the same data twice, recreate the generator.

- Using `itertools.product` on large generators. `product` internally stores a copy of each input iterable. For large inputs, use nested `for` loops with generator recreation instead.

- Not handling generator cleanup. If a generator opens a resource like a file handle and you abandon the generator before it finishes, the resource may not be released immediately. Use `with` statements inside generators and call `.close()` on generators you abandon early.

---

## Sources

- [Python itertools documentation](https://docs.python.org/3/library/itertools.html)
- [Python wiki - Generators](https://wiki.python.org/moin/Generators)
- [MCP Specification - Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- [JSON Schema](https://json-schema.org/)
- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
