# 01 — Async I/O & Concurrency for Offensive AI

## Topic

This module teaches Python's `asyncio` and `aiohttp` through the lens of attacking AI systems. It covers how async concurrency works and how we can use it for offensive AI.

---

## asyncio

Python is single-threaded by default. When your code calls `requests.get()`, the entire thread blocks until the response arrives. It does nothing while it waits on network I/O. If you're sending 10,000 prompt injection candidates to an LLM endpoint one at a time, you're going to be waiting for a long time. Conversely, with this we need to be aware of rate-limiting, blocks, and possibly rotate source IPs to avoid getting blocked. 

`asyncio` solves this with somethign called cooperative multitasking. Instead of threads, you write coroutines which are basically just functions defined with `async def` that can give control back to the event loop with `await` while they wait on I/O. The event loop runs other coroutines during that wait time. The result is thousands of concurrent network operations on a single thread with minimal overhead.

Key building blocks:

- **`async def` / `await`** — Define and call coroutines. `await` suspends the current coroutine until the awaited operation completes, letting other coroutines run.
- **`asyncio.gather(*coros)`** — Schedule multiple coroutines concurrently and wait for all of them. Returns results in the same order they were passed.
- **`asyncio.Semaphore(n)`** — A concurrency limiter. Only `n` coroutines can hold the semaphore at once; the rest wait. Essential for rate-limiting.
- **`asyncio.run(coro)`** — The top-level entry point that creates the event loop, runs your coroutine, and tears everything down.

Source: [Python asyncio documentation](https://docs.python.org/3/library/asyncio.html) and [Coroutines and Tasks reference](https://docs.python.org/3/library/asyncio-task.html).

---

## Prompt Injection Fuzzing at Scale

Prompt injection is [OWASP LLM01:2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf). The #1 risk in LLM applications for the second consecutive year. It exploits the fact that LLMs process instructions and data in the same channel with no reliable separation. 

When you're red-teaming an LLM-powered application, you need to test thousands of injection variants:
- Direct injections ("ignore previous instructions...")
- Indirect injections (payloads embedded in documents the model retrieves via RAG or embedded in fetched and ingested web pages)
- Encoding tricks (base64-wrapped instructions, low-density languages, unicode smuggling)
- Multi-turn escalations (building context across messages to bypass guardrails)

Doing this effectively means hitting the target's API endpoint with high throughput while staying under rate limits. `asyncio` turns what would be a sequential hours-long crawl into a minutes-long concurrent sweep assuming the app doesn't block you.

Tools like [Garak](https://docs.garak.ai/garak/examples/prompt-injection) (NVIDIA's LLM vulnerability scanner) and [PyRIT](https://github.com/Azure/PyRIT) (Microsoft's red-teaming framework) both use async patterns internally.

Here's the mapping between the Python primitives and the AI offensive use case:

| Python Primitive | AI Offensive Use |

| `aiohttp.ClientSession` | Maintains a connection pool to the target LLM API — reuses TCP/TLS connections instead of renegotiating per request. LLM APIs (OpenAI, Anthropic, Azure) all serve over HTTPS, so TLS handshake savings are significant. |

| `asyncio.Semaphore` | Caps concurrent requests to stay under the target's rate limit. OpenAI enforces [RPM (requests per minute) and TPM (tokens per minute)](https://platform.openai.com/docs/guides/rate-limits) limits that vary by tier. Hit them and you get 429s that waste time and signal scanning activity. |

| `asyncio.gather` | Fires all prompt injection candidates concurrently and collects results in order. `return_exceptions=True` ensures one bad response doesn't kill the entire batch — critical when some payloads trigger 500s or timeouts. |

| `async with` (context manager) | Ensures the `ClientSession` and `Semaphore` are properly acquired and released, even if a coroutine raises. Leaked connections mean leaked sockets, which means your scan dies at scale. |

---

## Walking Through the Code

See `core_example.py` and here's what it does:

**1. Semaphore as a rate governor**

```python
SEM = asyncio.Semaphore(50)
```

This caps in-flight requests at 50 and you tune it based on the target's rate limits. As one example, OpenAI's Tier 1 allows 500 RPM for GPT-4, so 50 concurrent with ~6s average response time keeps you at roughly 500 RPM. The semaphore is acquired with `async with SEM:` which blocks the coroutine (not the thread) until a slot opens.

**2. Connection reuse via ClientSession**

```python
async with aiohttp.ClientSession() as session:
```

A `ClientSession` maintains a [connection pool](https://docs.aiohttp.org/en/stable/client_advanced.html) which by default is up to 100 total connections, with keep-alive enabled. Every coroutine that calls `session.post()` reuses an existing TCP+TLS connection from the pool instead of doing a full handshake.

**3. Probing for guardrail bypass**

```python
return {"payload": payload, "status": resp.status, "leaked": "SYSTEM_PROMPT" in body}
```

Each response is checked for signs that the system prompt leaked which might be an indicator of [LLM07:2025 System Prompt Leakage](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf). In practice you'd check for more signals as well like role/permission escalation, tool-call traces in the output, or specific sentinel strings you planted in the system prompt.

**4. Gathering results**

```python
return await asyncio.gather(*(probe_prompt(session, p) for p in payloads))
```

`gather` schedules all probe coroutines at once. The semaphore prevents them from all firing simultaneously, they queue up and execute as slots free up. Results come back in the same order as the input payloads, making it easy to correlate which injection triggered which response.

---

## Antipatterns

- **Don't mix blocking calls into coroutines.** `requests.get()`, `time.sleep()`, or any synchronous I/O inside an `async def` blocks the entire event loop. Use `aiohttp` for HTTP, `asyncio.sleep()` for delays. If you *must* call blocking code, wrap it in `asyncio.to_thread()`.

- **`asyncio.gather` default behavior kills your scan.** Without `return_exceptions=True`, one exception cancels everything. In a fuzzing run against an LLM API, some payloads will trigger 500s, timeouts, or malformed responses. Always pass `return_exceptions=True` so you get the exception objects in the results list instead of losing the entire batch.

- **Rate limits are per-key AND per-org.** On OpenAI, [rate limits](https://platform.openai.com/docs/guides/rate-limits) apply at both the API key level and the organization level. Rotating keys doesn't help if the org limit is the bottleneck. Check `x-ratelimit-remaining` response headers to tune your semaphore dynamically.

- **429 ≠ always rate limit.** A 429 from an LLM API can mean RPM exceeded, TPM exceeded, or a billing/quota issue. Each requires a different fix. [OpenAI's rate limit guide](https://developers.openai.com/cookbook/examples/how_to_handle_rate_limits) recommends exponential backoff with jitter not an immediate retry.

---

## Sources

- [Python asyncio documentation](https://docs.python.org/3/library/asyncio.html)
- [Python Coroutines and Tasks](https://docs.python.org/3/library/asyncio-task.html)
- [aiohttp ClientSession — Advanced Usage (connection pooling)](https://docs.aiohttp.org/en/stable/client_advanced.html)
- [OWASP Top 10 for LLM Applications 2025 (PDF)](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
- [OpenAI API Rate Limits](https://platform.openai.com/docs/guides/rate-limits)
- [OpenAI Cookbook — How to Handle Rate Limits](https://developers.openai.com/cookbook/examples/how_to_handle_rate_limits)
- [Garak — LLM Vulnerability Scanner (NVIDIA)](https://docs.garak.ai/garak/examples/prompt-injection)
- [PyRIT — Python Risk Identification Toolkit (Microsoft)](https://github.com/Azure/PyRIT)
- [Promptfoo — Does Fuzzing LLMs Actually Work?](https://www.promptfoo.dev/blog/llm-fuzzing/)
