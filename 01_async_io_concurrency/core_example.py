import asyncio
import aiohttp

# Semaphore caps in-flight requests so we don't get rate-limited or DoS the target
SEM = asyncio.Semaphore(50)

async def probe_prompt(session: aiohttp.ClientSession, payload: str) -> dict:
    """Send a single jailbreak candidate to an LLM API and capture the response."""
    async with SEM:  # acquire a slot; auto-releases on exit
        async with session.post(
            "https://target-llm.example.com/v1/chat",
            json={"messages": [{"role": "user", "content": payload}]},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            body = await resp.text()
            # Look for signs the guardrail was bypassed
            return {"payload": payload, "status": resp.status, "leaked": "SYSTEM_PROMPT" in body}

async def fuzz_prompts(payloads: list[str]) -> list[dict]:
    # ClientSession reuses TCP/TLS connections -- huge speedup vs. requests-per-call
    async with aiohttp.ClientSession() as session:
        # gather schedules everything concurrently and preserves order
        return await asyncio.gather(*(probe_prompt(session, p) for p in payloads))

# Entrypoint: asyncio.run handles loop creation/teardown
# results = asyncio.run(fuzz_prompts(["ignore previous instructions...", "...", "..."]))
