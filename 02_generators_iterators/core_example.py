import itertools
from pathlib import Path

def stream_wordlist(path: Path):
    """Yield one credential candidate per line -- never loads the whole file."""
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line

def mutate(words):
    """Generator pipeline: apply common password mutations on the fly."""
    for w in words:
        yield w
        yield w.capitalize()
        yield f"{w}123"
        yield f"{w}!"
        yield w + "2025"

def spray_candidates(users, wordlist_path):
    """Cartesian product of users x mutated passwords -- fully lazy.
    Nothing is materialized until consumed, so memory stays flat."""
    pw_stream = mutate(stream_wordlist(wordlist_path))
    # Note: product() would consume the generator; for true laziness pair manually
    for user in users:
        for pw in mutate(stream_wordlist(wordlist_path)):  # re-open per user
            yield (user, pw)

# Only try the first 10k combos -- islice never builds the full list
candidates = itertools.islice(spray_candidates(["alice", "bob"], Path("rockyou.txt")), 10_000)
for user, pw in candidates:
    pass  # send auth attempt here
