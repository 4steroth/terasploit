import random


def align(n: int, a: int) -> int:
    """Aligns n up to the next multiple of a."""
    return (n + a - 1) & ~(a - 1)


def random_section_name() -> bytes:
    """Generates a random dot-prefixed 5-character section name."""
    suffix = "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(4))
    return f".{suffix}".encode()
