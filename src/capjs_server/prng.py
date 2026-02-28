"""Deterministic PRNG matching the Cap.js JavaScript implementation.

Algorithm: FNV-1a hash for seeding, xorshift32 for generation.
Output is a hex string of the requested length.
"""

__all__ = ["prng"]

_MASK = 0xFFFFFFFF


def prng(seed: str, length: int) -> str:
    """Generate a deterministic hex string from *seed* of *length* chars.

    Uses FNV-1a to convert the seed to a 32-bit state, then xorshift32
    to produce hex output. This must match the Cap.js widget's PRNG exactly.
    """
    state = _fnv1a(seed)
    result = ""
    while len(result) < length:
        state ^= (state << 13) & _MASK
        state ^= state >> 17
        state ^= (state << 5) & _MASK
        state &= _MASK
        result += format(state, "08x")
    return result[:length]


def _fnv1a(s: str) -> int:
    """FNV-1a hash producing a 32-bit unsigned integer."""
    h = 2166136261
    for ch in s:
        h ^= ord(ch)
        h = (h + (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) & _MASK
    return h
