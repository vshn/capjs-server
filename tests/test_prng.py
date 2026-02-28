"""Tests for FNV-1a + xorshift32 PRNG (must match Cap.js JavaScript implementation)."""
from capjs_server.prng import prng


class TestPrng:
    def test_deterministic(self):
        assert prng("test", 16) == prng("test", 16)

    def test_different_seeds_differ(self):
        assert prng("seed1", 16) != prng("seed2", 16)

    def test_length_respected(self):
        for length in (1, 8, 16, 32, 64):
            assert len(prng("x", length)) == length

    def test_hex_output(self):
        result = prng("abc", 32)
        int(result, 16)  # raises ValueError if not hex

    def test_known_vectors_from_js(self):
        """Verified against the reference Cap.js JavaScript implementation."""
        assert prng("hello", 8) == "eb492c6e"
        assert prng("hello", 16) == "eb492c6e1655ea8c"
        assert prng("test", 32) == "9c7ca3730a4a283aa6e4bc1c1d83b14f"
        assert prng("a", 8) == "441aaeb8"
        assert prng("z", 8) == "da40eb31"

    def test_long_seed(self):
        """Realistic Cap.js token seed (50 hex chars + counter)."""
        token = "aabbccdd11223344556677889900aabbccdd11223344556677"
        result = prng(token + "1", 32)
        assert len(result) == 32
        int(result, 16)
