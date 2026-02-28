import pytest


@pytest.fixture(autouse=True)
def _clear_cap_cache():
    try:
        from capjs_server.django import get_cap_server

        get_cap_server.cache_clear()
        yield
        get_cap_server.cache_clear()
    except ImportError:
        yield
