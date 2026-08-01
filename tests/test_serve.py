import socket

import pytest

from threatlens.serve import PortInUseError, is_port_in_use, serve_pages


def test_is_port_in_use_detects_bound_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    try:
        assert is_port_in_use("127.0.0.1", sock.getsockname()[1]) is True
    finally:
        sock.close()


def test_is_port_in_use_false_for_free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    assert is_port_in_use("127.0.0.1", port) is False


def test_serve_pages_fails_when_port_busy_by_default():
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()
    port = blocker.getsockname()[1]
    try:
        with pytest.raises(PortInUseError, match=str(port)):
            serve_pages(
                {"/": "<html>ok</html>"},
                port=port,
                open_browser=False,
                allow_port_fallback=False,
            )
    finally:
        blocker.close()


def test_serve_pages_uses_next_port_with_fallback():
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()
    port = blocker.getsockname()[1]
    seen: dict[str, str] = {}

    def _start(info):
        seen["url"] = info.url
        seen["port"] = str(info.port)
        raise KeyboardInterrupt

    try:
        serve_pages(
            {"/": "<html>ok</html>"},
            port=port,
            open_browser=False,
            allow_port_fallback=True,
            on_start=_start,
        )
    except KeyboardInterrupt:
        pass
    finally:
        blocker.close()

    assert seen["port"] == str(port + 1)
    assert seen["url"] == f"http://127.0.0.1:{port + 1}/"
