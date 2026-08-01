"""Serve a multi-page HTML report from a tiny local HTTP server.

Pages are held in memory (path → bytes) — nothing written to disk.
"""

from __future__ import annotations

import socket
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_PORT_TRIES = 20


class PortInUseError(OSError):
    """Raised when the requested port is already bound by another process."""


@dataclass(frozen=True)
class ServeInfo:
    url: str
    host: str
    port: int
    requested_port: int
    port_fallback: bool


def is_port_in_use(host: str, port: int) -> bool:
    """Return True when something is already accepting TCP connections on ``port``."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def port_in_use_message(host: str, port: int) -> str:
    return (
        f"Port {port} on {host} is already in use — another report may still be "
        f"running there.\n"
        f"Stop the old ThreatLens server (Ctrl+C in its terminal) or free the port, "
        f"then re-run.\n"
        f"Windows: for /f \"tokens=5\" %a in ('netstat -ano ^| findstr :{port} "
        f"^| findstr LISTENING') do taskkill /PID %a /F\n"
        f"Or serve a saved report on another port:\n"
        f"  threatlens report serve <report.json> --port {port + 1}\n"
        f"Or allow auto-fallback: add --allow-port-fallback"
    )


def _make_handler(pages: dict[str, bytes]):
    class ReportHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path in pages:
                body = pages[path]
            elif path.rstrip("/") in pages:
                body = pages[path.rstrip("/")]
            else:
                self.send_error(404, "Not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            pass

    return ReportHandler


def serve_pages(
    pages: dict[str, str],
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    open_browser: bool = True,
    allow_port_fallback: bool = False,
    on_start: Callable[[ServeInfo], None] | None = None,
) -> None:
    """Serve ``pages`` (URL path → HTML) until Ctrl+C."""
    encoded = {p: html.encode("utf-8") for p, html in pages.items()}
    if "/" not in encoded and "/index.html" in encoded:
        encoded["/"] = encoded["/index.html"]

    handler = _make_handler(encoded)
    server: ThreadingHTTPServer | None = None
    last_err: OSError | None = None
    chosen = port
    port_fallback = False

    if not allow_port_fallback and is_port_in_use(host, port):
        raise PortInUseError(port_in_use_message(host, port))

    port_range = range(port, port + MAX_PORT_TRIES) if allow_port_fallback else range(port, port + 1)
    for candidate in port_range:
        try:
            server = ThreadingHTTPServer((host, candidate), handler)
            chosen = candidate
            port_fallback = candidate != port
            break
        except OSError as exc:
            last_err = exc

    if server is None:
        if allow_port_fallback:
            raise OSError(
                f"Could not bind a port in {port}..{port + MAX_PORT_TRIES - 1}: {last_err}"
            )
        raise PortInUseError(port_in_use_message(host, port))

    url = f"http://{host}:{chosen}/"
    info = ServeInfo(
        url=url,
        host=host,
        port=chosen,
        requested_port=port,
        port_fallback=port_fallback,
    )
    if on_start is not None:
        on_start(info)
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def serve_html(
    html: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    open_browser: bool = True,
    allow_port_fallback: bool = False,
    on_start: Callable[[ServeInfo], None] | None = None,
) -> None:
    """Back-compat: serve a single HTML document at ``/``."""
    serve_pages(
        {"/": html, "/index.html": html},
        host=host,
        port=port,
        open_browser=open_browser,
        allow_port_fallback=allow_port_fallback,
        on_start=on_start,
    )
