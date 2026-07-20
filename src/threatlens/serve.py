"""Serve a rendered HTML report from a tiny local HTTP server.

Keeps the report in memory instead of writing a file to disk — the report is
held as a byte string and served on every request until interrupted.
"""

from __future__ import annotations

import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_PORT_TRIES = 20


def _make_handler(body: bytes):
    class ReportHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            path = self.path.split("?", 1)[0]
            if path not in ("/", "/index.html"):
                self.send_error(404, "Not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:  # silence default request logging
            pass

    return ReportHandler


def serve_html(
    html: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    open_browser: bool = True,
    on_start=None,
) -> None:
    """Serve ``html`` on ``http://host:port/`` until Ctrl+C.

    If ``port`` is busy, the next free port (up to ``MAX_PORT_TRIES`` higher) is
    used. ``on_start(url)`` is called once the server is bound.
    """
    body = html.encode("utf-8")
    handler = _make_handler(body)

    server: ThreadingHTTPServer | None = None
    last_err: OSError | None = None
    chosen = port
    for candidate in range(port, port + MAX_PORT_TRIES):
        try:
            server = ThreadingHTTPServer((host, candidate), handler)
            chosen = candidate
            break
        except OSError as exc:  # port in use / not available
            last_err = exc
    if server is None:
        raise OSError(
            f"Could not bind a port in {port}..{port + MAX_PORT_TRIES - 1}: {last_err}"
        )

    url = f"http://{host}:{chosen}/"
    if on_start is not None:
        on_start(url)
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # headless / no browser — non-fatal
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
