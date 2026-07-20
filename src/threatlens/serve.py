"""Serve a multi-page HTML report from a tiny local HTTP server.

Pages are held in memory (path → bytes) — nothing written to disk.
"""

from __future__ import annotations

import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_PORT_TRIES = 20


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
    on_start=None,
) -> None:
    """Serve ``pages`` (URL path → HTML) until Ctrl+C."""
    encoded = {p: html.encode("utf-8") for p, html in pages.items()}
    if "/" not in encoded and "/index.html" in encoded:
        encoded["/"] = encoded["/index.html"]

    handler = _make_handler(encoded)
    server: ThreadingHTTPServer | None = None
    last_err: OSError | None = None
    chosen = port
    for candidate in range(port, port + MAX_PORT_TRIES):
        try:
            server = ThreadingHTTPServer((host, candidate), handler)
            chosen = candidate
            break
        except OSError as exc:
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
    on_start=None,
) -> None:
    """Back-compat: serve a single HTML document at ``/``."""
    serve_pages(
        {"/": html, "/index.html": html},
        host=host,
        port=port,
        open_browser=open_browser,
        on_start=on_start,
    )
