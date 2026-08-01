"""ASCII startup banner: compact owl perched above the THREATLENS title.

The art is stored as a raw multiline string so every space, comma, paren, quote
and hyphen survives verbatim. No figlet/emoji substitution at runtime.
"""

from __future__ import annotations

from rich.console import Console

OWL = r'''          ,_,
         (O,O)
         (   )
         -"-"--------------------------------'''

TITLE = r"""████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗██╗     ███████╗███╗   ██╗███████╗
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║     ██╔════╝████╗  ██║██╔════╝
   ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██║     █████╗  ██╔██╗ ██║███████╗
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║     ██╔══╝  ██║╚██╗██║╚════██║
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ███████╗███████╗██║ ╚████║███████║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝

          THREATLENS • Watching Every Code Path - By Prasanna"""

BANNER = f"{OWL}\n\n{TITLE}"


def render_banner(console: Console | None = None) -> None:
    """Print the banner as-is: no markup, no highlighting, no wrapping."""
    console = console or Console()
    console.print(BANNER, markup=False, highlight=False, soft_wrap=True)
