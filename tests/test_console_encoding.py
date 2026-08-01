from threatlens.console_encoding import configure_utf8_stdio


def test_configure_utf8_stdio_is_safe_to_call():
    # Must never raise, even when streams are redirected or already configured.
    configure_utf8_stdio()
    configure_utf8_stdio()
