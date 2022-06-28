import os
import sys
import typing
from enum import Enum
from functools import partial

CSI = '\033['

Color = Enum('Color', 'BLACK RED GREEN YELLOW BLUE MAGENTA CYAN WHITE', start=0)


def echo(
    message: typing.Any,
    *args: typing.Any,
    color: str | Color | None = None,
    stream: typing.TextIO = sys.stdout,
    append: str | None = os.linesep,
    prepend: str | None = None,
    **kwargs: typing.Any,
) -> None:
    message = str(message)
    if args:
        message %= args
    if prepend:
        message = f'{prepend} {message}'
    # Цвета отображаются только при выводе в сосноль
    if color and stream.isatty():
        if isinstance(color, str):
            color = Color[color.upper()]
        assert isinstance(color, Color)
        message = f'{CSI}{color.value + 30}m{message}{CSI}0m'
    print(message, end=append, file=stream, flush=True, **kwargs)


log = partial(echo, stream=sys.stderr)
info = partial(log, color=Color.BLUE, prepend='[!]')
error = partial(log, color=Color.RED, prepend='[-]')
success = partial(log, color=Color.GREEN, prepend='[+]')


if __name__ == '__main__':
    # Outputs to STDOUT
    echo(
        "The Answer to the Ultimate Question of Life, the Universe, and Everything is %d.",
        42,
    )
    # Otputs to STDERR
    info("INFO")
    error("Error: %s", Exception('err'))
    success("OK")
