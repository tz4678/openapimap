import logging
from enum import Enum

CSI = '\033['

Color = Enum(
    'Color', 'BLACK RED GREEN YELLOW BLUE MAGENTA CYAN WHITE', start=30
)


class AnsiColorHandler(logging.StreamHandler):
    LOGLEVEL_COLORS = {
        'DEBUG': Color.BLUE,
        'INFO': Color.GREEN,
        'WARNING': Color.RED,
        'ERROR': Color.RED,
        'CRITICAL': Color.RED,
    }

    def __init__(self) -> None:
        super().__init__()
        self.formatter = logging.Formatter("%(levelname)-8s - %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        message: str = super().format(record)
        # use colors in tty
        if self.stream.isatty() and (
            color := self.LOGLEVEL_COLORS.get(record.levelname)
        ):
            message = f'{CSI}{color.value}m{message}{CSI}0m'
        return message


# setup logger
logger = logging.getLogger(__package__)
logger.addHandler(AnsiColorHandler())
