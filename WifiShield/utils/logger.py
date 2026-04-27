"""Logging helpers for Wifishield."""

import logging


def setup_logger(log_file: str = "logs.txt") -> logging.Logger:
    """Configure and return app logger."""
    logger = logging.getLogger("wifishield")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers if setup_logger is called again.
    if logger.handlers:
        return logger

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger
