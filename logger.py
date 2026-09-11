import logging
import os

from config import LOG_PATH


def setup_logger():

    log_directory = os.path.dirname(
        LOG_PATH
    )

    if log_directory:
        os.makedirs(
            log_directory,
            exist_ok=True,
        )

    logger = logging.getLogger(
        "HomeSOC"
    )

    logger.setLevel(
        logging.INFO
    )

    logger.propagate = False

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"
    )

    file_handler = logging.FileHandler(
        LOG_PATH,
        encoding="utf-8",
    )

    file_handler.setFormatter(
        formatter
    )

    logger.addHandler(
        file_handler
    )

    return logger


logger = setup_logger()