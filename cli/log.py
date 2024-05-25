import logging
import os
import sys
from logging.handlers import TimedRotatingFileHandler


PRINT_LOG_TO_FILE = True
PRINT_LOG_TO_STDOUT = False


def get_cryptopro_cli_logger(name: str = 'cryptcli', level: int = logging.DEBUG) -> logging.Logger:
    """Создать/получить лог."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    file_name = os.path.join(os.getcwd(), 'logs')
    if not os.path.isdir(file_name):
        os.mkdir(file_name)

    file_name = os.path.join(file_name, f'{name}.log')
    log_format = logging.Formatter('%(levelname)-9s %(asctime)s %(message)s')

    if hasattr(logging, 'handlers'):
        if PRINT_LOG_TO_FILE:
            log_file_handler = TimedRotatingFileHandler(
                file_name,
                encoding='utf-8',
                interval=1,
                backupCount=5,
                when='midnight',
            )
            log_file_handler.setFormatter(log_format)
            logger.addHandler(log_file_handler)

        if PRINT_LOG_TO_STDOUT:
            log_std_handler = logging.StreamHandler(sys.stdout)
            log_std_handler.setFormatter(log_format)
            logger.addHandler(log_std_handler)

    return logger
