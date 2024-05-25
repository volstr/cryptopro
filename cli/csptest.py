import subprocess  # nosec
from typing import Dict

from .log import get_cryptopro_cli_logger
from .utils import build_command_line_args

logger = get_cryptopro_cli_logger('csptest')


def keyset() -> Dict[str, str]:
    """
    Перечисление контейнеров с уникальными именами.
    :return:
    """
    cmd = build_command_line_args('csptest', '-keyset', '-enum_cont', '-fqcn', '-verifyc', '-uniq')
    logger.info(' '.join(cmd).strip())

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)  # nosec

    containers = {}
    for line in iter(proc.stdout.readline, b''):
        if not line.rstrip():
            continue

        line = line.rstrip().decode(encoding='utf-8')
        logger.debug(line)
        if line.startswith('\\\\.\\'):
            name, uniq = line.split('|')
            containers[name.strip()] = uniq.strip()

    return containers
