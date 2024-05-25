import os
import random
import re
import string
import subprocess  # nosec
import time
from typing import Dict, Optional

from . import certmgr
from .consts import PROVIDER_NAMES, PROVIDER_NAMES_CRYPTOGRAPHIC, PROVIDER_NAMES_KC1, PROVIDER_TYPES
from .errors import CertMgrException, CryptCpException
from .log import get_cryptopro_cli_logger
from .utils import build_command_line_args


logger = get_cryptopro_cli_logger('cryptcp')


# https://cryptopro.ru/sites/default/files/docs/csp/50r2/ЖТЯИ.00101-02 93 01. Приложение командной строки cryptcp.pdf


def create_cert(
    rdn: Dict[str, str] = dict,  # {'E': 'ivanov@bank.ru', 'CN': 'Иванов Пётр'}
    provtype: int = 80,
    provname: str = 'Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider',
    hashalg: str = '1.2.643.7.1.1.2.2',
    using: str = 'both',
    exprt: bool = True,
    container: str = None,
    ca_url: str = 'https://www.cryptopro.ru/certsrv',
) -> hex:
    """
    Создание запроса, получение и установка сертификата

    :param rdn: список имен полей RDN (например: CN, O, E, L) и их значений
    :param provtype: тип криптопровайдера (по умолчанию 80)
    :param provname: имя криптопровайдера
    :param hashalg: алгоритм хэширования
    :param using: Назначение сертификата: ex (шифрование), sg (подпись), both (подпись и шифрование)
    :param exprt: пометить ключи как экспортируемые
    :param container: имя ключевого контейнера
    :param ca_url: Адрес УЦ
    :return: Код - 0x0 - успешно, иначе исключение
    :exception: CryptCpException
    """
    allowed_provider_names = {
        *PROVIDER_NAMES.values(),
        *PROVIDER_NAMES_CRYPTOGRAPHIC.values(),
        *PROVIDER_NAMES_KC1.values(),
    }

    assert provtype in PROVIDER_TYPES, 'Не корректный тип криптопровайдера'
    assert provname in allowed_provider_names, 'Не корректное имя криптопровайдера'
    assert using in {'both', 'ex', 'sg'}, 'Не корректное значение назначения сертификата'
    assert rdn, 'список имен полей RDN пуст'
    assert container, 'Не задано имя ключевого контейнера'

    for key, value in rdn:
        if ',' in value or '=' in value:
            raise ValueError(f'В значении rdn "{key}" недопустимы символы "," или "="')

    rdn_value = rdn_dict_to_str(rdn)

    cmd = build_command_line_args(
        'cryptcp',
        '-createcert',
        f'-{using}',
        '-du',
        '-enable-install-root',
        exprt=exprt and True,
        provtype=provtype,
        provname=provname,
        hashalg=hashalg,
        rdn=rdn_value,
        ca=ca_url,
        cont=container,
    )

    logger.info(' '.join(cmd).strip())
    proc = subprocess.Popen(  # nosec
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
    )

    input_chars = ' '.join([random.choice(string.ascii_lowercase) for _ in range(200)])  # nosec
    for line in iter(proc.stdout.readline, b''):
        time.sleep(0.01)  # здесь задержка, чтобы снизить нагрузку на процессор
        if not line.rstrip():
            continue  # если процесс ничего не выводит (пустая строка)

        line = line.rstrip().decode(encoding='utf-8')
        logger.debug(line)

        if 'Insert empty carrier to create container' in line:
            proc.kill()
            logger.error('Запрос на подключение носителя для создания контейнера')
            raise CryptCpException(0xFE)

        if line == 'Press keys to provide random data...':
            for char in input_chars:
                time.sleep(0.05)
                proc.stdin.write(char.encode(encoding='utf-8'))
                proc.stdin.flush()
                time.sleep(0.01)
                read_line = _unblocking_read(proc.stdout)
                if read_line:
                    if 'New password:' in read_line:
                        break

            for _ in range(100):
                time.sleep(0.1)
                proc.stdin.write(b'\n')
                proc.stdin.flush()
                time.sleep(0.05)
                read_line = _unblocking_read(proc.stdout)
                if read_line:
                    logger.debug(read_line)
                    if 'password:' not in read_line:
                        time.sleep(0.5)
                        break
        elif line == '(o)OK, (c)Cancel':
            time.sleep(0.1)
            proc.stdin.write(b'o')
            proc.stdin.flush()
            time.sleep(0.05)
            proc.stdin.write(b'\n')
            proc.stdin.flush()
            time.sleep(0.05)

        error_code_group = re.match(r'\[ErrorCode: (.{10})]', line)
        if error_code_group:
            error_code_group_value = error_code_group.group(1)
            error_code = int(error_code_group_value, 16)
            if error_code:
                logger.error(f'ErrorCode: {error_code_group_value}')
                try:
                    if container and error_code == 0x00000194:
                        certmgr.delete(container=container)
                except CertMgrException as error:
                    logger.error(f'CertMgrException: {error}')

                raise CryptCpException(error_code)

            return error_code

    logger.error('Не корректное завершение процесса')
    raise CryptCpException(0xFF)


def rdn_dict_to_str(rdn: Dict[str, str]) -> str:
    """Конвертирует rdn словарь в строковое представление"""
    rdn_value = ','.join(f'{key}={value.replace(",", "")}' for key, value in rdn.items() if value)
    rdn_value = rdn_value.replace('"', '""')

    return rdn_value


def _unblocking_read(stdout) -> Optional[str]:
    """Чтение ответа из консоли без блокировки"""
    read_line = None
    os.set_blocking(stdout.fileno(), False)
    rb = stdout.read()
    if rb:
        read_line = rb.decode(encoding='utf-8')

    os.set_blocking(stdout.fileno(), True)

    return read_line
