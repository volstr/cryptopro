import re
import subprocess  # nosec
import time
from typing import List, Optional, Union

from .consts import PROVIDER_NAMES, PROVIDER_NAMES_CRYPTOGRAPHIC, PROVIDER_TYPES
from .errors import CertMgrException
from .log import get_cryptopro_cli_logger
from .utils import build_command_line_args


logger = get_cryptopro_cli_logger('certmgr')


def export(
    file_name: str,
    *,
    thumbprint: Optional[str] = None,
    subj_key_id: Optional[str] = None,
    pin: str = '',
    provtype: Optional[int] = None,
    provname: Optional[str] = None,
    fmt: str = 'cert',
    base64_view: bool = False,
) -> int:
    """
    Экспортировать сертификат или CRL из хранилища или контейнера в файл.

    :param file_name: Файл для декодированного сертификата или CRL
    :param thumbprint: Цифровой отпечаток сертификата для фильтрации.
    :param subj_key_id: Идентификатор ключа для фильтрации.
    :param pin: Новый пин-код для контейнера
    :param provtype: тип криптопровайдера (по умолчанию 80)
    :param provname: имя криптопровайдера
    :param fmt: Формат - pfx, cert, crl
    :param base64_view: Использовать для представления сертификата или CRL кодировку base64.
    :return: Код - 0x0 - успешно, иначе исключение
    :exception: CertMgrException
    """
    allowed_provider_names = [*PROVIDER_NAMES.values(), *PROVIDER_NAMES_CRYPTOGRAPHIC.values()]

    assert file_name, 'Не указано имя файла'
    assert thumbprint or subj_key_id, 'Не задан ни один параметр для фильтрации'
    assert not provtype or provtype in PROVIDER_TYPES, 'Не корректный тип криптопровайдера'
    assert not provname or provname in allowed_provider_names, 'Не корректное имя криптопровайдера'
    assert fmt in {'pfx', 'cert', 'crl'}
    assert thumbprint, 'Не указан цифровой отпечаток сертификата'

    cmd = build_command_line_args(
        'certmgr',
        '-export',
        f'-{fmt}',
        dest=file_name,
        base64=base64_view,
        pin=pin,
        thumbprint=thumbprint.lower() if thumbprint else None,
        keyid=subj_key_id.lower() if subj_key_id else None,
        provtype=provtype if provtype else None,
        provname=provname if provname else None,
    )

    return _exec_certmng(cmd)


def install(
    file_name: str,
    *,
    pin: str = '',
    store: Optional[str] = None,
    provtype: Optional[int] = None,
    provname: Optional[str] = None,
    keep_exportable: bool = True,
    fmt: str = 'cert',
    container: Optional[str] = None,
    all_certs: bool = False,
) -> int:
    """
    Установить сертификат или CRL в хранилище. Может создать ссылку из сертификата на закрытый ключ, если необходимо.

    :param file_name: Путь к файлу с сертификатом или CRL (DER или base64-закодированным или сериализованным хранилищем)
    :param pin: Пин-код контейнера.
    :param store: Имя хранилища.
    :param provtype: Тип провайдера (значение по умолчанию 75 ).
    :param provname: Имя провайдера
    :param keep_exportable: Пометить импортированные ключи как экспортируемые.
    :param fmt: Формат - pfx, cert, crl
    :param container: Указать имя контейнера с сертификатом или закрытым ключом. Имя имеет формат вида \\.\reader\name.
    :param all_certs: Использовать все подходящие сертификаты (CRL).
    :return: Код - 0x0 - успешно, иначе исключение
    :exception: CertMgrException
    """
    assert file_name, 'Не указано имя файла'
    assert fmt in {'pfx', 'cert', 'crl'}

    cmd = build_command_line_args(
        'certmgr',
        '-install',
        f'-{fmt}',
        '-silent',
        store=store,
        provtype=provtype,
        provname=provname,
        file=file_name,
        pin=pin,
        container=container,
        keep_exportable=keep_exportable and True,
        all=all_certs and True,
    )

    return _exec_certmng(cmd)


def delete(
    *,
    container: str = None,
    thumbprint: Optional[str] = None,
) -> int:
    """
    Удаление сертификата.

    :param container: Имя контейнера
    :param thumbprint: Отпечаток сертификата
    :return: Код - 0x0 - успешно, иначе исключение
    :exception: CertMgrException
    """
    assert container or thumbprint, 'Не задан ни один параметр для фильтрации'

    cmd = build_command_line_args(
        'certmgr',
        '-delete',
        container=container,
        thumbprint=thumbprint,
    )

    return _exec_certmng(cmd)


def _exec_certmng(cmd: List[Union[str, int]]) -> int:
    cmd = [str(x) for x in cmd if x is not None]
    logger.info(' '.join(cmd).strip())

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)  # nosec

    for line in iter(proc.stdout.readline, b''):
        time.sleep(0.01)
        if not line.rstrip():
            continue

        line = line.rstrip().decode(encoding='utf-8')
        logger.debug(line)

        error_code_group = re.match(r'\[ErrorCode: (.{10})]', line)
        if error_code_group:
            error_code_group_value = error_code_group.group(1)
            error_code = int(error_code_group_value, 16)
            if error_code:
                logger.error(f'ErrorCode: {error_code_group_value}')
                raise CertMgrException(error_code)

            return error_code

    logger.error('Не корректное завершение процесса')
    raise CertMgrException(0xFF)
