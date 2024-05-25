import base64
import datetime
from typing import Dict, List, Optional, Union

import pycades  # noqa

from .algorithm import CADESCOM_CADES_BES, CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256


CERT_TYPE_BASE64 = 0  # Тип сертификата в base64 формате
CERT_TYPE_DER = 1  # Тип сертификата в der формате


class CertInfo:
    """Информация о сертификате"""

    def __init__(self, pycades_cert: pycades.Certificate):
        self._cert: pycades.Certificate = pycades_cert

    @property
    def subject_simple_name(self) -> str:
        """
        Возвращает отображаемое имя субъекта сертификата.
        :return: 'Иванов Иван'
        """
        return self._cert.GetInfo(pycades.CAPICOM_CERT_INFO_SUBJECT_SIMPLE_NAME)

    @property
    def issuer_simple_name(self) -> str:
        """
        Возвращает отображаемое имя издателя сертификата.
        :return: 'CRYPTO-PRO Test Center 2'
        """
        return self._cert.GetInfo(pycades.CAPICOM_CERT_INFO_ISSUER_SIMPLE_NAME)

    @property
    def subject_email_name(self) -> str:
        """
        Возвращает адрес электронной почты издателя сертификата.
        :return: 'ivanov@example.com'
        """
        return self._cert.GetInfo(pycades.CAPICOM_CERT_INFO_SUBJECT_EMAIL_NAME)

    @property
    def subject_upn(self) -> str:
        """
        Возвращает имя участника-пользователя субъекта сертификата. (в CAPICOM 2.0).
        :return: ''
        """
        return self._cert.GetInfo(pycades.CAPICOM_CERT_INFO_SUBJECT_UPN)

    @property
    def issuer_upn(self) -> str:
        """
        Возвращает имя участника-пользователя издателя сертификата. (в CAPICOM 2.0).
        :return: ''
        """
        return self._cert.GetInfo(pycades.CAPICOM_CERT_INFO_ISSUER_UPN)

    @property
    def subject_dns_name(self) -> str:
        """
        Возвращает DNS-имя субъекта сертификата. Представлено в CAPICOM 2.0.
        :return: 'Иванов Иван'
        """
        return self._cert.GetInfo(pycades.CAPICOM_CERT_INFO_SUBJECT_DNS_NAME)

    @property
    def issuer_dns_name(self) -> str:
        """
        Возвращает DNS-имя издателя сертификата. Представлено в CAPICOM 2.0.
        :return: 'CRYPTO-PRO Test Center 2'
        """
        return self._cert.GetInfo(pycades.CAPICOM_CERT_INFO_ISSUER_DNS_NAME)

    def __str__(self):
        return self.subject_simple_name


class PrivateKey:
    """Описывает закрытый ключ сертификата"""

    def __init__(self, pycades_cert: pycades.Certificate):
        self._cert: pycades.Certificate = pycades_cert

    @property
    def container_name(self) -> str:
        """
        Возвращает строку с именем контейнера закрытого ключа.
        :return: 'container_ivanov'
        """
        return self._cert.PrivateKey.ContainerName

    @property
    def unique_container_name(self) -> str:
        """
        Возвращает уникальное имя контейнера закрытого ключа.
        :return: 'HDIMAGE\\\\pfx-aa36.000\\3759'
        """
        return self._cert.PrivateKey.UniqueContainerName

    @property
    def provider_name(self) -> str:
        """
        Возвращает имя криптографического провайдера.
        :return: 'Crypto-Pro GOST R 34.10-2012 KC1 CSP'
        """
        return self._cert.PrivateKey.ProviderName

    @property
    def provider_type(self) -> int:
        """
        Возвращает имя криптографического провайдера.
        :return: 80
        """
        return self._cert.PrivateKey.ProviderType

    @property
    def key_spec(self) -> int:
        """
        Возвращает назначение ключа.
        :return: 1
        """
        return self._cert.PrivateKey.KeySpec

    def __str__(self):
        return self.container_name


class PublicKey:
    """Описывает открытый ключ сертификата."""

    def __init__(self, pycades_cert: pycades.Certificate):
        self._cert: pycades.Certificate = pycades_cert

    @property
    def encoded_key(self) -> str:
        """
        Возвращает значение открытого ключа.
        :return: 'BECXPTzTHOM8CHgxzKJyqkwTqDjX3bv0Ge5XGQJhty8oTy4S/cvX+c+OWnNP2kAU\njTX0HCzrulDaHH9HOZzR9fip\n'
        """
        return self._cert.PublicKey().EncodedKey.Value()

    @property
    def length(self) -> int:
        """
        Возвращает длину открытого ключа в битах.
        :return: 512
        """
        return self._cert.PublicKey().Length

    @property
    def algorithm_oid(self) -> str:
        """
        Возвращает OID алгоритма открытого ключа.
        :return: '1.2.643.7.1.1.1.1'
        """
        return self._cert.PublicKey().Algorithm.Value

    @property
    def algorithm_friendly_name(self) -> str:
        """
        Возвращает имя алгоритма открытого ключа.
        :return: 'ГОСТ Р 34.10-2012 256 бит'
        """
        return self._cert.PublicKey().Algorithm.FriendlyName

    @property
    def encoded_parameters(self) -> str:
        """
        Возвращает параметры алгоритма открытого ключа.
        :return: 'MBMGByqFAwICJAAGCCqFAwcBAQIC\n'
        """
        return self._cert.PublicKey().EncodedParameters.Value()

    def __str__(self):
        return self.algorithm_friendly_name


class Certificate:
    """Сертификат"""

    def __init__(self, pycades_cert: pycades.Certificate):
        self._cert: pycades.Certificate = pycades_cert

    @property
    def issuer_name(self) -> str:
        """
        rdn издателя сертификата.
        :return: 'CN=CRYPTO-PRO Test Center 2, O=CRYPTO-PRO LLC, L=Moscow, C=RU, E=support@cryptopro.ru'
        """
        return self._cert.IssuerName

    @property
    def issuer_rdn(self) -> Dict[str, str]:
        """
        rdn издателя сертификата.
        :return: {'CN': 'CRYPTO-PRO Test Center 2', 'O': 'CRYPTO-PRO LLC', 'L': 'Moscow', 'E': 'support@cryptopro.ru'}
        """
        return {key: value for key, value in map(lambda value: value.split('='), self.issuer_name.split(', '))}

    @property
    def serial_number(self) -> str:
        """
        Серийный номер сертификата.
        :return: '12006291E5FB6A7F5C811DB2460001006291E5'
        """
        return self._cert.SerialNumber

    @property
    def subject_name(self) -> str:
        """
        rdn сертификата.
        :return: 'CN=Иванов Иван, E=ivanov@example.com'
        """
        return self._cert.SubjectName

    @property
    def subject_rdn(self) -> Dict[str, str]:
        """
        rdn сертификата.
        :return: {'CN': 'Иванов Иван', 'E': 'ivanov@example.com'}
        """
        return {key: value for key, value in map(lambda value: value.split('='), self.subject_name.split(', '))}

    @property
    def thumbprint(self) -> str:
        """
        Отпечаток сертификата.
        :return: '81b54c53627af463871bb6de5175787eecb21fe2'
        """
        return self._cert.Thumbprint.lower()

    @property
    def valid_from_date(self) -> datetime.datetime:
        """
        Валидный с...
        :return: datetime
        """
        return datetime.datetime.strptime(self._cert.ValidFromDate, '%d.%m.%Y %H:%M:%S')

    @property
    def valid_to_date(self) -> datetime.datetime:
        """
        Валидный по...
        :return: datetime
        """
        return datetime.datetime.strptime(self._cert.ValidToDate, '%d.%m.%Y %H:%M:%S')

    @property
    def has_private_key(self) -> bool:
        """
        Имеется ли закрытый ключ для сертификата?
        :return: datetime
        """
        return self._cert.HasPrivateKey()

    @property
    def is_valid(self) -> bool:
        """
        Является ли сертификат валидным?
        :return: datetime
        """
        return self._cert.IsValid().Result

    @property
    def version(self) -> int:
        """
        Версия сертификата.
        :return: 3
        """
        return self._cert.Version

    @property
    def info(self) -> CertInfo:
        """
        Информация о сертификате.
        :return: CertInfo
        """
        return CertInfo(self._cert)

    @property
    def private_key(self) -> PrivateKey:
        """
        Описывает закрытый ключ сертификата.
        :return: PrivateKey
        """
        return PrivateKey(self._cert)

    @property
    def public_key(self) -> PublicKey:
        """
        Описывает открытый ключ сертификата.
        :return: PublicKey
        """
        return PublicKey(self._cert)

    def sign(
        self,
        content: Union[bytes, str],
        *,
        cades_type: int = CADESCOM_CADES_BES,
        hash_algorithm: int = CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256,
        pin: Optional[str] = None,
        check_certificate: bool = False,
        formatted: bool = False,
    ) -> str:
        """
        Создание отделенной подписи
        https://docs.cryptopro.ru/cades/pycades/pycades-samples/pycades-signhash-verifyhash
        :param content: Подписываемое сообщение
        :param check_certificate: Проверять подпись
        :param cades_type: Тип усовершенствованной подписи.
        :param hash_algorithm: Алгоритм хэширования.
        :param pin: Пин-код к контейнеру.
        :param formatted: Форматировать подпись переносами строк
        :return: Подпись
        """
        signer = pycades.Signer()
        signer.Certificate = self._cert
        signer.CheckCertificate = check_certificate
        if pin:
            signer.KeyPin = pin

        hashed_data = CryptoPro.pycades_hashed_data(content, hash_algorithm)

        signed_data = pycades.SignedData()
        signature = signed_data.SignHash(hashed_data, signer, cades_type)

        if not formatted:
            signature = signature.replace('\r', '').replace('\n', '')

        return signature

    def sign_cades(
        self,
        content: Union[bytes, str],
        *,
        cades_type: int = CADESCOM_CADES_BES,
        pin: Optional[str] = None,
        check_certificate: bool = False,
        detached: bool = False,
        formatted: bool = False,
    ) -> str:
        """
        Добавляет к сообщению усовершенствованную подпись
        :param content: Подписываемое сообщение
        :param cades_type: Тип усовершенствованной подписи.
        :param pin: Пин-код к контейнеру.
        :param check_certificate: Проверять подпись
        :param detached: Вид подписи: отделенная (true) или совмещенная (false). По умолчанию совмещенная.
        :param formatted: Форматировать подпись переносами строк
        :return: Подпись
        """
        signer = pycades.Signer()
        signer.Certificate = self._cert
        signer.CheckCertificate = check_certificate
        if pin:
            signer.KeyPin = pin

        signed_data = pycades.SignedData()
        if isinstance(content, str):
            signed_data.Content = content
        elif isinstance(content, bytes):
            signed_data.ContentEncoding = pycades.CADESCOM_BASE64_TO_BINARY
            signed_data.Content = base64.b64encode(content).decode()
        else:
            raise TypeError(f'{type(content)} недопустимый тип данных для подписи')

        signature: str = signed_data.SignCades(signer, cades_type, detached)

        if not formatted:
            signature = signature.replace('\r', '').replace('\n', '').replace('\t', '').replace(' ', '')

        return signature

    def raw_sign(
        self,
        data: Union[bytes, str],
        hash_algorithm: int = CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256,
        invert: bool = True,
    ):
        """
        Значение подписи. raw подпись.
        Возвращает либо signature либо invert signature
        :param data: Данные для подписи.
        :param hash_algorithm: Алгоритм хэширования.
        :param invert: Инвертировать подпись.
        :return: 'vbP0lcOtF/7H4mRQHsCQtoMYPOpSmcLFsql3E2xFFx61BNp34qGQbbfwmaS0MpcFJ6JJqrw/4vNwsYY4P61JFQ=='
        """
        base64_hash = CryptoPro.gost_hash(data, hash_algorithm)

        hash_value = base64.b64decode(base64_hash)
        hash_value = hash_value.hex()

        hashed_data = pycades.HashedData()
        hashed_data.Algorithm = hash_algorithm
        hashed_data.DataEncoding = pycades.CADESCOM_BASE64_TO_BINARY
        hashed_data.SetHashValue(hash_value)

        raw_signature = pycades.RawSignature()
        signature = raw_signature.SignHash(hashed_data, self._cert)

        bytes_signature = bytes.fromhex(signature)[::-1] if invert else bytes.fromhex(signature)
        signature = base64.b64encode(bytes_signature).decode()

        return signature

    def export(self, export_type: int = CERT_TYPE_BASE64, formatted: bool = False) -> Union[bytes, str]:
        """
        Экспорт сертификата
        :param export_type: Тип сертификата der, base64
        :param formatted: в случае если base64 форматировать строку или нет
        :return: str - для base64 формата. bytes - для der формата.
        """
        export_data = self._cert.Export(export_type)
        if export_type == CERT_TYPE_BASE64 and not formatted:
            export_data = export_data.replace('\r', '').replace('\n', '')

        return export_data

    def __str__(self):
        valid_from_date = self.valid_from_date.strftime('%d.%m.%Y')
        valid_to_date = self.valid_to_date.strftime('%d.%m.%Y')
        return f'{self.info.subject_simple_name} (с {valid_from_date} по {valid_to_date})'


class Certificates:
    """Работа со списком сертификатов из хранилища"""

    def __init__(self, store):
        self._store: pycades.Store = store

    def find(
        self,
        *,
        thumbprint: Optional[str] = None,
        subject_name: Optional[str] = None,
        issuer_name: Optional[str] = None,
        root_name: Optional[str] = None,
        template_name: Optional[str] = None,
        extension: Optional[str] = None,
        extended_property: Optional[str] = None,
        certificate_policy: Optional[str] = None,
        time_valid: bool = False,
        time_not_yet_valid: bool = False,
        time_expired: bool = False,
        key_usage: Optional[str] = None,
    ) -> List[Certificate]:
        """
        Функция поиска сертификатов.
        :param thumbprint: сертификаты соответствующие указанному хэшу SHA1. Отпечаток сертификата.
        :param subject_name: сертификаты, наименование которого точно или частично совпадает с указанным.
        :param issuer_name: сертификаты, наименование издателя которого точно или частично совпадает с указанным.
        :param root_name: сертификаты, у которых наименование корневого точно или частично совпадает с указанным.
        :param template_name: сертификаты, у которых шаблонное имя точно или частично совпадает с указанным.
        :param extension: сертификаты, у которых имеется раcширение, совпадающее с указанным.
        :param extended_property: сертификаты, у которых идентификатор раcширенного свойства совпадает с указанным.
        :param certificate_policy: сертификаты, содержащие указанный OID политики.
        :param time_valid: действующие на текущее время сертификаты.
        :param time_not_yet_valid: сертификаты, время которых невалидно.
        :param time_expired: просроченные сертификаты.
        :param key_usage: сертификаты, содержащие ключи, которые могут быть использованны указанным способом.
        :return:
        """
        certs = self._store.Certificates
        conditions = {
            pycades.CAPICOM_CERTIFICATE_FIND_SHA1_HASH: thumbprint,
            pycades.CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME: subject_name,
            pycades.CAPICOM_CERTIFICATE_FIND_ISSUER_NAME: issuer_name,
            pycades.CAPICOM_CERTIFICATE_FIND_ROOT_NAME: root_name,
            pycades.CAPICOM_CERTIFICATE_FIND_TEMPLATE_NAME: template_name,
            pycades.CAPICOM_CERTIFICATE_FIND_EXTENSION: extension,
            pycades.CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY: extended_property,
            pycades.CAPICOM_CERTIFICATE_FIND_CERTIFICATE_POLICY: certificate_policy,
            pycades.CAPICOM_CERTIFICATE_FIND_TIME_VALID: time_valid,
            pycades.CAPICOM_CERTIFICATE_FIND_TIME_NOT_YET_VALID: time_not_yet_valid,
            pycades.CAPICOM_CERTIFICATE_FIND_TIME_EXPIRED: time_expired,
            pycades.CAPICOM_CERTIFICATE_FIND_KEY_USAGE: key_usage,
        }

        for key, value in conditions.items():
            if value and isinstance(value, bool):
                certs = certs.Find(key)
            elif value and isinstance(value, str):
                certs = certs.Find(key, value)

        return [Certificate(certs.Item(index + 1)) for index in range(certs.Count)]

    def all(self) -> List[Certificate]:
        """
        Возвращает все сертификаты из хранилища.
        :return:
        """
        certs = self._store.Certificates
        return [Certificate(certs.Item(index + 1)) for index in range(certs.Count)]

    def __len__(self):
        return self._store.Certificates.Count

    def __bool__(self):
        return self._store.Certificates.Count > 0


class CryptoPro:
    """Основной класс для работы с КриптоПро"""

    def __init__(self):
        self._store: pycades.Store = pycades.Store()
        self._store.Open(
            pycades.CADESCOM_CONTAINER_STORE, pycades.CAPICOM_MY_STORE, pycades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED
        )

    @staticmethod
    def module_version() -> str:
        """Возвращает версию pycades"""
        return pycades.ModuleVersion()

    @property
    def certs(self) -> Certificates:
        """
        Возвращает список сертификатов из хранилища.
        :return: Certificates
        """
        return Certificates(self._store)

    @staticmethod
    def pycades_hashed_data(
        content: Union[bytes, str],
        hash_algorithm: int = CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256,
    ) -> pycades.HashedData:
        """
        Создает объект HashedData для хэширования текстовых или байтовых данных
        :param content: Данные для хэширования.
        :param hash_algorithm: алгоритм хэширования.
        :return:
        """
        hashed_data = pycades.HashedData()
        hashed_data.Algorithm = hash_algorithm
        hashed_data.DataEncoding = pycades.CADESCOM_BASE64_TO_BINARY
        if isinstance(content, str):
            hashed_data.Hash(base64.b64encode(content.encode(encoding='utf-8')).decode())
        elif isinstance(content, bytes):
            hashed_data.Hash(base64.b64encode(content).decode())
        else:
            raise TypeError(f'{type(content)} недопустимый тип данных для хэширования')

        return hashed_data

    @classmethod
    def gost_hash(
        cls,
        content: Union[bytes, str],
        hash_algorithm: int = CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256,
    ) -> str:
        """
        Хэширование текстовых или байтовых данных.
        :param content: Данные для хэширования.
        :param hash_algorithm: алгоритм хэширования.
        :return: 'p43Cs22sY6vnuPAXicOnVibxt425GD7freseC/vO9dQ='
        """
        hashed_data = cls.pycades_hashed_data(content, hash_algorithm)

        hex_hash = hashed_data.Value
        byte_hash = bytes.fromhex(hex_hash)
        return base64.b64encode(byte_hash).decode()

    @classmethod
    def verify(
        cls,
        content: Union[bytes, str],
        signature: str,
        *,
        cades_type: int = CADESCOM_CADES_BES,
        hash_algorithm: int = CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256,
    ) -> bool:
        """
        Проверяет отделенную подпись.
        Документация: https://docs.cryptopro.ru/cades/pycades/pycades-samples/pycades-signhash-verifyhash
        :param content:
        :param signature:
        :param cades_type:
        :param hash_algorithm:
        :return:
        """
        signed_data = pycades.SignedData()
        hashed_data = cls.pycades_hashed_data(content, hash_algorithm)
        try:
            signed_data.VerifyHash(hashed_data, signature, cades_type)
            return True
        except Exception:  # noqa
            return False

    @staticmethod
    def verify_cades(signature: str, content: Union[bytes, str]) -> bool:
        """
        Проверяет усовершенствованную подпись.
        :param signature: проверяемая подпись. Значение в формате base64
        :param content: сообщение которое подписывалось
        :return:
        """
        signed_data = pycades.SignedData()
        if content:
            # https://www.cryptopro.ru/forum2/default.aspx?g=posts&t=16656
            signed_data.ContentEncoding = pycades.CADESCOM_ENCODE_BINARY
            if isinstance(content, bytes):
                signed_data.Content = base64.b64encode(content).decode()
            elif isinstance(content, str):
                signed_data.Content = base64.b64encode(content.encode(encoding='utf-8')).decode()
            else:
                raise TypeError(f'{type(content)} недопустимый тип данных для проверки подписи')

        try:
            signed_data.VerifyCades(signature, CADESCOM_CADES_BES)
            return True
        except Exception:  # noqa
            return False
