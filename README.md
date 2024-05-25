# Обертка для pycades КриптоПро на python

Автор этой библиотеки не имеет никакого отношения к КриптоПро и написал ее для собственных ознакомительных целей и получения удобных методов api через официальную библиотеку `pycades`.

Библиотека названа как `cryptopro` исключительно только лишь для ассоциации в коде с одноименным ПО компании `КриптоПро`.

Библиотека распространяется "как есть" и автор не несет никакой ответственности за ее использование, в том числе финансовых и репутационных. Проверяйте все перед ее использованием.

## Сборка библиотеки

Для того что бы работать с api `КриптоПро` Нужно самостоятельно скомпилировать `pycades.so`

Подробный процесс сборки расширения `pycades` для языка `python` описан в [официальной документации](https://docs.cryptopro.ru/cades/pycades/pycades-build).

В нашем случае сборка будет происходить в `docker`

Для компиляции необходимо скачать и положить в директорию `build` следующие файлы:

 - [архив с КриптоПро CSP](https://cryptopro.ru/products/csp/downloads) - inux-amd64_deb.tgz
 - [КриптоПро ЭЦП SDK](https://cryptopro.ru/products/cades/downloads) - cades-linux-amd64.tar.gz
 - [pycades.zip](https://cryptopro.ru/sites/default/files/products/cades/pycades/pycades.zip)

После добавления файлов, структура каталога `build` должна выглядеть следующим образом:

```
├── cades-linux-amd64.tar.gz  
├── Dockerfile  
├── linux-amd64_deb.tgz  
└── pycades.zip
```

Сборка образа:
```bash
cd build
docker build -t pycades .
```

Библиотека `pycades.so` была скомпилирована на этапе сборки образа, но она осталась внутри нашего `docker` образа. Давайте теперь достанем ее из контейнера.

```bash
docker run --rm --name criptopro -v .:/usr/src/package pycades bash -c "cd pycades_* && cp pycades.so /usr/src/package/"
```

В результате мы должны увидеть файл `pycades.so`:

```
├── cades-linux-amd64.tar.gz  
├── Dockerfile  
├── linux-amd64_deb.tgz
├── pycades.so                  <<<<<<<  
└── pycades.zip
```

Его нужно будет переместить на уровень выше или в корено проекта:
```bash
mv pycades.so ../
```

Теперь можно перейти в корень библиотеки и посмотреть, что получилось:

```bash
cd ..
```

```
├── build  
|   ├── cades-linux-amd64.tar.gz  
|   ├── Dockerfile  
|   ├── linux-amd64_deb.tgz
|   └── pycades.zip
├── cli
├── __init__.py
├── algorithm.py
├── cryptopro.py
├── pycades.so          <<<<<<<
└── README.md
```

После этого, архивы, которые мы скачивали для сборки, нам больше не нужны, их можно удалить.


## Примеры

### Получить версию `pycades`

```python
from cryptopro import CryptoPro
CryptoPro.module_version()
```

```python
'0.1.44290'
```

### Получить список сертификатов из хранилища:

```python
from cryptopro import CryptoPro

for cert in CryptoPro().certs.all():
    print('issuer_name:', cert.issuer_name)
    print('issuer_rdn:', cert.issuer_rdn)
    print('serial_number:', cert.serial_number)
    print('subject_name:', cert.subject_name)
    print('subject_rdn:', cert.subject_rdn)
    print('thumbprint:', cert.thumbprint)
    print('valid_from_date:', cert.valid_from_date)
    print('valid_to_date:', cert.valid_to_date)
    print('issuer_name', cert.has_private_key)
    print('is_valid:', cert.is_valid)
    print('version:', cert.version)
    print('info:', cert.info)
    print('private_key:', cert.private_key)
    print('public_key:', cert.public_key)
    print('_' * 80)
```

```python
issuer_name: CN=CRYPTO-PRO Test Center 2, O=CRYPTO-PRO LLC, L=Moscow, C=RU, E=support@cryptopro.ru
issuer_rdn: {'CN': 'CRYPTO-PRO Test Center 2', 'O': 'CRYPTO-PRO LLC', 'L': 'Moscow', 'C': 'RU', 'E': 'support@cryptopro.ru'}
serial_number: 120063FDA5AC20AAEC04568A3700020063FFA7
subject_name: E=ivanov@bank.ru, CN=Иванов Пётр
subject_rdn: {'E': 'ivanov@bank.ru', 'CN': 'Иванов Пётр'}
thumbprint: b7e59b51d01b36e2a99e0d6c1cba8c2076155e7a
valid_from_date: 2023-05-21 08:26:30
valid_to_date: 2023-07-21 08:36:30
issuer_name True
is_valid: True
version: 3
info: Иванов Пётр
private_key: 05d1890e-4a61-4d01-abd1-91deaab09c7f
public_key: ГОСТ Р 34.10-2012 256 бит
________________________________________________________________________________
```

### Информация о сертификате:

```python
from cryptopro import CryptoPro

crypto_pro = CryptoPro()
cert = crypto_pro.certs.find(thumbprint='b7e59b51d01b36e2a99e0d6c1cba8c2076155e7a')[0]

print('subject_simple_name:', cert.info.subject_simple_name)
print('issuer_simple_name:', cert.info.issuer_simple_name)
print('subject_email_name:', cert.info.subject_email_name)
print('subject_dns_name:', cert.info.subject_dns_name)
print('issuer_dns_name:', cert.info.issuer_dns_name)
```

```
subject_simple_name: Иванов Пётр
issuer_simple_name: CRYPTO-PRO Test Center 2
subject_email_name: ivanov@bank.ru
subject_dns_name: Иванов Пётр
issuer_dns_name: CRYPTO-PRO Test Center 2
```


### Информация о закрытом ключе:

```python
from cryptopro import CryptoPro

crypto_pro = CryptoPro()
cert = crypto_pro.certs.find(thumbprint='b7e59b51d01b36e2a99e0d6c1cba8c2076155e7a')[0]

print('container_name:', cert.private_key.container_name)
print('unique_container_name:', cert.private_key.unique_container_name)
print('provider_name:', cert.private_key.provider_name)
print('provider_type:', cert.private_key.provider_type)
print('key_spec:', cert.private_key.key_spec)
```

```
container_name: 98fe80e3-4e19-4b78-9c37-7006aebe41a3
unique_container_name: HDIMAGE\\98fe80e3.000\D107
provider_name: Crypto-Pro GOST R 34.10-2012 KC1 CSP
provider_type: 80
key_spec: 1
```


### Информация об открытом ключе:

```python
from cryptopro import CryptoPro

crypto_pro = CryptoPro()
cert = crypto_pro.certs.find(thumbprint='b7e59b51d01b36e2a99e0d6c1cba8c2076155e7a')[0]

print('encoded_key:', cert.public_key.encoded_key)
print('length:', cert.public_key.length)
print('algorithm_oid:', cert.public_key.algorithm_oid)
print('algorithm_friendly_name:', cert.public_key.algorithm_friendly_name)
print('encoded_parameters:', cert.public_key.encoded_parameters)
```

```
encoded_key: BEBQsYspFjuWLfaXSlwhZGEz+4+fbE5EB1dbR/ptMxz7k62UbyL5WtlASYf0W+D7
sgWa3NFyt/YlHBfX+BXB0Ie2

length: 512
algorithm_oid: 1.2.643.7.1.1.1.1
algorithm_friendly_name: ГОСТ Р 34.10-2012 256 бит
encoded_parameters: MBMGByqFAwICJAAGCCqFAwcBAQIC

```


### Создание отделенной подписи

```python
from cryptopro import CryptoPro

crypto_pro = CryptoPro()
cert = crypto_pro.certs.find(thumbprint='b7e59b51d01b36e2a99e0d6c1cba8c2076155e7a')[0]
sign_data = cert.sign('my data', formatted=True)
print(sign_data)
```

```
MIIFzgYJKoZIhvcNAQcCoIIFvzCCBbsCAQExDjAMBggqhQMHAQECAgUAMAsGCSqGSIb3DQEHAaCC
AywwggMoMIIC1aADAgECAhMSAGQB1ahqNxQQksFCAAIAZAHVMAoGCCqFAwcBAQMCMH8xIzAhBgkq
hkiG9w0BCQEWFHN1cHBvcnRAY3J5cHRvcHJvLnJ1MQswCQYDVQQGEwJSVTEPMA0GA1UEBxMGTW9z
...
IDICExIAZAHVqGo3FBCSwUIAAgBkAdUwHwYIKoUDBwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEBAgIE
QGNcKcc2fraiQoDiXOk3M4oEShb/XD6fjCWAaVHnUbqIRwzYCOGAvdQgOc32MwuP8FsP/XFTmvlV
sIuoVTLIZZ4=
```


### Добавить к сообщению усовершенствованную подпись

```python
from cryptopro import CryptoPro

crypto_pro = CryptoPro()
cert = crypto_pro.certs.find(thumbprint='b7e59b51d01b36e2a99e0d6c1cba8c2076155e7a')[0]
sign_data = cert.sign_cades('my data', formatted=True)
print(sign_data)
```

```
MIIFxwYJKoZIhvcNAQcCoIIFuDCCBbQCAQExDDAKBggqhQMHAQECAjAdBgkqhkiG9w0BBwGgEAQO
bQB5ACAAZABhAHQAYQCgggMsMIIDKDCCAtWgAwIBAgITEgBkAdWoajcUEJLBQgACAGQB1TAKBggq
hQMHAQEDAjB/MSMwIQYJKoZIhvcNAQkBFhRzdXBwb3J0QGNyeXB0b3Byby5ydTELMAkGA1UEBhMC
...
Uk8gVGVzdCBDZW50ZXIgMgITEgBkAdWoajcUEJLBQgACAGQB1TAKBggqhQMHAQEBAQRABmQmxcNS
mHNMY3mvgqjYbSE6PhLMw6rs2mlRKxWg3wkPvTYEeItjs3S/97g8wGTGNu76u6EwPlOhbDc+fGxZ
lA==
```


### Получить значение подписи. raw подпись.

```python
from cryptopro import CryptoPro

crypto_pro = CryptoPro()
cert = crypto_pro.certs.find(thumbprint='b7e59b51d01b36e2a99e0d6c1cba8c2076155e7a')[0]
sign_data = cert.raw_sign('my data')
print(sign_data)
```

```
345DyJDD6aKgIK4YsaBWqwa7yERPpn0NjJ6T6ugsHtBrFru2s6KqNYE93BKxkkPREs/xB/j82FqyAmv7rizKKg==
```


### Получить значение сертификата

```python
from cryptopro import CryptoPro

crypto_pro = CryptoPro()
cert = crypto_pro.certs.find(thumbprint='b7e59b51d01b36e2a99e0d6c1cba8c2076155e7a')[0]
cert_value = cert.export(formatted=True)
print(cert_value)
```

```
MIIDKDCCAtWgAwIBAgITEgBkAdWoajcUEJLBQgACAGQB1TAKBggqhQMHAQEDAjB/
MSMwIQYJKoZIhvcNAQkBFhRzdXBwb3J0QGNyeXB0b3Byby5ydTELMAkGA1UEBhMC
...
b2NzcC9vY3NwLnNyZjAKBggqhQMHAQEDAgNBAKA1BRcniiFL1bZZPuxSlWul/z/T
OYWGu4iVVkGlofLzA5Nb7v0T/g+/tI5dL/i+UJ2jHPS6OZbIyVc3DKS+tH4=
```


### Хэширование текстовых или байтовых данных

```python
from cryptopro import CryptoPro

hash_data = CryptoPro.gost_hash('my data')
print(hash_data)
```

```
AFXz7/w1R/7+EMMs9F7Kz68wmBWmnfZs0Qp2n2ojs8Q=
```

### Проверить отделенную подпись

```python
verify
```

### Проверить усовершенствованную подпись

```python
verify_cades
```


## Интерфейс командной строки

### certmgr

```python
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
```

```python
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
```

```python
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
```

### cryptcp

```python
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
```


### csptest

```python
def keyset() -> Dict[str, str]:
    """
    Перечисление контейнеров с уникальными именами.
    :return:
    """
```