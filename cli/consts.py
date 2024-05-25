# Provider type
# https://cryptopro.ru/forum2/default.aspx?g=posts&t=11041
# $ cpconfig -defprov -view_type
# Listing Available Provider Types:
# Provider type   Provider Type Name
# _____________   _____________________________________
#       75        GOST R 34.10-2001 Signature with Diffie-Hellman Key Exchange
#       80        GOST R 34.10-2012 (256) Signature with Diffie-Hellman Key Exchange
#       81        GOST R 34.10-2012 (512) Signature with Diffie-Hellman Key Exchange
PROVIDER_TYPES = {75, 80, 81}

PROVIDER_NAMES = {
    75: 'GOST R 34.10-2001 Signature with Diffie-Hellman Key Exchange',
    80: 'GOST R 34.10-2012 (256) Signature with Diffie-Hellman Key Exchange',
    81: 'GOST R 34.10-2012 (512) Signature with Diffie-Hellman Key Exchange',
}

PROVIDER_NAMES_CRYPTOGRAPHIC = {
    75: 'Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider',
    80: 'Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider',
    81: 'Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider',
}

PROVIDER_NAMES_KC1 = {
    75: 'Crypto-Pro GOST R 34.10-2001 KC1 CSP',
    80: 'Crypto-Pro GOST R 34.10-2012 KC1 CSP',
    81: 'Crypto-Pro GOST R 34.10-2012 KC1 Strong CSP',
}
