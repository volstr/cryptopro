FROM ubuntu:20.04

ARG UID=1000
ARG GID=1000
ENV UID=${UID}
ENV GID=${GID}

ENV TZ Europe/Moskow
ENV DEBIAN_FRONTEND noninteractive

RUN apt update && \
    apt install -y cmake build-essential libboost-all-dev unzip && \
    apt install -y python3.9-dev libpython3.9-dev

WORKDIR /usr/src/

COPY . .

# 2. Скачать архив с КриптоПро CSP, распаковать этот архив и установить КриптоПро CSP
# КриптоПро CSP 5.0 для Linux (x64, deb) R2 или R3: https://cryptopro.ru/products/csp/downloads#latest_csp50r2
RUN tar xvf linux-amd64_deb.tgz && \
    ./linux-amd64_deb/install.sh && \
    apt install ./linux-amd64_deb/lsb-cprocsp-devel_5.0*.deb

# 4. Скачать архив с КриптоПро ЭЦП SDK, распаковать этот архив и установить пакет cprocsp-pki-cades (версия не ниже 2.0.14071)
RUN tar xvf cades-linux-amd64.tar.gz && \
    apt install ./cades-linux-amd64/cprocsp-pki-cades*.deb

# 5. Скачать и распаковать архив с исходниками pycades:
RUN unzip pycades.zip && \
    cd pycades_* && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make -j4

RUN mkdir package && \
    groupadd --gid 2000 cript && \
    useradd --uid 2000 --gid cript --shell /bin/bash --create-home cript && \
    usermod -u $UID cript && \
    groupmod -g $GID cript

CMD [ "bash" ]
