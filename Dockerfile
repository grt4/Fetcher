FROM python:slim-buster
WORKDIR /fetcher
COPY requirements.txt ./
RUN apt-get update && apt-get install -y\
    python3-magic\
    expect\
    libxml2\
    libxslt1-dev\
    gcc
RUN python3 -m pip install --upgrade pip
RUN pip3 install oletools\
    quark-engine\
    yara-python\
    prettytable\
    puremagic\
    pyaxmlparser\
    pycryptodomex\
    python-magic\
    requests\
    virustotal_api
RUN pip3 install -U oletools
COPY . .
