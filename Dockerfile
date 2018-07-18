FROM python:3.6

ENV PYTHONPATH /src

RUN mkdir /src
WORKDIR /src

RUN pip install pytest

COPY . /src/
