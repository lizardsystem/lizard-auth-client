FROM ubuntu:bionic

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

ENV REFRESHED_AT 2019-01-04
ARG DEBIAN_FRONTEND=noninteractive
LABEL maintainer="ops@nelen-schuurmans.nl"

RUN apt-get update && apt-get install -y \
    gettext \
    python3-dev \
    python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && pip3 install zc.buildout

WORKDIR /code
