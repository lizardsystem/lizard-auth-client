FROM ubuntu:xenial

MAINTAINER OPS <ops@nelen-schuurmans.nl>

# Change the date to force rebuilding the whole image
ENV REFRESHED_AT 2016-09-13

# system dependencies
RUN apt-get update && apt-get install -y \
#   python-software-properties \
#   wget \
#   build-essential \
#   git \
#   libevent-dev \
#   libfreetype6-dev \
#   libpng12-dev \
    python3-dev \
    python3-pip \
    gettext \
&& rm -rf /var/lib/apt/lists/*

WORKDIR /code
