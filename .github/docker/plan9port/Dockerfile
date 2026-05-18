FROM ubuntu:24.04

ENV PLAN9=/opt/plan9port
ENV PATH=$PLAN9/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates \
        gcc libx11-dev libxt-dev libxext-dev libfontconfig1-dev \
        libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/9fans/plan9port $PLAN9 \
    && cd $PLAN9 \
    && ./INSTALL \
    && rm -rf $PLAN9/.git
