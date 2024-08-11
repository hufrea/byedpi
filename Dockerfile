FROM alpine:latest AS builder

RUN apk update && apk add --no-cache \
    git \
    build-base \
    openssl-dev \
    libpcap-dev \
    linux-headers \
    musl-dev

RUN git clone https://github.com/hufrea/byedpi /opt/byedpi

WORKDIR /opt/byedpi

RUN make

FROM alpine:latest

COPY --from=builder /opt /opt

EXPOSE 1080

ENTRYPOINT ["/opt/byedpi/ciadpi"]