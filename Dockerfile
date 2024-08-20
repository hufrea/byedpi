FROM alpine:latest AS builder

RUN apk update && apk add --no-cache \
    git \
    build-base \
    openssl-dev \
    libpcap-dev \
    linux-headers \
    musl-dev \
    curl

RUN git clone -b $(basename $(curl -Ls -o /dev/null -w %{url_effective} https://github.com/hufrea/byedpi/releases/latest)) https://github.com/hufrea/byedpi.git /opt/byedpi

WORKDIR /opt/byedpi

RUN make

FROM alpine:latest

COPY --from=builder /opt/byedpi/ciadpi /opt/byedpi/ciadpi

EXPOSE 1080

ENTRYPOINT ["/opt/byedpi/ciadpi"]