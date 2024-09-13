FROM alpine:3.20 AS builder
RUN apk update && apk add --no-cache \
    build-base \
    curl \
    git \
    linux-headers && \
    git clone -b \
    $(basename $(curl -Ls -o /dev/null -w %{url_effective} \
    https://github.com/hufrea/byedpi/releases/latest)) \ 
    https://github.com/hufrea/byedpi.git \
    /opt/byedpi
WORKDIR /opt/byedpi
RUN make
FROM alpine:3.20
COPY --from=builder /opt/byedpi/ciadpi /opt/byedpi/ciadpi
EXPOSE 1080
ENTRYPOINT ["/opt/byedpi/ciadpi"]