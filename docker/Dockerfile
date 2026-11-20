FROM ubuntu:latest

RUN apt-get update && apt-get install -y make

COPY . /app

WORKDIR /app

RUN make

ENTRYPOINT ["./ciadpi"]
