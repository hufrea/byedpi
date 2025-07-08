# Docker

## Docker Hub

An official container image available at https://hub.docker.com/r/hufrea/byedpi.

Images are tagged by full version number (`major.minor.patch`) and `major.minor`. As usual the latest stable release has `latest` tag.

## Building

To build a container image from the source execute:

```sh
docker build . --tag my/byedpi
```

A tag allows to reference built image by human-readable name instead of hash and is optional.

Provided `Dockerfile` is compatible with podman if you want an alternative to docker.

## Running

To run a byedpi container use the command:

```sh
docker run -it --rm hufrea/byedpi --help
```

Don't forget to expose a port to communicate with the container. For example to have local only access to byedpi SOCKS proxy on port 1234 add `-p 127.0.0.1:1234:1080` before the image name:

```sh
docker run -it --rm -p 127.0.0.1:1234:1080 hufrea/byedpi --fake -1 --md5sig
```

## Compose

Docker compose is useful to simplify management of docker containers.

To use provided `compose.yaml` edit
1) arguments passed to byedpi in `command` array
2) `published` port if 1080 is already allocated
and run the command inside a directory containing `compose.yaml`

```sh
docker compose up -d
```

If docker daemon configured to start on system boot, it will keep byedpi container always up.
