# Environment

Use [gvm](https://github.com/moovweb/gvm) to match the project's golang version,
or use a version of golang from your system that matches the one indicated in `go.mod`.

# Building

Verify the operator builds:
```bash
./task build
```

```bash
./task docker:build
```

If you want to maintain development version of the artifacts locally,
you can set the following:
```bash
LOCAL_REPO=nexus.example.com:8443/mydockerepo/example
LOCAL_HELM_CM=example-cm
```

Releasing the dev docker image to your local repo:
```bash
./task docker:develop
```

Releasing the dev helm chart to your local repo:
```bash
./task chart:develop
```

## Building behind corporate proxy

Docker/Podman support passing the proxy environment variable to the image
being built.
```bash
https_proxy=http://proxy.example.com:8080
http_proxy=http://proxy.example.com:8080
no_proxy=example.com
```

## Building behind TLS termination proxy

To use a custom certificate authority during the docker build,
simply drop your custom CA in pem format in the `.ca-bundle/`
directory.

```bash
# On Ubuntu
cp /usr/local/share/ca-certificates/* .ca-bundle/
```
```bash
# On RHEL
cp /etc/pki/ca-trust/source/anchors/* .ca-bundle/
```

It will be added to the docker intermediate build image to fetch
dependencies, but not to the final image.
