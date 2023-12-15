# Environment

Use [gvm](https://github.com/moovweb/gvm) to match the project's golang version,
or use a version of golang from your system that matches the one indicated in `go.mod`.

# Building

Verify the operator builds:
```bash
make build
```

Verify the helm chart builds:
```bash
make helm
```

Verify the docker image builds:
```bash
docker build .
```

Build the docker image, and upload it to a local repository
for build purposes:
```bash
make develop
```
> This command alone is enough during development iterations.

## Building behind corporate proxy

Docker/Podman support passing the proxy environment variable to the image
being built.
```bash
https_proxy=http://proxy.example.com:8080
http_proxy=http://proxy.example.com:8080
```

## Building behind TLS termination proxy

To use a custom certificate authority during the docker build,
simply drop your custom CA in pem format in the `.ca-bundle/`
directory.

```
Make sure the in-project CA directory exists
mkdir -p .ca-bundle/

# On Ubuntu
cp /usr/local/share/ca-certificates/* .ca-bundle/

# On RHEL
cp /etc/pki/ca-trust/source/anchors/* .ca-bundle/
```

It will be added to the docker intermediate build image to fetch
dependencies, but not to the final image.


