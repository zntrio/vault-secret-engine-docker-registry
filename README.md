# Docker Registry - Vault Secret Engine

**NOT PRODUCTION READY**

## Setup

Compile and test env bootstrap

```sh
make
```

## Usage

Enable secret engine

```sh
vault secrets enable docker-registry
```

Setup engine authentication

```sh
vault write docker-registry/config endpoint_url=<https://auth.docker.io> username=.... password=....
```

Create a role

```sh
vault write docker-registry/roles/admin name=admin service=registry.docker.io scope=repository:samalba/my-app:pull,push
```

Request for token

```sh
$ vault read docker-registry/creds/admin
Key             Value
---             -----
access_token    eyJhbG... omitted ...
registry_url    https://auth.docker.io
scope           repository:samalba/my-app:pull,push
service         registry.docker.io
token           eyJhbG... omitted ...
```

Update Docker config

```sh
export REGISTRY_TOKEN=$(vault read -field token docker-registry/creds/admin)
echo '{"auths":{"registry-1.docker.io":{"registrytoken": "$REGISTRY_TOKEN"}}}' | jq -s ".[0] * .[1]" ~/.docker/config.json - > ~/.docker/config.json
```
