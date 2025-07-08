# go-varsig

`go-varsig` implements the upcoming v1.0.0 release of the [`varsig` specification](https://github.com/ChainAgnostic/varsig/pull/18)
with limited (and soon to be deprecated) support for the `varsig` < v1.0
specification.  This is predominantly included to support the UCAN v1.0
use-case.

## Usage

Include the `go-varsig` library by running the following command:

```bash
go get github.com/ucan-wg/go-varsig@latest
```

## Documentation

Documentation for this library is provided as Go docs at
https://pkg.go.dev/github.com/ucan-wg/go-varsig.

## Development

Install the required development tools using `asdf` by running the
following command in this repository (or install them manually):

```bash
asdf install
```

### Checks

This repository contains a set of pre-commit hooks that are run prior to
each `git commit`.  You can also run these checks manually using the
following command:

```bash
pre-commit run --all-files
```

### Github workflows development

ASDF installs `act` to support Github workflow development - in general,
follow these steps to test the workflow:

If you're using `podman` instead of `docker`, use the `podman` socket to
simulate the `docker` daemon:

```bash
export DOCKER_HOST=unix:///var/run/podman/podman.sock
```

Since there's only one workflow, the simplest command to test it is:

```bash
act
```
