# go-varsig

`go-varsig` is a go implementation of the [`varsig` specification](https://github.com/ChainAgnostic/varsig).

Built with ❤️ by [Consensys](https://consensys.io/).

## Usage

Include the `go-varsig` library by running the following command:

```bash
go get github.com/ucan-wg/go-varsig@latest
```

## Quickstart

```go
func ExampleDecode() {
	example, err := base64.RawStdEncoding.DecodeString("NAHtAe0BE3E")
	handleErr(err)

	vs, err := varsig.Decode(example)
	handleErr(err)

	fmt.Printf("%T\n", vs)
	fmt.Printf("Discriminator: %d\n", vs.Discriminator())
	fmt.Printf("Hash: %d\n", vs.Hash())
	fmt.Printf("PayloadEncoding: %d\n", vs.PayloadEncoding())

	// Output:
	// varsig.EdDSAVarsig
	// Discriminator: 237
	// Hash: 19
	// PayloadEncoding: 3
}

func ExampleEncode() {
	edDSAVarsig := varsig.NewEdDSAVarsig(
		varsig.CurveEd25519,
		varsig.HashSha2_512,
		varsig.PayloadEncodingDAGCBOR,
	)

	b64 := base64.RawStdEncoding.EncodeToString(edDSAVarsig.Encode())
	fmt.Print(b64)

	// Output:
	// NAHtAe0BE3E
}
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

The simplest command to test it is:

```bash
act
```

## License

This project is dual-licensed under Apache 2.0 and MIT terms:

- Apache License, Version 2.0, ([LICENSE-APACHE](https://github.com/ucan-wg/go-varsig/blob/master/LICENSE-APACHE-2.0) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](https://github.com/ucan-wg/go-varsig/blob/master/LICENSE-MIT) or http://opensource.org/licenses/MIT)
