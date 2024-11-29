// Package varsig implements v0.1.0 of the [Varsig specification].
//
// # Algorithm naming
//
// While there is no strict need for compatibility with JWA/JWT/JWE/JWS,
// all attempts are made to keep the algorithm names here consisten with
// the table provided in [section 3.1] of RFC7518 titled "JSON Web Algorithms.
// In cases where there is no equivalent name for an algorithm, a best-
// effort attempt at creating a name in the spirit of that specification is
// made.
//
// It should also be noted that algorithm in this context might in fact be
// a pseudonym - for cryptographical signing algorithms that require the
// signed data to be hashed first, these names commonly refer to the
// combination of that signing algorithm and the hash algorithm.
//
// [section 3.1]: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
//
// [Varsig Specification]: https://github.com/ChainAgnostic/varsig
package varsig
