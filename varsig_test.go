package varsig_test

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-varsig"
)

func ExampleDecode() {
	example, err := base64.RawStdEncoding.DecodeString("NAHtAe0BE3E")
	handleErr(err)

	vs, err := varsig.Decode(example)
	handleErr(err)

	fmt.Printf("%T\n", vs)
	fmt.Printf("Algorithm: %d\n", vs.Algorithm())
	fmt.Printf("Hash: %d\n", vs.Hash())
	fmt.Printf("PayloadEncoding: %d\n", vs.PayloadEncoding())

	// Output:
	// varsig.EdDSAVarsig
	// Algorithm: 237
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

func TestDecode(t *testing.T) {
	t.Parallel()

	t.Run("passes - section 3 example", func(t *testing.T) {
		t.Skip()
		t.Parallel()
		data, err := hex.DecodeString("34ed01ae3784f03f9ee1163382fa6efa73b0c31ecf58c899c836709303ba4621d1e6df20e09aaa568914290b7ea124f5b38e70b9b69c7de0d216880eac885edd41c302")
		require.NoError(t, err)

		// TODO

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrNotYetImplemented)
		assert.Equal(t, nil, vs)
	})

	t.Run("fails - no data (empty prefix)", func(t *testing.T) {
		t.Parallel()

		vs, err := varsig.Decode([]byte{})
		require.ErrorIs(t, err, io.EOF)
		require.ErrorIs(t, err, varsig.ErrBadPrefix)
		assert.Nil(t, vs)
	})

	t.Run("fails - wrong prefix", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString("42")
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrBadPrefix)
		assert.Nil(t, vs)
	})

	t.Run("fails - unsupported version", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString("3402")
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrUnsupportedVersion)
		assert.Nil(t, vs)
	})

	t.Run("fails - unknown signature algorithm - v1", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString("340164")
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrUnknownAlgorithm)
		assert.Nil(t, vs)
	})

	// The tests below this point require the RSAVarsig implementation
	// in order to test the private varsig.decodePayEncAndSig method.

	const (
		rsaHex    = "8524"
		sha256Hex = "12"
		keyLen    = "8002"
		rsaBaseV1 = "3401" + rsaHex + sha256Hex + keyLen
	)

	t.Run("passes - v1", func(t *testing.T) {
		t.Parallel()
		data, err := hex.DecodeString(rsaBaseV1 + "5f")
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.NoError(t, err)
		assert.NotNil(t, vs)
	})

	t.Run("fails - truncated varsig (no payload encoding)", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString(rsaBaseV1)
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrUnsupportedPayloadEncoding)
		require.ErrorIs(t, err, io.EOF)
		assert.Nil(t, vs)
	})

	t.Run("fails - unsupported payload encoding", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString(rsaBaseV1 + "42") // 0x42 is not a valid payload encoding
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrUnsupportedPayloadEncoding)
		assert.Nil(t, vs)
	})
}

func handleErr(err error) {
	if err != nil {
		panic(err)
	}
}
