package varsig_test

import (
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/selesy/go-varsig"
)

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

	t.Run("fails - unknown signature algorithm - v0", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString("3464")
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrUnknownSignAlgorithm)
		assert.Nil(t, vs)
	})

	t.Run("fails - unknown signature algorithm - v1", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString("340164")
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrUnknownSignAlgorithm)
		assert.Nil(t, vs)
	})

	// The tests below this point require the RSAVarsig implementation
	// in order to test the private varsig.decodePayEncAndSig method.

	const (
		rsaHex    = "8524"
		sha256Hex = "12"
		keyLen    = "8002"
		rsaBaseV0 = "34" + rsaHex + sha256Hex + keyLen
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

	t.Run("fails - unexpected signature length - v0", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString(rsaBaseV0 + "5f" + "42") // 0x42 is only a single byte - 256 bytes are expected
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrUnexpectedSignatureSize)
		assert.Nil(t, vs)
	})

	t.Run("fails - unexpected signature present - v1", func(t *testing.T) {
		t.Parallel()

		data, err := hex.DecodeString(rsaBaseV1 + "5f" + "42") // 0x42 is only a single byte - 256 bytes are expected
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrUnexpectedSignaturePresent)
		assert.Nil(t, vs)
	})

	t.Run("passes with error - v0", func(t *testing.T) {
		t.Parallel()
		data, err := hex.DecodeString(rsaBaseV0 + "5f")
		require.NoError(t, err)

		vs, err := varsig.Decode(data)
		require.ErrorIs(t, err, varsig.ErrMissingSignature)
		assert.NotNil(t, vs) // varsig is still returned with just "header"
	})
}

// func TestReadUvarint(t *testing.T) {
// 	t.Parallel()

// 	var r io.ByteReader = &bytes.Reader{}

// 	u, err := binary.ReadUvarint(r)
// 	require.ErrorIs(t, err, io.EOF)
// 	assert.Equal(t, uint64(0), u)

// 	var buf []byte
// 	buf = binary.AppendUvarint(buf, 0x100)
// 	t.Log("0x100 varint:", hex.EncodeToString(buf))
// 	t.Fail()
// }
