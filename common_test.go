package varsig_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-varsig"
)

func TestRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name      string
		varsig    varsig.Varsig
		dataHex   string
		dataBytes []byte
	}{
		// Arbitrary use of presets
		{
			name:    "Ed25519",
			varsig:  varsig.Ed25519(varsig.PayloadEncodingDAGCBOR),
			dataHex: "3401ed01ed011371",
		},
		{
			name:    "Ed448",
			varsig:  varsig.Ed448(varsig.PayloadEncodingDAGCBOR),
			dataHex: "3401ed0183241971",
		},
		{
			name:    "RS256",
			varsig:  varsig.RS256(0x100, varsig.PayloadEncodingDAGCBOR),
			dataHex: "3401852412800271",
		},
		{
			name:    "RS384",
			varsig:  varsig.RS384(0x100, varsig.PayloadEncodingDAGCBOR),
			dataHex: "3401852420800271",
		},
		{
			name:    "RS512",
			varsig:  varsig.RS512(0x100, varsig.PayloadEncodingDAGCBOR),
			dataHex: "3401852413800271",
		},
		{
			name:    "ES256",
			varsig:  varsig.ES256(varsig.PayloadEncodingDAGCBOR),
			dataHex: "3401ec0180241271",
		},
		{
			name:    "ES256K",
			varsig:  varsig.ES256K(varsig.PayloadEncodingDAGCBOR),
			dataHex: "3401ec01e7011271",
		},
		{
			name:    "ES384",
			varsig:  varsig.ES384(varsig.PayloadEncodingDAGCBOR),
			dataHex: "3401ec0181242071",
		},
		{
			name:    "ES512",
			varsig:  varsig.ES512(varsig.PayloadEncodingDAGCBOR),
			dataHex: "3401ec0182241371",
		},
		{
			name:    "EIP191",
			varsig:  must(varsig.EIP191(varsig.PayloadEncodingEIP191Raw)),
			dataHex: "3401ec01e7011b91c3035f",
		},

		// from https://github.com/hugomrdias/iso-repo/blob/main/packages/iso-ucan/test/varsig.test.js
		{
			name:      "RS256+RAW",
			varsig:    varsig.RS256(256, varsig.PayloadEncodingVerbatim),
			dataBytes: []byte{52, 1, 133, 36, 18, 128, 2, 95},
		},
		{
			name:      "ES256+RAW",
			varsig:    varsig.ES256(varsig.PayloadEncodingVerbatim),
			dataBytes: []byte{52, 1, 236, 1, 128, 36, 18, 95},
		},
		{
			name:      "ES512+RAW",
			varsig:    varsig.ES512(varsig.PayloadEncodingVerbatim),
			dataBytes: []byte{52, 1, 236, 1, 130, 36, 19, 95},
		},
		{
			name:      "ES256K+RAW",
			varsig:    varsig.ES256K(varsig.PayloadEncodingVerbatim),
			dataBytes: []byte{52, 1, 236, 1, 231, 1, 18, 95},
		},
		{
			name:      "EIP191+RAW",
			varsig:    must(varsig.EIP191(varsig.PayloadEncodingEIP191Raw)),
			dataBytes: []byte{52, 1, 236, 1, 231, 1, 27, 145, 195, 3, 95},
		},
		{
			name:      "EIP191+DAG-CBOR",
			varsig:    must(varsig.EIP191(varsig.PayloadEncodingEIP191Cbor)),
			dataBytes: []byte{52, 1, 236, 1, 231, 1, 27, 145, 195, 3, 113},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// round-trip encode and back
			data := tc.varsig.Encode()

			if tc.dataBytes != nil {
				require.Equal(t, tc.dataBytes, data)
			}
			if tc.dataHex != "" {
				require.Equal(t, tc.dataHex, hex.EncodeToString(data))
			}

			rt, err := varsig.Decode(data)
			require.NoError(t, err)

			require.Equal(t, tc.varsig.Version(), rt.Version())
			require.Equal(t, tc.varsig.Discriminator(), rt.Discriminator())
			require.Equal(t, tc.varsig.PayloadEncoding(), rt.PayloadEncoding())

			switch vs := tc.varsig.(type) {
			case varsig.EdDSAVarsig:
				rt := rt.(varsig.EdDSAVarsig)
				require.Equal(t, vs.Curve(), rt.Curve())
				require.Equal(t, vs.Hash(), rt.Hash())
			case varsig.ECDSAVarsig:
				rt := rt.(varsig.ECDSAVarsig)
				require.Equal(t, vs.Curve(), rt.Curve())
				require.Equal(t, vs.Hash(), rt.Hash())
			case varsig.RSAVarsig:
				rt := rt.(varsig.RSAVarsig)
				require.Equal(t, vs.Hash(), rt.Hash())
				require.Equal(t, vs.KeyLength(), rt.KeyLength())
			default:
				t.Fatalf("unexpected varsig type: %T", vs)
			}
		})
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
