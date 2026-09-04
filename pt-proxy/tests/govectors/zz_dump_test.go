// zz_dump_test.go dumps byte-exact obfs4 test fixtures for
// umbra-pt-proxy's tests/vectors.c. DEV TOOLING ONLY — it lives in the
// lyrebird tree (common/ntor) because it needs the ntor.Keypair
// internals (the DIRTY Elligator public key, which the exported
// constructors cannot produce).
//
// Run: go test ./common/ntor/ -run TestDumpVectors -v > out.txt
//
// All inputs are fixed (deterministic private keys, tweaks, padding and
// epoch), so the output is a stable C header consumed by the C tests.
package ntor

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/x25519ell2"
)

func dumpEmit(name string, b []byte) {
	fmt.Printf("static const uint8_t %s[%d] = {\n", name, len(b))
	for i := 0; i < len(b); i += 8 {
		fmt.Printf("\t")
		end := i + 8
		if end > len(b) {
			end = len(b)
		}
		for _, v := range b[i:end] {
			fmt.Printf("0x%02x, ", v)
		}
		fmt.Printf("\n")
	}
	fmt.Printf("};\n\n")
}

func dumpHmac128(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)[:16]
}

// dumpBytes32 derives a deterministic 32-byte key from a pattern byte.
func dumpBytes32(v byte) []byte {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = v
	}
	d := sha512.Sum512(seed)
	out := make([]byte, 32)
	copy(out, d[:32])
	return out
}

func TestDumpVectors(t *testing.T) {
	fmt.Printf("/* Generated from the Go reference (lyrebird, common/ntor).\n")
	fmt.Printf(" * DO NOT EDIT — regenerate per tests/govectors/README.md. */\n\n")

	// --- 1. Elligator 2 keypair vectors --------------------------------
	privs := [][]byte{dumpBytes32(0x11), dumpBytes32(0x22), dumpBytes32(0x33), dumpBytes32(0x44)}
	tweaks := []byte{0x01, 0xfe, 0x80, 0x7f}
	nOk := 0
	for i, priv := range privs {
		tweak := tweaks[i]
		var pub, repr [32]byte
		ok := x25519ell2.ScalarBaseMult((*[32]byte)(pub[:]), (*[32]byte)(repr[:]), (*[32]byte)(priv[:]), tweak)
		dumpEmit(fmt.Sprintf("vec_ell%d_priv", i), priv)
		fmt.Printf("#define VEC_ELL%d_TWEAK 0x%02x\n", i, tweak)
		if ok {
			fmt.Printf("#define VEC_ELL%d_OK 1\n", i)
			dumpEmit(fmt.Sprintf("vec_ell%d_pub", i), pub[:])
			dumpEmit(fmt.Sprintf("vec_ell%d_repr", i), repr[:])
			var back [32]byte
			x25519ell2.RepresentativeToPublicKey((*[32]byte)(back[:]), (*[32]byte)(repr[:]))
			if !hmac.Equal(back[:], pub[:]) {
				t.Fatalf("elligator round-trip mismatch at %d", i)
			}
			nOk++
		} else {
			fmt.Printf("#define VEC_ELL%d_OK 0\n", i)
		}
		fmt.Printf("\n")
	}
	if nOk < 2 {
		t.Fatalf("too few successful elligator vectors: %d", nOk)
	}

	// --- 2. Full handshake vector --------------------------------------
	epoch := "499999"

	// Server identity (long-term): private b, public B.
	idKp, err := KeypairFromHex(hex.EncodeToString(dumpBytes32(0xbb)))
	if err != nil {
		t.Fatal(err)
	}
	var nodeIDBytes [20]byte
	for i := range nodeIDBytes {
		nodeIDBytes[i] = uint8(0xa0 + i)
	}
	nodeID, err := NewNodeID(nodeIDBytes[:])
	if err != nil {
		t.Fatal(err)
	}

	// Client session keypair with representative (dirty public key).
	// ~50% of keys have no representative at all (tweak-independent), so
	// scan seed bytes until one works; the tweak is arbitrary.
	var xPriv []byte
	var xPub, xRepr [32]byte
	xTweak := byte(0x42)
	found := false
	for seed := 0xcc; seed < 0x100 && !found; seed++ {
		cand := dumpBytes32(byte(seed))
		if x25519ell2.ScalarBaseMult((*[32]byte)(xPub[:]), (*[32]byte)(xRepr[:]), (*[32]byte)(cand[:]), xTweak) {
			xPriv, found = cand, true
		}
	}
	if !found {
		t.Fatal("client elligator failed for all seeds")
	}
	clientKp := &Keypair{
		public:         NewPublicKeyMust(xPub[:]),
		private:        privFromBytes(xPriv),
		representative: reprFromBytes(xRepr[:]),
	}

	// Server session keypair with representative (dirty public key).
	var yPriv []byte
	var yPub, yRepr [32]byte
	yTweak := byte(0x24)
	found = false
	for seed := 0xdd; seed < 0x100 && !found; seed++ {
		cand := dumpBytes32(byte(seed))
		if x25519ell2.ScalarBaseMult((*[32]byte)(yPub[:]), (*[32]byte)(yRepr[:]), (*[32]byte)(cand[:]), yTweak) {
			yPriv, found = cand, true
		}
	}
	if !found {
		t.Fatal("server elligator failed for all seeds")
	}
	serverKp := &Keypair{
		public:         NewPublicKeyMust(yPub[:]),
		private:        privFromBytes(yPriv),
		representative: reprFromBytes(yRepr[:]),
	}

	// Client request with fixed padding.
	padC := make([]byte, 100)
	for i := range padC {
		padC[i] = uint8(i * 7)
	}
	macKey := append(idKp.Public().Bytes()[:], nodeID.Bytes()[:]...)
	markC := dumpHmac128(macKey, xRepr[:])
	macInputC := append(append(append([]byte{}, xRepr[:]...), padC...), markC...)
	macC := dumpHmac128(macKey, append(macInputC, []byte(epoch)...))
	request := append(append(append([]byte{}, xRepr[:]...), padC...), markC...)
	request = append(request, macC...)

	// Server side: ntor over the mapped client public key.
	var xPubMapped [32]byte
	x25519ell2.RepresentativeToPublicKey((*[32]byte)(xPubMapped[:]), (*[32]byte)(xRepr[:]))
	xPubNtor, err := NewPublicKey(xPubMapped[:])
	if err != nil {
		t.Fatal(err)
	}
	ok, seed, auth := ServerHandshake(xPubNtor, serverKp, idKp, nodeID)
	if !ok {
		t.Fatal("server ntor failed")
	}

	// Client side cross-check must derive the same KEY_SEED/AUTH.
	var yPubMapped [32]byte
	x25519ell2.RepresentativeToPublicKey((*[32]byte)(yPubMapped[:]), (*[32]byte)(yRepr[:]))
	yPubNtor, err := NewPublicKey(yPubMapped[:])
	if err != nil {
		t.Fatal(err)
	}
	ok2, seed2, auth2 := ClientHandshake(clientKp, yPubNtor, idKp.Public(), nodeID)
	if !ok2 || !hmac.Equal(seed.Bytes()[:], seed2.Bytes()[:]) || !hmac.Equal(auth.Bytes()[:], auth2.Bytes()[:]) {
		t.Fatal("client/server ntor mismatch")
	}

	// Server response with fixed padding.
	padS := make([]byte, 40)
	for i := range padS {
		padS[i] = uint8(0xf0 - i)
	}
	markS := dumpHmac128(macKey, yRepr[:])
	respHead := append(append(append([]byte{}, yRepr[:]...), auth.Bytes()[:]...), padS...)
	macS := dumpHmac128(macKey, append(append(append([]byte{}, respHead...), markS...), []byte(epoch)...))
	response := append(append(respHead, markS...), macS...)

	// Derived link keys.
	okm := Kdf(seed.Bytes()[:], 144)

	dumpEmit("vec_node_id", nodeID.Bytes()[:])
	certRaw := append(nodeID.Bytes()[:], idKp.Public().Bytes()[:]...)
	fmt.Printf("#define VEC_CERT_B64 \"%s\"\n\n",
		strings.TrimSuffix(base64.StdEncoding.EncodeToString(certRaw), "=="))
	dumpEmit("vec_server_id_priv", dumpBytes32(0xbb))
	dumpEmit("vec_server_id_pub", idKp.Public().Bytes()[:])
	dumpEmit("vec_client_priv", xPriv)
	fmt.Printf("#define VEC_CLIENT_TWEAK 0x%02x\n\n", xTweak)
	dumpEmit("vec_client_pub", xPub[:])
	dumpEmit("vec_client_repr", xRepr[:])
	dumpEmit("vec_server_priv", yPriv)
	fmt.Printf("#define VEC_SERVER_TWEAK 0x%02x\n\n", yTweak)
	dumpEmit("vec_server_repr", yRepr[:])
	dumpEmit("vec_pad_c", padC)
	dumpEmit("vec_pad_s", padS)
	fmt.Printf("#define VEC_EPOCH \"%s\"\n\n", epoch)
	dumpEmit("vec_request", request)
	dumpEmit("vec_response", response)
	dumpEmit("vec_key_seed", seed.Bytes()[:])
	dumpEmit("vec_auth", auth.Bytes()[:])
	dumpEmit("vec_okm", okm)

	t.Logf("request=%dB response=%dB", len(request), len(response))
}

func privFromBytes(b []byte) *PrivateKey {
	k := new(PrivateKey)
	copy(k.Bytes()[:], b)
	return k
}

func reprFromBytes(b []byte) *Representative {
	r := new(Representative)
	copy(r.Bytes()[:], b)
	return r
}

func NewPublicKeyMust(b []byte) *PublicKey {
	p, err := NewPublicKey(b)
	if err != nil {
		panic(err)
	}
	return p
}
