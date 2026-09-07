// zz_dump_probdist_test.go dumps probdist table fixtures for
// umbra-pt-proxy's tests/vectors.c. DEV TOOLING ONLY — lives in the
// lyrebird tree (common/probdist) because the table fields are
// unexported.
//
// Run: go test ./common/probdist/ -run TestDumpProbdist -v
package probdist

import (
	"crypto/sha256"
	"fmt"
	"math"
	"testing"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/drbg"
)

func dumpDist(t *testing.T, name string, max int, seedBytes []byte) {
	seed, err := drbg.SeedFromBytes(seedBytes)
	if err != nil {
		t.Fatal(err)
	}
	w := New(seed, 0, max, false)

	fmt.Printf("#define %s_N %d\n", name, len(w.values))

	fmt.Printf("static const int32_t %s_values[%s_N] = {", name, name)
	for i, v := range w.values {
		if i%12 == 0 {
			fmt.Printf("\n\t")
		}
		fmt.Printf("%d, ", v)
	}
	fmt.Printf("\n};\n\n")

	fmt.Printf("static const uint64_t %s_weights[%s_N] = {", name, name)
	for i, v := range w.weights {
		if i%4 == 0 {
			fmt.Printf("\n\t")
		}
		fmt.Printf("0x%016x, ", math.Float64bits(v))
	}
	fmt.Printf("\n};\n\n")

	fmt.Printf("static const int32_t %s_alias[%s_N] = {", name, name)
	for i, v := range w.alias {
		if i%12 == 0 {
			fmt.Printf("\n\t")
		}
		fmt.Printf("%d, ", v)
	}
	fmt.Printf("\n};\n\n")

	fmt.Printf("static const uint64_t %s_prob[%s_N] = {", name, name)
	for i, v := range w.prob {
		if i%4 == 0 {
			fmt.Printf("\n\t")
		}
		fmt.Printf("0x%016x, ", math.Float64bits(v))
	}
	fmt.Printf("\n};\n\n")
}

func TestDumpProbdist(t *testing.T) {
	fmt.Printf("/* probdist fixtures — same regeneration recipe as the header above. */\n\n")

	// Fixed 24-byte DRBG seeds.
	seeds := [][]byte{
		make([]byte, drbg.SeedLength),
		make([]byte, drbg.SeedLength),
	}
	for i := range seeds[0] {
		seeds[0][i] = uint8(i * 5)
	}
	for i := range seeds[1] {
		seeds[1][i] = uint8(0xa5 ^ i)
	}

	dumpDist(t, "vec_len_dist", 1448, seeds[0])
	dumpDist(t, "vec_len_dist2", 1448, seeds[1])

	// The iat derivation chain: iatSeed = sha256(lenSeed) -> dist [0,100].
	iatSeedSrc := sha256.Sum256(seeds[0])
	dumpDist(t, "vec_iat_dist", 100, iatSeedSrc[:])
}
