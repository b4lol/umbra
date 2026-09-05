# govectors — byte-exact fixture dump from the Go reference

**Dev tooling only. Nothing in this directory is built, shipped, or
linked.** `zz_dump_test.go` is a Go *test* file that regenerates
`../vectors_fixtures.h` from the reference obfs4 implementation
([lyrebird](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird)).
It cannot compile standalone: it needs lyrebird's module tree because
it touches `ntor.Keypair` internals (the "dirty" Elligator public key
that the exported constructors never expose).

The fixtures currently committed were produced from lyrebird commit
`fc105a03c0e0acc2479301c361c012ffed359c43`.

## Regenerating

```sh
git clone https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird.git
cd lyrebird
git checkout fc105a03c0e0acc2479301c361c012ffed359c43
cp /path/to/umbra/pt-proxy/tests/govectors/zz_dump_test.go common/ntor/
cp /path/to/umbra/pt-proxy/tests/govectors/zz_dump_probdist_test.go common/probdist/
{
  go test ./common/ntor/ -run TestDumpVectors -v \
    | grep -v '^=== RUN\|^--- PASS\|^PASS\|^ok  \|^=== CONT' \
    | grep -v 'zz_dump_test.go'
  go test ./common/probdist/ -run TestDumpProbdist -v \
    | grep -v '^=== RUN\|^--- PASS\|^PASS\|^ok  \|^=== CONT' \
    | grep -v 'zz_dump_probdist_test.go'
} > /path/to/umbra/pt-proxy/tests/vectors_fixtures.h
```

The test self-verifies before printing: client and server ntor halves
must derive identical KEY_SEED/AUTH, and every representative must
round-trip through the map. If the upstream wire format ever changes,
the regenerated header will fail `make vectors` — that is the alarm
working as intended.

## What the fixtures cover

- `vec_ell0..3`: Elligator 2 keygen (private key + tweak -> dirty public
  key + representative), including two keys that have NO representative
  (the ~50% failure path).
- `vec_request`: a full client request `X' | P_C | M_C | MAC_C` with
  fixed padding and epoch — byte-exact against the C builder.
- `vec_response`: the matching server response `Y' | AUTH | P_S | M_S |
  MAC_S`, plus `vec_key_seed` and the 144-byte HKDF key block
  (`vec_okm`) the C parser must derive.
- `vec_drbg_seed` / `vec_drbg_blocks`: 16 consecutive SipHash-2-4-DRBG
  length-mask blocks — pins down the streaming SipHash state machine.
- Frame vectors: fixed per-direction key block, two encoded frames
  (short + maximum-size payload) from the Go `framing.Encoder`, and the
  corresponding decode expectations — byte-exact against the C framing
  layer.
- `vec_probdist_*`: the length-distribution shaping primitives from
  `zz_dump_probdist_test.go` (separate `common/probdist` package):
  Go `math/rand.Rand` helper semantics (Int63/Int31n/Float64/Perm) over
  the obfs4 SipHash-2-4-OFB DRBG, the uniform weighted-distribution
  tables (values/weights/alias/prob from Vose's method), and a
  100k-sample stream whose full range must be reproducible. Byte-exact
  against `src/gorand.c` + `src/probdist.c`.
