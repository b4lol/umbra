# Umbra — Code Craftsmanship & Quality Manifesto

> *"Security is not a feature bolted on after the fact; it is a mathematical discipline inherent in every line of code, every type definition, and every architectural decision."*

This manifesto establishes the **code-writing, code-quality, and engineering principles that are indisputable, non-negotiable, and uncompromisingly binding** for every developer, engineer, and AI agent contributing to the **Umbra** project.

---

## 🏛️ The Ten Pillars of Code Quality

```mermaid
graph TD
    subgraph Kalite_Doktrinleri [Umbra Code Quality Manifesto]
        Pillar1[1. Zero Panic & Type-Safe Error Management]
        Pillar2[2. 100% Safe Rust & Isolated Hardware Unsafe]
        Pillar3[3. Typestate: Make Illegal States Unrepresentable]
        Pillar4[4. Mandatory Deep Documentation: #![deny(missing_docs)]]
        Pillar5[5. Anti-Bloat & Extreme Resource Discipline]
        Pillar6[6. Continuous Aggressive Security and Fuzzing Scans]
        Pillar7[7. Constant-Time Execution & Side-Channel Isolation]
        Pillar8[8. Uncompromising Unix Philosophy & Composability]
        Pillar9[9. Deterministic Memory Wiping & Zeroize]
        Pillar10[10. Mutation and Property-Based Validation]
    end

    subgraph Hedef_Standart [Achieved Engineering Standard]
        WorldClass["A Resilient, Auditable, and High-Performance Codebase"]
    end

    Pillar1 & Pillar2 & Pillar3 & Pillar4 & Pillar5 --> WorldClass
    Pillar6 & Pillar7 & Pillar8 & Pillar9 & Pillar10 --> WorldClass
```

---

## 1. Zero Panic and Zero Assumptions Doctrine

1. **`unwrap()`, `expect()` and `panic!()` are Strictly Forbidden:**
   - Not a single bare `unwrap()` or `expect()` capable of crashing (crash/panic) the process at runtime may exist in the codebase.
   - Without exception, every error is handled through explicit enum types defined with `thiserror` and propagated upward via `Result<T, E>`.
2. **Array and Slice Indexing Rule:**
   - Bare `buffer[i]` access is forbidden; to prevent out-of-bounds access panics, `buffer.get(i)` or safe slicing (`split_at_checked`) is always used.
3. **`unreachable!()` and `todo!()` Ban:**
   - Production code must contain no `unreachable!()` or `todo!()` macros; all possibilities are exhausted at the compiler level with `match` patterns (`exhaustive pattern matching`).

---

## 2. Safe Rust with Isolated Unsafe

1. **The `#![forbid(unsafe_code)]` Default:**
   - The core engine (`umbra-core`), cryptography (`umbra-crypto`), networking (`umbra-net`), protocol (`umbra-protocol`), and user interfaces are written in `100% Safe Rust`.
2. **The Single Exception: Direct Hardware/Kernel Communication:**
   - `unsafe` is permitted only in the isolated `umbra-hardware` module that directly touches physical hardware (`mlock`, TPM/Secure Enclave, FIDO2 USB-NFC, hardware TRNG).
3. **Hardware Unsafe Rules:**
   - **`// SAFETY:` Documentation is Mandatory:** Every `unsafe` block must be preceded by a comment explaining the memory invariants and why it is safe (`-D clippy::undocumented_unsafe_blocks`).
   - **Encapsulation:** All `unsafe` operations are hidden behind a `100% Safe` API; no `unsafe fn` may ever leak to the outside world.

---

## 3. Type-Driven State Design: Make Illegal States Unrepresentable

1. **Typestate Pattern:**
   - State transitions are enforced not with boolean flags (`is_authenticated: bool`) but with distinct type definitions:
     $$\text{UnauthenticatedPacket} \xrightarrow{\text{verify()}} \text{VerifiedPacket} \xrightarrow{\text{decrypt()}} \text{PlaintextMessage}$$
   - Unencrypted data (`Plaintext`) cannot be handed directly to a network socket; the compiler rejects invalid calls.
2. **Semantic Newtypes (Newtype Pattern):**
   - Primitive `u64`, `u32`, `String` types cannot be used directly in business logic; type wrappers such as `SequenceNumber(u64)`, `EpochId(u32)`, and `OnionAddress(String)` are mandatory.
3. **Checked Arithmetic (Overflow Protection):**
   - Instead of the bare `+`, `-`, `*` operators, `checked_add()`, `saturating_sub()`, and `checked_mul()` are always used.

---

## 4. Mandatory and In-Depth Documentation Doctrine (`#![deny(missing_docs)]`)

1. **Compile-Time Documentation:**
   - `#![deny(missing_docs)]` is active in all crates. A single undocumented module (`//!`), struct, enum, trait, function, or field (`///`) is a compile error.
2. **"Why"-Focused Comments:**
   - Code comments must elaborate not only *what* the code does but **why** it was designed that way (cryptographic RFC references, NIST standards, timing-bound rationales).

---

## 5. Extreme Resource Discipline and Zero Bloat

1. **Zero Unnecessary Allocations:**
   - Using `clone()`, `to_vec()`, or `format!()` in hot paths is forbidden; zero-copy references (`&[u8]`) and fixed-size stack arrays (`[u8; 1024]`) are essential.
2. **Zero Garbage Collector & Zero Bloated Libraries:**
   - Electron, Node.js, and external C/C++ dependencies are strictly forbidden; pure Rust, a minimal dependency tree, and `lto = "fat"`, `strip = true` target the smallest possible binary size.
3. **Deterministic Memory Allocation:**
   - On both Linux and Android, the **GrapheneOS `hardened_malloc`** global allocator is used (`PROT_NONE` guard pages, out-of-line metadata, slab quarantine).

---

## 6. Constant-Time by Design and Side-Channel Protection

1. **Constant-Time Comparisons:**
   - All encryption key, password hash, and MAC tag comparisons are performed with `subtle::ConstantTimeEq`; the standard `==` operator is forbidden.
2. **Branchless Execution:**
   - `if`/`else` branches and array lookups (LUT) that depend on sensitive data are forbidden; conditional selections are performed with `subtle::ConditionallySelectable`.
3. **Timing Analysis Verification:**
   - Cryptographic timing boundaries (AEAD verify path, SAS derivation; X25519/ML-KEM/ML-DSA via upstream constant-time implementations) are verified in the CI pipeline with the `dudect` Welch t-test (`constant_time_tests.rs`); SMP modexp remains a documented non-CT residual.

---

## 7. Deterministic Memory Wiping: Universal Zeroize on Drop

1. **Automatic Zeroization (`ZeroizeOnDrop`):**
   - Every struct holding sensitive keys, passwords, or plaintext messages must implement the `zeroize::ZeroizeOnDrop` trait.
2. **Compiler Optimization Shield:**
   - Memory wiping is performed not with a standard `memset` but with `volatile`/`atomic` barriers (the `zeroize` crate) that the compiler cannot eliminate as dead code.
3. **CPU Register Wiping:**
   - With the LLVM `-Z zero-call-used-regs=all` flag, all CPU registers (`rax`, `ymm`, `zmm`) are zeroed on function exit.

---

## 8. The Uncompromising Unix Philosophy and Modularity

1. **Do One Thing Well:**
   - Every module and CLI command has a single, explicit responsibility; monolithic bloat is rejected.
2. **Pipeline Integration (Pipes & Streams):**
   - Standard byte streams are provided via `stdin`/`stdout` (`cat payload | umbra send <dest>`).
3. **Rule of Silence:**
   - Successful CLI commands print no decorative text to the `stdout` channel; only the requested data is produced, and logs are routed to `stderr`.
4. **Process Separation:**
   - The UI, Engine, and Media Parser (Sanitizer) layers are isolated by Unix Domain Socket (`AF_UNIX`) boundaries.

---

## 9. Aggressive Verification, Fuzzing, and Mutation Testing

1. **Hermetic Unit and Integration Tests:**
   - Every module is 100% tested with deterministic fixtures and mock objects, without depending on the external network or the real system.
2. **Property-Based Tests (`proptest`):**
   - Cryptographic functions and protocol state machines are mathematically verified with thousands of randomly generated inputs.
3. **Mandatory Mutation Testing (`cargo-mutants`):**
   - Incomplete tests that fail to catch operator mutations in code lines (`>` $\to$ `<`, `+` $\to$ `-`) are rejected.
4. **Coverage-Guided Fuzzing (`cargo-fuzz`):**
   - All parsers are fuzzed against mutated inputs with libFuzzer for 10 million+ cycles.

---

## 10. Pull Request (PR) and Contribution Quality Pledge

Every line of code added to the Umbra codebase represents the following pledge:

> *"I am aware that every line of code I write protects the lives, freedom, and privacy of users. I swear that I will never compromise security, stability, performance, or documentation for the sake of any convenience."*
