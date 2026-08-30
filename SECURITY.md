# Umbra Security Policy

Umbra is designed with a zero-trust architecture for journalists, diplomats, and intelligence professionals whose lives are at risk.

---

## 🔒 Security Level and Supported Versions

| Version | Status | Security Support |
|---|---|---|
| 0.1.x (Development) | Active Development | :white_check_mark: |
| < 0.1.0 | Not Supported | :x: |

---

## 🛡️ Core Security Commitments

1. **Zero Personal Data (Zero-PII):** Under no circumstances does the system collect, store, or transmit usernames, phone numbers, emails, or identity information.
2. **Post-Quantum Assurance:** All handshakes are post-quantum resilient via ML-KEM-768 (Kyber).
3. **Zero Metadata and Fixed-Size Packets:** Traffic analysis is thwarted by Poisson artificial traffic and 1024-byte fixed blocks.
4. **RAM-Only and Anti-Forensics:** Data is never written to disk by default; it is isolated from swap space with `mlock` and instantly destroyed with `zeroize`.
5. **Safe Rust and Isolation:** In the source code, `unsafe` blocks are confined solely to direct hardware interfaces; the process is isolated via Linux Seccomp and Landlock.

---

## 🚨 Vulnerability Reporting (Responsible Disclosure)

If you have discovered a security vulnerability or cryptographic weakness in Umbra:

1. **Under no circumstances share it on public GitHub Issues or forums.**
2. Send your security report PGP-encrypted directly to `security@umbra-project.org` (or with the maintainer PGP key).
3. **Your Report Must Include:**
   - The type and impact of the vulnerability (crypto, memory, traffic analysis, etc.),
   - Step-by-step reproduction instructions (PoC code attached encrypted, if available),
   - A proposed patch or fix method, if any.
4. Our security team will respond within 24 hours, and a coordinated disclosure process will be carried out until the patch is released.
