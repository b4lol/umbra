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

---

## 🔐 Secret Leakage Prevention and Response

**Prevention layers (automated):** every push and pull request is scanned for secrets with gitleaks over the FULL git history (`.github/workflows/secret-scan.yml`, pinned and SHA256-verified binary, findings redacted from logs), with a weekly scheduled re-scan as detection rules evolve; a failing scan blocks the merge. At the GitHub layer, secret scanning with **push protection** is enabled on the repository, rejecting pushes containing recognized credentials before they land. Locally, `just secrets` runs the same scan before you push.

**If a secret ever reaches the repository anyway, CI deliberately does NOT rewrite history automatically** — an automated force-push cannot revoke a credential and would race human judgment. The manual procedure, in this exact order:

1. **ROTATE / REVOKE the secret IMMEDIATELY.** Assume it is compromised the moment it lands: GitHub indexes public repositories within seconds, and history rewrite is never a substitute for revocation.
2. **Rewrite history** to erase it: `git filter-repo --invert-paths --path <file>` (or `--replace-text` for an in-file secret), then force-push every branch and tag that contained it.
3. **Ask GitHub Support to purge cached views** of the repository (force-pushed commits remain reachable via their SHA in caches and in any forks until then).
4. **Notify all clones to re-clone** (their local histories still carry the secret).
5. Record the incident and the rotated credential's scope in the project's internal log.
