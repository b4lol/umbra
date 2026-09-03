# Umbra Resilient Network Protocol

This document describes **Umbra**'s binary packet structure, its multiple anonymity networks (Tor/Nym Mixnet), the DPI-resistant Pluggable Transport layer, and the Off-Grid Mesh protocol that operates during internet outages.

---

## 1. Network Transport Architecture (Multi-Path and Censorship Resistance)

```mermaid
graph TD
    AppLayer[Umbra Secure Communication Engine] --> Router[Dynamic Transport Router]
    
    Router -->|Default Internet| ArtiTor[Embedded Arti Tor v3 Onion]
    Router -->|Heavy DPI / Censorship| Pluggable[Pluggable Transports: Obfs4 / Snowflake]
    Router -->|High-Grade Mixnet| NymMix[Nym Mixnet / Loopix Delayed Mixer]
    Router -->|Internet Outage / Blackout| OffGrid[Off-Grid Mesh: BLE / Wi-Fi Direct / LoRa]

    ArtiTor --> P2POut[Tor Circuit]
    Pluggable --> P2POut
    NymMix --> P2POut
    OffGrid --> MeshPeer[Direct Local Device Mesh Network]
```

---

## 2. Binary Packet Structure (1024-Byte Fixed Block)

**EVERY** data packet passing over the network is **1024 Bytes** in length, without exception:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Protocol Ver  |  Packet Type  |        Message Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   ChaCha20-Poly1305 Nonce                     |
|                           (12 Byte)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                       Encrypted Payload                       |
|        (Actual Data + Cryptographic Random Padding)           |
|                         (992 Byte)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Poly1305 Auth Tag (16 Byte)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 3. Censorship Circumvention and Traffic Masking (Pluggable Transports)

To bypass censoring firewalls (e.g., the GFW) that apply state-level Deep Packet Inspection (DPI):
- **Obfs4 / Lyrebird:** Makes Tor packets appear as completely meaningless noise data with random entropy.
- **Snowflake (WebRTC Masking):** Disguises client traffic as an ordinary video conference or browser WebRTC stream and routes it through temporary volunteer proxies.

### The Umbra PT model (ADR-030, v2 line)

Umbra never spawns or links PT binaries. A pluggable transport runs as
an **OS-managed proxy process** exposing a **loopback-only SOCKS5
endpoint**; the embedded Arti client is configured with arti's
*unmanaged transport* support (`--pt-socks 127.0.0.1:PORT` plus
user-supplied `--bridge` lines or a `bridges` file next to the
keystore). This preserves the Seccomp no-`execve` allowlist, the
Landlock zero-FS sandbox, and the process-isolation doctrine. The
managed-PT (binary-spawning) model is rejected by design. Snowflake is
currently blocked: no Rust or C client implementation exists.

---

## 4. Internet Outage / Crisis Mode: Off-Grid Mesh

In crisis/wartime environments where the communication infrastructure has been crippled, the internet is cut off (blackout), or base stations have been shut down:
- **Bluetooth Low Energy (BLE) & Wi-Fi Direct:** Without internet, devices establish encrypted ad-hoc mesh networks with each other within a 50-100 meter radius.
- **DTN - Delay-Tolerant Routing / Store-and-Forward:** Even if the destination device is out of range, a message is delivered to its destination through intermediate nodes (other secure devices physically on the move) as sealed encrypted envelopes. Intermediate nodes can neither see the message's contents nor whom it belongs to.

---

## 5. Poisson Artificial Cover Traffic & Nym Mixnet Integration

- **Loopix / Sphinx Packet Format:** As packets traverse the mixnet nodes, they are randomly reordered and micro-delays are added, making timing correlation attacks significantly harder.
- **Poisson-Distributed Queue:** Whether or not there is a real message, dummy/cover packets are continuously pumped according to the configured $\lambda$ parameter.
