# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduction

**Low-Power Wide Area Network** (LPWAN) is a group of wireless, low-power, wide-area network technologies designed for **long-range communications** at a low bit rate.
They can reach more than **six miles** and their **batteries** can last up to **20 years**.

Long Range (**LoRa**) is currently the most deployed LPWAN physical layer and its open MAC-layer specification is **LoRaWAN**.

---

## LPWAN, LoRa, and LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) physical layer developed by Semtech (proprietary but documented).
* LoRaWAN – Open MAC/Network layer maintained by the LoRa-Alliance. Versions 1.0.x and 1.1 are common in the field.
* Typical architecture: *end-device → gateway (packet-forwarder) → network-server → application-server*.

> The **security model** relies on two AES-128 root keys (AppKey/NwkKey) that derive session keys during the *join* procedure (OTAA) or are hard-coded (ABP). If any key leaks the attacker gains full read/write capability over the corresponding traffic.

---

## Attack surface summary

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | 100 % packet loss demonstrated with single SDR and <1 W output |
| MAC | Join-Accept & data-frame replay (nonce reuse, ABP counter rollover) | Device spoofing, message injection, DoS |
| Network-Server | Insecure packet-forwarder, weak MQTT/UDP filters, outdated gateway firmware | RCE on gateways → pivot into OT/IT network |
| Application | Hard-coded or predictable AppKeys | Brute-force/decrypt traffic, impersonate sensors |

---

## Recent vulnerabilities (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* accepted TCP packets that bypassed stateful firewall rules on Kerlink gateways, allowing remote management interface exposure. Fixed in 4.0.11 / 4.2.1 respectively .
* **Dragino LG01/LG308 series** – Multiple 2022-2024 CVEs (e.g. 2022-45227 directory traversal, 2022-45228 CSRF) still observed unpatched in 2025; enable unauthenticated firmware dump or config overwrite on thousands of public gateways .
* Semtech *packet-forwarder UDP* overflow (unreleased advisory, patched 2023-10): crafted uplink larger than 255 B triggered stack-smash ‑> RCE on SX130x reference gateways (found by Black Hat EU 2023 “LoRa Exploitation Reloaded”).

---

## Practical attack techniques

### 1. Sniff & Decrypt traffic

```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
    --freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```

### 2. OTAA join-replay (DevNonce reuse)

1. Capture a legitimate **JoinRequest**.
2. Immediately retransmit it (or increment RSSI) before the original device transmits again.
3. The network-server allocates a new DevAddr & session keys while the target device continues with the old session → attacker owns vacant session and can inject forged uplinks.

### 3. Adaptive Data-Rate (ADR) downgrading

Force SF12/125 kHz to increase airtime → exhaust duty-cycle of gateway (denial-of-service) while keeping battery impact low on attacker (just send network-level MAC commands).

### 4. Reactive jamming

*HackRF One* running GNU Radio flowgraph triggers a wide-band chirp whenever preamble detected – blocks all spreading factors with ≤200 mW TX; full outage measured at 2 km range .

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Craft/parse/attack LoRaWAN frames, DB-backed analyzers, brute-forcer | Docker image, supports Semtech UDP input |
| **LoRaPWN** | Trend Micro Python utility to brute OTAA, generate downlinks, decrypt payloads | Demo released 2023, SDR-agnostic |
| **LoRAttack** | Multi-channel sniffer + replay with USRP; exports PCAP/LoRaTap | Good Wireshark integration |
| **gr-lora / gr-lorawan** | GNU Radio OOT blocks for baseband TX/RX | Foundation for custom attacks |

---

## Defensive recommendations (pentester checklist)

1. Prefer **OTAA** devices with truly random DevNonce; monitor duplicates.
2. Enforce **LoRaWAN 1.1**: 32-bit frame counters, distinct FNwkSIntKey / SNwkSIntKey.
3. Store frame-counter in non-volatile memory (**ABP**) or migrate to OTAA.
4. Deploy **secure-element** (ATECC608A/SX1262-TRX-SE) to protect root keys against firmware extraction.
5. Disable remote UDP packet-forwarder ports (1700/1701) or restrict with WireGuard/VPN.
6. Keep gateways updated; Kerlink/Dragino provide 2024-patched images.
7. Implement **traffic anomaly detection** (e.g., LAF analyzer) – flag counter resets, duplicate joins, sudden ADR changes.



## References

* LoRaWAN Auditing Framework (LAF) – [https://github.com/IOActive/laf](https://github.com/IOActive/laf)
* Trend Micro LoRaPWN overview – [https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
{{#include ../../banners/hacktricks-training.md}}
