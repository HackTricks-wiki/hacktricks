# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduction

**Low-Power Wide Area Network** (LPWAN) is a group of wireless, low-power, wide-area network technologies designed for **long-range communications** at a low bit rate.
Depending on the radio parameters, antenna, regulatory region, terrain, and duty cycle, LPWAN deployments can trade throughput for multi-kilometre coverage and multi-year battery life. Treat vendor range and battery figures as design targets rather than guarantees.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) is currently the most deployed LPWAN physical layer and its open MAC-layer specification is **LoRaWAN**.

---

## LPWAN, LoRa, and LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) physical layer developed by Semtech (proprietary but documented).
* LoRaWAN – Open MAC/Network layer maintained by the LoRa-Alliance. Versions 1.0.x and 1.1 are common in the field.
* Typical architecture: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> In LoRaWAN 1.1, the **security model** uses separate AES-128 application and network root keys to derive role-specific session keys during OTAA. Earlier 1.0.x deployments normally use one AppKey to derive the network and application session keys, while ABP provisions session keys directly. The capability obtained from a leaked key therefore depends on the LoRaWAN version and which key was exposed.<sup>[[3]](#references)</sup>

---

## Attack surface summary

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Localized packet loss; effectiveness depends on link budget, timing, bandwidth, and regulatory constraints |
| MAC | Join and data-frame replay where nonce/counter state is reused | Device desynchronization, spoofing or injection if the server/device violates replay protections |
| Network-Server | Insecure packet-forwarder, weak MQTT/UDP filters, outdated gateway firmware | RCE on gateways → pivot into OT/IT network |
| Application | Hard-coded or predictable AppKeys | Brute-force/decrypt traffic, impersonate sensors |

---

## Representative implementation vulnerabilities

* **CVE-2024-29862** – Affected ChirpStack Gateway Bridge versions before 4.0.11 and MQTT Forwarder versions before 4.2.1 could connect to an attacker-controlled MQTT broker because TLS server-certificate validation was disabled. This could expose credentials and gateway traffic; upgrade to the fixed releases.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 describes an unauthenticated `/lib/` directory listing containing a downloadable backup file; CVE-2022-45228 is a low-severity CSRF in the logout page. These records do not establish the claimed LG308 impact, configuration overwrite, population size, or 2025 patch state.<sup>[[6]](#references)[[7]](#references)</sup>
* An earlier version of this page described an alleged Semtech UDP packet-forwarder issue as a **greater-than-255-byte crafted uplink causing a stack smash and RCE on SX130x reference gateways**, attributed to a “LoRa Exploitation Reloaded” Black Hat Europe 2023 presentation and an October 2023 private patch. Those precise details are retained here as a research lead, but no matching public advisory, presentation, or patch could be corroborated. Do not treat the issue as a known vulnerability without obtaining the affected product/version and a verifiable primary source.

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

These commands preserve the original workflow as **illustrative syntax**; repository layout and flags differ between projects/releases. Passive capture does not reveal a strong AppKey. Offline guessing is useful only when the root key is weak enough to be found and a captured join exchange provides a value that can validate candidates.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Test OTAA replay protection and nonce state

1. In an authorized test network, capture a legitimate **JoinRequest**.
2. Replay the same request and confirm that the network server rejects the reused `DevNonce`.
3. Reboot or reset the test device and repeat the check to detect lost nonce state. A compliant server must track used nonces; replaying a JoinRequest alone does not disclose the newly derived session keys or give the replayer control of a session.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Adaptive Data-Rate (ADR) downgrading

An attacker who can authenticate network-layer MAC commands—for example, after compromising the applicable network session key or network server—may try to force inefficient data-rate parameters and increase airtime. A nearby unauthenticated transmitter cannot legitimately issue ADR commands merely by knowing a device address.<sup>[[3]](#references)</sup>

### 4. Reactive jamming

A reactive jammer can transmit after detecting a LoRa preamble and selectively disrupt frames. The earlier page claimed a HackRF/GNU Radio setup caused a full outage at **2 km with no more than 200 mW**, but no supporting measurement source was provided; retain those numbers only as a reproduction target, not an expected result. Required transmit power, timing, bandwidth, affected spreading factors, and range are environment-specific. Test only inside an authorized, RF-contained setup and comply with local spectrum rules.

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Craft/parse/attack LoRaWAN frames, DB-backed analyzers, brute-forcer | Docker image; supports Semtech UDP input<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Trend Micro Python utility to brute OTAA, generate downlinks, decrypt payloads | Public research utility; verify supported hardware and protocol versions<sup>[[2]](#references)</sup> |
| **LoRAttack** | Research framework for multi-channel LoRaWAN capture, session analysis, key derivation, and replay testing | Described in a 2024 master's thesis; obtain and verify the exact implementation before relying on the example flags<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | GNU Radio out-of-tree blocks for LoRa baseband reception or transceiver research | Projects differ in GNU Radio compatibility and feature set<sup>[[9]](#references)</sup> |

---

## Defensive recommendations (pentester checklist)

1. Prefer **OTAA** and verify that devices and servers persist the required nonce state; monitor rejected duplicate joins.
2. Prefer **LoRaWAN 1.1** where supported so network functions use distinct session keys and updated nonce handling.<sup>[[3]](#references)</sup>
3. Store frame-counter in non-volatile memory (**ABP**) or migrate to OTAA.
4. Deploy a suitable **secure element** (for example, ATECC608A in a supported design) to reduce exposure of root keys in ordinary firmware storage.
5. Do not expose configured packet-forwarder UDP listeners (commonly 1700) to untrusted networks; authenticate/encrypt gateway backhaul or restrict it with a VPN.
6. Keep gateways on vendor-supported firmware and confirm the exact model/version against applicable advisories.
7. Implement **traffic anomaly detection** (e.g., LAF analyzer) – flag counter resets, duplicate joins, sudden ADR changes.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1 specification](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1 regional parameters and join synchronization](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU thesis catalogue - LPWAN Protocol Security Analysis Leveraging SDR Technology](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio transceiver](https://github.com/tapparelj/gr-lora_sdr)

{{#include ../../banners/hacktricks-training.md}}
