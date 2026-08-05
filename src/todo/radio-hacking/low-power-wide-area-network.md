# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduction

**Low-Power Wide Area Network** (LPWAN) wireless, low-power, wide-area network technologies का एक समूह है, जिसे कम bit rate पर **long-range communications** के लिए design किया गया है।
ये **छह मील** से अधिक दूरी तक पहुंच सकते हैं और इनकी **batteries** **20 वर्षों** तक चल सकती हैं।

Long Range (**LoRa**) वर्तमान में सबसे अधिक deployed LPWAN physical layer है और इसका open MAC-layer specification **LoRaWAN** है।

---

## LPWAN, LoRa, और LoRaWAN

* LoRa – Semtech द्वारा विकसित Chirp Spread Spectrum (CSS) physical layer (proprietary लेकिन documented)।
* LoRaWAN – LoRa-Alliance द्वारा maintain की जाने वाली Open MAC/Network layer। Versions 1.0.x और 1.1 field में common हैं।
* Typical architecture: *end-device → gateway (packet-forwarder) → network-server → application-server*।

> **security model** दो AES-128 root keys (AppKey/NwkKey) पर निर्भर करता है, जो *join* procedure (OTAA) के दौरान session keys derive करती हैं या hard-coded (ABP) होती हैं। यदि कोई key leak हो जाती है, तो attacker को corresponding traffic पर full read/write capability मिल जाती है।

---

## Attack surface summary

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Single SDR और <1 W output के साथ 100 % packet loss demonstrated |
| MAC | Join-Accept और data-frame replay (nonce reuse, ABP counter rollover) | Device spoofing, message injection, DoS |
| Network-Server | Insecure packet-forwarder, weak MQTT/UDP filters, outdated gateway firmware | Gateways पर RCE → OT/IT network में pivot |
| Application | Hard-coded या predictable AppKeys | Brute-force/decrypt traffic, sensors का impersonation |

---

## Recent vulnerabilities (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* ने ऐसे TCP packets स्वीकार किए जो Kerlink gateways पर stateful firewall rules को bypass कर देते थे, जिससे remote management interface exposure संभव हो गया। इसे क्रमशः 4.0.11 / 4.2.1 में fix किया गया।
* **Dragino LG01/LG308 series** – 2022-2024 की कई CVEs (जैसे 2022-45227 directory traversal, 2022-45228 CSRF) 2025 में भी unpatched देखी गईं; ये हजारों public gateways पर unauthenticated firmware dump या config overwrite enable करती हैं।
* Semtech *packet-forwarder UDP* overflow (unreleased advisory, patched 2023-10): 255 B से बड़े crafted uplink ने stack-smash ‑> RCE trigger किया, जिससे SX130x reference gateways पर असर पड़ा (Black Hat EU 2023 “LoRa Exploitation Reloaded” द्वारा खोजा गया)।

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

1. एक legitimate **JoinRequest** capture करें।
2. इसे तुरंत retransmit करें (या RSSI बढ़ाएं), इससे पहले कि original device फिर से transmit करे।
3. network-server एक नया DevAddr और session keys allocate करता है, जबकि target device पुराने session के साथ जारी रहता है → attacker vacant session का मालिक बन जाता है और forged uplinks inject कर सकता है।

### 3. Adaptive Data-Rate (ADR) downgrading

SF12/125 kHz को force करके airtime बढ़ाएं → gateway का duty-cycle समाप्त करें (denial-of-service), जबकि attacker पर battery impact कम रहे (सिर्फ network-level MAC commands भेजकर)।

### 4. Reactive jamming

*HackRF One*, जो GNU Radio flowgraph चला रहा है, preamble detect होने पर wide-band chirp trigger करता है – ≤200 mW TX के साथ सभी spreading factors को block करता है; 2 km range पर full outage मापा गया है।

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN frames को craft/parse/attack करना, DB-backed analyzers, brute-forcer | Docker image, Semtech UDP input को support करता है |
| **LoRaPWN** | OTAA को brute-force करने, downlinks generate करने और payloads decrypt करने वाला Trend Micro Python utility | Demo 2023 में released, SDR-agnostic |
| **LoRAttack** | USRP के साथ multi-channel sniffer + replay; PCAP/LoRaTap export करता है | Wireshark integration अच्छा है |
| **gr-lora / gr-lorawan** | Baseband TX/RX के लिए GNU Radio OOT blocks | Custom attacks की foundation |

---

## Defensive recommendations (pentester checklist)

1. सचमुच random DevNonce वाले **OTAA** devices को प्राथमिकता दें; duplicates monitor करें।
2. **LoRaWAN 1.1** enforce करें: 32-bit frame counters, distinct FNwkSIntKey / SNwkSIntKey।
3. Frame-counter को non-volatile memory (**ABP**) में store करें या OTAA पर migrate करें।
4. Root keys को firmware extraction से सुरक्षित रखने के लिए **secure-element** (ATECC608A/SX1262-TRX-SE) deploy करें।
5. Remote UDP packet-forwarder ports (1700/1701) disable करें या WireGuard/VPN के साथ restrict करें।
6. Gateways को updated रखें; Kerlink/Dragino 2024-patched images provide करते हैं।
7. **Traffic anomaly detection** (जैसे LAF analyzer) implement करें – counter resets, duplicate joins और अचानक होने वाले ADR changes को flag करें।<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
