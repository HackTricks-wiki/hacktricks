# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

**Low-Power Wide Area Network** (LPWAN) ni kundi la teknolojia za wireless, low-power, wide-area network zilizoundwa kwa ajili ya **mawasiliano ya masafa marefu** kwa bit rate ya chini.
Zinaweza kufikia zaidi ya **maili sita**, na **betri** zake zinaweza kudumu hadi **miaka 20**.

Long Range (**LoRa**) kwa sasa ndiyo physical layer ya LPWAN inayotumika zaidi, na specification yake ya wazi ya MAC-layer ni **LoRaWAN**.

---

## LPWAN, LoRa, and LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) physical layer iliyotengenezwa na Semtech (proprietary lakini documented).
* LoRaWAN – Open MAC/Network layer inayodumishwa na LoRa-Alliance. Versions 1.0.x na 1.1 ni za kawaida kwenye field.
* Typical architecture: *end-device → gateway (packet-forwarder) → network-server → application-server*.

> **Security model** inategemea root keys mbili za AES-128 (AppKey/NwkKey) zinazozalisha session keys wakati wa utaratibu wa *join* (OTAA), au huwa hard-coded (ABP). Ikiwa key yoyote inaleak, attacker hupata uwezo kamili wa kusoma/kuandika traffic inayohusika.

---

## Muhtasari wa attack surface

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | 100 % packet loss ilionyeshwa kwa kutumia SDR moja na output ya chini ya 1 W |
| MAC | Join-Accept & data-frame replay (nonce reuse, ABP counter rollover) | Device spoofing, message injection, DoS |
| Network-Server | Insecure packet-forwarder, weak MQTT/UDP filters, outdated gateway firmware | RCE kwenye gateways → pivot kuingia kwenye OT/IT network |
| Application | Hard-coded au predictable AppKeys | Brute-force/decrypt traffic, impersonate sensors |

---

## Vulnerabilities za hivi karibuni (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* zilikubali TCP packets zilizopita stateful firewall rules kwenye Kerlink gateways, hivyo kuruhusu remote management interface exposure. Zilirekebishwa katika 4.0.11 / 4.2.1 mtawalia .
* **Dragino LG01/LG308 series** – CVEs nyingi za 2022-2024 (k.m. 2022-45227 directory traversal, 2022-45228 CSRF) bado zilionekana hazijafanyiwa patch mwaka 2025; ziliwezesha firmware dump isiyohitaji authentication au config overwrite kwenye maelfu ya public gateways .
* Semtech *packet-forwarder UDP* overflow (unreleased advisory, patched 2023-10): crafted uplink kubwa kuliko 255 B ilisababisha stack-smash ‑> RCE kwenye SX130x reference gateways (iliyogunduliwa na Black Hat EU 2023 “LoRa Exploitation Reloaded”).

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

1. Nasa **JoinRequest** halali.
2. Itume tena mara moja (au ongeza RSSI) kabla kifaa asili hakijatuma tena.
3. Network-server hutenga DevAddr mpya na session keys huku kifaa lengwa kikiendelea na session ya zamani → attacker anamiliki session iliyo wazi na anaweza kuingiza uplinks ghushi.

### 3. Adaptive Data-Rate (ADR) downgrading

Lazimisha SF12/125 kHz ili kuongeza airtime → tumia duty-cycle ya gateway hadi kuisha (denial-of-service), huku ukipunguza athari kwa betri ya attacker (tuma tu network-level MAC commands).

### 4. Reactive jamming

*HackRF One* inayoendesha GNU Radio flowgraph huanzisha wide-band chirp kila preamble inapogunduliwa – huzuia spreading factors zote kwa ≤200 mW TX; full outage ilipimwa katika umbali wa 2 km .

---

## Zana za mashambulizi (2025)

| Zana | Kusudi | Maelezo |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Kutengeneza/kuchanganua/kushambulia LoRaWAN frames, DB-backed analyzers, brute-forcer | Docker image, inasaidia Semtech UDP input |
| **LoRaPWN** | Python utility ya Trend Micro ya kufanya brute OTAA, kutengeneza downlinks na kusimbua payloads | Demo ilitolewa 2023, SDR-agnostic |
| **LoRAttack** | Multi-channel sniffer + replay yenye USRP; huhamisha data kama PCAP/LoRaTap | Ujumuishaji mzuri na Wireshark |
| **gr-lora / gr-lorawan** | GNU Radio OOT blocks za baseband TX/RX | Msingi wa custom attacks |

---

## Mapendekezo ya ulinzi (pentester checklist)

1. Pendelea vifaa vya **OTAA** vyenye DevNonce random kweli; fuatilia duplicates.
2. Tekeleza **LoRaWAN 1.1**: frame counters za biti 32, FNwkSIntKey / SNwkSIntKey tofauti.
3. Hifadhi frame-counter kwenye non-volatile memory (**ABP**) au hamia OTAA.
4. Tumia **secure-element** (ATECC608A/SX1262-TRX-SE) kulinda root keys dhidi ya firmware extraction.
5. Zima remote UDP packet-forwarder ports (1700/1701) au zuia ufikiaji wake kwa WireGuard/VPN.
6. Weka gateways zilizosasishwa; Kerlink/Dragino hutoa images zilizopatiwa marekebisho ya 2024.
7. Tekeleza **traffic anomaly detection** (kwa mfano, LAF analyzer) – weka alama kwenye counter resets, duplicate joins na mabadiliko ya ghafla ya ADR.<sup>[[1]](#references)</sup>



## Marejeo

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
