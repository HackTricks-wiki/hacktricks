# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduction

**Low-Power Wide Area Network** (LPWAN) ni kundi la teknolojia za mtandao wa wireless, zenye nguvu ya chini, na eneo kubwa zinazoundwa kwa ajili ya **mawasiliano ya umbali mrefu** kwa kiwango cha chini cha bit. 
Zinaweza kufikia zaidi ya **maili sita** na **betri** zao zinaweza kudumu hadi **miaka 20**.

Long Range (**LoRa**) kwa sasa ndiyo tabaka la LPWAN lililotumika zaidi na spesifikesheni yake ya MAC-layer ya wazi ni **LoRaWAN**.

---

## LPWAN, LoRa, na LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) tabaka la kimwili lililoundwa na Semtech (miliki lakini imeandikwa).
* LoRaWAN – Tabaka la MAC/Network la wazi linaloshughulikiwa na LoRa-Alliance. Matoleo 1.0.x na 1.1 ni ya kawaida katika uwanja.
* Muundo wa kawaida: *kifaa cha mwisho → lango (packet-forwarder) → seva ya mtandao → seva ya programu*.

> **Mfano wa usalama** unategemea funguo mbili za msingi za AES-128 (AppKey/NwkKey) ambazo zinapata funguo za kikao wakati wa mchakato wa *kujiunga* (OTAA) au zimeandikwa kwa ngumu (ABP). Ikiwa funguo yoyote inavuja, mshambuliaji anapata uwezo kamili wa kusoma/kandika juu ya trafiki inayohusiana.

---

## Muhtasari wa uso wa shambulio

| Tabaka | Udhaifu | Athari halisi |
|-------|----------|------------------|
| PHY | Jamming ya reaktivi / ya kuchagua | Upotevu wa pakiti 100 % umeonyeshwa kwa SDR moja na pato <1 W |
| MAC | Kujiunga-Kubali & kurudiwa kwa data-frame (tena matumizi ya nonce, ABP counter rollover) | Ulaghai wa kifaa, sindano ya ujumbe, DoS |
| Network-Server | Packet-forwarder isiyo salama, filters dhaifu za MQTT/UDP, firmware ya lango isiyosasishwa | RCE kwenye lango → kuhamasisha kwenye mtandao wa OT/IT |
| Application | AppKeys zilizoandikwa kwa ngumu au zinazoweza kutabirika | Kujaribu nguvu/kufichua trafiki, kujifanya kuwa sensorer |

---

## Uthibitisho wa hivi karibuni (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* ilikubali pakiti za TCP ambazo zilipita sheria za firewall za hali kwenye lango za Kerlink, kuruhusu kufichuliwa kwa kiolesura cha usimamizi wa mbali. Imefanyiwa marekebisho katika 4.0.11 / 4.2.1 mtawalia.
* **Dragino LG01/LG308 series** – CVEs nyingi za 2022-2024 (mfano 2022-45227 directory traversal, 2022-45228 CSRF) bado zinaonekana hazijarekebishwa mwaka 2025; wezesha dump ya firmware isiyo na uthibitisho au kuandika over config kwenye maelfu ya lango za umma.
* Semtech *packet-forwarder UDP* overflow (tahadhari isiyoachiliwa, ilirekebishwa 2023-10): uplink iliyoundwa kubwa zaidi ya 255 B ilizindua stack-smash ‑> RCE kwenye lango za rejea za SX130x (ilionekana na Black Hat EU 2023 “LoRa Exploitation Reloaded”).

---

## Mbinu za shambulio za vitendo

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (DevNonce reuse)

1. Pata **JoinRequest** halali.
2. Mara moja itumie tena (au ongeza RSSI) kabla ya kifaa cha asili kutuma tena.
3. Mtandao-server inatoa DevAddr mpya & funguo za kikao wakati kifaa kilicholengwa kinaendelea na kikao cha zamani → mshambuliaji anamiliki kikao kilichokuwa wazi na anaweza kuingiza uplinks za uongo.

### 3. Adaptive Data-Rate (ADR) downgrading

Lazimisha SF12/125 kHz kuongeza muda wa hewa → choma duty-cycle ya gateway (denial-of-service) wakati ukihifadhi athari za betri chini kwa mshambuliaji (tuma tu amri za MAC za kiwango cha mtandao).

### 4. Reactive jamming

*HackRF One* inayoendesha GNU Radio flowgraph inasababisha chirp ya bendi pana kila wakati preamble inagunduliwa – inazuia sababu zote za kueneza zikiwa ≤200 mW TX; kukosekana kabisa kunapimwa kwa umbali wa 2 km.

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

* LoRaWAN Auditing Framework (LAF) – https://github.com/IOActive/laf
* Trend Micro LoRaPWN overview – https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a
{{#include ../../banners/hacktricks-training.md}}
