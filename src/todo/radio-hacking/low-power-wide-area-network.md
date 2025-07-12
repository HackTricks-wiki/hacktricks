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
| Network-Server | Packet-forwarder isiyo salama, filters dhaifu za MQTT/UDP, firmware ya lango isiyosasishwa | RCE kwenye lango → kuhamia kwenye mtandao wa OT/IT |
| Application | AppKeys zilizoandikwa kwa ngumu au zinazoweza kutabirika | Kujaribu nguvu/kufichua trafiki, kujifanya kuwa sensorer |

---

## Uthibitisho wa hivi karibuni (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* ilikubali pakiti za TCP ambazo zilipita sheria za firewall za hali kwenye lango za Kerlink, kuruhusu kufichuliwa kwa kiolesura cha usimamizi wa mbali. Imefanyiwa marekebisho katika 4.0.11 / 4.2.1 mtawalia.
* **Dragino LG01/LG308 series** – CVEs nyingi za 2022-2024 (mfano 2022-45227 directory traversal, 2022-45228 CSRF) bado zinaonekana hazijarekebishwa mwaka 2025; wezesha dump ya firmware isiyo na uthibitisho au kuandika over config kwenye maelfu ya lango za umma.
* Semtech *packet-forwarder UDP* overflow (tahadhari isiyoachiliwa, ilirekebishwa 2023-10): uplink iliyoundwa kubwa zaidi ya 255 B ilichochea stack-smash ‑> RCE kwenye lango za rejea za SX130x (ilionekana na Black Hat EU 2023 “LoRa Exploitation Reloaded”).

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
### 2. OTAA join-replay (Kurudi kwa DevNonce)

1. Pata **JoinRequest** halali.
2. Mara moja itumie tena (au ongeza RSSI) kabla ya kifaa asilia kutuma tena.
3. Mtandao-server inatoa DevAddr mpya & funguo za kikao wakati kifaa kilicholengwa kinaendelea na kikao cha zamani → mshambuliaji anamiliki kikao kilichokuwa wazi na anaweza kuingiza uplinks za uongo.

### 3. Adaptive Data-Rate (ADR) kudunisha

Lazimisha SF12/125 kHz kuongeza muda wa hewa → choma mzunguko wa wajibu wa lango (kukataa huduma) wakati ukihifadhi athari za betri chini kwa mshambuliaji (tuma tu amri za MAC za kiwango cha mtandao).

### 4. Jamming ya majibu

*HackRF One* inayoendesha GNU Radio flowgraph inasababisha chirp ya bendi pana kila wakati preamble inagunduliwa – inazuia sababu zote za kueneza zikiwa ≤200 mW TX; kukosekana kabisa kunapimwa kwa umbali wa 2 km.

---

## Zana za mashambulizi (2025)

| Zana | Kusudi | Maelezo |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Tengeneza/pitia/shambulia fremu za LoRaWAN, wachambuzi wanaoungwa mkono na DB, brute-forcer | Picha ya Docker, inasaidia Semtech UDP input |
| **LoRaPWN** | Zana ya Python ya Trend Micro kutekeleza OTAA, kuunda downlinks, kufungua payloads | Onyesho lililotolewa 2023, SDR-agnostic |
| **LoRAttack** | Sniffer wa chaneli nyingi + replay na USRP; inasafirisha PCAP/LoRaTap | Uunganisho mzuri wa Wireshark |
| **gr-lora / gr-lorawan** | Blocks za GNU Radio OOT kwa TX/RX ya baseband | Msingi wa mashambulizi maalum |

---

## Mapendekezo ya kujihami (orodha ya ukaguzi wa pentester)

1. Prefer **OTAA** vifaa vyenye DevNonce halisi za nasibu; angalia nakala.
2. Lazimisha **LoRaWAN 1.1**: 32-bit frame counters, funguo tofauti za FNwkSIntKey / SNwkSIntKey.
3. Hifadhi frame-counter katika kumbukumbu isiyohamishika (**ABP**) au hamasisha kwa OTAA.
4. Weka **secure-element** (ATECC608A/SX1262-TRX-SE) kulinda funguo za mzizi dhidi ya uchimbaji wa firmware.
5. Zima bandari za kupeleka UDP za mbali (1700/1701) au punguza kwa WireGuard/VPN.
6. Weka lango zikiwa za kisasa; Kerlink/Dragino hutoa picha zilizorekebishwa za 2024.
7. Tekeleza **ugunduzi wa anomali za trafiki** (mfano, mchambuzi wa LAF) – alama upya wa kaunta, kujiunga kwa nakala, mabadiliko ya ghafla ya ADR.

## Marejeo

* LoRaWAN Auditing Framework (LAF) – [https://github.com/IOActive/laf](https://github.com/IOActive/laf)
* Muhtasari wa Trend Micro LoRaPWN – [https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
{{#include ../../banners/hacktricks-training.md}}
