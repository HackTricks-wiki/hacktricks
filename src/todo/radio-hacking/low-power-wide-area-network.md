# Lae-krag-wyegebiednetwerk

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

**Lae-krag-wyegebiednetwerk** (LPWAN) is ’n groep draadlose, lae-krag-wyegebiednetwerktegnologieë wat ontwerp is vir **langafstandkommunikasie** teen ’n lae bis-tempo.
Hulle kan meer as **ses myl** bereik, en hul **batterye** kan tot **20 jaar** hou.

Long Range (**LoRa**) is tans die mees ontplooide LPWAN-fisiese laag, en die oop MAC-laag-spesifikasie daarvan is **LoRaWAN**.

---

## LPWAN, LoRa en LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS)-fisiese laag wat deur Semtech ontwikkel is (eiendomsregtelik, maar gedokumenteer).
* LoRaWAN – Oop MAC-/netwerklaag wat deur die LoRa-Alliance onderhou word. Weergawes 1.0.x en 1.1 is algemeen in die veld.
* Tipiese argitektuur: *end-device → gateway (packet-forwarder) → network-server → application-server*.

> Die **sekuriteitsmodel** maak staat op twee AES-128-wortelsleutels (AppKey/NwkKey) wat sessiesleutels aflei tydens die *join*-prosedure (OTAA), of wat hardgekodeer is (ABP). As enige sleutel lek, verkry die aanvaller volledige lees-/skryfvermoë oor die ooreenstemmende verkeer.

---

## Opsomming van die aanvaloppervlak

| Laag | Swakheid | Praktiese impak |
|-------|----------|------------------|
| PHY | Reaktiewe / selektiewe jamming | 100 % pakkieverlies gedemonstreer met ’n enkele SDR en <1 W uitset |
| MAC | Join-Accept- en data-frame-replay (nonce-hergebruik, ABP-telleromloop) | Toestel-spoofing, boodskap-inspuiting, DoS |
| Network-Server | Onveilige packet-forwarder, swak MQTT/UDP-filters, verouderde gateway-firmware | RCE op gateways → pivot na OT/IT-netwerk |
| Application | Hardgekodeerde of voorspelbare AppKeys | Brute-force/decrypt traffic, sensors naboots |

---

## Onlangse kwesbaarhede (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* het TCP-pakkette aanvaar wat stateful firewall-reëls op Kerlink-gateways omseil het, wat blootstelling van die afgeleë bestuurskoppelvlak moontlik gemaak het. Reggestel in onderskeidelik 4.0.11 / 4.2.1 .
* **Dragino LG01/LG308 series** – Veelvuldige 2022-2024-CVE’s (bv. 2022-45227 directory traversal, 2022-45228 CSRF) word steeds in 2025 ongepatch waargeneem; dit aktiveer ’n ongeauthentiseerde firmware-dump of konfigurasie-oorskrywing op duisende openbare gateways .
* Semtech *packet-forwarder UDP* overflow (onuitgereikte advies, gepatch in 2023-10): ’n Gespesifiseerde uplink groter as 255 B het stack-smash ‑> RCE op SX130x-verwysingsgateways veroorsaak (gevind deur Black Hat EU 2023 “LoRa Exploitation Reloaded”).

---

## Praktiese aanvalstegnieke

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (DevNonce reuse)

1. Capture ’n legitieme **JoinRequest**.
2. Stuur dit onmiddellik weer uit (of verhoog RSSI) voordat die oorspronklike toestel weer uitstuur.
3. Die netwerkbediener ken ’n nuwe DevAddr en sessiesleutels toe terwyl die teikentoestel met die ou sessie voortgaan → die aanvaller besit die ongebruikte sessie en kan vervalste uplinks inspuit.

### 3. Adaptive Data-Rate (ADR) downgrading

Dwing SF12/125 kHz af om airtime te verhoog → put die gateway se duty-cycle uit (denial-of-service) terwyl die impak op die aanvaller se battery laag bly (stuur bloot MAC commands op netwerkvlak).

### 4. Reactive jamming

*HackRF One* wat GNU Radio flowgraph uitvoer, aktiveer ’n wide-band chirp wanneer preamble bespeur word – blokkeer alle spreading factors met ≤200 mW TX; volledige onderbreking is op ’n afstand van 2 km gemeet .

---

## Offensive tooling (2025)

| Tool | Doel | Aantekeninge |
|------|------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Stel LoRaWAN frames saam/parseer dit, DB-backed analyzers, brute-forcer | Docker image, ondersteun Semtech UDP input |
| **LoRaPWN** | Trend Micro Python utility om OTAA te brute-force, downlinks te genereer en payloads te decrypt | Demo in 2023 vrygestel, SDR-agnostic |
| **LoRAttack** | Multi-channel sniffer + replay met USRP; exporteer PCAP/LoRaTap | Goeie Wireshark-integrasie |
| **gr-lora / gr-lorawan** | GNU Radio OOT blocks vir baseband TX/RX | Grondslag vir custom attacks |

---

## Defensive recommendations (pentester-kontrolelys)

1. Verkies **OTAA**-toestelle met werklik random DevNonce; monitor duplikate.
2. Dwing **LoRaWAN 1.1** af: 32-bit frame counters, afsonderlike FNwkSIntKey / SNwkSIntKey.
3. Stoor frame-counter in non-volatile memory (**ABP**) of migreer na OTAA.
4. Ontplooi ’n **secure-element** (ATECC608A/SX1262-TRX-SE) om root keys teen firmware extraction te beskerm.
5. Deaktiveer remote UDP packet-forwarder-poorte (1700/1701) of beperk dit met WireGuard/VPN.
6. Hou gateways opgedateer; Kerlink/Dragino verskaf 2024-patched images.
7. Implementeer **traffic anomaly detection** (bv. LAF analyzer) – merk counter resets, duplicate joins en skielike ADR changes.<sup>[[1]](#references)</sup>



## Verwysings

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
