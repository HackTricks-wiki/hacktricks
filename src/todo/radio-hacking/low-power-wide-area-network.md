# Lae-Power Wye Area Network

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

**Lae-Power Wye Area Network** (LPWAN) is 'n groep draadlose, lae-krag, wye-area netwerk tegnologieë wat ontwerp is vir **langafstand kommunikasie** teen 'n lae bitoordragspoed. 
Hulle kan meer as **ses myl** bereik en hul **batterye** kan tot **20 jaar** hou.

Long Range (**LoRa**) is tans die mees toegepaste LPWAN fisiese laag en sy oop MAC-laag spesifikasie is **LoRaWAN**.

---

## LPWAN, LoRa, en LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) fisiese laag ontwikkel deur Semtech (besit, maar gedokumenteer).
* LoRaWAN – Oop MAC/Netwerk laag wat deur die LoRa-Alliance onderhou word. Weergawes 1.0.x en 1.1 is algemeen in die veld.
* Tipiese argitektuur: *eind-toestel → gateway (pakket-voorwaarts) → netwerk-bediener → toepassing-bediener*.

> Die **veiligheidsmodel** berus op twee AES-128 wortelsleutels (AppKey/NwkKey) wat sessiesleutels aflei tydens die *join* prosedure (OTAA) of hard-gecodeer is (ABP). As enige sleutel lek, verkry die aanvaller volle lees/skryf vermoë oor die ooreenstemmende verkeer.

---

## Aanval oppervlak opsomming

| Laag | Swakheid | Praktiese impak |
|-------|----------|------------------|
| PHY | Reaktiewe / selektiewe jamming | 100 % pakketverlies gedemonstreer met 'n enkele SDR en <1 W uitset |
| MAC | Join-Accept & data-raam herhaling (nonce hergebruik, ABP teenrol) | Toestel spoofing, boodskap inspuiting, DoS |
| Netwerk-Bediener | Onveilige pakket-voorwaarts, swak MQTT/UDP filters, verouderde gateway firmware | RCE op gateways → pivot in OT/IT netwerk |
| Toepassing | Hard-gecodeerde of voorspelbare AppKeys | Brute-force/dekripteer verkeer, verpersoonlik sensors |

---

## Onlangse kwesbaarhede (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* het TCP-pakkette aanvaar wat stateful firewall reëls op Kerlink gateways omseil, wat afstandsbestuur koppelvlak blootstelling moontlik gemaak het. Reggestel in 4.0.11 / 4.2.1 onderskeidelik.
* **Dragino LG01/LG308 reeks** – Meerdere 2022-2024 CVEs (bv. 2022-45227 gids traversering, 2022-45228 CSRF) steeds waargeneem onopgelos in 2025; stel nie-geverifieerde firmware dump of konfigurasie oorskry op duisende openbare gateways in.
* Semtech *pakket-voorwaarts UDP* oorgeloop (nie vrygestel advies, reggestel 2023-10): vervaardigde uplink groter as 255 B het stapel-slaan geaktiveer ‑> RCE op SX130x verwysingsgateways (gevind deur Black Hat EU 2023 “LoRa Exploitation Reloaded”).

---

## Praktiese aanval tegnieke

### 1. Sniff & Dekripteer verkeer
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (DevNonce hergebruik)

1. Capture 'n legitieme **JoinRequest**.
2. Hertransmit dit onmiddellik (of verhoog RSSI) voordat die oorspronklike toestel weer transmet.
3. Die netwerk-bediener toeken 'n nuwe DevAddr & sessiesleutels terwyl die teiken toestel met die ou sessie voortgaan → aanvaller besit 'n vakante sessie en kan vervalste uplinks inspuit.

### 3. Aanpasbare Data-Tempo (ADR) afgrading

Force SF12/125 kHz om lugtyd te verhoog → verbruik die pligsyklus van die gateway (denial-of-service) terwyl die battery-impak op die aanvaller laag bly (stuur net netwerk-vlak MAC-opdragte).

### 4. Reaktiewe jamming

*HackRF One* wat GNU Radio flowgraph uitvoer, aktiveer 'n wye-band chirp wanneer preamble gedetecteer word – blokkeer alle verspreidingsfaktore met ≤200 mW TX; volle uitval gemeet op 2 km afstand.

---

## Offensiewe gereedskap (2025)

| Tool | Doel | Aantekeninge |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Skep/parse/aanval LoRaWAN rame, DB-ondersteunde ontleders, brute-forcer | Docker beeld, ondersteun Semtech UDP invoer |
| **LoRaPWN** | Trend Micro Python nut om OTAA te brute, genereer afladings, dekripteer payloads | Demo vrygestel 2023, SDR-agnosties |
| **LoRAttack** | Multi-kanaal sniffer + replay met USRP; voer PCAP/LoRaTap uit | Goeie Wireshark integrasie |
| **gr-lora / gr-lorawan** | GNU Radio OOT blokke vir basisband TX/RX | Grondslag vir pasgemaakte aanvalle |

---

## Defensiewe aanbevelings (pentester kontrolelys)

1. Verkies **OTAA** toestelle met werklik ewekansige DevNonce; monitor duplikate.
2. Handhaaf **LoRaWAN 1.1**: 32-bis rame tellers, unieke FNwkSIntKey / SNwkSIntKey.
3. Stoor rame-teller in nie-vlugtige geheue (**ABP**) of migreer na OTAA.
4. Ontplooi **secure-element** (ATECC608A/SX1262-TRX-SE) om wortelsleutels teen firmware-uitkapping te beskerm.
5. Deaktiveer afstand UDP-pakket-forwarder poorte (1700/1701) of beperk met WireGuard/VPN.
6. Hou gateways opgedateer; Kerlink/Dragino bied 2024-gepatchte beelde.
7. Implementeer **verkeersanomalie-detektering** (bv. LAF ontleder) – merk teenstellingsherinstellings, duplikaat aansluitings, skielike ADR veranderinge.

## References

* LoRaWAN Auditing Framework (LAF) – [https://github.com/IOActive/laf](https://github.com/IOActive/laf)
* Trend Micro LoRaPWN oorsig – [https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
{{#include ../../banners/hacktricks-training.md}}
