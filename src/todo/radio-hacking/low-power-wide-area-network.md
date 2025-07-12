# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduction

**Low-Power Wide Area Network** (LPWAN) je grupa bežičnih, niskopotrošnih, širokopojasnih mrežnih tehnologija dizajniranih za **dugometražne komunikacije** sa niskom brzinom prenosa podataka. 
Mogu dostići više od **šest milja** i njihove **baterije** mogu trajati do **20 godina**.

Long Range (**LoRa**) je trenutno najrasprostranjeniji LPWAN fizički sloj, a njegova otvorena MAC-sloj specifikacija je **LoRaWAN**.

---

## LPWAN, LoRa, i LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) fizički sloj razvijen od strane Semtech (vlasnički, ali dokumentovan).
* LoRaWAN – Otvoreni MAC/mrežni sloj koji održava LoRa-Alliance. Verzije 1.0.x i 1.1 su uobičajene na terenu.
* Tipična arhitektura: *kraj uređaja → prolaznik (packet-forwarder) → mrežni server → aplikacioni server*.

> **Model bezbednosti** se oslanja na dva AES-128 korenska ključa (AppKey/NwkKey) koja izvode sesijske ključeve tokom *join* procedure (OTAA) ili su hard-kodirani (ABP). Ako bilo koji ključ procuri, napadač dobija potpunu mogućnost čitanja/pisanja nad odgovarajućim saobraćajem.

---

## Sažetak napadačke površine

| Sloj | Slabost | Praktični uticaj |
|-------|----------|------------------|
| PHY | Reaktivno / selektivno ometanje | 100 % gubitak paketa demonstriran sa jednim SDR i <1 W izlazom |
| MAC | Join-Accept & ponavljanje podataka (ponovna upotreba nonce, ABP counter rollover) | Lažno predstavljanje uređaja, injekcija poruka, DoS |
| Mrežni server | Nesiguran packet-forwarder, slabi MQTT/UDP filteri, zastarela firmware prolaznika | RCE na prolaznicima → pivot u OT/IT mrežu |
| Aplikacija | Hard-kodirani ili predvidljivi AppKeys | Brute-force/dekripcija saobraćaja, lažno predstavljanje senzora |

---

## Nedavne ranjivosti (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* prihvatao TCP pakete koji su zaobišli pravila stanja vatrozida na Kerlink prolaznicima, omogućavajući izlaganje udaljenog upravljačkog interfejsa. Ispravljeno u 4.0.11 / 4.2.1.
* **Dragino LG01/LG308 serija** – Više CVE-a iz 2022-2024 (npr. 2022-45227 prolaz kroz direktorijum, 2022-45228 CSRF) još uvek primećeni bez zakrpa 2025; omogućava neautentifikovano preuzimanje firmware-a ili prepisivanje konfiguracije na hiljadama javnih prolaznika.
* Semtech *packet-forwarder UDP* prelivanje (neobjavljeno obaveštenje, zakrpljeno 2023-10): kreirani uplink veći od 255 B izazvao stack-smash ‑> RCE na SX130x referentnim prolaznicima (otkriveno na Black Hat EU 2023 “LoRa Exploitation Reloaded”).

---

## Praktične napadačke tehnike

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (ponovna upotreba DevNonce)

1. Zabeležite legitimni **JoinRequest**.
2. Odmah ga ponovo prenesite (ili povećajte RSSI) pre nego što originalni uređaj ponovo prenese.
3. Mrežni server dodeljuje novu DevAddr i sesijske ključeve dok ciljni uređaj nastavlja sa starom sesijom → napadač poseduje praznu sesiju i može da ubaci lažne uplinke.

### 3. Smanjenje adaptivnog protoka podataka (ADR)

Prisilite SF12/125 kHz da poveća vreme prenosa → iscrpite radni ciklus prolaza (usluga uskraćivanja) dok održavate mali uticaj na bateriju napadača (samo šaljite MAC komande na mrežnom nivou).

### 4. Reaktivno ometanje

*HackRF One* koji pokreće GNU Radio flowgraph aktivira širokopojasni chirp kada se detektuje preambula – blokira sve faktore širenja sa ≤200 mW TX; potpuni prekid meren na udaljenosti od 2 km.

---

## Ofanzivni alati (2025)

| Alat | Svrha | Napomene |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Kreiranje/parsiranje/napad na LoRaWAN okvire, analitičari sa DB podrškom, brute-forcer | Docker slika, podržava Semtech UDP ulaz |
| **LoRaPWN** | Trend Micro Python alat za brute OTAA, generisanje downlink-ova, dešifrovanje tereta | Demo objavljen 2023, SDR-agnostičan |
| **LoRAttack** | Multi-kanalni sniffer + ponovna reprodukcija sa USRP; izvozi PCAP/LoRaTap | Dobra integracija sa Wireshark-om |
| **gr-lora / gr-lorawan** | GNU Radio OOT blokovi za osnovni TX/RX | Osnova za prilagođene napade |

---

## Preporuke za odbranu (checklist za pentestere)

1. Preferirajte **OTAA** uređaje sa zaista nasumičnim DevNonce; pratite duplikate.
2. Sprovodite **LoRaWAN 1.1**: 32-bitni brojači okvira, različiti FNwkSIntKey / SNwkSIntKey.
3. Čuvajte brojač okvira u nevolatilnoj memoriji (**ABP**) ili migrirajte na OTAA.
4. Implementirajte **secure-element** (ATECC608A/SX1262-TRX-SE) da zaštitite korenske ključeve od ekstrakcije firmvera.
5. Onemogućite udaljene UDP portove za prosleđivanje paketa (1700/1701) ili ih ograničite sa WireGuard/VPN.
6. Održavajte prolaze ažuriranim; Kerlink/Dragino pružaju slike sa zakrpama iz 2024.
7. Implementirajte **otkrivanje anomalija u saobraćaju** (npr. LAF analitičar) – označite resetovanja brojača, duplikate pridruživanja, iznenadne promene ADR-a.

## Reference

* LoRaWAN Auditing Framework (LAF) – https://github.com/IOActive/laf
* Trend Micro LoRaPWN pregled – https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a
{{#include ../../banners/hacktricks-training.md}}
