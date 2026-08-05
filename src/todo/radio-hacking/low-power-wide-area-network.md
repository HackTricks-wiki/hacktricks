# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Uvod

**Low-Power Wide Area Network** (LPWAN) je grupa bežičnih mrežnih tehnologija male potrošnje i širokog područja, dizajniranih za **komunikaciju velikog dometa** pri niskoj bitskoj brzini.
Mogu doseći više od **šest milja**, a njihove **baterije** mogu trajati do **20 godina**.

Long Range (**LoRa**) je trenutno najzastupljeniji fizički sloj LPWAN-a, a njegova otvorena specifikacija MAC sloja je **LoRaWAN**.

---

## LPWAN, LoRa i LoRaWAN

* LoRa – fizički sloj Chirp Spread Spectrum (CSS) koji je razvio Semtech (proprietary, ali dokumentovan).
* LoRaWAN – otvoreni MAC/mrežni sloj koji održava LoRa-Alliance. Verzije 1.0.x i 1.1 su uobičajene na terenu.
* Tipična arhitektura: *end-device → gateway (packet-forwarder) → network-server → application-server*.

> **Security model** se oslanja na dva AES-128 root ključa (AppKey/NwkKey) koji izvode session ključeve tokom *join* procedure (OTAA) ili su hard-kodovani (ABP). Ako bilo koji ključ leak-uje, napadač dobija punu read/write sposobnost nad odgovarajućim saobraćajem.

---

## Sažetak attack surface-a

| Sloj | Slabost | Praktičan uticaj |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | 100 % gubitak paketa demonstriran pomoću jednog SDR-a i izlazne snage <1 W |
| MAC | Ponovna reprodukcija Join-Accept i data-frame poruka (ponovna upotreba nonce-a, prelivanje ABP brojača) | Spoofing uređaja, ubacivanje poruka, DoS |
| Network-Server | Nezaštićen packet-forwarder, slabi MQTT/UDP filteri, zastareli firmware gateway-a | RCE na gateway-ima → pivot u OT/IT mrežu |
| Application | Hard-kodovani ili predvidljivi AppKeys | Brute-force/dešifrovanje saobraćaja, impersonacija senzora |

---

## Nedavne ranjivosti (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* prihvatali su TCP pakete koji su zaobilazili stateful firewall pravila na Kerlink gateway-ima, omogućavajući izlaganje interfejsa za remote management. Ispravljeno u verzijama 4.0.11 / 4.2.1.
* **Dragino LG01/LG308 series** – Više CVE-ova iz perioda 2022-2024 (npr. 2022-45227 directory traversal, 2022-45228 CSRF) i dalje je primećeno kao nepatch-ovano tokom 2025; omogućavaju neautentifikovani firmware dump ili prepisivanje konfiguracije na hiljadama javnih gateway-a.
* Semtech *packet-forwarder UDP* overflow (neobjavljen advisory, patched 2023-10): posebno napravljen uplink veći od 255 B aktivirao je stack-smash ‑> RCE na referentnim SX130x gateway-ima (otkriveno na Black Hat EU 2023 „LoRa Exploitation Reloaded“).

---

## Praktične attack tehnike

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (ponovna upotreba DevNonce-a)

1. Snimite legitimni **JoinRequest**.
2. Odmah ga ponovo pošaljite (ili povećajte RSSI) pre nego što originalni uređaj ponovo pošalje zahtev.
3. Network-server dodeljuje novi DevAddr i session keys, dok ciljni uređaj nastavlja sa starom sesijom → napadač preuzima neiskorišćenu sesiju i može da ubacuje falsifikovane uplink poruke.

### 3. Snižavanje Adaptive Data-Rate (ADR)

Prisilite SF12/125 kHz da biste povećali vreme emitovanja → iscrpite duty-cycle gateway-a (denial-of-service), uz mali uticaj na bateriju napadača (dovoljno je slati MAC commands na nivou mreže).

### 4. Reactive jamming

*HackRF One* koji pokreće GNU Radio flowgraph aktivira širokopojasni chirp čim detektuje preamble – blokira sve spreading factors sa ≤200 mW TX; potpuni prekid rada izmeren je na dometu od 2 km .

---

## Offensive tooling (2025)

| Tool | Namena | Napomene |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Kreiranje/parsiranje/napad na LoRaWAN frames, analyzers sa DB podrškom, brute-forcer | Docker image, podržava Semtech UDP input |
| **LoRaPWN** | Trend Micro Python utility za brute OTAA, generisanje downlinks, dešifrovanje payloads | Demo objavljen 2023, SDR-agnostic |
| **LoRAttack** | Multi-channel sniffer + replay sa USRP; izvozi PCAP/LoRaTap | Dobra Wireshark integracija |
| **gr-lora / gr-lorawan** | GNU Radio OOT blocks za baseband TX/RX | Osnova za custom attacks |

---

## Defensive recommendations (pentester checklist)

1. Preferirajte uređaje sa **OTAA** i zaista nasumičnim DevNonce-om; nadgledajte duplikate.
2. Prisilite korišćenje **LoRaWAN 1.1**: 32-bitni frame counters, odvojeni FNwkSIntKey / SNwkSIntKey.
3. Čuvajte frame-counter u non-volatile memoriji (**ABP**) ili pređite na OTAA.
4. Uvedite **secure-element** (ATECC608A/SX1262-TRX-SE) radi zaštite root keys od ekstrakcije firmware-a.
5. Onemogućite udaljene UDP packet-forwarder portove (1700/1701) ili ih ograničite pomoću WireGuard/VPN-a.
6. Održavajte gateway-e ažurnim; Kerlink/Dragino obezbeđuju images sa zakrpama iz 2024.
7. Implementirajte **traffic anomaly detection** (npr. LAF analyzer) – označite resetovanja counter-a, duplirane join-ove i nagle ADR promene.<sup>[[1]](#references)</sup>



## Reference

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
