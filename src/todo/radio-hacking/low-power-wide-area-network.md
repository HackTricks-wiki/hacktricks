# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

**Low-Power Wide Area Network** (LPWAN) is 'n groep draadlose, lae-krag, wye-area-netwerktegnologieë wat ontwerp is vir **langafstandkommunikasie** teen 'n lae bis-tempo.
Afhangend van die radio parameters, antenna, regulatoriese streek, terrein en duty cycle, kan LPWAN-ontplooiings deurset verruil vir dekking oor verskeie kilometer en 'n batterylewe van verskeie jare. Behandel verskaffer se reikafstand- en battery-syfers as ontwerpteikens eerder as waarborge.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) is tans die mees ontplooide LPWAN fisiese laag, en sy oop MAC-laag-spesifikasie is **LoRaWAN**.

---

## LPWAN, LoRa en LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) fisiese laag, ontwikkel deur Semtech (eiendomlik maar gedokumenteer).
* LoRaWAN – Oop MAC/Network-laag, onderhou deur die LoRa-Alliance. Weergawes 1.0.x en 1.1 is algemeen in die veld.
* Tipiese argitektuur: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> In LoRaWAN 1.1 gebruik die **security model** afsonderlike AES-128-toepassings- en netwerk-root keys om rolspesifieke session keys tydens OTAA af te lei. Vroeëre 1.0.x-ontplooiings gebruik normaalweg een AppKey om die netwerk- en toepassings-session keys af te lei, terwyl ABP session keys direk voorsien. Die vermoë wat uit 'n gelekte sleutel verkry word, hang dus af van die LoRaWAN-weergawe en watter sleutel blootgestel is.<sup>[[3]](#references)</sup>

---

## Opsomming van attack surface

| Laag | Swakheid | Praktiese impak |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Gelokaliseerde packet loss; doeltreffendheid hang af van link budget, tydsberekening, bandwydte en regulatoriese beperkings |
| MAC | Join- en data-frame-replay wanneer nonce/counter-status hergebruik word | Device-desynchronization, spoofing of injection indien die server/device replay-beskerming oortree |
| Network-Server | Onveilige packet-forwarder, swak MQTT/UDP-filters, verouderde gateway-firmware | RCE op gateways → pivot in OT/IT-netwerk |
| Application | Hard-coded of voorspelbare AppKeys | Brute-force/decrypt traffic, sensors impersonate |

---

## Verteenwoordigende implementeringskwesbaarhede

* **CVE-2024-29862** – ChirpStack Gateway Bridge-weergawes voor 4.0.11 en MQTT Forwarder-weergawes voor 4.2.1 kon aan 'n attacker-controlled MQTT broker koppel omdat TLS-server-certificate validation gedeaktiveer was. Dit kon credentials en gateway-traffic blootstel; gradeer op na die reggestelde releases.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 beskryf 'n unauthenticated `/lib/` directory listing wat 'n downloadable backup file bevat; CVE-2022-45228 is 'n low-severity CSRF in die logout page. Hierdie rekords bevestig nie die beweerde LG308-impact, configuration overwrite, population size of 2025 patch state nie.<sup>[[6]](#references)[[7]](#references)</sup>
* 'n Vroeëre weergawe van hierdie bladsy het 'n beweerde Semtech UDP packet-forwarder-kwessie beskryf as 'n **greater-than-255-byte crafted uplink causing a stack smash and RCE on SX130x reference gateways**, toegeskryf aan 'n “LoRa Exploitation Reloaded”-aanbieding by Black Hat Europe 2023 en 'n private patch van Oktober 2023. Daardie presiese besonderhede word hier as 'n navorsingsaanwysing behou, maar geen ooreenstemmende openbare advisory, aanbieding of patch kon bevestig word nie. Moenie die kwessie as 'n bekende kwesbaarheid beskou sonder om die geaffekteerde produk/weergawe en 'n verifieerbare primêre bron te verkry nie.

---

## Praktiese attack techniques

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
Hierdie commands behou die oorspronklike workflow as **illustrative syntax**; repository-uitleg en flags verskil tussen projekte/releases. Passiewe capture onthul nie 'n sterk AppKey nie. Offline guessing is slegs nuttig wanneer die root key swak genoeg is om gevind te word en 'n captured join exchange 'n waarde verskaf wat candidates kan valideer.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Toets OTAA-replay protection en nonce-state

1. In 'n gemagtigde test network, capture 'n legitieme **JoinRequest**.
2. Replay dieselfde request en bevestig dat die network server die hergebruikte `DevNonce` verwerp.
3. Reboot of reset die test device en herhaal die check om verlore nonce-state op te spoor. 'n Compliant server moet gebruikte nonces track; die replay van 'n JoinRequest alleen openbaar nie die nuut afgeleide session keys of gee die replayer beheer oor 'n session nie.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Adaptive Data-Rate (ADR)-downgrading

'n Attacker wat network-layer MAC commands kan authenticate—byvoorbeeld nadat die toepaslike network session key of network server compromised is—kan probeer om ondoeltreffende data-rate-parameters af te dwing en airtime te verhoog. 'n Nabygeleë unauthenticated transmitter kan nie ADR commands wettig uitreik bloot omdat dit 'n device address ken nie.<sup>[[3]](#references)</sup>

### 4. Reactive jamming

'n Reactive jammer kan transmit nadat dit 'n LoRa-preamble bespeur het en frames selektief disrupt. Die vorige bladsy het beweer dat 'n HackRF/GNU Radio-opstelling 'n volledige outage by **2 km met nie meer as 200 mW nie** veroorsaak het, maar geen ondersteunende measurement source is verskaf nie; behou daardie getalle slegs as 'n reproduction target, nie as 'n verwagte resultaat nie. Vereiste transmit power, timing, bandwidth, affected spreading factors en range is environment-specific. Toets slegs binne 'n gemagtigde, RF-contained setup en comply met plaaslike spectrum rules.

---

## Offensive tooling (2025)

| Tool | Doel | Notas |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Craft/parse/attack LoRaWAN frames, DB-backed analyzers, brute-forcer | Docker image; ondersteun Semtech UDP input<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Trend Micro Python utility om OTAA te brute-force, downlinks te generate en payloads te decrypt | Public research utility; verifieer supported hardware en protocol versions<sup>[[2]](#references)</sup> |
| **LoRAttack** | Research framework vir multi-channel LoRaWAN capture, session analysis, key derivation en replay testing | Beskryf in 'n 2024-meestersverhandeling; verkry en verifieer die presiese implementering voordat jy op die voorbeeldflags staatmaak<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | GNU Radio out-of-tree blocks vir LoRa-baseband-ontvangs of transceiver research | Projekte verskil in GNU Radio-compatibility en feature set<sup>[[9]](#references)</sup> |

---

## Defensive recommendations (pentester checklist)

1. Verkies **OTAA** en verifieer dat devices en servers die vereiste nonce-state persisteer; monitor rejected duplicate joins.
2. Verkies **LoRaWAN 1.1** waar dit ondersteun word sodat network functions distinct session keys en updated nonce handling gebruik.<sup>[[3]](#references)</sup>
3. Stoor frame-counter in non-volatile memory (**ABP**) of migreer na OTAA.
4. Deploy 'n geskikte **secure element** (byvoorbeeld ATECC608A in 'n supported design) om blootstelling van root keys in gewone firmware storage te verminder.
5. Moenie gekonfigureerde packet-forwarder UDP listeners (algemeen 1700) aan untrusted networks blootstel nie; authenticate/encrypt gateway backhaul of beperk dit met 'n VPN.
6. Hou gateways op vendor-supported firmware en bevestig die presiese model/version teenoor toepaslike advisories.
7. Implementeer **traffic anomaly detection** (bv. LAF analyzer) – flag counter resets, duplicate joins en skielike ADR changes.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN-oorsig](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1-spesifikasie](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1-streekparameters en join-synchronisasie](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU-verhandelingkatalogus - LPWAN-protokol-sekuriteitsanalise deur SDR-tegnologie te benut](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio-transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
