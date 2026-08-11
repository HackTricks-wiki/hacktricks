# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Uvod

**Low-Power Wide Area Network** (LPWAN) je grupa bežičnih tehnologija za mreže širokog područja i male potrošnje, dizajniranih za **komunikaciju velikog dometa** uz malu brzinu prenosa podataka.
U zavisnosti od radio-parametara, antene, regulatornog regiona, terena i radnog ciklusa, LPWAN deployments mogu žrtvovati propusni opseg zarad pokrivanja od više kilometara i višegodišnjeg trajanja baterije. Vrednosti dometa i trajanja baterije koje navodi proizvođač posmatrajte kao ciljeve pri projektovanju, a ne kao garancije.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) je trenutno najrasprostranjeniji LPWAN fizički sloj, a njegova otvorena specifikacija MAC sloja je **LoRaWAN**.

---

## LPWAN, LoRa i LoRaWAN

* LoRa – fizički sloj Chirp Spread Spectrum (CSS) koji je razvio Semtech (proprietary, ali dokumentovan).
* LoRaWAN – otvoreni MAC/Network sloj koji održava LoRa-Alliance. Verzije 1.0.x i 1.1 su uobičajene u praksi.
* Tipična arhitektura: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> U LoRaWAN 1.1, **security model** koristi odvojene AES-128 aplikacione i mrežne root ključeve za izvođenje session ključeva specifičnih za uloge tokom OTAA procesa. Ranije deployments verzije 1.0.x obično koriste jedan AppKey za izvođenje mrežnih i aplikacionih session ključeva, dok ABP direktno provisionuje session ključeve. Mogućnosti dobijene iz leaked ključa zato zavise od LoRaWAN verzije i od toga koji je ključ bio exposed.<sup>[[3]](#references)</sup>

---

## Sažetak attack surface-a

| Sloj | Slabost | Praktični uticaj |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Lokalizovani gubitak paketa; efikasnost zavisi od link budget-a, tajminga, bandwidth-a i regulatornih ograničenja |
| MAC | Replay join i data-frame poruka kada se stanje nonce-a/counter-a ponovo koristi | Desinhronizacija uređaja, spoofing ili injection ako server/uređaj krši replay zaštite |
| Network-Server | Nezaštićen packet-forwarder, slabi MQTT/UDP filteri, zastareo firmware gateway-a | RCE na gateway-ima → pivot u OT/IT mrežu |
| Application | Hard-coded ili predvidljivi AppKeys | Brute-force/decrypt saobraćaja, impersonacija senzora |

---

## Reprezentativne ranjivosti implementacija

* **CVE-2024-29862** – Pogođene verzije ChirpStack Gateway Bridge-a pre 4.0.11 i MQTT Forwarder-a pre 4.2.1 mogle su da se povežu na MQTT broker pod kontrolom napadača zato što je validacija TLS server-certificate-a bila onemogućena. Ovo je moglo da izloži credentials i saobraćaj gateway-a; pređite na verzije sa ispravkom.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 opisuje neautentifikovani listing direktorijuma `/lib/` koji sadrži backup fajl dostupan za preuzimanje; CVE-2022-45228 je CSRF niskog intenziteta na logout stranici. Ovi zapisi ne potvrđuju navodni uticaj na LG308, prepisivanje konfiguracije, veličinu populacije niti stanje patch-a iz 2025. godine.<sup>[[6]](#references)[[7]](#references)</sup>
* Ranija verzija ove stranice opisivala je navodni Semtech UDP packet-forwarder problem kao **crafted uplink veći od 255 bajtova koji izaziva stack smash i RCE na SX130x referentnim gateway-ima**, pripisan prezentaciji „LoRa Exploitation Reloaded“ na Black Hat Europe 2023 i privatnom patch-u iz oktobra 2023. Ti precizni detalji su ovde zadržani kao istraživački trag, ali nije bilo moguće potvrditi odgovarajući javni advisory, prezentaciju ili patch. Ne smatrajte ovaj problem poznatom ranjivošću bez pribavljanja pogođenog proizvoda/verzije i proverljivog primarnog izvora.

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
Ove komande čuvaju originalni workflow kao **ilustrativnu sintaksu**; raspored repozitorijuma i flagovi razlikuju se između projekata/izdanja. Pasivno presretanje ne otkriva jak AppKey. Offline pogađanje je korisno samo kada je root key dovoljno slab da može da se pronađe i kada uhvaćena join razmena pruža vrednost za validaciju kandidata.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Testiranje OTAA zaštite od replay napada i stanja nonce vrednosti

1. U autorizovanoj testnoj mreži uhvatite legitiman **JoinRequest**.
2. Ponovite isti zahtev i potvrdite da network server odbija ponovo upotrebljeni `DevNonce`.
3. Ponovo pokrenite ili resetujte testni uređaj i ponovite proveru da biste otkrili izgubljeno stanje nonce vrednosti. Server usklađen sa specifikacijom mora da prati iskorišćene nonce vrednosti; samo ponavljanje JoinRequest-a ne otkriva novoderivane session keys niti omogućava napadaču koji ponavlja zahtev da preuzme kontrolu nad sesijom.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Snižavanje Adaptive Data-Rate-a (ADR)

Napadač koji može da se autentifikuje za network-layer MAC komande — na primer, nakon kompromitovanja odgovarajućeg network session key-a ili network server-a — može pokušati da nametne neefikasne parametre data-rate-a i poveća airtime. Obližnji neautentifikovani transmitter ne može legitimno da izdaje ADR komande samo zato što zna adresu uređaja.<sup>[[3]](#references)</sup>

### 4. Reactive jamming

Reactive jammer može da emituje nakon detektovanja LoRa preamble-a i selektivno ometa frame-ove. Prethodna stranica je tvrdila da je HackRF/GNU Radio setup izazvao potpuni prekid rada na **2 km sa najviše 200 mW**, ali nije naveden izvor merenja koji to podržava; te vrednosti zadržite samo kao cilj za reprodukciju, a ne kao očekivani rezultat. Potrebna transmit power, timing, bandwidth, pogođeni spreading factors i domet zavise od okruženja. Testirajte samo u autorizovanom, RF-contained setup-u i poštujte lokalna pravila za spectrum.

---

## Alati za napad (2025)

| Tool | Svrha | Napomene |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Kreiranje/parsiranje/napad na LoRaWAN frame-ove, analyzers sa DB backend-om, brute-forcer | Docker image; podržava Semtech UDP input<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Trend Micro Python utility za brute OTAA, generisanje downlink-ova i dešifrovanje payload-a | Public research utility; proverite podržani hardware i verzije protokola<sup>[[2]](#references)</sup> |
| **LoRAttack** | Research framework za multi-channel LoRaWAN capture, analizu sesije, key derivation i replay testing | Opisan u master radu iz 2024. godine; pre oslanjanja na example flags pribavite i proverite tačnu implementaciju<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | GNU Radio out-of-tree blocks za LoRa baseband prijem ili transceiver research | Projekti se razlikuju po kompatibilnosti sa GNU Radio-om i skupu funkcija<sup>[[9]](#references)</sup> |

---

## Defanzivne preporuke (pentester kontrolna lista)

1. Prednost dajte **OTAA** i proverite da uređaji i serveri čuvaju zahtevano stanje nonce vrednosti; pratite odbijene duplirane join-ove.
2. Prednost dajte **LoRaWAN 1.1** gde je podržan, kako bi network funkcije koristile odvojene session keys i ažurirano upravljanje nonce vrednostima.<sup>[[3]](#references)</sup>
3. Čuvajte frame-counter u non-volatile memory (**ABP**) ili pređite na OTAA.
4. Implementirajte odgovarajući **secure element** (na primer, ATECC608A u podržanom dizajnu) da biste smanjili izloženost root keys u uobičajenom firmware storage-u.
5. Ne izlažite konfigurisane UDP listenere packet-forwarder-a (najčešće 1700) nepouzdanim mrežama; autentifikujte/enkriptujte gateway backhaul ili ga ograničite pomoću VPN-a.
6. Održavajte gateway-e na firmware-u koji podržava vendor i proverite tačan model/verziju u odnosu na relevantne advisories.
7. Implementirajte **traffic anomaly detection** (npr. LAF analyzer) – označite resetovanja brojača, duplirane join-ove i iznenadne ADR promene.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Pregled Trend Micro LoRaPWN alata](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1 specifikacija](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1 regionalni parametri i join sinhronizacija](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU katalog teza - Analiza bezbednosti LPWAN protokola korišćenjem SDR tehnologije](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
