# Mreža širokog dometa i male potrošnje

{{#include ../../banners/hacktricks-training.md}}

## Uvod

**Mreža širokog dometa i male potrošnje** (LPWAN) obuhvata bežične tehnologije za mreže širokog dometa i male potrošnje, namenjene **komunikaciji na velikim udaljenostima** pri maloj brzini prenosa bitova.
U zavisnosti od radio-parametara, antene, regulatornog područja, terena i radnog ciklusa, LPWAN implementacije mogu da žrtvuju propusni opseg zarad pokrivenosti od više kilometara i višegodišnjeg trajanja baterije. Podatke proizvođača o dometu i trajanju baterije posmatrajte kao ciljne vrednosti, a ne kao garancije.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) je trenutno najrasprostranjeniji LPWAN fizički sloj, a njegova otvorena specifikacija MAC sloja je **LoRaWAN**.

---

## LPWAN, LoRa i LoRaWAN

* LoRa – fizički sloj Chirp Spread Spectrum (CSS), koji je razvio Semtech (vlasnički, ali dokumentovan).
* LoRaWAN – otvoreni MAC/mrežni sloj koji održava LoRa-Alliance. Verzije 1.0.x i 1.1 su česte u praksi.
* Tipična arhitektura: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> U LoRaWAN 1.1, **bezbednosni model** koristi odvojene AES-128 korenske ključeve za aplikaciju i mrežu, iz kojih se tokom OTAA postupka izvode ključevi sesije specifični za pojedine uloge. U starijim implementacijama verzije 1.0.x, jedan AppKey se obično koristi za izvođenje ključeva sesije za mrežu i aplikaciju, dok se kod ABP-a ključevi sesije direktno dodeljuju. Mogućnosti koje omogućava leaked key zato zavise od verzije LoRaWAN-a i od toga koji je ključ otkriven.<sup>[[3]](#references)</sup>

---

## Pregled napadne površine

| Sloj | Slabost | Praktični uticaj |
|-------|----------|------------------|
| PHY | Reaktivno / selektivno ometanje | Lokalizovan gubitak paketa; efikasnost zavisi od budžeta veze, vremena, propusnog opsega i regulatornih ograničenja |
| MAC | Ponovno slanje zahteva za pridruživanje i okvira podataka kada se stanje nonce/counter ponovo koristi | Desinhronizacija uređaja, lažno predstavljanje ili ubacivanje podataka ako server/uređaj ne sprovodi zaštitu od ponovljenog slanja |
| Network-Server | Nezaštićen packet-forwarder, slabi MQTT/UDP filteri, zastareo firmver gateway-a | RCE na gateway uređajima → prelazak u OT/IT mrežu |
| Aplikacija | Tvrdo kodirani ili predvidivi AppKeys | Brute-force/dešifrovanje saobraćaja, lažno predstavljanje senzora |

---

## Primeri ranjivosti u implementacijama

* **CVE-2024-29862** – U pogođenim verzijama ChirpStack Gateway Bridge-a pre 4.0.11 i MQTT Forwarder-a pre 4.2.1 bilo je moguće povezivanje sa MQTT brokerom pod kontrolom napadača, jer validacija TLS serverskog sertifikata nije bila omogućena. To je moglo da otkrije akreditive i saobraćaj gateway-a; nadogradite na ispravljene verzije.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 opisuje neautentifikovan prikaz sadržaja direktorijuma `/lib/` koji uključuje datoteku rezervne kopije za preuzimanje; CVE-2022-45228 je CSRF niskog stepena ozbiljnosti na stranici za odjavu. Ovi zapisi ne potvrđuju navodni uticaj na LG308, prepisivanje konfiguracije, broj pogođenih uređaja niti stanje zakrpa iz 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Starija verzija ove stranice opisivala je navodni problem u Semtech UDP packet-forwarder-u kao **specijalno napravljen uplink veći od 255 bajtova koji izaziva oštećenje steka i RCE na referentnim SX130x gateway uređajima**, pripisan prezentaciji „LoRa Exploitation Reloaded” na Black Hat Europe 2023 i privatnoj zakrpi iz oktobra 2023. Ti konkretni detalji su ovde zadržani kao trag za dalja istraživanja, ali nije bilo moguće potvrditi postojanje odgovarajućeg javnog upozorenja, prezentacije ili zakrpe. Ne smatrajte ovo poznatom ranjivošću bez pribavljanja podataka o pogođenom proizvodu/verziji i proverljivog primarnog izvora.

---

## Praktične tehnike napada

### 1. Sniff & Decrypt traffic

```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
    --freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```

Ove komande čuvaju originalni tok rada kao **ilustrativnu sintaksu**; struktura repozitorijuma i zastavice razlikuju se među projektima i izdanjima. Pasivno hvatanje saobraćaja ne otkriva jak AppKey. Pogađanje van mreže korisno je samo kada je root ključ dovoljno slab da može da se pronađe i kada razmena pridruživanja koju ste uhvatili pruža vrednost kojom se kandidati mogu proveriti.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Testirajte zaštitu od ponavljanja OTAA zahteva i stanje nonce vrednosti

1. U ovlašćenoj testnoj mreži uhvatite legitiman **JoinRequest**.
2. Ponovite isti zahtev i proverite da li mrežni server odbija ponovo upotrebljeni `DevNonce`.
3. Ponovo pokrenite ili resetujte testni uređaj i ponovite proveru kako biste otkrili gubitak stanja nonce vrednosti. Usklađen server mora da prati upotrebljene nonce vrednosti; samo ponavljanje JoinRequest-a ne otkriva novoderivisane ključeve sesije niti omogućava onome ko ponavlja zahtev da preuzme kontrolu nad sesijom.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Snižavanje Adaptive Data-Rate (ADR) vrednosti

Napadač koji može da autentifikuje MAC komande mrežnog sloja — na primer, nakon kompromitovanja odgovarajućeg ključa mrežne sesije ili mrežnog servera — može pokušati da nametne neefikasne parametre brzine prenosa podataka i poveća vreme emitovanja. Transmiter u blizini koji nije autentifikovan ne može legitimno da šalje ADR komande samo na osnovu poznavanja adrese uređaja.<sup>[[3]](#references)</sup>

### 4. Reaktivno ometanje

Reaktivni ometač može da emituje signal nakon što detektuje LoRa preambulu i selektivno ometa frejmove. Na prethodnoj stranici je navedeno da je konfiguracija HackRF/GNU Radio izazvala potpuni prekid rada na **2 km uz najviše 200 mW**, ali nije naveden izvor merenja koji bi to potkrepio; te vrednosti zadržite samo kao cilj za ponavljanje testa, a ne kao očekivani rezultat. Potrebna snaga prenosa, tajming, propusni opseg, pogođeni spreading faktori i domet zavise od okruženja. Testirajte samo u ovlašćenom, RF-izolovanom okruženju i poštujte lokalne propise o radio-spektru.

---

## Ofanzivni alati (2025)

| Alat | Svrha | Napomene |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Kreiranje i parsiranje LoRaWAN frejmova, napadi na njih, analizatori povezani s bazom podataka, brute-forcer | Docker image; podržava Semtech UDP ulaz<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Python alat kompanije Trend Micro za brute OTAA, generisanje downlink-ova i dešifrovanje payload-ova | Javni istraživački alat; proverite koji hardver i verzije protokola podržava<sup>[[2]](#references)</sup> |
| **LoRAttack** | Istraživački framework za višekanalno hvatanje LoRaWAN saobraćaja, analizu sesija, izvođenje ključeva i testiranje ponavljanja | Opisan u master tezi iz 2024; pribavite i proverite tačnu implementaciju pre nego što se oslonite na primere zastavica<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | GNU Radio out-of-tree blokovi za prijem LoRa baseband signala ili istraživanje transivera | Projekti se razlikuju po kompatibilnosti sa GNU Radio i skupu funkcija<sup>[[9]](#references)</sup> |

---

## Preporuke za odbranu (kontrolna lista za pentestere)

1. Dajte prednost **OTAA** i proverite da li uređaji i serveri čuvaju neophodno stanje nonce vrednosti; pratite odbijena ponovljena pridruživanja.
2. Dajte prednost **LoRaWAN 1.1** tamo gde je podržan, kako bi mrežne funkcije koristile zasebne ključeve sesije i ažurirano rukovanje nonce vrednostima.<sup>[[3]](#references)</sup>
3. Čuvajte brojač frejmova u nevolatilnoj memoriji (**ABP**) ili pređite na OTAA.
4. Koristite odgovarajući **secure element** (na primer, ATECC608A u podržanom dizajnu) kako biste smanjili izloženost root ključeva u uobičajenom skladištu firmvera.
5. Ne izlažite konfigurisane UDP listener-e packet-forwarder-a (često na portu 1700) nepouzdanim mrežama; autentifikujte i šifrujte backhaul gateway-a ili ga ograničite VPN-om.
6. Održavajte gateway-e na firmveru koji podržava proizvođač i proverite tačan model/verziju u odnosu na primenljive bezbednosne preporuke.
7. Implementirajte **detekciju anomalija u saobraćaju** (npr. LAF analyzer) – označavajte resetovanja brojača, duplirana pridruživanja i nagle ADR promene.<sup>[[1]](#references)</sup>



## References

- [1] [Okvir za bezbednosnu proveru LoRaWAN-a (LAF)](https://github.com/IOActive/laf)
- [2] [Pregled alata Trend Micro LoRaPWN](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - Specifikacija LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - Regionalni parametri LoRaWAN 1.1 i sinhronizacija pridruživanja](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Katalog teza CTU - Analiza bezbednosti LPWAN protokola uz SDR tehnologiju](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio transiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
