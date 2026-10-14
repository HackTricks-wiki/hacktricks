# Laekrag-wye-area-netwerk

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

**Laekrag-wye-area-netwerk** (LPWAN) is ’n groep draadlose, laekrag-wye-area-netwerktegnologieë wat ontwerp is vir **langafstandkommunikasie** teen ’n lae bistempo.
Afhangend van die radioparameters, antenna, regulatoriese streek, terrein en dienssiklus, kan LPWAN-ontplooiings deurset verruil vir dekking oor verskeie kilometers en ’n batterylewe van verskeie jare. Beskou verskaffers se reikwydte- en batterysyfers as ontwerpteikens, nie waarborge nie.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) is tans die LPWAN-fisiese laag wat die meeste ontplooi word, en die oop MAC-laag-spesifikasie daarvan is **LoRaWAN**.

---

## LPWAN, LoRa en LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS)-fisiese laag, ontwikkel deur Semtech (eienaarspesifiek, maar gedokumenteer).
* LoRaWAN – Oop MAC-/netwerklaag wat deur die LoRa-Alliance onderhou word. Weergawe 1.0.x en 1.1 kom algemeen in die veld voor.
* Tipiese argitektuur: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> In LoRaWAN 1.1 gebruik die **sekuriteitsmodel** afsonderlike AES-128-toepassings- en netwerkwortelsleutels om rolspesifieke sessiesleutels tydens OTAA af te lei. Vorige 1.0.x-ontplooiings gebruik normaalweg een AppKey om die netwerk- en toepassingsessiesleutels af te lei, terwyl ABP sessiesleutels direk voorsien. Die vermoë wat ’n uitgelekte sleutel bied, hang dus af van die LoRaWAN-weergawe en watter sleutel blootgestel is.<sup>[[3]](#references)</sup>

---

## Opsomming van aanvalsvlak

| Laag | Swakheid | Praktiese impak |
|-------|----------|------------------|
| PHY | Reaktiewe / selektiewe jamming | Plaaslike pakkieverlies; doeltreffendheid hang af van die skakelbegroting, tydsberekening, bandwydte en regulatoriese beperkings |
| MAC | Hertoespeling van aansluitings- en datarame wanneer nonce-/tellertoestand hergebruik word | Toestel-desinchronisering, spoofing of injection indien die bediener/toestel herhalingsbeskerming oortree |
| Network-Server | Onveilige packet-forwarder, swak MQTT-/UDP-filters, verouderde gateway-firmware | RCE op gateways → pivot na OT-/IT-netwerk |
| Toepassing | Hardgekodeerde of voorspelbare AppKeys | Brute-force/decrypt verkeer, sensor-nabootsing |

---

## Verteenwoordigende implementeringskwesbaarhede

* **CVE-2024-29862** – Weergawes van ChirpStack Gateway Bridge voor 4.0.11 en MQTT Forwarder-weergawes voor 4.2.1 kon aan ’n aanvallerbeheerde MQTT-broker koppel omdat TLS-bedienersertifikaatvalidering gedeaktiveer was. Dit kon geloofsbriewe en gateway-verkeer blootstel; gradeer op na die reggestelde weergawes.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 beskryf ’n ongeverifieerde `/lib/`-gidsgidsinskrywing wat ’n aflaaibare rugsteunlêer bevat; CVE-2022-45228 is ’n CSRF met lae erns op die uittekenbladsy. Hierdie rekords bevestig nie die beweerde impak op LG308, konfigurasie-oorskryf, aantal toestelle of pleisterstatus in 2025 nie.<sup>[[6]](#references)[[7]](#references)</sup>
* ’n Vorige weergawe van hierdie bladsy het ’n beweerde Semtech UDP packet-forwarder-probleem beskryf as ’n **gespesialiseerde uplink van meer as 255 grepe wat ’n stack smash en RCE op SX130x-verwysingsgateways veroorsaak**, toegeskryf aan ’n “LoRa Exploitation Reloaded”-aanbieding by Black Hat Europe 2023 en ’n private pleister van Oktober 2023. Daardie presiese besonderhede word hier as ’n navorsingsleidraad behou, maar geen ooreenstemmende openbare advies, aanbieding of pleister kon bevestig word nie. Moenie die probleem as ’n bekende kwesbaarheid beskou sonder om die betrokke produk/weergawe en ’n verifieerbare primêre bron te bekom nie.

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

Hierdie opdragte behou die oorspronklike werkvloei as **illustratiewe sintaksis**; die bewaarplekuitleg en vlae verskil tussen projekte/vrystellings. Passiewe capture onthul nie ’n sterk AppKey nie. Vanlyn raaiwerk is slegs nuttig wanneer die wortelsleutel swak genoeg is om gevind te word en ’n vasgelegde join-uitruiling ’n waarde verskaf waarmee kandidate gevalideer kan word.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Toets OTAA-replaybeskerming en nonce-toestand

1. Neem in ’n gemagtigde toetsnetwerk ’n geldige **JoinRequest** vas.
2. Replay dieselfde versoek en bevestig dat die netwerkbediener die hergebruikte `DevNonce` verwerp.
3. Herbegin of herstel die toetstoestel en herhaal die kontrole om verlore nonce-toestand op te spoor. ’n Voldoenende bediener moet gebruikte nonces naspoor; om ’n JoinRequest te replay, onthul op sigself nie die nuut afgeleide sessiesleutels nie en gee die persoon wat dit replay nie beheer oor ’n sessie nie.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Adaptive Data-Rate (ADR) downgrading

’n Aanvaller wat netwerklaag-MAC-opdragte kan autentiseer—byvoorbeeld nadat die toepaslike netwerksessiesleutel of netwerkbediener gekompromitteer is—kan probeer om ondoeltreffende data-rate-parameters af te dwing en airtime te verhoog. ’n Nabygeleë, nie-geauthentiseerde sender kan nie bloot deur ’n toesteladres te ken, geldig ADR-opdragte uitreik nie.<sup>[[3]](#references)</sup>

### 4. Reactive jamming

’n Reaktiewe jammer kan uitsaai nadat dit ’n LoRa-preambule bespeur het en rame selektief ontwrig. Die vorige bladsy het beweer dat ’n HackRF/GNU Radio-opstelling ’n volledige onderbreking op **2 km met hoogstens 200 mW** veroorsaak het, maar geen ondersteunende meetbron is verskaf nie; behou daardie syfers slegs as ’n teiken vir reproduksie, nie as ’n verwagte resultaat nie. Die vereiste uitsaaikrag, tydsberekening, bandwydte, geraakte spreading factors en reikwydte is omgewingspesifiek. Toets slegs binne ’n gemagtigde, RF-afgeskermde opstelling en voldoen aan plaaslike spektrumreëls.

---

## Aanvallende tooling (2025)

| Tool | Doel | Notas |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Skep/ontleed/aanval LoRaWAN-rame, databasisondersteunde ontleders, brute-forcer | Docker-image; ondersteun Semtech UDP-invoer<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Trend Micro se Python-hulpmiddel om OTAA te brute-force, downlinks te genereer en payloads te dekripteer | Openbare navorsingshulpmiddel; verifieer ondersteunde hardeware en protokolweergawes<sup>[[2]](#references)</sup> |
| **LoRAttack** | Navorsingsraamwerk vir LoRaWAN-capture oor meerkanale, sessie-ontleding, sleutelafleiding en replay-toetsing | Beskryf in ’n meestersgraadtesis van 2024; verkry en verifieer die presiese implementering voordat jy op die voorbeeldvlae staatmaak<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | GNU Radio se out-of-tree-blokke vir LoRa-basisbandontvangs of transceiver-navorsing | Projekte verskil in GNU Radio-versoenbaarheid en kenmerkstel<sup>[[9]](#references)</sup> |

---

## Verdedigingsaanbevelings (pentester-kontrolelys)

1. Verkies **OTAA** en verifieer dat toestelle en bedieners die vereiste nonce-toestand behou; monitor afgekeurde duplikaat-joins.
2. Verkies **LoRaWAN 1.1** waar dit ondersteun word, sodat netwerkfunksies afsonderlike sessiesleutels en opgedateerde nonce-hantering gebruik.<sup>[[3]](#references)</sup>
3. Stoor die frame counter in nie-vlugtige geheue (**ABP**) of migreer na OTAA.
4. Ontplooi ’n geskikte **secure element** (byvoorbeeld ATECC608A in ’n ondersteunde ontwerp) om blootstelling van wortelsleutels in gewone firmwareberging te verminder.
5. Stel nie gekonfigureerde UDP-luisteraars vir packet forwarders (gewoonlik 1700) aan onbetroubare netwerke bloot nie; autentiseer/kripteer gateway-backhaul of beperk dit met ’n VPN.
6. Hou gateways op firmware wat deur die verskaffer ondersteun word en bevestig die presiese model/weergawe aan die hand van toepaslike veiligheidsbulletins.
7. Implementeer **verkeer-anomaliebespeuring** (bv. LAF-ontleder) – merk tellerterugstellings, duplikaat-joins en skielike ADR-veranderinge aan.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN-ouditraamwerk (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN-oorsig](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1-spesifikasie](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1-streekparameters en join-sinchronisering](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU-tesisekatalogus - LPWAN-protokolveiligheidsontleding met behulp van SDR-tegnologie](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio-transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
