# Side-Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel-aanvalle herwin geheime deur fisiese of mikro-argitektoniese "leakage" waar te neem wat *gekorreleer* is met interne toestand, maar *nie* deel is van die toestel se logiese koppelvlak nie. Voorbeelde wissel van die meting van die oombliklike stroom wat ’n slimkaart trek tot die misbruik van CPU-kragbestuurseffekte oor ’n netwerk.

Vir ’n teiken met toeganklike ARM-ontfoutingshardeware kan [CoreSight ETM tracing over SWO](arm-coresight-instruction-tracing.md) ’n verwysing na die uitvoeringspad bied saam met krag- of EM-opnames; dit is ’n ontfoutingspoor, nie ’n leakage-kanaal nie.<sup>[[17]](#references)</sup>

---

## Hoof-leakage-kanale

| Kanaal | Tipiese teiken | Instrumentasie |
|---------|---------------|-----------------|
| Kragverbruik | Slimkaarte, IoT-MCU's, FPGA's | Ossilloskoop plus shuntweerstand of differensiële probe; die CW503 is ’n kragbron vir probes/LNA's, nie self ’n probe nie<sup>[[11]](#references)</sup> |
| Elektromagnetiese veld (EM) | CPU's, RFID, AES-versnellers | H-veld-/nabyveld-probe plus laeruisversterker en ossilloskoop of SDR-ontvanger soos ’n RTL-SDR<sup>[[13]](#references)</sup> |
| Uitvoeringstyd / caches | Desktop- en cloud-CPU's | Hoëpresisie-timers (`rdtsc`/`rdtscp`) of afstandtydmeting |
| Akoesties / meganies | Sleutelborde, 3D-drukkers, drukkers, relais en CPU-spanningsreguleerders | MEMS-mikrofoon of laservibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Opties en termies | Status-LED's, skerms, DRAM en termies gekoppelde toestelle | Fotodiode, hoëspoedkamera of IR-kamera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC/MCU-kriptografie | Klok-/spanningsglitch, EMFI of laserinspuiting |

---

## Kraganalise

### Simple Power Analysis (SPA)
Neem ’n *enkele* spoor waar en koppel sigbare kenmerke aan bewerkings soos vertakkings, modulêre vermenigvuldiging of verskillende instruksievolgordes.<sup>[[1]](#references)</sup>

Die presiese opstelling hang van die teiken af. Die volgende gebruik die huidige hoëvlak ChipWhisperer capture API nadat die ossilloskoop en teiken gekoppel en gekonfigureer is:<sup>[[1]](#references)</sup>

```python
import chipwhisperer as cw

scope = cw.scope()
scope.default_setup()
target = cw.target(scope)
ktp = cw.ktp.Basic()
key, plaintext = ktp.next()
trace = cw.capture_trace(scope, target, plaintext, key)
if trace is not None:
    print(trace.wave)  # NumPy array of power samples
```

### Differential/Correlation Power Analysis (DPA/CPA)
Versamel meerdere traces, formuleer ’n hipotese oor ’n sleutelgreep `k`, bereken ’n Hamming-weight (HW)- of Hamming-distance (HD)-lekkasiemodel en bereken die korrelasie daarvan met elke sample. Die vereiste aantal traces hang af van die teiken, geraas, belyning, teenmaatreëls en lekkasiemodel; daar is nie ’n vaste drempel nie.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA is ’n standaardbasislyn. Template attacks, mutual-information analysis en machine-learning-benaderings kan nuttig wees wanneer leakage nie-lineêr is of spore swak belyn is.

---

## Elektromagnetiese analise (EMA)
Nabyveld-EM-analise kan data-afhanklike aktiwiteit waarneem sonder om ’n shunt in die toevoerpad in te voeg. Dit stel nie noodwendig dieselfde sein as ’n kragspoor bloot nie: die posisie en oriëntasie van die sonde, bandwydte, versterking van die voorkant, triggerkwaliteit en afstand speel almal ’n rol.

---

## Tydsberekening- en mikro-argitektoniese aanvalle
Moderne SVE’s lek geheime deur gedeelde hulpbronne:
* **Hertzbleed (2022)** – Data-afhanklike dinamiese spannings- en frekwensieskaalverandering skep ’n afgeleë tydsberekeningskanaal. Die oorspronklike end-to-end-demonstrasie van sleutelherwinning het SIKE geteiken; opvolgwerk bespreek ander primitiewe.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transiënte uitvoering kan data blootstel wat deur vector-gather-instruksies oor sekuriteitsgrense heen gebruik word.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Verkeerde hantering van spekulatiewe vektorregistertoestand kan data van dieselfde fisiese kern openbaar maak.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – ’n Transiënte-uitvoeringsaanval kombineer phantom execution met opleiding in transiënte uitvoering om misvoorspellingsgadgets te skep wat deur die aanvaller beheer word.<sup>[[5]](#references)</sup>

---

## Akoestiese en optiese aanvalle
Akoestiese leakage is in ’n beheerde eksperiment gebruik om RSA-sleutels uit skootrekenaargeruis te herwin, onder meer met ’n mikrofoon in ’n nabygeleë selfoon.<sup>[[6]](#references)</sup> ’n Afsonderlike sleutelbordstudie uit 2023 het toetsaanslae met 95% akkuraatheid geklassifiseer toe dit opgelei is op opnames van ’n nabygeleë foon, en met 93% toe dit op Zoom-klank opgelei is; hierdie syfers beskryf die opgelei-op-toestel-eksperiment in daardie artikel, nie enige willekeurige sleutelbord of slagoffer nie.<sup>[[9]](#references)</sup> Optiese uitstraling van status-LED’s kan ook met verwerkte data gekorreleer word. Hierdie resultate is spesifiek vir die teiken en opstelling; moenie die omvang of sukseskoers daarvan na onverwante toestelle veralgemeen nie.<sup>[[7]](#references)</sup>

---

## Foutinspuiting en Differential Fault Analysis (DFA)
Die kombinasie van beheerde foute met sykanaalwaarnemings kan die sleutelsoektog vir sommige algoritmes en implementasies verklein. Algemene laboratoriumplatforms sluit ChipWhisperer se spannings-/klokglitch-funksies en toegewyde EM-foutinspuitingsnutsgoed soos ChipSHOUTER of PicoEMP in. Die vorige konsep se “sub-1 ns”-beskrywing moet nie as ’n spesifikasie gebruik word nie: ChipSHOUTER se gepubliseerde handleiding lys tipiese ingevoegde pulswydtes van **15–80 ns** met sy 1 mm-punt en **24–480 ns** met sy 4 mm-punt (hoewel trigger-/pulsjitter in pikosekondes gespesifiseer word). Die vereiste tydsberekeningsresolusie, sondeplasing en aantal foutiewe uitsette hang af van die teiken en foutmodel.<sup>[[1]](#references)[[10]](#references)</sup>

## Ongeverifieerde navorsingsleidrade wat uit die vorige konsep behou is

Die vorige konsep het ook beweer: ’n **500 MHz–3 GHz** EM-opstelling wat ’n STM32-sleutel van meer as **10 cm** afstand met ’n RTL-SDR herwin; ’n DDR4-aktiwiteits-LED wat ’n AES-ronde-sleutel binne minder as een minuut by “Black Hat 2023” onthul; en ’n oopbron-RISC-V-glitchplatform uit 2025 genaamd **GlitchKit-R5**. Geen ooreenstemmende primêre artikel, konferensiemateriaal of projekbewaarplek kon tydens hierdie oudit gevind word nie. Hierdie presiese besonderhede word as soek-/reproduksieleidrade behou, nie as gevestigde resultate of aanbevelings vir nutsgoed nie.

---

## Tipiese aanvalswerksvloei
1. Identifiseer die lekkanaal en monteerpunt (VCC-pen, ontkoppelkapasitor, nabyveldplek).
2. Voeg ’n trigger in (GPIO of patroon-gebaseer).  
3. Versamel genoeg spore vir die gekose statistiese toets en teken die plaintext/ciphertext en ander metadata aan.
4. Voorverwerk (belyning, gemiddelde verwydering, LP/HP-filter, wavelet, PCA).
5. Statistiese of ML-sleutelherwinning (CPA, MIA, DL-SCA).
6. Valideer en herhaal met uitskieters.

---

## Verdediging en verharding
* **Constant-time**-implementasies en geheue-harde algoritmes.
* **Masking/shuffling** – verdeel geheime in ewekansige shares; eerste-orde weerstand gesertifiseer deur TVLA.
* **Hiding** – spanningsreguleerders op die skyfie, ewekansige klok, dual-rail-logika, EM-afskerming.
* **Foutopsporing** – oortollige berekening, drempelhandtekeninge.
* **Operasioneel** – deaktiveer DVFS/turbo in kriptografiese kerne, isoleer SMT, verbied saamplekking in multi-tenant-wolke.

---

## Nutsgoed en raamwerke
* **ChipWhisperer-Husky** (2024) – 500 MS/s-ossilloskoop + Cortex-M-trigger; Python API soos hierbo.<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – kommersiële analise- en geoutomatiseerde toetsnutsgoed.
* **scaaml** – TensorFlow-gebaseerde deep-learning-SCA-nutsgoed en datastelle.<sup>[[12]](#references)</sup>
* **pyecsca** – oopbronnutsgoedstel vir die omgekeerde ontleding van swartboks-ECC-implementasies deur middel van sykanale.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer-dokumentasie](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed-aanvalartikel](https://www.hertzbleed.com/)
- [3] [Downfall: Uitbuiting van spekulatiewe data-insameling](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Onthulling van nuwe aanvaloppervlakke met opleiding in transiënte uitvoering](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [RSA-sleutelekstraksie via laebandwydte-akoestiese kriptanalise](https://eprint.iacr.org/2013/857.pdf)
- [7] [Inligtinglekkasie deur optiese uitstraling](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca-artefakdokumentasie](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [’n Praktiese akoestiese sykanaalaanval op sleutelborde gebaseer op deep learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER-gebruikershandleiding](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer-dokumentasie — CW503-sondekragtoevoer](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML-dokumentasie](https://google.github.io/scaaml/)
- [13] [FOSDEM — Uitvoering van laekoste-elektromagnetiese sykanaalaanvalle met RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Dekodering van intellektuele eiendom: Akoestiese en magnetiese sykanaalaanval op ’n 3-D-drukker](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Akoestiese sykanaalaanvalle op drukkers](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Spioenasie op temperatuur met DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
- [17] [Volg die instruksies: Regstreekse ARM-nasporing met ETM, ITM en TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
{{#include ../../banners/hacktricks-training.md}}
