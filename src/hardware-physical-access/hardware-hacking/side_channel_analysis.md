# Aanvalle met sykanaalontleding

{{#include ../../banners/hacktricks-training.md}}

Sykanaalaanvalle herwin geheime deur fisiese of mikro-argitektoniese “leakage” waar te neem wat *gekorreleer* is met interne toestand, maar nie deel is van die toestel se logiese koppelvlak nie. Voorbeelde wissel van die meting van die oombliklike stroomverbruik van ’n slimkaart tot die misbruik van SVE-kragbestuurseffekte oor ’n netwerk.

---

## Hooflekkasiekanale

| Kanaal | Tipiese teiken | Meetinstrumente |
|---------|---------------|-----------------|
| Kragverbruik | Slimkaarte, IoT-MCU’s, FPGA’s | Ossilloskoop plus shuntweerstand of differensiële sonde; die CW503 is ’n kragtoevoer vir probes/LNA’s, nie self ’n sonde nie<sup>[[11]](#references)</sup> |
| Elektromagnetiese veld (EM) | SVE’s, RFID, AES-versnellers | H-veld-/nabyveldsonde plus ’n laeruisversterker en ossilloskoop of SDR-ontvanger soos ’n RTL-SDR<sup>[[13]](#references)</sup> |
| Uitvoeringstyd / kasgeheue | Werkskerm- en wolk-SVE’s | Hoëpresisie-timers (`rdtsc`/`rdtscp`) of afgeleë tyd-van-vlug |
| Akoesties / meganies | Sleutelborde, 3D-drukkers, drukkers, relais en SVE-spanningsreguleerders | MEMS-mikrofoon of laservibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Opties en termies | Status-LED’s, skerms, DRAM en termies gekoppelde toestelle | Fotodiode, hoëspoedkamera of IR-kamera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC-/MCU-kriptografie | Klok-/spanningsglitch, EMFI of laserinspuiting |

---

## Kragontleding

### Simple Power Analysis (SPA)
Neem ’n *enkele* spoor waar en koppel sigbare kenmerke aan bewerkings soos takke, modulêre vermenigvuldiging of verskillende instruksiereekse.<sup>[[1]](#references)</sup>

Die presiese opstelling hang van die teiken af. Die volgende gebruik die huidige hoëvlak-ChipWhisperer-opname-API nadat die ossilloskoop en teiken gekoppel en opgestel is:<sup>[[1]](#references)</sup>

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
Verkry meerdere traces, maak 'n hipotese oor 'n sleutelgreep `k`, bereken 'n Hamming-weight (HW)- of Hamming-distance (HD)-leakage model en korreleer dit met elke sample. Die vereiste aantal traces hang af van die teiken, geraas, alignment, countermeasures en leakage model; dit is nie 'n vaste drempel nie.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA is ’n standaardbasislyn. Template attacks, mutual-information analysis en machine-learning-benaderings kan nuttig wees wanneer leakage nie-lineêr is of traces swak belyn is.

---

## Elektromagnetiese Analise (EMA)
Nabyveld-EM-analise kan data-afhanklike aktiwiteit waarneem sonder om ’n shunt in die toevoerpad in te voeg. Dit ontbloot nie noodwendig dieselfde sein as ’n power trace nie: die sonde se posisie, oriëntasie, bandwydte, front-end gain, snellerkwaliteit en afstand speel alles ’n rol.

---

## Tydsberekening- en mikro-argitektoniese aanvalle
Moderne SVE’s leak geheime deur gedeelde hulpbronne:
* **Hertzbleed (2022)** – Data-afhanklike dinamiese spanning- en frekwensieskaalverandering skep ’n afgeleë tydsberekeningskanaal. Die oorspronklike end-tot-end sleutelherwinningsdemonstrasie het SIKE geteiken; opvolgwerk bespreek ander primitiewe.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Tydelike uitvoering kan data blootlê wat deur vector gather-instruksies oor sekuriteitsgrense heen gebruik word.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Verkeerde hantering van spekulatiewe vectorregistertoestand kan data vanaf dieselfde fisiese kern openbaar maak.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – ’n Tydelike-uitvoeringsaanval kombineer phantom execution met opleiding in tydelike uitvoering om verkeerdevoorspellingsgadgets te skep wat deur die aanvaller beheer word.<sup>[[5]](#references)</sup>

---

## Akoestiese en optiese aanvalle
Akoestiese leakage is in ’n beheerde eksperiment gebruik om RSA-sleutels uit skootrekenaargeruis te herwin, ook met ’n nabygeleë selfoonmikrofoon.<sup>[[6]](#references)</sup> ’n Afsonderlike sleutelbordstudie uit 2023 het toetsaanslae met 95% akkuraatheid geklassifiseer wanneer dit opgelei is op opnames vanaf ’n nabygeleë foon, en met 93% wanneer dit op Zoom-klank opgelei is; hierdie syfers beskryf die toestelopleidingseksperiment in daardie artikel, nie ’n willekeurige sleutelbord of slagoffer nie.<sup>[[9]](#references)</sup> Optiese uitstraling vanaf status-LED’s kan ook met verwerkte data gekorreleer word. Hierdie resultate is spesifiek vir die teiken en opstelling; moenie die bereik of sukseskoers daarvan na onverwante toestelle veralgemeen nie.<sup>[[7]](#references)</sup>

---

## Foutinspuiting en Differensiële Foutanalise (DFA)
Die kombinasie van beheerde foute met sykanaalwaarnemings kan die sleutelsoektog vir sommige algoritmes en implementasies verklein. Algemene laboratoriumplatforms sluit ChipWhisperer se spannings-/klok-glitching-kenmerke in, asook toegewyde EM-foutinspuitingsnutsgoed soos ChipSHOUTER of PicoEMP. Die vroeëre konsep se beskrywing “sub-1 ns” moet nie as ’n spesifikasie gebruik word nie: ChipSHOUTER se gepubliseerde handleiding gee tipiese ingevoegde pulsbreedtes van **15–80 ns** met sy 1 mm-punt en **24–480 ns** met sy 4 mm-punt (hoewel sneller-/pulsskommeling in pikosekondes gespesifiseer word). Die vereiste tydsresolusie, sondeplasing en aantal foutiewe uitsette hang af van die teiken en foutmodel.<sup>[[1]](#references)[[10]](#references)</sup>

## Ongeverifieerde navorsingsleidrade wat uit die vroeëre konsep behou is

Die vroeëre konsep het ook die volgende beweer: ’n **500 MHz–3 GHz** EM-opstelling wat ’n STM32-sleutel van meer as **10 cm** ver af met ’n RTL-SDR herwin; ’n DDR4-aktiwiteits-LED wat ’n AES-rondsleutel binne minder as een minuut by “Black Hat 2023” openbaar; en ’n oopbron-RISC-V-glitching-platform uit 2025 genaamd **GlitchKit-R5**. Geen ooreenstemmende primêre artikel, konferensiemateriaal of projekbewaarplek kon tydens hierdie oudit gevind word nie. Hierdie presiese besonderhede word as soek-/reproduksieleidrade behou, nie as gevestigde resultate of aanbevelings vir nutsgoed nie.

---

## Tipiese aanvalswerkvloei
1. Identifiseer die leakage-kanaal en meetpunt (VCC-pen, ontkoppelingskapasitor, nabyveldplek).
2. Voeg ’n sneller in (GPIO of patroon-gebaseerd).
3. Versamel genoeg traces vir die gekose statistiese toets en teken plaintext/ciphertext en ander metadata aan.
4. Voorverwerk (belyning, gemiddelde verwyder, LP/HP-filter, wavelet, PCA).
5. Statistiese of ML-sleutelherwinning (CPA, MIA, DL-SCA).
6. Valideer en herhaal met uitskieters.

---

## Verdediging en verharding
* **Constant-time**-implementasies en geheueharde algoritmes.
* **Maskering/shuffling** – verdeel geheime in ewekansige shares; eerste-orde-weerstand gesertifiseer deur TVLA.
* **Verberging** – spanningsreguleerders op die skyfie, ewekansige klok, dual-rail-logika, EM-afskerming.
* **Foutopsporing** – oortollige berekening, drempelhandtekeninge.
* **Operasioneel** – deaktiveer DVFS/turbo in kriptografiese kernels, isoleer SMT, verbied saamplasing in multi-tenant-wolke.

---

## Nutsgoed en raamwerke
* **ChipWhisperer-Husky** (2024) – 500 MS/s-ossilloskoop + Cortex-M-sneller; Python API soos hierbo.<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – kommersiële analise- en outomatiese toetsnutsgoed.
* **scaaml** – TensorFlow-gebaseerde deep-learning-SCA-nutsgoed en datastelle.<sup>[[12]](#references)</sup>
* **pyecsca** – oopbronnutsgoedstel vir reverse-engineering van black-box ECC-implementasies deur sykanale.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer-dokumentasie](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed-aanvalartikel](https://www.hertzbleed.com/)
- [3] [Downfall: Uitbuiting van spekulatiewe dataversameling](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Ontbloting van nuwe aanvalsvlakke met opleiding in tydelike uitvoering](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [RSA-sleutelonttrekking via laebandwydte-akoestiese kripto-analise](https://eprint.iacr.org/2013/857.pdf)
- [7] [Inligtinglekkasie vanaf optiese uitstralings](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca-artefakdokumentasie](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [’n Praktiese akoestiese sykanaalaanval op sleutelborde gebaseer op deep learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER-gebruikershandleiding](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer-dokumentasie — CW503-sondekragtoevoer](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML-dokumentasie](https://google.github.io/scaaml/)
- [13] [FOSDEM — Uitvoering van laekoste-elektromagnetiese sykanaalaanvalle met RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Dekodering van intellektuele eiendom: Akoestiese en magnetiese sykanaalaanval op ’n 3D-drukker](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Akoestiese sykanaalaanvalle op drukkers](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Spioenasie op temperatuur met DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
