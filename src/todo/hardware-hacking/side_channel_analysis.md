# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel aanvalle herstel geheime inligting deur fisiese of mikro-argitektoniese "lek" te observeer wat *gecorreleer* is met die interne toestand, maar *nie* deel is van die logiese koppelvlak van die toestel nie. Voorbeelde wissel van die meting van die onmiddellike stroom wat deur 'n slimkaart getrek word tot die misbruik van CPU-kragbestuurseffekte oor 'n netwerk.

---

## Hoof Lekkanaal

| Kanaal | Tipiese Teiken | Instrumentasie |
|--------|----------------|-----------------|
| Kragverbruik | Slimkaarte, IoT MCU's, FPGA's | Osilloskoop + shunt weerstand/HS-sonde (bv. CW503) |
| Elektromagnetiese veld (EM) | CPU's, RFID, AES versnellings | H-veld sonde + LNA, ChipWhisperer/RTL-SDR |
| Uitvoeringstyd / caches | Desktop & wolk CPU's | Hoë-presisie timers (rdtsc/rdtscp), afstand tyd-van-vlug |
| Akoesties / meganies | Sleutelborde, 3-D drukkers, relais | MEMS mikrofoon, laser vibrometer |
| Opties & termies | LED's, laserdrukkers, DRAM | Fotodiode / hoë-snelheid kamera, IR kamera |
| Fout-geïnduseer | ASIC/MCU kripto's | Klok/spanning glip, EMFI, laser inspuiting |

---

## Kraganalise

### Eenvoudige Kraganalise (SPA)
Observeer 'n *enkele* spoor en assosieer direk pieke/dale met operasies (bv. DES S-boxes).
```python
# ChipWhisperer-husky example – capture one AES trace
from chipwhisperer.capture.api.programmers import STMLink
from chipwhisperer.capture import CWSession
cw = CWSession(project='aes')
trig = cw.scope.trig
cw.connect(cw.capture.scopes[0])
cw.capture.init()
trace = cw.capture.capture_trace()
print(trace.wave)  # numpy array of power samples
```
### Differensiële/Korrelerende Kraganalise (DPA/CPA)
Verkry *N > 1 000* spore, hipotese sleutelbyte `k`, bereken HW/HD-model en korreleer met lekkasie.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA bly toonaangewend, maar masjienleer variasies (MLA, diep-leer SCA) oorheers nou kompetisies soos ASCAD-v2 (2023).

---

## Elektromagnetiese Analise (EMA)
Naby-veld EM-probes (500 MHz–3 GHz) lek identiese inligting aan kraganalise *sonder* om shunts in te voeg. 2024 navorsing het sleutelherwinning by **>10 cm** van 'n STM32 gedemonstreer deur middel van spektrum korrelasie en laekoste RTL-SDR voorfront.

---

## Tyds- & Mikro-argitektoniese Aanvalle
Moderne CPU's lek geheime deur gedeelde hulpbronne:
* **Hertzbleed (2022)** – DVFS frekwensie skaal korreleer met Hamming gewig, wat *afgeleë* ekstraksie van EdDSA sleutels moontlik maak.
* **Downfall / Gather Data Sampling (Intel, 2023)** – tydelike uitvoering om AVX-gather data oor SMT-drade te lees.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – spekulatiewe vektor misvoorspelling lek registers oor domeine.

Vir 'n breë behandeling van Spectre-klas kwessies, sien {{#ref}}
../../cpu-microarchitecture/microarchitectural-attacks.md
{{#endref}}

---

## Akoestiese & Optiese Aanvalle
* 2024 "​iLeakKeys" het 95 % akkuraatheid getoon in die herwinning van laptop-toetsdrukke vanaf 'n **slimfoon mikrofoon oor Zoom** met 'n CNN klassifiseerder.
* Hoëspoed fotodiodes vang DDR4 aktiwiteit LED en herbou AES ronde sleutels binne <1 minuut (BlackHat 2023).

---

## Foutinjeksie & Differensiële Foutanalise (DFA)
Die kombinasie van foute met kantkanaallek versnel sleutelsoektog (bv. 1-trace AES DFA). Onlangse stokperdjiegereedskap:
* **ChipSHOUTER & PicoEMP** – sub-1 ns elektromagnetiese puls glits.
* **GlitchKit-R5 (2025)** – oopbron klok/spanning glits platform wat RISC-V SoCs ondersteun.

---

## Tipiese Aanval Werkvloei
1. Identifiseer lek kanaal & monteerpunt (VCC pen, ontkoppelkap, naby-veld plek).
2. Voeg trigger in (GPIO of patroon-gebaseerd).
3. Versamel >1 k spore met behoorlike monsterneming/filters.
4. Voorverwerk (uitlijning, gemiddelde verwydering, LP/HP filter, golflet, PCA).
5. Statistiese of ML sleutelherwinning (CPA, MIA, DL-SCA).
6. Valideer en herhaal op uitskieters.

---

## Verdedigings & Versterking
* **Konstante-tyd** implementasies & geheue-harde algoritmes.
* **Maskering/suddeling** – verdeel geheime in ewekansige aandele; eerste-orde weerstand gesertifiseer deur TVLA.
* **Versteek** – op-skyf spanning reguleerders, ewekansige klok, dubbele spoor logika, EM skilde.
* **Foutdetectie** – oortollige berekening, drempel handtekeninge.
* **Operasioneel** – deaktiveer DVFS/turbo in crypto-kernels, isoleer SMT, verbied medekolokasie in multi-huurder wolke.

---

## Gereedskap & Raamwerke
* **ChipWhisperer-Husky** (2024) – 500 MS/s skoop + Cortex-M trigger; Python API soos hierbo.
* **Riscure Inspector & FI** – kommersieel, ondersteun outomatiese lek assessering (TVLA-2.0).
* **scaaml** – TensorFlow-gebaseerde diep-leer SCA biblioteek (v1.2 – 2025).
* **pyecsca** – ANSSI oopbron ECC SCA raamwerk.

---

## Verwysings

* [ChipWhisperer Dokumentasie](https://chipwhisperer.readthedocs.io/en/latest/)
* [Hertzbleed Aanval Papier](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
