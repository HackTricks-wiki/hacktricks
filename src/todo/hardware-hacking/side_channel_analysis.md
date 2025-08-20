# Napadi Analize Sporednih Kanala

{{#include ../../banners/hacktricks-training.md}}

Napadi sporednih kanala otkrivaju tajne posmatranjem fizičkog ili mikro-arhitektonskog "curenja" koje je *korelirano* sa unutrašnjim stanjem, ali *nije* deo logičkog interfejsa uređaja. Primeri se kreću od merenja trenutne potrošnje struje pametne kartice do zloupotrebe efekata upravljanja snagom CPU-a preko mreže.

---

## Glavni Kanali Curenja

| Kanal | Tipični Cilj | Instrumentacija |
|-------|--------------|-----------------|
| Potrošnja energije | Pametne kartice, IoT MCU, FPGA | Osciloskop + shunt otpornik/HS sonda (npr. CW503) |
| Elektromagnetno polje (EM) | CPU, RFID, AES akceleratori | H-poljska sonda + LNA, ChipWhisperer/RTL-SDR |
| Vreme izvršenja / kešovi | Desktop i cloud CPU | Tajmeri visoke preciznosti (rdtsc/rdtscp), daljinsko merenje vremena leta |
| Akustični / mehanički | Tastature, 3-D štampači, releji | MEMS mikrofon, laserski vibrometar |
| Optički i termalni | LED, laserski štampači, DRAM | Fotodioda / kamera visoke brzine, IR kamera |
| Greške izazvane | ASIC/MCU kriptos | Greška u satu/napajanju, EMFI, laserska injekcija |

---

## Analiza Snage

### Jednostavna Analiza Snage (SPA)
Posmatrajte *jedan* trag i direktno povežite vrhove/doline sa operacijama (npr. DES S-boxovi).
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
### Differential/Correlation Power Analysis (DPA/CPA)
Prikupite *N > 1 000* tragova, postavite hipotezu o bajtu ključa `k`, izračunajte HW/HD model i korelirajte sa leak-om.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA ostaje na vrhuncu, ali varijante mašinskog učenja (MLA, duboko učenje SCA) sada dominiraju takmičenjima kao što je ASCAD-v2 (2023).

---

## Elektromagnetna analiza (EMA)
Probes EM u blizini (500 MHz–3 GHz) otkrivaju identične informacije kao analiza snage *bez* umetanja shuntova. Istraživanje iz 2024. godine pokazalo je oporavak ključeva na **>10 cm** od STM32 koristeći spektralnu korelaciju i niskobudžetne RTL-SDR prednje strane.

---

## Napadi na vreme i mikro-arhitekturu
Savremeni CPU-ovi otkrivaju tajne kroz deljene resurse:
* **Hertzbleed (2022)** – DVFS skaliranje frekvencije korelira sa Hammingovom težinom, omogućavajući *daljinsko* vađenje EdDSA ključeva.
* **Downfall / Gather Data Sampling (Intel, 2023)** – prolazno izvršenje za čitanje AVX-gather podataka preko SMT niti.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – spekulativna pogrešna predikcija vektora otkriva registre između domena.

---

## Akustični i optički napadi
* 2024. "​iLeakKeys" pokazao je 95 % tačnosti u oporavku otkucaja na laptopu sa **mikrofona pametnog telefona preko Zoom-a** koristeći CNN klasifikator.
* Brzi fotodiodi hvataju DDR4 aktivnost LED i rekonstruišu AES runde ključeva za manje od 1 minuta (BlackHat 2023).

---

## Umetanje grešaka i diferencijalna analiza grešaka (DFA)
Kombinovanje grešaka sa curenjem iz bočnih kanala skraćuje pretragu ključeva (npr. 1-trace AES DFA). Nedavni alati po ceni hobista:
* **ChipSHOUTER & PicoEMP** – sub-1 ns elektromagnetno pulsno greškanje.
* **GlitchKit-R5 (2025)** – platforma za greškanje sa otvorenim kodom koja podržava RISC-V SoCs.

---

## Tipičan radni tok napada
1. Identifikujte kanal curenja i tačku montiranja (VCC pin, dekoupling kapacitor, mesto u blizini).
2. Umetnite okidač (GPIO ili na osnovu obrazaca).
3. Sakupite >1 k tragova sa pravilnim uzorkovanjem/filterima.
4. Pre-procesuirajte (poravnanje, uklanjanje srednje vrednosti, LP/HP filter, wavelet, PCA).
5. Statistički ili ML oporavak ključeva (CPA, MIA, DL-SCA).
6. Validirajte i iterirajte na odstupanjima.

---

## Odbrane i učvršćivanje
* **Implementacije konstantnog vremena** i algoritmi otporni na memoriju.
* **Maskiranje/šuffling** – podelite tajne u nasumične delove; otpornost prvog reda sertifikovana od strane TVLA.
* **Skrivenje** – regulatori napona na čipu, nasumična satnica, dual-rail logika, EM štitovi.
* **Detekcija grešaka** – redundantno računanje, potpisivanje praga.
* **Operativno** – onemogućite DVFS/turbo u kripto jezgrima, izolujte SMT, zabranite ko-lokaciju u multi-tenant cloud-ovima.

---

## Alati i okviri
* **ChipWhisperer-Husky** (2024) – 500 MS/s osciloskop + Cortex-M okidač; Python API kao gore.
* **Riscure Inspector & FI** – komercijalno, podržava automatsku procenu curenja (TVLA-2.0).
* **scaaml** – biblioteka dubokog učenja SCA zasnovana na TensorFlow-u (v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA okvir.

---

## Reference

* [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
* [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
