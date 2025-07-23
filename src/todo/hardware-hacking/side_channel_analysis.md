# Uchambuzi wa Mashambulizi ya Kando

{{#include ../../banners/hacktricks-training.md}}

Mashambulizi ya kando yanapata siri kwa kuangalia "kuvuja" kwa kimwili au micro-architectural ambayo ni *husika* na hali ya ndani lakini *siyo* sehemu ya kiolesura cha kimantiki cha kifaa. Mifano inajumuisha kupima sasa ya papo hapo inayotolewa na kadi ya smart hadi kutumia athari za usimamizi wa nguvu za CPU kupitia mtandao.

---

## Makanali Makuu ya Kuvuja

| Mkanali | Lengo la Kawaida | Vifaa |
|---------|---------------|-----------------|
| Matumizi ya nguvu | Kadi za smart, MCU za IoT, FPGAs | Oscilloscope + shunt resistor/HS probe (e.g. CW503)
| Uwanja wa umeme (EM) | CPUs, RFID, wakandarasi wa AES | H-field probe + LNA, ChipWhisperer/RTL-SDR
| Wakati wa utekelezaji / caches | CPUs za desktop & cloud | Wakati wa juu wa usahihi (rdtsc/rdtscp), wakati wa mbali wa kuruka
| Kihisia / mitambo | Kibodi, printers za 3-D, relays | MEMS microphone, laser vibrometer
| Mwangaza & joto | LEDs, printers za laser, DRAM | Photodiode / kamera ya kasi ya juu, kamera ya IR
| Kufaulu kwa sababu | ASIC/MCU cryptos | Clock/voltage glitch, EMFI, laser injection

---

## Uchambuzi wa Nguvu

### Uchambuzi wa Nguvu Rahisi (SPA)
Angalia *alama* moja na uhusishe moja kwa moja kilele/makundi na operesheni (e.g. DES S-boxes).
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
Pata *N > 1 000* traces, dhania funguo byte `k`, hesabu HW/HD model na uhusishe na leak.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA inabaki kuwa ya kisasa lakini toleo la kujifunza mashine (MLA, deep-learning SCA) sasa linatawala mashindano kama ASCAD-v2 (2023).

---

## Uchambuzi wa Electromagnetic (EMA)
Probes za EM za karibu (500 MHz–3 GHz) zinatoa taarifa sawa na uchambuzi wa nguvu *bila* kuingiza shunts. Utafiti wa 2024 ulionyesha urejeleaji wa funguo kwa **>10 cm** kutoka kwa STM32 kwa kutumia uhusiano wa spektra na vifaa vya RTL-SDR vya gharama nafuu.

---

## Mashambulizi ya Wakati & Micro-architectural
CPUs za kisasa zinatoa siri kupitia rasilimali zinazoshirikiwa:
* **Hertzbleed (2022)** – upanuzi wa DVFS wa frequency unahusiana na uzito wa Hamming, kuruhusu *uchimbaji wa mbali* wa funguo za EdDSA.
* **Downfall / Gather Data Sampling (Intel, 2023)** – utekelezaji wa muda mfupi kusoma data ya AVX-gather kupitia nyuzi za SMT.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – makosa ya utabiri wa vector yanavuja register za cross-domain.

Kwa matibabu pana ya masuala ya Spectre-class ona {{#ref}}
../../cpu-microarchitecture/microarchitectural-attacks.md
{{#endref}}

---

## Mashambulizi ya Acoustic & Optical
* 2024 "​iLeakKeys" ilionyesha usahihi wa 95 % katika kurejesha keystrokes za laptop kutoka kwa **mike ya simu mahiri kupitia Zoom** kwa kutumia mwezo wa CNN.
* Photodiodes za kasi ya juu zinakamata shughuli za DDR4 LED na kujenga funguo za raundi za AES ndani ya <1 dakika (BlackHat 2023).

---

## Uingizaji wa Makosa & Uchambuzi wa Makosa ya Tofauti (DFA)
Kuunganisha makosa na uvujaji wa upande wa channel kunarahisisha utafutaji wa funguo (kwa mfano, 1-trace AES DFA). Zana za hivi karibuni zenye bei ya hobbyist:
* **ChipSHOUTER & PicoEMP** – glitching ya pulse ya electromagnetic chini ya 1 ns.
* **GlitchKit-R5 (2025)** – jukwaa la glitch la saa/voltage la chanzo wazi linalounga mkono RISC-V SoCs.

---

## Mchakato wa Kawaida wa Shambulizi
1. Tambua channel ya uvujaji & mahali pa kuingilia (pin ya VCC, capacitor ya decoupling, spot ya karibu).
2. Ingiza kichocheo (GPIO au msingi wa muundo).
3. Kusanya >1 k traces kwa sampuli sahihi/filter.
4. Pre-process (mwelekeo, kuondoa wastani, LP/HP filter, wavelet, PCA).
5. Urejeleaji wa funguo wa takwimu au ML (CPA, MIA, DL-SCA).
6. Thibitisha na rudia kwenye outliers.

---

## Ulinzi & Kuimarisha
* **Mtekelezaji wa wakati thabiti** & algorithimu ngumu za kumbukumbu.
* **Masking/shuffling** – gawanya siri katika sehemu za nasibu; upinzani wa kiwango cha kwanza umeidhinishwa na TVLA.
* **Kuficha** – regulators za voltage kwenye chip, saa za nasibu, mantiki ya dual-rail, kinga za EM.
* **Ugunduzi wa makosa** – hesabu za ziada, saini za kigezo.
* **Kazi** – zima DVFS/turbo katika nyuzi za crypto, tengeneza SMT, kataza ushirikiano katika mawingu ya wapangaji wengi.

---

## Zana & Mifumo
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; Python API kama ilivyo hapo juu.
* **Riscure Inspector & FI** – kibiashara, inasaidia tathmini ya uvujaji wa kiotomatiki (TVLA-2.0).
* **scaaml** – maktaba ya deep-learning SCA inayotumia TensorFlow (v1.2 – 2025).
* **pyecsca** – mfumo wa ECC SCA wa chanzo wazi wa ANSSI.

---

## Marejeleo

* [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
* [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
