# Атаки аналізу побічних каналів

{{#include ../../banners/hacktricks-training.md}}

Атаки через побічні канали відновлюють секрети, спостерігаючи за фізичним або мікроархітектурним "leakage", який *корелює* з внутрішнім станом, але *не є* частиною логічного інтерфейсу пристрою. Приклади варіюються від вимірювання миттєвого струму, споживаного smart-card, до зловживання ефектами керування живленням CPU через мережу.

---

## Основні канали leakage

| Канал | Типова ціль | Інструментарій |
|---------|---------------|-----------------|
| Споживання енергії | Smart-cards, IoT MCUs, FPGAs | Осцилограф + шунтувальний резистор/HS probe (наприклад, CW503)
| Електромагнітне поле (EM) | CPUs, RFID, AES accelerators | H-field probe + LNA, ChipWhisperer/RTL-SDR
| Час виконання / caches | Desktop і cloud CPUs | Високоточні таймери (rdtsc/rdtscp), віддалене вимірювання часу проходження
| Акустичні / механічні | Клавіатури, 3-D printers, relays | MEMS microphone, laser vibrometer
| Оптичні й теплові | LEDs, laser printers, DRAM | Photodiode / high-speed camera, IR camera
| Індуковані збійні умови | Криптосистеми ASIC/MCU | Clock/voltage glitch, EMFI, laser injection

---

## Аналіз потужності

### Simple Power Analysis (SPA)
Спостерігайте за *одним* trace і безпосередньо пов'язуйте піки/спади з операціями (наприклад, DES S-boxes).
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
Зберіть *N > 1 000* traces, висуньте гіпотезу щодо байта ключа `k`, обчисліть HW/HD model і встановіть кореляцію з leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA залишається state-of-the-art, але варіанти на основі machine learning (MLA, deep-learning SCA) тепер домінують у змаганнях на кшталт ASCAD-v2 (2023).

---

## Electromagnetic Analysis (EMA)
Near-field EM probes (500 MHz–3 GHz) витікають ідентичну інформацію до power analysis *без* встановлення shunts. Дослідження 2024 року продемонструвало відновлення ключа на відстані **>10 см** від STM32 за допомогою spectrum correlation і недорогих RTL-SDR front-end.

---

## Timing & Micro-architectural Attacks
Сучасні CPU витікають секрети через спільні ресурси:
* **Hertzbleed (2022)** – масштабування частоти DVFS корелює з вагою Хеммінга, що дає змогу *віддалено* отримувати ключі EdDSA.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution для читання даних AVX-gather між SMT threads.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction витікає регістри між доменами.

---

## Acoustic & Optical Attacks
* У 2024 році "​iLeakKeys" продемонстрував точність 95 % під час відновлення натискань клавіш на laptop за аудіозаписом зі **smart-phone microphone через Zoom** із використанням CNN classifier.
* High-speed photodiodes захоплюють активність DDR4 activity LED і відновлюють AES round keys менш ніж за 1 хвилину (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Поєднання faults із side-channel leakage скорочує пошук ключа (наприклад, 1-trace AES DFA). Сучасні інструменти за ціною для hobbyist:
* **ChipSHOUTER & PicoEMP** – electromagnetic pulse glitching із тривалістю імпульсу менше 1 нс.
* **GlitchKit-R5 (2025)** – open-source clock/voltage glitch platform із підтримкою RISC-V SoCs.

---

## Typical Attack Workflow
1. Визначити leakage channel і mount point (VCC pin, decoupling cap, near-field spot).
2. Додати trigger (GPIO або pattern-based).
3. Зібрати >1 k traces із належними sampling/filters.
4. Виконати pre-process (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Виконати statistical або ML key recovery (CPA, MIA, DL-SCA).
6. Перевірити результат і повторити процес для outliers.

---

## Defences & Hardening
* Реалізації **constant-time** та memory-hard algorithms.
* **Masking/shuffling** – розділяти секрети на random shares; first-order resistance сертифікується за допомогою TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – вимикати DVFS/turbo у crypto kernels, ізолювати SMT, забороняти co-location у multi-tenant clouds.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – oscilloscope на 500 MS/s + Cortex-M trigger; Python API, як зазначено вище.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – комерційний інструмент із підтримкою автоматизованої оцінки leakage (TVLA-2.0).
* **scaaml** – TensorFlow-based deep-learning SCA library (v1.2 – 2025).
* **pyecsca** – open-source ECC SCA framework від ANSSI.

---

## References

- [1] [Документація ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Дослідження атаки Hertzbleed](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
