# Атаки Side Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Атаки side-channel відновлюють секрети шляхом спостереження за фізичним або мікроархітектурним "leakage", який *корельований* із внутрішнім станом, але *не є* частиною логічного інтерфейсу пристрою. Приклади варіюються від вимірювання миттєвого струму, споживаного смарт-картою, до використання ефектів керування живленням CPU через мережу.

---

## Основні канали Leakage

| Канал | Типова ціль | Прилади |
|---------|---------------|-----------------|
| Споживання енергії | Смарт-карти, IoT MCU, FPGA | Осцилограф + шунтувальний резистор/HS-пробник (наприклад, CW503)
| Електромагнітне поле (EM) | CPU, RFID, AES-прискорювачі | H-field-пробник + LNA, ChipWhisperer/RTL-SDR
| Час виконання / кеші | Настільні та хмарні CPU | Високоточні таймери (rdtsc/rdtscp), віддалене вимірювання часу проходження
| Акустичні / механічні | Клавіатури, 3-D-принтери, реле | MEMS-мікрофон, лазерний віброметр
| Оптичні та теплові | LED, лазерні принтери, DRAM | Фотодіод / високошвидкісна камера, IR-камера
| Викликані збоями | Криптосистеми ASIC/MCU | Глітчинг тактового сигналу/напруги, EMFI, лазерна інжекція

---

## Power Analysis

### Simple Power Analysis (SPA)
Спостерігайте за *одним* trace і безпосередньо пов’язуйте піки/спади з операціями (наприклад, DES S-boxes).<sup>[[1]](#references)</sup>
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
### Диференціальний/кореляційний аналіз потужності (DPA/CPA)
Зберіть *N > 1 000* трас, висуньте гіпотезу щодо байта ключа `k`, обчисліть модель HW/HD і визначте кореляцію з витоком.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA залишається state-of-the-art, але варіанти на основі machine learning (MLA, deep-learning SCA) тепер домінують на змаганнях, таких як ASCAD-v2 (2023).

---

## Electromagnetic Analysis (EMA)
Near-field EM probes (500 MHz–3 GHz) leak ідентичну інформацію, що й power analysis, *без* встановлення шунтів. Дослідження 2024 року продемонструвало відновлення ключа на відстані **понад 10 см** від STM32 за допомогою spectrum correlation і недорогих RTL-SDR front-end.

---

## Timing & Micro-architectural Attacks
Сучасні CPU leak секрети через спільні ресурси:
* **Hertzbleed (2022)** – масштабування частоти DVFS корелює з Hamming weight, що дозволяє *віддалено* отримувати ключі EdDSA.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution для читання AVX-gather data між SMT threads.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction leak регістри між доменами.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
* У 2024 році "​iLeakKeys" продемонстрував точність 95 % під час відновлення laptop keystrokes із **мікрофона смартфона через Zoom** за допомогою CNN classifier.
* High-speed photodiodes захоплюють активність DDR4 activity LED і відновлюють AES round keys менш ніж за 1 хвилину (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Поєднання faults із side-channel leakage скорочує пошук ключа (наприклад, 1-trace AES DFA). Сучасні інструменти за ціною для hobbyist:
* **ChipSHOUTER & PicoEMP** – electromagnetic pulse glitching із тривалістю імпульсу менш ніж 1 нс.
* **GlitchKit-R5 (2025)** – open-source clock/voltage glitch platform із підтримкою RISC-V SoCs.

---

## Typical Attack Workflow
1. Визначити канал leakage і mount point (VCC pin, decoupling cap, near-field spot).
2. Додати trigger (GPIO або pattern-based).
3. Зібрати понад 1 k traces із належними sampling/filters.
4. Виконати pre-process (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Виконати statistical або ML key recovery (CPA, MIA, DL-SCA).
6. Перевірити результати та повторити процес для outliers.

---

## Defences & Hardening
* Реалізації **constant-time** і memory-hard algorithms.
* **Masking/shuffling** – розділяти секрети на random shares; first-order resistance сертифікується за допомогою TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – вимикати DVFS/turbo у crypto kernels, ізолювати SMT, забороняти co-location у multi-tenant clouds.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; Python API, як описано вище.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – комерційний інструмент із підтримкою automated leakage assessment (TVLA-2.0).
* **scaaml** – TensorFlow-based deep-learning SCA library (v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA framework.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
