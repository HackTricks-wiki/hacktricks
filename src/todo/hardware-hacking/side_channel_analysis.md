# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Атаки на основі побічних каналів відновлюють секрети, спостерігаючи за фізичним або мікроархітектурним "витоком", який *корелює* з внутрішнім станом, але *не є* частиною логічного інтерфейсу пристрою. Приклади варіюються від вимірювання миттєвого струму, споживаного смарт-карткою, до зловживання ефектами управління енергією ЦП через мережу.

---

## Main Leakage Channels

| Channel | Typical Target | Instrumentation |
|---------|---------------|-----------------|
| Power consumption | Smart-cards, IoT MCUs, FPGAs | Oscilloscope + shunt resistor/HS probe (e.g. CW503)
| Electromagnetic field (EM) | CPUs, RFID, AES accelerators | H-field probe + LNA, ChipWhisperer/RTL-SDR
| Execution time / caches | Desktop & cloud CPUs | High-precision timers (rdtsc/rdtscp), remote time-of-flight
| Acoustic / mechanical | Keyboards, 3-D printers, relays | MEMS microphone, laser vibrometer
| Optical & thermal | LEDs, laser printers, DRAM | Photodiode / high-speed camera, IR camera
| Fault-induced | ASIC/MCU cryptos | Clock/voltage glitch, EMFI, laser injection

---

## Power Analysis

### Simple Power Analysis (SPA)
Спостерігайте за *однією* траєкторією та безпосередньо асоціюйте піки/долини з операціями (наприклад, DES S-boxes).
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
Отримайте *N > 1 000* трас, гіпотезуйте байт ключа `k`, обчисліть модель HW/HD та корелюйте з витоком.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA залишається передовою технологією, але варіанти машинного навчання (MLA, глибоке навчання SCA) тепер домінують у змаганнях, таких як ASCAD-v2 (2023).

---

## Електромагнітний аналіз (EMA)
Проби EM ближнього поля (500 МГц–3 ГГц) витікають ідентичну інформацію до аналізу потужності *без* вставлення шунтів. Дослідження 2024 року продемонструвало відновлення ключа на **>10 см** від STM32, використовуючи кореляцію спектра та недорогі RTL-SDR фронтенди.

---

## Атаки на час та мікроархітектуру
Сучасні ЦП витікають секрети через спільні ресурси:
* **Hertzbleed (2022)** – масштабування частоти DVFS корелює з вагою Хеммінга, що дозволяє *віддалене* витягування ключів EdDSA.
* **Downfall / Gather Data Sampling (Intel, 2023)** – транзитне виконання для читання даних AVX-gather через потоки SMT.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – спекулятивне неправильне передбачення векторів витікає регістри між доменами.

---

## Акустичні та оптичні атаки
* 2024 "​iLeakKeys" показав 95 % точності відновлення натискань клавіш ноутбука з **мікрофона смартфона через Zoom**, використовуючи класифікатор CNN.
* Швидкі фотодіоди захоплюють активність LED DDR4 і реконструюють AES раундові ключі за <1 хвилину (BlackHat 2023).

---

## Впровадження помилок та диференційний аналіз помилок (DFA)
Комбінування помилок з витоками з бокового каналу скорочує пошук ключів (наприклад, 1-трасовий AES DFA). Останні інструменти за ціною хобі:
* **ChipSHOUTER & PicoEMP** – спотворення електромагнітним імпульсом менше 1 нс.
* **GlitchKit-R5 (2025)** – платформа для спотворення годинника/напруги з відкритим кодом, що підтримує RISC-V SoC.

---

## Типовий робочий процес атаки
1. Визначити канал витоку та точку монтажу (пін VCC, конденсатор декуплінгу, точка ближнього поля).
2. Вставити тригер (GPIO або на основі шаблону).
3. Зібрати >1 тис. трас з належним семплюванням/фільтрами.
4. Попередня обробка (вирівнювання, видалення середнього, LP/HP фільтр, вейвлет, PCA).
5. Статистичне або ML відновлення ключа (CPA, MIA, DL-SCA).
6. Перевірити та ітеративно працювати з викидами.

---

## Захист та зміцнення
* **Постійний час** реалізації та алгоритми, стійкі до пам'яті.
* **Маскування/перемішування** – розділити секрети на випадкові частки; сертифікована стійкість першого порядку TVLA.
* **Приховування** – регулятори напруги на чіпі, випадковий годинник, двоє рейкової логіки, електромагнітні екрани.
* **Виявлення помилок** – надмірні обчислення, порогові підписи.
* **Операційний** – вимкнути DVFS/турбо в криптографічних ядрах, ізолювати SMT, заборонити спільне розміщення в багатокористувацьких хмарах.

---

## Інструменти та фреймворки
* **ChipWhisperer-Husky** (2024) – осцилограф 500 MS/s + тригер Cortex-M; Python API як вище.
* **Riscure Inspector & FI** – комерційний, підтримує автоматизовану оцінку витоків (TVLA-2.0).
* **scaaml** – бібліотека глибокого навчання SCA на базі TensorFlow (v1.2 – 2025).
* **pyecsca** – відкритий фреймворк ECC SCA ANSSI.

---

## Посилання

* [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
* [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
