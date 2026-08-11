# Атаки аналізу бічних каналів

{{#include ../../banners/hacktricks-training.md}}

Атаки бічних каналів відновлюють секрети, спостерігаючи за фізичним або мікроархітектурним «витоком», який *корелює* з внутрішнім станом, але не є частиною логічного інтерфейсу пристрою. Приклади варіюються від вимірювання миттєвого струму, споживаного smart-card, до використання ефектів керування живленням CPU через мережу.

---

## Основні канали витоку

| Канал | Типова ціль | Інструментарій |
|---------|---------------|-----------------|
| Споживання електроенергії | Smart cards, IoT MCUs, FPGAs | Осцилограф із шунтувальним резистором або диференціальним пробником; CW503 є джерелом живлення для пробників/LNA, а не пробником<sup>[[11]](#references)</sup> |
| Електромагнітне поле (EM) | CPUs, RFID, AES accelerators | H-field/near-field probe із малошумним підсилювачем та осцилографом або SDR-приймачем, наприклад RTL-SDR<sup>[[13]](#references)</sup> |
| Час виконання / caches | Desktop і cloud CPUs | Високоточні таймери (`rdtsc`/`rdtscp`) або віддалене вимірювання часу проходження |
| Акустичні / механічні сигнали | Клавіатури, 3-D printers, printers, relays і регулятори напруги CPU | MEMS-мікрофон або лазерний віброметр<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Оптичні та теплові сигнали | Status LEDs, displays, DRAM і термічно пов’язані пристрої | Фотодіод, високошвидкісна камера або IR-камера<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | Криптографія ASIC/MCU | Clock/voltage glitch, EMFI або лазерна ін’єкція |

---

## Аналіз живлення

### Простий аналіз потужності (SPA)
Спостерігайте за *одним* trace та пов’язуйте видимі особливості з такими операціями, як розгалуження, модульне множення або різні послідовності інструкцій.<sup>[[1]](#references)</sup>

Точна конфігурація залежить від цілі. Нижче використовується поточний високорівневий API захоплення ChipWhisperer після підключення та налаштування scope і target:<sup>[[1]](#references)</sup>
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
Зберіть кілька трас, висуньте гіпотезу щодо байта ключа `k`, обчисліть модель витоку за вагою Геммінга (HW) або відстанню Геммінга (HD) і визначте її кореляцію з кожним відліком. Необхідна кількість трас визначається ціллю, шумом, вирівнюванням, контрзаходами та моделлю витоку; це не фіксований поріг.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA є стандартною базовою методикою. Template attacks, mutual-information analysis і підходи машинного навчання можуть бути корисними, коли leakage є нелінійним або traces погано вирівняні.

---

## Електромагнітний аналіз (EMA)
Ближньопольовий EM-аналіз дає змогу спостерігати активність, залежну від даних, без встановлення шунта в ланцюг живлення. Він не обов'язково виявляє той самий сигнал, що й power trace: важливі положення та орієнтація probe, bandwidth, front-end gain, якість trigger і відстань.

---

## Timing & Micro-architectural Attacks
Сучасні CPU витікають секрети через спільні ресурси:
* **Hertzbleed (2022)** – Залежне від даних динамічне масштабування напруги та частоти створює віддалений timing channel. Оригінальна наскрізна демонстрація відновлення ключа була спрямована на SIKE; подальші дослідження розглядають інші примітиви.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution може розкрити дані, які використовуються vector gather instructions, через межі безпеки.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Неправильна обробка спекулятивного стану vector-register може розкрити дані з того самого фізичного ядра.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Атака transient execution поєднує phantom execution із training in transient execution для створення gadgets із misprediction, контрольованим атакувальником.<sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
Acoustic leakage використовувався для відновлення RSA-ключів із шуму ноутбука в контрольованому експерименті, зокрема за допомогою мікрофона мобільного телефона, розташованого поруч.<sup>[[6]](#references)</sup> В окремому дослідженні клавіатур 2023 року натискання клавіш класифікувалися з точністю 95%, коли модель навчали на записах із телефона поблизу, і 93% — коли навчання проводилося на аудіо з Zoom; ці показники описують експеримент із пристроєм, на якому проводилося навчання, а не довільну клавіатуру чи жертву.<sup>[[9]](#references)</sup> Оптичні emanations від status LED також можна корелювати з оброблюваними даними. Ці результати залежать від конкретної цілі та конфігурації; не слід узагальнювати їхню дальність або success rate для інших пристроїв.<sup>[[7]](#references)</sup>

---

## Fault Injection & Differential Fault Analysis (DFA)
Поєднання контрольованих fault із side-channel observations може скоротити пошук ключа для деяких алгоритмів та реалізацій. Поширені лабораторні платформи включають функції voltage/clock glitching у ChipWhisperer і спеціалізовані інструменти EM fault-injection, такі як ChipSHOUTER або PicoEMP. Опис “sub-1 ns” з попередньої версії не слід використовувати як специфікацію: в опублікованому manual для ChipSHOUTER наведено типову тривалість inserted pulse **15–80 ns** для його наконечника 1 mm і **24–480 ns** для наконечника 4 mm (хоча trigger/pulse jitter задано в picoseconds). Необхідна роздільна здатність за часом, розташування probe та кількість faulty outputs залежать від цілі й fault model.<sup>[[1]](#references)[[10]](#references)</sup>

## Неперевірені напрями досліджень, збережені з попередньої версії

У попередній версії також стверджувалося: що EM setup із діапазоном **500 MHz–3 GHz** відновлював ключ STM32 на відстані понад **10 cm** за допомогою RTL-SDR; що LED-індикатор активності DDR4 розкривав round key AES менш ніж за одну хвилину на “Black Hat 2023”; і що у 2025 році існувала open-source RISC-V glitching platform під назвою **GlitchKit-R5**. Під час цього аудиту не вдалося знайти відповідної первинної статті, матеріалів конференції або repository проєкту. Ці точні деталі збережено як напрями для пошуку та відтворення, а не як підтверджені результати чи рекомендації щодо інструментів.

---

## Типовий процес атаки
1. Визначити канал leakage і mount point (контакт VCC, decoupling cap, точка near-field).
2. Додати trigger (GPIO або на основі pattern).
3. Зібрати достатню кількість traces для вибраного statistical test, записуючи plaintext/ciphertext та інші metadata.
4. Виконати pre-process (вирівнювання, видалення середнього, LP/HP filter, wavelet, PCA).
5. Statistical або ML key recovery (CPA, MIA, DL-SCA).
6. Перевірити результати та повторити процес для outliers.

---

## Захист і hardening
* Реалізації **constant-time** та memory-hard algorithms.
* **Masking/shuffling** – розділення секретів на random shares; resistance першого порядку, сертифікована за допомогою TVLA.
* **Hiding** – on-chip voltage regulators, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – redundant computation, threshold signatures.
* **Operational** – вимкнення DVFS/turbo у crypto kernels, ізоляція SMT, заборона co-location у multi-tenant clouds.

---

## Інструменти та frameworks
* **ChipWhisperer-Husky** (2024) – осцилограф 500 MS/s + Cortex-M trigger; Python API, як зазначено вище.<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – комерційні інструменти аналізу та автоматизованого тестування.
* **scaaml** – SCA tooling і datasets для deep learning на основі TensorFlow.<sup>[[12]](#references)</sup>
* **pyecsca** – open-source toolkit для reverse-engineering black-box ECC implementations через side channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [Документація ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Стаття про атаку Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: експлуатація спекулятивного збору даних](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: виявлення нових поверхонь атак за допомогою training in transient execution](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Вилучення RSA-ключа за допомогою низькосмугового акустичного криптоаналізу](https://eprint.iacr.org/2013/857.pdf)
- [7] [Витік інформації через оптичні emanations](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Документація артефакту pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Практична атака на клавіатури через акустичний side channel на основі deep learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE — посібник користувача ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Документація ChipWhisperer — живлення probe CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Документація Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — виконання недорогих електромагнітних side-channel атак за допомогою RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Декодування інтелектуальної власності: акустична та магнітна side-channel атака на 3D-принтер](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — акустичні side-channel атаки на принтери](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Шпигування за температурою за допомогою DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
