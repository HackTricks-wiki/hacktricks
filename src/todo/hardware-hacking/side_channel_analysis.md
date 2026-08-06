# Ataques de Side Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Los ataques de side-channel recuperan secretos observando el "leakage" físico o microarquitectónico que está *correlacionado* con el estado interno, pero que *no* forma parte de la interfaz lógica del dispositivo. Los ejemplos van desde medir la corriente instantánea consumida por una smart-card hasta abusar de los efectos de power-management de la CPU a través de una red.

---

## Canales principales de Leakage

| Canal | Objetivo típico | Instrumentación |
|---------|---------------|-----------------|
| Consumo de energía | Smart-cards, IoT MCUs, FPGAs | Osciloscopio + resistencia shunt/sonda HS (p. ej., CW503)
| Campo electromagnético (EM) | CPUs, RFID, aceleradores AES | Sonda de campo H + LNA, ChipWhisperer/RTL-SDR
| Tiempo de ejecución / caches | CPUs de escritorio y cloud | Timers de alta precisión (rdtsc/rdtscp), time-of-flight remoto
| Acústico / mecánico | Teclados, impresoras 3-D, relés | Micrófono MEMS, vibrometro láser
| Óptico y térmico | LEDs, impresoras láser, DRAM | Fotodiodo / cámara de alta velocidad, cámara IR
| Inducido por faults | Criptografía de ASIC/MCU | Clock/voltage glitch, EMFI, inyección láser

---

## Análisis de Power

### Simple Power Analysis (SPA)
Observar un *único* trace y asociar directamente los picos y valles con operaciones (p. ej., las S-boxes de DES).<sup>[[1]](#references)</sup>
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
Adquirir *N > 1 000* trazas, plantear la hipótesis del byte de clave `k`, calcular el modelo HW/HD y correlacionarlo con el leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA sigue siendo el estado del arte, pero las variantes de machine learning (MLA, deep-learning SCA) ahora dominan competiciones como ASCAD-v2 (2023).

---

## Análisis electromagnético (EMA)
Las sondas EM de campo cercano (500 MHz–3 GHz) filtran información idéntica a la del análisis de potencia *sin* insertar shunts. Una investigación de 2024 demostró la recuperación de claves a **más de 10 cm** de un STM32 mediante correlación espectral y front-ends RTL-SDR de bajo coste.

---

## Ataques de temporización y microarquitectura
Las CPU modernas filtran secretos a través de recursos compartidos:
* **Hertzbleed (2022)** – el escalado de frecuencia DVFS se correlaciona con el peso de Hamming, lo que permite la extracción *remota* de claves EdDSA.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – ejecución transitoria para leer datos de AVX-gather entre hilos SMT.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023) e Inception (AMD, 2023)** – la predicción incorrecta especulativa de vectores filtra registros entre dominios.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Ataques acústicos y ópticos
* En 2024, "​iLeakKeys" mostró una precisión del 95 % al recuperar pulsaciones de teclas de un portátil desde un **micrófono de smartphone a través de Zoom** usando un clasificador CNN.
* Los fotodiodos de alta velocidad capturan la actividad del LED de DDR4 y reconstruyen las claves de ronda de AES en menos de 1 minuto (BlackHat 2023).

---

## Inyección de fallos y Differential Fault Analysis (DFA)
Combinar fallos con leakage de side-channel acorta la búsqueda de claves (por ejemplo, DFA de AES con 1 traza). Herramientas recientes con precios al alcance de aficionados:
* **ChipSHOUTER y PicoEMP** – glitching mediante pulsos electromagnéticos de menos de 1 ns.
* **GlitchKit-R5 (2025)** – plataforma open-source de clock/voltage glitching compatible con SoC RISC-V.

---

## Flujo de trabajo típico de un ataque
1. Identificar el canal de leakage y el punto de conexión (pin VCC, condensador de desacoplamiento, punto de campo cercano).
2. Insertar un trigger (GPIO o basado en patrones).
3. Recopilar >1 k trazas con un muestreo y filtros adecuados.
4. Preprocesar (alineación, eliminación de la media, filtro LP/HP, wavelet, PCA).
5. Recuperación estadística o mediante ML de la clave (CPA, MIA, DL-SCA).
6. Validar e iterar sobre los outliers.

---

## Defensas y hardening
* Implementaciones **constant-time** y algoritmos memory-hard.
* **Masking/shuffling** – dividir los secretos en shares aleatorios; resistencia de primer orden certificada por TVLA.
* **Hiding** – reguladores de voltaje on-chip, clock aleatorio, lógica dual-rail, escudos EM.
* **Detección de fallos** – computación redundante, firmas de umbral.
* **Operativas** – deshabilitar DVFS/turbo en kernels criptográficos, aislar SMT, prohibir la co-localización en clouds multi-tenant.

---

## Herramientas y frameworks
* **ChipWhisperer-Husky** (2024) – osciloscopio de 500 MS/s + trigger Cortex-M; API de Python como la anterior.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – comercial, compatible con la evaluación automatizada de leakage (TVLA-2.0).
* **scaaml** – biblioteca de SCA mediante deep-learning basada en TensorFlow (v1.2 – 2025).
* **pyecsca** – framework open-source de SCA para ECC de ANSSI.

---

## Referencias

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
