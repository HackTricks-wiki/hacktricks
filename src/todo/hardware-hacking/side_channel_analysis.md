# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Los ataques de side-channel recuperan secretos observando la "leakage" física o microarquitectónica que está *correlacionada* con el estado interno, pero que *no* forma parte de la interfaz lógica del dispositivo. Los ejemplos van desde medir la corriente instantánea consumida por una smart-card hasta abusar de los efectos de power-management de la CPU a través de una red.

---

## Principales canales de leakage

| Canal | Objetivo habitual | Instrumentación |
|---------|---------------|-----------------|
| Consumo de energía | Smart-cards, IoT MCUs, FPGAs | Osciloscopio + resistencia shunt/sonda HS (p. ej., CW503)
| Campo electromagnético (EM) | CPUs, RFID, aceleradores AES | Sonda de campo H + LNA, ChipWhisperer/RTL-SDR
| Tiempo de ejecución / caches | CPUs de escritorio y cloud | Timers de alta precisión (rdtsc/rdtscp), time-of-flight remoto
| Acústico / mecánico | Teclados, impresoras 3-D, relés | Micrófono MEMS, vibrometro láser
| Óptico y térmico | LEDs, impresoras láser, DRAM | Fotodiodo / cámara de alta velocidad, cámara IR
| Inducido por fallos | Criptografía de ASIC/MCU | Glitch de clock/voltaje, EMFI, inyección láser

---

## Análisis de energía

### Simple Power Analysis (SPA)
Observa una única traza y asocia directamente los picos y valles con operaciones (p. ej., las S-boxes de DES).
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
Adquiere *N > 1 000* trazas, plantea como hipótesis el byte de clave `k`, calcula el modelo HW/HD y correlaciónalo con el leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA sigue siendo state-of-the-art, pero las variantes de machine learning (MLA, deep-learning SCA) ahora dominan competiciones como ASCAD-v2 (2023).

---

## Análisis electromagnético (EMA)
Las sondas EM de campo cercano (500 MHz–3 GHz) leak información idéntica al power analysis *sin* insertar shunts. Una investigación de 2024 demostró la recuperación de claves a **>10 cm** de un STM32 mediante correlación de espectro y front-ends RTL-SDR de bajo coste.

---

## Ataques de Timing y Microarquitectura
Las CPUs modernas leak secretos mediante recursos compartidos:
* **Hertzbleed (2022)** – el escalado de frecuencia DVFS se correlaciona con el peso de Hamming, lo que permite la extracción *remota* de claves EdDSA.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – ejecución transitoria para leer datos de AVX-gather entre hilos SMT.
* **Zenbleed (AMD, 2023) e Inception (AMD, 2023)** – la mispredicción vectorial especulativa leak registros entre dominios.

---

## Ataques Acústicos y Ópticos
* En 2024, "​iLeakKeys" mostró una precisión del 95 % al recuperar pulsaciones de teclas de un portátil a partir de un **micrófono de smartphone mediante Zoom**, usando un clasificador CNN.
* Los fotodiodos de alta velocidad capturan la actividad del LED de DDR4 y reconstruyen round keys de AES en menos de 1 minuto (BlackHat 2023).

---

## Inyección de Fallos y Análisis Diferencial de Fallos (DFA)
La combinación de fallos con side-channel leakage acorta la búsqueda de claves (por ejemplo, 1-trace AES DFA). Herramientas recientes con precios al alcance de aficionados:
* **ChipSHOUTER y PicoEMP** – glitching mediante pulsos electromagnéticos de menos de 1 ns.
* **GlitchKit-R5 (2025)** – plataforma open-source de clock/voltage glitching compatible con SoCs RISC-V.

---

## Flujo de Trabajo Típico de un Ataque
1. Identificar el canal de leakage y el punto de acceso (pin VCC, condensador de desacoplamiento, punto de campo cercano).
2. Insertar el trigger (GPIO o basado en patrones).
3. Recopilar >1 k trazas con un muestreo y filtros adecuados.
4. Preprocesar (alineación, eliminación de la media, filtro LP/HP, wavelet, PCA).
5. Recuperación estadística o mediante ML de la clave (CPA, MIA, DL-SCA).
6. Validar e iterar sobre los outliers.

---

## Defensas y Hardening
* Implementaciones de **constant-time** y algoritmos memory-hard.
* **Masking/shuffling** – dividir los secretos en shares aleatorios; resistencia de primer orden certificada mediante TVLA.
* **Hiding** – reguladores de voltaje on-chip, clock aleatorio, lógica dual-rail, blindaje EM.
* **Detección de fallos** – computación redundante, threshold signatures.
* **Operativa** – deshabilitar DVFS/turbo en kernels criptográficos, aislar SMT, prohibir la colocación conjunta en clouds multi-tenant.

---

## Herramientas y Frameworks
* **ChipWhisperer-Husky** (2024) – osciloscopio de 500 MS/s + trigger Cortex-M; API de Python como se indicó anteriormente.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – comercial, compatible con la evaluación automatizada de leakage (TVLA-2.0).
* **scaaml** – librería de deep-learning SCA basada en TensorFlow (v1.2 – 2025).
* **pyecsca** – framework open-source de SCA para ECC de ANSSI.

---

## Referencias

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
