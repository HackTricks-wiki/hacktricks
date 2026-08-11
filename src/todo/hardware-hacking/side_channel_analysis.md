# Side-Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Los ataques de side-channel recuperan secretos observando la "leakage" física o microarquitectónica que está *correlacionada* con el estado interno, pero que *no* forma parte de la interfaz lógica del dispositivo. Los ejemplos van desde medir la corriente instantánea consumida por una smart card hasta abusar de los efectos de power-management de la CPU a través de una red.

---

## Main Leakage Channels

| Canal | Objetivo habitual | Instrumentación |
|---------|---------------|-----------------|
| Consumo de energía | Smart cards, IoT MCUs, FPGAs | Osciloscopio junto con una resistencia shunt o una sonda diferencial; el CW503 es una fuente de alimentación para probes/LNAs, no una probe por sí mismo<sup>[[11]](#references)</sup> |
| Campo electromagnético (EM) | CPUs, RFID, aceleradores AES | Sonda H-field/near-field junto con un amplificador de bajo ruido y un osciloscopio o receptor SDR, como un RTL-SDR<sup>[[13]](#references)</sup> |
| Tiempo de ejecución / caches | CPUs de escritorio y cloud | Temporizadores de alta precisión (`rdtsc`/`rdtscp`) o time-of-flight remoto |
| Acústico / mecánico | Teclados, impresoras 3D, impresoras, relés y reguladores de voltaje de CPU | Micrófono MEMS o vibrometer láser<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Óptico y térmico | LEDs de estado, pantallas, DRAM y dispositivos con acoplamiento térmico | Fotodiodo, cámara de alta velocidad o cámara IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | Criptografía de ASIC/MCU | Glitch de clock/voltaje, EMFI o inyección láser |

---

## Power Analysis

### Simple Power Analysis (SPA)
Observar un *único* trace y asociar características visibles con operaciones como branches, multiplicación modular o diferentes secuencias de instrucciones.<sup>[[1]](#references)</sup>

La configuración exacta depende del objetivo. El siguiente ejemplo utiliza la API de captura de alto nivel actual de ChipWhisperer después de conectar y configurar el scope y el target:<sup>[[1]](#references)</sup>
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
Adquiere múltiples trazas, plantea la hipótesis de un byte de clave `k`, calcula un modelo de leak de Hamming-weight (HW) o Hamming-distance (HD), y correlaciónalo con cada muestra. El número de trazas necesario depende del objetivo, el ruido, la alineación, las contramedidas y el modelo de leak; no es un umbral fijo.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA es una baseline estándar. Template attacks, mutual-information analysis y los enfoques de machine learning pueden ser útiles cuando el leakage es no lineal o las trazas están mal alineadas.

---

## Análisis electromagnético (EMA)
El análisis EM de campo cercano puede observar actividad dependiente de los datos sin insertar un shunt en la ruta de alimentación. No necesariamente expone la misma señal que una traza de potencia: la posición y orientación de la sonda, el ancho de banda, la ganancia del front-end, la calidad del trigger y la distancia son factores importantes.

---

## Ataques de temporización y microarquitectónicos
Las CPU modernas filtran secretos a través de recursos compartidos:
* **Hertzbleed (2022)** – El escalado dinámico de voltaje y frecuencia dependiente de los datos crea un canal remoto de temporización. La demostración original de recuperación de claves end-to-end tenía como objetivo SIKE; trabajos posteriores analizan otras primitivas.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – La ejecución transitoria puede exponer datos utilizados por instrucciones vectoriales gather a través de límites de seguridad.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – El manejo incorrecto del estado especulativo de los registros vectoriales puede divulgar datos del mismo núcleo físico.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Un ataque de ejecución transitoria combina la ejecución phantom con training en la ejecución transitoria para crear gadgets de misprediction controlados por el atacante.<sup>[[5]](#references)</sup>

---

## Ataques acústicos y ópticos
El leakage acústico se ha utilizado para recuperar claves RSA a partir del ruido de un portátil en un experimento controlado, incluso mediante el micrófono de un teléfono móvil cercano.<sup>[[6]](#references)</sup> Un estudio independiente de 2023 sobre teclados clasificó las pulsaciones con una precisión del 95 % al entrenarse con grabaciones de un teléfono cercano y del 93 % al entrenarse con audio de Zoom; estas cifras describen el experimento del dispositivo entrenado de ese artículo, no un teclado o víctima arbitrarios.<sup>[[9]](#references)</sup> Las emanaciones ópticas de los LED de estado también pueden correlacionarse con los datos procesados. Estos resultados dependen del objetivo y de la configuración; no generalices su alcance ni su tasa de éxito a dispositivos no relacionados.<sup>[[7]](#references)</sup>

---

## Inyección de fallos y Differential Fault Analysis (DFA)
La combinación de fallos controlados con observaciones de side-channel puede reducir la búsqueda de claves para algunos algoritmos e implementaciones. Las plataformas de laboratorio habituales incluyen las funciones de voltage/clock glitching de ChipWhisperer y herramientas especializadas de inyección de fallos EM, como ChipSHOUTER o PicoEMP. La descripción anterior del borrador de “menos de 1 ns” no debe utilizarse como especificación: el manual publicado de ChipSHOUTER indica anchos típicos de pulsos insertados de **15–80 ns** con su punta de 1 mm y de **24–480 ns** con su punta de 4 mm (aunque el jitter del trigger/pulso se especifica en picosegundos). La resolución temporal necesaria, la colocación de la sonda y el número de salidas defectuosas dependen del objetivo y del modelo de fallos.<sup>[[1]](#references)[[10]](#references)</sup>

## Líneas de investigación no verificadas conservadas del borrador anterior

El borrador anterior también afirmaba: una configuración EM de **500 MHz–3 GHz** que recuperaba una clave de STM32 desde más de **10 cm** mediante un RTL-SDR; un LED de actividad DDR4 que revelaba una clave de ronda de AES en menos de un minuto en “Black Hat 2023”; y una plataforma open-source de glitching para RISC-V de 2025 llamada **GlitchKit-R5**. Durante esta auditoría no se pudo localizar ningún artículo primario, material de conferencia o repositorio del proyecto coincidente. Estos detalles exactos se conservan como líneas de búsqueda/reproducción, no como resultados establecidos ni recomendaciones de tooling.

---

## Flujo de trabajo típico de un ataque
1. Identificar el canal de leakage y el punto de conexión (pin VCC, condensador de desacoplamiento, punto de campo cercano).
2. Insertar el trigger (GPIO o basado en patrones).
3. Recopilar suficientes trazas para la prueba estadística elegida, registrando el texto plano/cifrado y otros metadatos.
4. Preprocesar (alineación, eliminación de la media, filtro LP/HP, wavelet, PCA).
5. Recuperación estadística o mediante ML de la clave (CPA, MIA, DL-SCA).
6. Validar e iterar sobre los outliers.

---

## Defensas y hardening
* Implementaciones **constant-time** y algoritmos memory-hard.
* **Masking/shuffling** – dividir los secretos en shares aleatorios; resistencia de primer orden certificada mediante TVLA.
* **Hiding** – reguladores de voltaje on-chip, clock aleatorio, lógica dual-rail, escudos EM.
* **Detección de fallos** – computación redundante, firmas threshold.
* **Operacional** – desactivar DVFS/turbo en kernels criptográficos, aislar SMT, prohibir la co-location en clouds multi-tenant.

---

## Herramientas y frameworks
* **ChipWhisperer-Husky** (2024) – osciloscopio de 500 MS/s + trigger Cortex-M; API de Python como arriba.<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – herramientas comerciales de análisis y testing automatizado.
* **scaaml** – tooling y datasets de SCA mediante deep learning basado en TensorFlow.<sup>[[12]](#references)</sup>
* **pyecsca** – toolkit open-source para reverse engineering de implementaciones ECC black-box mediante side-channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [Documentación de ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Artículo sobre el ataque Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: explotación de la recopilación especulativa de datos](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: exposición de nuevas superficies de ataque mediante training en la ejecución transitoria](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Extracción de claves RSA mediante criptoanálisis acústico de bajo ancho de banda](https://eprint.iacr.org/2013/857.pdf)
- [7] [Filtración de información a partir de emanaciones ópticas](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Documentación del artefacto pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Un ataque práctico de side-channel acústico basado en deep learning contra teclados](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - manual de usuario de ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Documentación de ChipWhisperer — fuente de alimentación de la sonda CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Documentación de Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — realización de ataques side-channel electromagnéticos de bajo coste mediante RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Decodificación de propiedad intelectual: ataque side-channel acústico y magnético contra una impresora 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — ataques side-channel acústicos contra impresoras](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Espionaje de la temperatura mediante DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
