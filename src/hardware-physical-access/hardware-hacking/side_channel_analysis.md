# Ataques de Side-Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Los ataques de side-channel recuperan secretos observando «leakage» físico o microarquitectónico que está *correlacionado* con el estado interno, pero que *no* forma parte de la interfaz lógica del dispositivo. Algunos ejemplos van desde medir la corriente instantánea que consume una smart card hasta aprovechar efectos de gestión de energía de la CPU a través de una red.

En un objetivo con hardware de depuración ARM accesible, el [trazado CoreSight ETM a través de SWO](arm-coresight-instruction-tracing.md) puede proporcionar una referencia de la ruta de ejecución junto con capturas de energía o EM; es un trazado de depuración, no un canal de leakage.<sup>[[17]](#references)</sup>

---

## Principales canales de leakage

| Canal | Objetivo típico | Instrumentación |
|---------|---------------|-----------------|
| Consumo de energía | Smart cards, MCU de IoT, FPGA | Osciloscopio más resistencia shunt o sonda diferencial; el CW503 es una fuente de alimentación para sondas/LNA, no una sonda en sí<sup>[[11]](#references)</sup> |
| Campo electromagnético (EM) | CPU, RFID, aceleradores AES | Sonda H-field/near-field más amplificador de bajo ruido y osciloscopio o receptor SDR como un RTL-SDR<sup>[[13]](#references)</sup> |
| Tiempo de ejecución / cachés | CPU de escritorio y cloud | Temporizadores de alta precisión (`rdtsc`/`rdtscp`) o tiempo de ida y vuelta remoto |
| Acústico / mecánico | Teclados, impresoras 3D, impresoras, relés y reguladores de voltaje de CPU | Micrófono MEMS o vibrometro láser<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Óptico y térmico | LED de estado, pantallas, DRAM y dispositivos con acoplamiento térmico | Fotodiodo, cámara de alta velocidad o cámara IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Inyección de fallos | Criptografía en ASIC/MCU | Glitch de reloj/voltaje, EMFI o inyección láser |

---

## Análisis de energía

### Simple Power Analysis (SPA)
Observa un *único* trazado y asocia características visibles con operaciones como saltos, multiplicación modular o distintas secuencias de instrucciones.<sup>[[1]](#references)</sup>

La configuración exacta depende del objetivo. El siguiente ejemplo utiliza la API de captura de alto nivel actual de ChipWhisperer, después de conectar y configurar el osciloscopio y el objetivo:<sup>[[1]](#references)</sup>

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
Adquiere múltiples trazas, plantea la hipótesis de un byte de clave `k`, calcula un modelo de filtración basado en el peso de Hamming (HW) o la distancia de Hamming (HD) y correlaciónalo con cada muestra. La cantidad de trazas necesaria depende del objetivo, el ruido, la alineación, las contramedidas y el modelo de filtración; no existe un umbral fijo.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA es una referencia estándar. Template attacks, mutual-information analysis y los enfoques de machine learning pueden ser útiles cuando el leakage es no lineal o las trazas están mal alineadas.

---

## Análisis electromagnético (EMA)
El análisis EM de campo cercano puede observar actividad dependiente de los datos sin insertar una resistencia shunt en la ruta de alimentación. No necesariamente expone la misma señal que una traza de potencia: la posición y orientación de la sonda, el ancho de banda, la ganancia de la etapa de entrada, la calidad del trigger y la distancia son factores importantes.

---

## Ataques de temporización y microarquitectura
Las CPU modernas filtran secretos a través de recursos compartidos:
* **Hertzbleed (2022)** – El escalado dinámico de voltaje y frecuencia dependiente de los datos crea un canal de temporización remoto. La demostración original de recuperación de claves de extremo a extremo tenía como objetivo SIKE; trabajos posteriores analizan otras primitivas.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – La ejecución transitoria puede exponer datos utilizados por instrucciones vectoriales gather a través de límites de seguridad.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – El manejo incorrecto del estado especulativo de los registros vectoriales puede revelar datos del mismo núcleo físico.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Un ataque de ejecución transitoria combina la ejecución fantasma con el entrenamiento en ejecución transitoria para crear gadgets de predicción errónea controlados por el atacante.<sup>[[5]](#references)</sup>

---

## Ataques acústicos y ópticos
Se ha utilizado el leakage acústico para recuperar claves RSA a partir del ruido de un portátil en un experimento controlado, incluso con el micrófono de un teléfono móvil cercano.<sup>[[6]](#references)</sup> Un estudio independiente sobre teclados publicado en 2023 clasificó pulsaciones con un 95% de precisión al entrenarse con grabaciones de un teléfono cercano y con un 93% al entrenarse con audio de Zoom; estas cifras describen el experimento con dispositivos de entrenamiento de ese artículo, no cualquier teclado o víctima.<sup>[[9]](#references)</sup> Las emanaciones ópticas de los LED de estado también pueden correlacionarse con los datos procesados. Estos resultados dependen del objetivo y de la configuración; no generalices su alcance ni su tasa de éxito a dispositivos no relacionados.<sup>[[7]](#references)</sup>

---

## Inyección de fallos y Differential Fault Analysis (DFA)
Combinar fallos controlados con observaciones de side-channel puede reducir la búsqueda de claves para algunos algoritmos e implementaciones. Entre las plataformas de laboratorio habituales están las funciones de glitching de voltaje/reloj de ChipWhisperer y las herramientas dedicadas de inyección de fallos EM, como ChipSHOUTER o PicoEMP. La descripción anterior del borrador de “menos de 1 ns” no debe utilizarse como especificación: el manual publicado de ChipSHOUTER indica anchos típicos de pulso insertado de **15–80 ns** con la punta de 1 mm y **24–480 ns** con la punta de 4 mm (aunque el jitter de trigger/pulso se especifica en picosegundos). La resolución temporal necesaria, la colocación de la sonda y el número de salidas defectuosas dependen del objetivo y del modelo de fallo.<sup>[[1]](#references)[[10]](#references)</sup>

## Pistas de investigación no verificadas conservadas del borrador anterior

El borrador anterior también afirmaba que: una configuración EM de **500 MHz–3 GHz** recuperaba una clave de STM32 desde más de **10 cm** mediante un RTL-SDR; un LED de actividad DDR4 revelaba una clave de ronda AES en menos de un minuto en “Black Hat 2023”; y que en 2025 se creó una plataforma open source de glitching para RISC-V llamada **GlitchKit-R5**. Durante esta auditoría no se encontró ningún artículo académico, material de conferencia ni repositorio de proyecto coincidente. Estos detalles exactos se conservan como pistas para búsquedas y reproducción, no como resultados establecidos ni recomendaciones de herramientas.

---

## Flujo de trabajo típico de un ataque
1. Identificar el canal de leakage y el punto de conexión (pin VCC, condensador de desacoplamiento, punto de campo cercano).
2. Insertar un trigger (GPIO o basado en patrones).  
3. Recopilar suficientes trazas para la prueba estadística elegida y registrar el texto en claro/cifrado y otros metadatos.
4. Preprocesar (alineación, eliminación de la media, filtros LP/HP, wavelet, PCA).
5. Recuperación estadística de claves o mediante ML (CPA, MIA, DL-SCA).
6. Validar e iterar sobre los valores atípicos.

---

## Defensas y endurecimiento
* Implementaciones de **tiempo constante** y algoritmos memory-hard.
* **Masking/shuffling** – Dividir los secretos en shares aleatorios; resistencia de primer orden certificada mediante TVLA.
* **Ocultación** – Reguladores de voltaje integrados en el chip, reloj aleatorizado, lógica de doble rail, blindajes EM.
* **Detección de fallos** – Cómputo redundante, firmas de umbral.
* **Operativas** – Desactivar DVFS/turbo en kernels criptográficos, aislar SMT, prohibir la colocación conjunta en clouds multi-tenant.

---

## Herramientas y frameworks
* **ChipWhisperer-Husky** (2024) – Osciloscopio de 500 MS/s + trigger Cortex-M; API de Python como se indicó arriba.<sup>[[1]](#references)</sup>
* **Riscure Inspector y productos de inyección de fallos** – Herramientas comerciales de análisis y pruebas automatizadas.
* **scaaml** – Herramientas y datasets de SCA de deep learning basados en TensorFlow.<sup>[[12]](#references)</sup>
* **pyecsca** – Toolkit open source para realizar ingeniería inversa de implementaciones ECC de caja negra mediante side-channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [Documentación de ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Artículo sobre el ataque Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: explotación de la recopilación especulativa de datos](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: exposición de nuevas superficies de ataque mediante entrenamiento en ejecución transitoria](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Extracción de claves RSA mediante criptoanálisis acústico de bajo ancho de banda](https://eprint.iacr.org/2013/857.pdf)
- [7] [Filtración de información a partir de emanaciones ópticas](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Documentación del artefacto pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Un ataque práctico de side-channel acústico a teclados basado en deep learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - Manual de usuario de ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Documentación de ChipWhisperer — fuente de alimentación para la sonda CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Documentación de Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — realización de ataques electromagnéticos de side-channel de bajo coste mediante RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Descifrado de propiedad intelectual: ataque de side-channel acústico y magnético a una impresora 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — ataques de side-channel acústico a impresoras](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Espionaje de la temperatura mediante DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
- [17] [Siguiendo las instrucciones: tracing ARM en vivo con ETM, ITM y TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
{{#include ../../banners/hacktricks-training.md}}
