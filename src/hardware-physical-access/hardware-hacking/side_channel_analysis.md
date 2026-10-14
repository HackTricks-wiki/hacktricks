# Ataques de análisis de canal lateral

{{#include ../../banners/hacktricks-training.md}}

Los ataques de canal lateral recuperan secretos observando «leakage» físico o microarquitectónico que está *correlacionado* con el estado interno, pero que no forma parte de la interfaz lógica del dispositivo. Los ejemplos van desde medir la corriente instantánea que consume una tarjeta inteligente hasta abusar de los efectos de gestión de energía de la CPU a través de una red.

---

## Canales principales de leakage

| Canal | Objetivo típico | Instrumentación |
|---------|---------------|-----------------|
| Consumo de energía | Tarjetas inteligentes, MCU de IoT, FPGA | Osciloscopio más resistencia shunt o sonda diferencial; el CW503 es una fuente de alimentación para sondas/LNA, no es una sonda por sí mismo<sup>[[11]](#references)</sup> |
| Campo electromagnético (EM) | CPU, RFID, aceleradores AES | Sonda de campo H/campo cercano más amplificador de bajo ruido y osciloscopio o receptor SDR, como un RTL-SDR<sup>[[13]](#references)</sup> |
| Tiempo de ejecución / cachés | CPU de escritorio y de la nube | Temporizadores de alta precisión (`rdtsc`/`rdtscp`) o medición remota del tiempo de vuelo |
| Acústico / mecánico | Teclados, impresoras 3D, impresoras, relés y reguladores de voltaje de CPU | Micrófono MEMS o vibrometro láser<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Óptico y térmico | LED de estado, pantallas, DRAM y dispositivos con acoplamiento térmico | Fotodiodo, cámara de alta velocidad o cámara IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Inyección de fallos | Criptografía ASIC/MCU | Glitch de reloj/voltaje, EMFI o inyección láser |

---

## Análisis de energía

### Análisis simple de energía (SPA)
Observa un *único* trace y asocia las características visibles con operaciones como ramas, multiplicación modular o distintas secuencias de instrucciones.<sup>[[1]](#references)</sup>

La configuración exacta depende del objetivo. El siguiente ejemplo usa la API de captura de alto nivel actual de ChipWhisperer, una vez conectados y configurados el osciloscopio y el objetivo:<sup>[[1]](#references)</sup>

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
Adquiere múltiples trazas, plantea como hipótesis un byte de clave `k`, calcula un modelo de fuga basado en el peso de Hamming (HW) o la distancia de Hamming (HD) y correlaciónalo con cada muestra. La cantidad de trazas necesaria depende del objetivo, el ruido, la alineación, las contramedidas y el modelo de fuga; no existe un umbral fijo.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA es una referencia estándar. Template attacks, el análisis de información mutua y los enfoques de machine learning pueden ser útiles cuando la fuga es no lineal o las trazas están mal alineadas.

---

## Análisis electromagnético (EMA)
El análisis EM de campo cercano puede observar actividad dependiente de los datos sin insertar un shunt en la ruta de alimentación. No necesariamente expone la misma señal que una traza de potencia: la posición y orientación de la sonda, el ancho de banda, la ganancia de la etapa de entrada, la calidad del trigger y la distancia son factores importantes.

---

## Ataques de temporización y microarquitectura
Las CPU modernas filtran secretos a través de recursos compartidos:
* **Hertzbleed (2022)** – El escalado dinámico de voltaje y frecuencia dependiente de los datos crea un canal de temporización remoto. La demostración original de recuperación de claves de extremo a extremo tenía como objetivo SIKE; trabajos posteriores analizan otros primitivos.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – La ejecución transitoria puede exponer datos usados por instrucciones vectoriales gather a través de límites de seguridad.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – El manejo incorrecto del estado especulativo de los registros vectoriales puede divulgar datos del mismo núcleo físico.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Un ataque de ejecución transitoria combina la ejecución fantasma con el entrenamiento en ejecución transitoria para crear gadgets de predicción errónea controlados por el atacante.<sup>[[5]](#references)</sup>

---

## Ataques acústicos y ópticos
Se ha usado una fuga acústica para recuperar claves RSA a partir del ruido de una laptop en un experimento controlado, incluso con el micrófono de un teléfono móvil cercano.<sup>[[6]](#references)</sup> En otro estudio de teclado de 2023, se clasificaron las pulsaciones con un 95% de precisión al entrenar con grabaciones de un teléfono cercano y con un 93% al entrenar con audio de Zoom; estas cifras describen el experimento con dispositivos entrenados de ese artículo, no cualquier teclado o víctima.<sup>[[9]](#references)</sup> Las emanaciones ópticas de los LED de estado también pueden correlacionarse con los datos procesados. Estos resultados dependen del objetivo y la configuración; no generalices su alcance ni su tasa de éxito a dispositivos no relacionados.<sup>[[7]](#references)</sup>

---

## Inyección de fallos y análisis diferencial de fallos (DFA)
Combinar fallos controlados con observaciones de canal lateral puede reducir la búsqueda de claves para algunos algoritmos e implementaciones. Entre las plataformas de laboratorio habituales se encuentran las funciones de glitching de voltaje/reloj de ChipWhisperer y herramientas específicas de inyección de fallos EM, como ChipSHOUTER o PicoEMP. No debe usarse como especificación la descripción anterior del borrador de “menos de 1 ns”: el manual publicado de ChipSHOUTER indica anchos típicos de pulso insertado de **15–80 ns** con su punta de 1 mm y de **24–480 ns** con su punta de 4 mm (aunque la fluctuación temporal del trigger/pulso se especifica en picosegundos). La resolución temporal necesaria, la colocación de la sonda y la cantidad de salidas erróneas dependen del objetivo y del modelo de fallo.<sup>[[1]](#references)[[10]](#references)</sup>

## Líneas de investigación no verificadas conservadas del borrador anterior

El borrador anterior también afirmaba lo siguiente: una configuración EM de **500 MHz–3 GHz** que recuperaba una clave STM32 desde más de **10 cm** usando un RTL-SDR; un LED de actividad DDR4 que revelaba una clave de ronda AES en menos de un minuto en “Black Hat 2023”; y una plataforma de glitching RISC-V de código abierto de 2025 llamada **GlitchKit-R5**. Durante esta auditoría no se pudo localizar ningún artículo primario, material de conferencia ni repositorio de proyecto coincidente. Estos detalles exactos se conservan como pistas para búsquedas y reproducción, no como resultados establecidos ni recomendaciones de herramientas.

---

## Flujo de trabajo habitual de un ataque
1. Identificar el canal de fuga y el punto de conexión (pin VCC, condensador de desacoplamiento, punto de campo cercano).
2. Insertar un trigger (GPIO o basado en patrones).  
3. Recopilar suficientes trazas para la prueba estadística elegida y registrar el texto plano/cifrado y otros metadatos.
4. Preprocesar (alineación, eliminación de la media, filtro LP/HP, wavelet, PCA).
5. Recuperación de claves estadística o con ML (CPA, MIA, DL-SCA).
6. Validar e iterar sobre los valores atípicos.

---

## Defensas y endurecimiento
* Implementaciones **constant-time** y algoritmos memory-hard.
* **Masking/shuffling** – dividir los secretos en partes aleatorias; resistencia de primer orden certificada por TVLA.
* **Hiding** – reguladores de voltaje en el chip, reloj aleatorizado, lógica de doble carril, blindajes EM.
* **Detección de fallos** – cálculo redundante, firmas de umbral.
* **Operativas** – deshabilitar DVFS/turbo en kernels criptográficos, aislar SMT, prohibir la colocación conjunta en clouds multiusuario.

---

## Herramientas y frameworks
* **ChipWhisperer-Husky** (2024) – osciloscopio de 500 MS/s + trigger Cortex-M; API de Python como la indicada arriba.<sup>[[1]](#references)</sup>
* **Riscure Inspector y productos de inyección de fallos** – herramientas comerciales de análisis y pruebas automatizadas.
* **scaaml** – herramientas de SCA basadas en deep learning con TensorFlow y conjuntos de datos.<sup>[[12]](#references)</sup>
* **pyecsca** – toolkit de código abierto para aplicar ingeniería inversa a implementaciones ECC de caja negra mediante canales laterales.<sup>[[8]](#references)</sup>

---

## References

- [1] [Documentación de ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Artículo sobre el ataque Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: Explotación de la recopilación especulativa de datos](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposición de nuevas superficies de ataque mediante entrenamiento en ejecución transitoria](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Extracción de claves RSA mediante criptoanálisis acústico de bajo ancho de banda](https://eprint.iacr.org/2013/857.pdf)
- [7] [Fuga de información a partir de emanaciones ópticas](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Documentación del artefacto pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Un ataque práctico de canal lateral acústico a teclados basado en deep learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - Manual de usuario de ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Documentación de ChipWhisperer — fuente de alimentación para la sonda CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Documentación de Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — Realización de ataques de canal lateral electromagnético de bajo costo mediante RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Descodificación de la propiedad intelectual: ataque de canal lateral acústico y magnético a una impresora 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Ataques de canal lateral acústico a impresoras](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Espionaje de la temperatura mediante DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
