# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introducción <a href="#introduction" id="introduction"></a>

Flipper Zero puede **recibir y transmitir radiofrecuencias en el rango de 300-928 MHz** con su módulo integrado, sujeto a las restricciones de frecuencia de la región configurada. Puede leer, guardar y emular controles remotos compatibles utilizados con puertas, barreras, cerraduras de radio, interruptores, timbres inalámbricos, luces inteligentes y otros dispositivos.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero tiene un módulo integrado de menos de 1 GHz basado en un transceptor CC1101 y una antena de radio. El alcance real depende de la frecuencia, la antena, el entorno y el transmisor; la documentación de Flipper indica hasta aproximadamente 50 metros en condiciones favorables. El hardware cubre 300-348 MHz, 387-464 MHz y 779-928 MHz, mientras que el firmware y las normativas regionales restringen aún más la transmisión.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Acciones

### Frequency Analyser

> [!TIP]
> Cómo encontrar la frecuencia utilizada por el control remoto

Durante el análisis, Flipper Zero escanea la intensidad de las señales (RSSI) en todas las frecuencias disponibles en la configuración de frecuencia. Flipper Zero muestra la frecuencia con el valor RSSI más alto, con una intensidad de señal superior a -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Para determinar la frecuencia del control remoto, haz lo siguiente:

1. Coloca el control remoto muy cerca, a la izquierda de Flipper Zero.
2. Ve a **Main Menu** **→ Sub-GHz**.
3. Selecciona **Frequency Analyzer** y mantén pulsado el botón del control remoto que quieras analizar.
4. Consulta el valor de la frecuencia en la pantalla.

### Read

> [!TIP]
> Encuentra información sobre la frecuencia utilizada (también es otra forma de encontrar qué frecuencia se utiliza)

La opción **Read** escucha en la frecuencia y modulación configuradas (433.92 MHz AM de forma predeterminada). Cuando reconoce una señal compatible, la pantalla muestra información que puede guardarse y reproducirse posteriormente.<sup>[[1]](#references)</sup>

Mientras se utiliza Read, es posible pulsar el **botón izquierdo** y **configurarlo**.\
En este momento tiene **4 modulaciones** (AM270, AM650, FM328 y FM476), y **varias frecuencias relevantes** almacenadas:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Puedes seleccionar cualquier frecuencia permitida. Si no estás seguro de qué frecuencia utiliza el control remoto, activa **Hopping** (desactivado de forma predeterminada) y pulsa varias veces el botón del control remoto hasta que Flipper capture la señal e indique la frecuencia.

> [!CAUTION]
> Cambiar entre frecuencias requiere cierto tiempo, por lo que pueden perderse las señales transmitidas durante el cambio. Para obtener una mejor recepción de señal, establece una frecuencia fija determinada mediante Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Roba (y reproduce) una señal en la frecuencia configurada

La opción **Read Raw** graba las señales enviadas en la frecuencia seleccionada. Esto puede utilizarse para capturar y reproducir una señal durante una prueba autorizada.<sup>[[1]](#references)</sup>

De forma predeterminada, **Read Raw también utiliza 433.92 MHz con AM650**. Si la opción Read encuentra una señal en una frecuencia o modulación diferente, pulsa Left dentro de Read Raw para cambiar esos ajustes.

### Brute-Force

Si conoces el protocolo utilizado por un dispositivo, como una puerta de garaje, puede ser posible **generar códigos candidatos y transmitirlos con Flipper Zero**. El proyecto `flipperzero-bruteforce` admite varios protocolos comunes de código estático.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Añade señales de una lista configurada de protocolos

#### Lista de protocolos compatibles <a href="#id-3iglu" id="id-3iglu"></a>

El menú Add Manually muestra los presets de protocolos documentados por Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (works with the majority of static code systems) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### Proveedores Sub-GHz compatibles

Consulta la lista de proveedores compatibles de Flipper Zero.<sup>[[5]](#references)</sup>

### Frecuencias compatibles por región

Consulta la lista oficial de frecuencias regionales antes de transmitir.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Obtén los dBm de las frecuencias guardadas

## References

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101 data sheet](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Add a manually created remote](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Supported Sub-GHz vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Regional Sub-GHz frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
