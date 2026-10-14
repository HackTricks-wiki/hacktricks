# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introducción <a href="#introduction" id="introduction"></a>

Flipper Zero puede **recibir y transmitir frecuencias de radio en el rango de 300-928 MHz** con su módulo integrado, sujeto a las restricciones de frecuencia de la región configurada. Puede leer, guardar y emular controles remotos compatibles usados con portones, barreras, cerraduras de radio, interruptores, timbres inalámbricos, luces inteligentes y otros dispositivos.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero tiene un módulo sub-1 GHz integrado basado en un transceptor CC1101 y una antena de radio. El alcance real depende de la frecuencia, la antena, el entorno y el transmisor; Flipper documenta un alcance de hasta aproximadamente 50 metros en condiciones favorables. El hardware cubre 300-348 MHz, 387-464 MHz y 779-928 MHz, mientras que el firmware y las normativas regionales restringen aún más la transmisión.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Acciones

### Analizador de frecuencia

> [!TIP]
> Cómo averiguar qué frecuencia usa el control remoto

Al analizar, Flipper Zero escanea la intensidad de las señales (RSSI) en todas las frecuencias disponibles en la configuración de frecuencia. Flipper Zero muestra la frecuencia con el valor RSSI más alto, con una intensidad de señal superior a -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Para determinar la frecuencia del control remoto, sigue estos pasos:

1. Coloca el control remoto muy cerca del lado izquierdo de Flipper Zero.
2. Ve a **Menú principal** **→ Sub-GHz**.
3. Selecciona **Analizador de frecuencia** y mantén pulsado el botón del control remoto que quieras analizar.
4. Consulta el valor de frecuencia en la pantalla.

### Read

> [!TIP]
> Averigua la frecuencia utilizada (también es otra forma de averiguar qué frecuencia se usa)

La opción **Read** escucha en la frecuencia y con la modulación configuradas (433.92 MHz AM de forma predeterminada). Cuando reconoce una señal compatible, la pantalla muestra información que se puede guardar y reproducir más adelante.<sup>[[1]](#references)</sup>

Mientras Read está en uso, puedes pulsar el **botón izquierdo** y **configurarlo**.\
Actualmente tiene **4 modulaciones** (AM270, AM650, FM328 y FM476) y **varias frecuencias relevantes** almacenadas:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Puedes seleccionar cualquier frecuencia permitida. Si no sabes qué frecuencia usa el control remoto, activa **Hopping** (desactivado de forma predeterminada) y pulsa el botón del control remoto varias veces hasta que Flipper capture la señal e indique la frecuencia.

> [!CAUTION]
> Cambiar de frecuencia lleva tiempo, por lo que se pueden perder las señales transmitidas durante el cambio. Para recibir mejor la señal, configura una frecuencia fija determinada con el Analizador de frecuencia.

### **Read Raw**

> [!TIP]
> Roba (y reproduce) una señal en la frecuencia configurada

La opción **Read Raw** graba las señales transmitidas en la frecuencia seleccionada. Se puede usar para capturar y reproducir una señal durante pruebas autorizadas.<sup>[[1]](#references)</sup>

De forma predeterminada, **Read Raw también usa 433.92 MHz con AM650**. Si la opción Read detectó una señal en otra frecuencia o modulación, pulsa Left dentro de Read Raw para cambiar esos ajustes.

### Brute-Force

Si conoces el protocolo que usa un dispositivo, como una puerta de garaje, quizá sea posible **generar códigos candidatos y transmitirlos con Flipper Zero**. El proyecto `flipperzero-bruteforce` es compatible con varios protocolos comunes de código estático.<sup>[[3]](#references)</sup>

### Añadir manualmente

> [!TIP]
> Añade señales de una lista de protocolos configurada

#### Lista de protocolos compatibles <a href="#id-3iglu" id="id-3iglu"></a>

El menú Add Manually muestra los ajustes preestablecidos de protocolo documentados por Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (funciona con la mayoría de los sistemas de código estático) | 433.92 | Static  |
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

### Prueba

> [!TIP]
> Obtén los valores en dBm de las frecuencias guardadas

## References

- [1] [Sub-GHz - Documentación de usuario de Flipper Zero](https://docs.flipperzero.one/sub-ghz)
- [2] [Hoja de datos del CC1101 de Texas Instruments](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Añadir un control remoto creado manualmente](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Proveedores Sub-GHz compatibles](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Frecuencias Sub-GHz regionales](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
