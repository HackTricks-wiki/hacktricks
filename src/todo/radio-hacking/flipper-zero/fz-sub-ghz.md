# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introducción <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero puede **recibir y transmitir radiofrecuencias en el rango de 300-928 MHz** con su módulo integrado, que puede leer, guardar y emular controles remotos. Estos controles se utilizan para interactuar con portones, barreras, cerraduras de radio, interruptores de control remoto, timbres inalámbricos, luces inteligentes y mucho más. Flipper Zero puede ayudarte a saber si tu seguridad está comprometida.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero tiene un módulo sub-1 GHz integrado basado en un [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[chip CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) y una antena de radio (el alcance máximo es de 50 metros). Tanto el chip CC1101 como la antena están diseñados para operar en las bandas de 300-348 MHz, 387-464 MHz y 779-928 MHz.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Acciones

### Frequency Analyser

> [!TIP]
> Cómo encontrar la frecuencia que utiliza el control remoto

Durante el análisis, Flipper Zero escanea la intensidad de las señales (RSSI) en todas las frecuencias disponibles en la configuración de frecuencias. Flipper Zero muestra la frecuencia con el valor RSSI más alto, con una intensidad de señal superior a -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Para determinar la frecuencia del control remoto, haz lo siguiente:

1. Coloca el control remoto muy cerca, a la izquierda de Flipper Zero.
2. Ve a **Main Menu** **→ Sub-GHz**.
3. Selecciona **Frequency Analyzer** y, a continuación, mantén presionado el botón del control remoto que quieras analizar.
4. Revisa el valor de la frecuencia en la pantalla.

### Read

> [!TIP]
> Encontrar información sobre la frecuencia utilizada (también es otra forma de encontrar qué frecuencia se utiliza)

La opción **Read** **escucha en la frecuencia configurada** con la modulación indicada: 433.92 AM de forma predeterminada. Si **se encuentra algo** durante la lectura, se muestra **información** en la pantalla. Esta información podría utilizarse para replicar la señal en el futuro.<sup>[[1]](#references)</sup>

Mientras se utiliza Read, es posible presionar el **botón izquierdo** y **configurarlo**.\
En este momento tiene **4 modulaciones** (AM270, AM650, FM328 y FM476), y **varias frecuencias relevantes** almacenadas:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Puedes establecer **cualquiera que te interese**; sin embargo, si **no estás seguro de qué frecuencia** podría utilizar el control remoto que tienes, **activa Hopping** (desactivado de forma predeterminada) y presiona el botón varias veces hasta que Flipper la capture y te proporcione la información necesaria para configurar la frecuencia.

> [!CAUTION]
> Cambiar entre frecuencias requiere cierto tiempo, por lo que las señales transmitidas durante el cambio pueden perderse. Para una mejor recepción de señal, establece una frecuencia fija determinada mediante Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Robar (y reproducir) una señal en la frecuencia configurada

La opción **Read Raw** **graba las señales** enviadas en la frecuencia de escucha. Esto puede utilizarse para **robar** una señal y **repetirla**.

De forma predeterminada, **Read Raw también está en 433.92 con AM650**, pero si con la opción Read descubriste que la señal que te interesa está en una **frecuencia/modulación diferente, también puedes modificarla** presionando el botón izquierdo (mientras estás dentro de la opción Read Raw).

### Fuerza bruta

Si conoces el protocolo utilizado, por ejemplo, por la puerta de un garaje, es posible **generar todos los códigos y enviarlos con Flipper Zero.** Este es un ejemplo compatible con tipos comunes y generales de garajes: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Añadir manualmente

> [!TIP]
> Añadir señales desde una lista configurada de protocolos

#### Lista de [protocolos compatibles](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (funciona con la mayoría de los sistemas de código estático) | 433.92 | Estático |
| -------------------------------------------------------------------------- | ------ | -------- |
| Nice Flo 12bit_433                                                         | 433.92 | Estático |
| Nice Flo 24bit_433                                                         | 433.92 | Estático |
| CAME 12bit_433                                                             | 433.92 | Estático |
| CAME 24bit_433                                                             | 433.92 | Estático |
| Linear_300                                                                 | 300.00 | Estático |
| CAME TWEE                                                                  | 433.92 | Estático |
| Gate TX_433                                                                 | 433.92 | Estático |
| DoorHan_315                                                                 | 315.00 | Dinámico |
| DoorHan_433                                                                 | 433.92 | Dinámico |
| LiftMaster_315                                                              | 315.00 | Dinámico |
| LiftMaster_390                                                              | 390.00 | Dinámico |
| Security+2.0_310                                                            | 310.00 | Dinámico |
| Security+2.0_315                                                            | 315.00 | Dinámico |
| Security+2.0_390                                                            | 390.00 | Dinámico |

### Proveedores Sub-GHz compatibles

Consulta la lista en [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Frecuencias compatibles por región

Consulta la lista en [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Prueba

> [!TIP]
> Obtener los dBms de las frecuencias guardadas

## Referencias

- [1] [Documentación Sub-GHz de Flipper Zero](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
