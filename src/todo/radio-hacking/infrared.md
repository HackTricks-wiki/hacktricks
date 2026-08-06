# Infrarrojo

{{#include ../../banners/hacktricks-training.md}}

## Cómo funciona el infrarrojo <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La luz infrarroja es invisible para los humanos**. La longitud de onda IR va de **0,7 a 1000 micras**. Los mandos domésticos utilizan una señal IR para transmitir datos y funcionan en el rango de longitudes de onda de 0,75..1,4 micras. Un microcontrolador en el mando hace parpadear un LED infrarrojo con una frecuencia específica, convirtiendo la señal digital en una señal IR.

Para recibir señales IR se utiliza un **fotoreceptor**. Este **convierte la luz IR en pulsos de voltaje**, que ya son **señales digitales**. Normalmente, hay un **filtro de luz oscura dentro del receptor**, que permite el paso **únicamente de la longitud de onda deseada** y elimina el ruido.<sup>[[1]](#references)</sup>

### Variedad de protocolos IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Los protocolos IR difieren en 3 factores:<sup>[[1]](#references)</sup>

- codificación de bits
- estructura de datos
- frecuencia portadora — normalmente en el rango de 36..38 kHz

#### Métodos de codificación de bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Los bits se codifican modulando la duración del espacio entre pulsos. La anchura del pulso permanece constante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Los bits se codifican mediante la modulación de la anchura del pulso. La anchura del espacio después del tren de pulsos permanece constante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

También se conoce como codificación Manchester. El valor lógico se define mediante la polaridad de la transición entre el tren de pulsos y el espacio. "Space to pulse burst" indica el valor lógico "0", mientras que "pulse burst to space" indica el valor lógico "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinación de los anteriores y otros exóticos**

> [!TIP]
> Existen protocolos IR que **intentan convertirse en universales** para varios tipos de dispositivos. Los más famosos son RC5 y NEC. Desafortunadamente, que sean los más famosos **no significa que sean los más comunes**. En mi entorno, solo he encontrado dos mandos NEC y ninguno RC5.
>
> A los fabricantes les encanta utilizar sus propios protocolos IR únicos, incluso dentro del mismo tipo de dispositivos (por ejemplo, TV-boxes). Por lo tanto, los mandos de distintas empresas y, en ocasiones, de distintos modelos de la misma empresa, no pueden funcionar con otros dispositivos del mismo tipo.

### Explorando una señal IR

La forma más fiable de ver el aspecto de la señal IR de un mando es utilizar un osciloscopio. Este no demodula ni invierte la señal recibida, sino que simplemente la muestra "tal cual". Esto resulta útil para realizar pruebas y debugging. Mostraré la señal esperada utilizando como ejemplo el protocolo IR NEC.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Normalmente, al principio de un paquete codificado hay un preámbulo. Esto permite al receptor determinar el nivel de ganancia y el fondo. También existen protocolos sin preámbulo, como Sharp.

A continuación, se transmiten los datos. La estructura, el preámbulo y el método de codificación de bits vienen determinados por el protocolo específico.

El **protocolo IR NEC** contiene un comando corto y un código de repetición, que se envía mientras se mantiene pulsado el botón. Tanto el comando como el código de repetición tienen el mismo preámbulo al principio.

El **comando** NEC, además del preámbulo, consta de un byte de dirección y un byte de número de comando, mediante los cuales el dispositivo entiende qué debe ejecutar. Los bytes de dirección y de número de comando se duplican con valores inversos para comprobar la integridad de la transmisión. Al final del comando hay un bit de parada adicional.

El **código de repetición** tiene un "1" después del preámbulo, que es un bit de parada.

Para los valores **lógicos "0" y "1"**, NEC utiliza Pulse Distance Encoding: primero se transmite un tren de pulsos, seguido de una pausa cuya longitud establece el valor del bit.

### Aires acondicionados

A diferencia de otros mandos, **los aires acondicionados no transmiten únicamente el código del botón pulsado**. También **transmiten toda la información** cuando se pulsa un botón para garantizar que la **máquina de aire acondicionado y el mando estén sincronizados**.\
Esto evita que una máquina configurada a 20 ºC se incremente a 21 ºC con un mando y que, posteriormente, al utilizar otro mando que todavía tiene la temperatura configurada a 20 ºC para aumentarla de nuevo, esta se "incremente" a 21 ºC (en lugar de a 22 ºC, al asumir que está a 21 ºC).<sup>[[1]](#references)</sup>

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

Puedes atacar el infrarrojo con Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Toma de control de Smart-TV / Set-top Box (EvilScreen)

Un trabajo académico reciente (EvilScreen, 2022) demostró que **los mandos multicanal que combinan infrarrojos con Bluetooth o Wi-Fi pueden utilizarse para secuestrar por completo Smart-TVs modernas**. El ataque encadena códigos de servicio IR con privilegios elevados y paquetes Bluetooth autenticados, evadiendo el aislamiento entre canales y permitiendo iniciar aplicaciones arbitrarias, activar el micrófono o realizar un factory-reset sin acceso físico. Se confirmó que ocho televisores convencionales de distintos proveedores —incluido un modelo de Samsung que afirmaba cumplir con ISO/IEC 27001— eran vulnerables. La mitigación requiere correcciones de firmware del proveedor o deshabilitar por completo los receptores IR que no se utilicen.<sup>[[2]](#references)</sup>

### Exfiltración de datos desde redes aisladas mediante LED IR (familia aIR-Jumper)

Las cámaras de seguridad, los routers e incluso los dispositivos USB maliciosos suelen incluir **LED IR de visión nocturna**. Las investigaciones demuestran que el malware puede modular estos LED (<10–20 kbit/s con OOK simple) para **exfiltrar secretos a través de paredes y ventanas** hacia una cámara externa situada a decenas de metros.<sup>[[3]](#references)</sup> Como la luz está fuera del espectro visible, los operadores rara vez lo notan. Contramedidas:

* Proteger físicamente o retirar los LED IR de las áreas sensibles
* Monitorizar el ciclo de trabajo de los LED de las cámaras y la integridad del firmware
* Implementar filtros IR-cut en ventanas y cámaras de vigilancia

Un atacante también puede utilizar proyectores IR potentes para **infiltrar** comandos en la red, enviando datos mediante flashes a cámaras inseguras.

### Brute-force de largo alcance y protocolos extendidos con Flipper Zero 1.0

El firmware 1.0 (septiembre de 2024) añadió **docenas de protocolos IR adicionales y módulos amplificadores externos opcionales**. Combinado con el modo universal-remote brute-force, un Flipper puede desactivar o reconfigurar la mayoría de los televisores y aires acondicionados públicos desde una distancia de hasta 30 m utilizando un diodo de alta potencia.

---

## Herramientas y ejemplos prácticos <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – transceptor portátil con modos de aprendizaje, replay y dictionary-bruteforce (véase arriba).
* **Arduino / ESP32** + LED IR / receptor TSOP38xx – analizador/transmisor DIY económico. Combínalo con la biblioteca `Arduino-IRremote` (v4.x admite >40 protocolos).
* **Analizadores lógicos** (Saleae/FX2) – capturan timings sin procesar cuando se desconoce el protocolo.
* **Smartphones con IR-blaster** (por ejemplo, Xiaomi) – prueba rápida en campo, pero con alcance limitado.

### Software

* **`Arduino-IRremote`** – biblioteca C++ mantenida activamente:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – decoders GUI que importan capturas sin procesar, identifican automáticamente el protocolo y generan código Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – reciben e inyectan IR desde la línea de comandos:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Medidas defensivas <a href="#defense" id="defense"></a>

* Deshabilitar o cubrir los receptores IR de los dispositivos instalados en espacios públicos cuando no sean necesarios.
* Exigir *pairing* o comprobaciones criptográficas entre Smart-TVs y mandos; aislar los códigos de servicio con privilegios.
* Implementar filtros IR-cut o detectores de onda continua alrededor de áreas clasificadas para interrumpir los covert channels ópticos.
* Monitorizar la integridad del firmware de las cámaras y los dispositivos IoT que expongan LED IR controlables.

## Referencias

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)

{{#include ../../banners/hacktricks-training.md}}
