# Infrarrojo

{{#include ../../banners/hacktricks-training.md}}

## Cómo funciona el infrarrojo <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La luz infrarroja es invisible para los humanos**. La longitud de onda IR va de **0.7 a 1000 micras**. Los mandos domésticos utilizan una señal IR para la transmisión de datos y funcionan en el rango de longitudes de onda de 0.75..1.4 micras. Un microcontrolador en el mando hace parpadear un LED infrarrojo con una frecuencia específica, convirtiendo la señal digital en una señal IR.

Para recibir señales IR se utiliza un **fotoreceptor**. Este **convierte la luz IR en pulsos de voltaje**, que ya son **señales digitales**. Normalmente, hay un **filtro de luz oscura dentro del receptor**, que deja pasar **solo la longitud de onda deseada** y elimina el ruido.<sup>[[1]](#references)</sup>

### Variedad de protocolos IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Los protocolos IR difieren en 3 factores:<sup>[[1]](#references)</sup>

- codificación de bits
- estructura de datos
- frecuencia portadora — a menudo en el rango de 36..38 kHz

#### Formas de codificación de bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Los bits se codifican modulando la duración del espacio entre pulsos. La anchura del pulso permanece constante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Los bits se codifican mediante la modulación de la anchura del pulso. La anchura del espacio después del burst del pulso permanece constante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

También se conoce como codificación Manchester. El valor lógico se define mediante la polaridad de la transición entre el burst del pulso y el espacio. "Space to pulse burst" representa la lógica "0", y "pulse burst to space" representa la lógica "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinación de las anteriores y otras exóticas**

> [!TIP]
> Hay protocolos IR que **intentan convertirse en universales** para varios tipos de dispositivos. Los más famosos son RC5 y NEC. Desafortunadamente, que sean los más famosos **no significa que sean los más comunes**. En mi entorno, solo encontré dos mandos NEC y ninguno RC5.
>
> A los fabricantes les encanta utilizar sus propios protocolos IR únicos, incluso dentro del mismo rango de dispositivos (por ejemplo, TV-boxes). Por lo tanto, los mandos de diferentes empresas y, en ocasiones, de diferentes modelos de la misma empresa, no pueden funcionar con otros dispositivos del mismo tipo.

### Exploración de una señal IR

La forma más fiable de ver cómo es la señal IR de un mando es utilizar un osciloscopio. No demodula ni invierte la señal recibida, simplemente la muestra "tal cual". Esto resulta útil para realizar pruebas y debugging. Mostraré la señal esperada utilizando como ejemplo el protocolo IR NEC.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Normalmente, al principio de un paquete codificado hay un preámbulo. Esto permite al receptor determinar el nivel de ganancia y el fondo. También existen protocolos sin preámbulo, como Sharp.

A continuación se transmiten los datos. La estructura, el preámbulo y el método de codificación de bits vienen determinados por el protocolo específico.

El **protocolo IR NEC** contiene un comando corto y un código de repetición, que se envía mientras se mantiene pulsado el botón. Tanto el comando como el código de repetición tienen el mismo preámbulo al principio.

El **comando** NEC, además del preámbulo, consta de un byte de dirección y un byte de número de comando, mediante los cuales el dispositivo entiende qué debe ejecutar. Los bytes de dirección y de número de comando se duplican con valores inversos para comprobar la integridad de la transmisión. Al final del comando hay un bit de parada adicional.

El **código de repetición** tiene un "1" después del preámbulo, que es un bit de parada.

Para la **lógica "0" y "1"**, NEC utiliza Pulse Distance Encoding: primero se transmite un burst de pulsos, seguido de una pausa cuya longitud establece el valor del bit.

### Acondicionadores de aire

A diferencia de otros mandos, **los acondicionadores de aire no transmiten únicamente el código del botón pulsado**. También **transmiten toda la información** cuando se pulsa un botón para garantizar que **el acondicionador de aire y el mando estén sincronizados**.\
Esto evita que un dispositivo configurado a 20 ºC aumente a 21 ºC con un mando y que, después, al utilizar otro mando que todavía tiene la temperatura configurada a 20 ºC para aumentarla más, la "aumente" a 21 ºC (en lugar de 22 ºC, al creer que está a 21 ºC).<sup>[[1]](#references)</sup>

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

Puedes atacar Infrared con Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Toma de control de Smart-TV / Set-top Box (EvilScreen)

Un trabajo académico reciente (EvilScreen, 2022) demostró que **los mandos multicanal que combinan Infrared con Bluetooth o Wi-Fi pueden utilizarse para secuestrar completamente Smart-TVs modernas**. El ataque encadena códigos de servicio IR con privilegios elevados junto con paquetes Bluetooth autenticados, eludiendo el aislamiento de canales y permitiendo iniciar aplicaciones arbitrarias, activar el micrófono o realizar un factory-reset sin acceso físico. Se confirmó que ocho televisores populares de distintos proveedores —incluido un modelo de Samsung que afirmaba cumplir con ISO/IEC 27001— eran vulnerables. La mitigación requiere correcciones de firmware del proveedor o deshabilitar por completo los receptores IR no utilizados.<sup>[[2]](#references)</sup>

### Exfiltración de datos desde redes aisladas mediante LED IR (familia aIR-Jumper)

Las cámaras de seguridad suelen incluir **LED IR de visión nocturna**. El prototipo aIR-Jumper demostró que el malware que controlara esos LED podía **exfiltrar secretos a través de ventanas** hacia una cámara externa a una velocidad de hasta **20 bit/s por cámara de vigilancia** a lo largo de decenas de metros. En la dirección inversa, los investigadores demostraron una infiltración de más de **100 bit/s** a distancias de cientos de metros a kilómetros.<sup>[[3]](#references)</sup> Como la luz está fuera del espectro visible, los operadores podrían no detectarla. Entre las contramedidas se incluyen:

* Blindar o retirar físicamente los LED IR en áreas sensibles
* Supervisar el duty-cycle de los LED de la cámara y la integridad del firmware
* Implementar filtros IR-cut en ventanas y cámaras de vigilancia

Un atacante también puede utilizar proyectores IR potentes para **infiltrar** comandos en la red mediante el flashing de datos hacia cámaras inseguras.

### Brute-Force de largo alcance y protocolos extendidos con Flipper Zero 1.0

El firmware 1.0 (septiembre de 2024) amplió la librería de universal-remotes y añadió la carga dinámica de archivos de recursos infrarrojos desde microSD.<sup>[[4]](#references)</sup> Sus funciones de aprendizaje y universal-remote pueden reproducir o probar comandos conocidos contra televisores y acondicionadores de aire cercanos. El alcance depende en gran medida del emisor, la óptica, la luz ambiental y el receptor; el hardware IR externo puede ampliarlo, pero no debe suponerse una distancia fija.

---

## Herramientas y ejemplos prácticos <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – transceiver portátil con modos de aprendizaje, replay y dictionary-bruteforce (véase arriba).
* **Arduino / ESP32** + LED IR / receptor TSOP38xx – analizador/transmisor DIY económico. Combínalo con la librería `Arduino-IRremote` (v4.x admite más de 40 protocolos).
* **Analizadores lógicos** (Saleae/FX2) – capturan tiempos sin procesar cuando se desconoce el protocolo.
* **Smartphones con IR-blaster** (por ejemplo, Xiaomi) – prueba rápida de campo, pero con alcance limitado.

### Software

* **`Arduino-IRremote`** – librería C++ mantenida activamente:<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – decoders con GUI que importan capturas sin procesar, identifican automáticamente el protocolo y generan código Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – reciben e inyectan IR desde la línea de comandos:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Medidas defensivas <a href="#defense" id="defense"></a>

* Deshabilita o cubre los receptores IR de los dispositivos instalados en espacios públicos cuando no sean necesarios.
* Exige *pairing* o comprobaciones criptográficas entre Smart-TVs y mandos; aísla los códigos de “servicio” privilegiados.
* Implementa filtros IR-cut o detectores de onda continua alrededor de áreas clasificadas para interrumpir los canales ópticos encubiertos.
* Supervisa la integridad del firmware de las cámaras y dispositivos IoT que expongan LED IR controlables.

## References

- [1] [Publicación del blog de Infrared de Flipper Zero](https://blog.flipperzero.one/infrared/)
- [2] [Ataque EvilScreen: secuestro de Smart TV mediante imitación de mandos multicanal (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: exfiltración/infiltración encubierta desde redes aisladas mediante cámaras de seguridad e infrarrojos (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Blog de Flipper Zero - Firmware 1.0 publicado](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - documentación de uso y protocolos](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
