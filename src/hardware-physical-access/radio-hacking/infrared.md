# Infrarrojo

{{#include ../../banners/hacktricks-training.md}}

## Cómo funciona el infrarrojo <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La luz infrarroja es invisible para los humanos**. La longitud de onda IR va de **0,7 a 1000 micras**. Los mandos domésticos utilizan una señal IR para transmitir datos y funcionan en el rango de longitud de onda de 0,75..1,4 micras. Un microcontrolador del mando hace parpadear un LED infrarrojo a una frecuencia específica, convirtiendo la señal digital en una señal IR.

Para recibir señales IR se utiliza un **fotorreceptor**. Este **convierte la luz IR en pulsos de voltaje**, que ya son **señales digitales**. Normalmente, el receptor lleva un **filtro óptico oscuro** que deja pasar **solo la longitud de onda deseada** y elimina el ruido.<sup>[[1]](#references)</sup>

### Variedad de protocolos IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Los protocolos IR difieren en 3 factores:<sup>[[1]](#references)</sup>

- codificación de bits
- estructura de datos
- frecuencia portadora — a menudo en el rango de 36..38 kHz

#### Métodos de codificación de bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codificación por distancia de pulso**

Los bits se codifican modulando la duración del espacio entre pulsos. La anchura del pulso es constante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Codificación por anchura de pulso**

Los bits se codifican modulando la anchura del pulso. La duración del espacio después de la ráfaga de pulsos es constante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Codificación de fase**

También se conoce como codificación Manchester. El valor lógico se define por la polaridad de la transición entre la ráfaga de pulsos y el espacio. «Espacio a ráfaga de pulsos» representa el lógico «0» y «ráfaga de pulsos a espacio» representa el lógico «1».

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinación de los anteriores y otros métodos exóticos**

> [!TIP]
> Hay protocolos IR que **intentan convertirse en universales** para varios tipos de dispositivos. Los más famosos son RC5 y NEC. Por desgracia, que sean los más famosos **no significa que sean los más comunes**. En mi entorno, solo me he encontrado con dos mandos NEC y ninguno RC5.
>
> A los fabricantes les encanta utilizar sus propios protocolos IR exclusivos, incluso dentro de la misma gama de dispositivos (por ejemplo, TV-boxes). Por lo tanto, los mandos de distintas empresas y, a veces, los de distintos modelos de la misma empresa, no pueden funcionar con otros dispositivos del mismo tipo.

### Exploración de una señal IR

La forma más fiable de ver cómo es la señal IR de un mando es utilizar un osciloscopio. No demodula ni invierte la señal recibida; simplemente la muestra «tal cual». Esto resulta útil para probar y depurar. Mostraré la señal esperada usando como ejemplo el protocolo IR NEC.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Normalmente, al principio de un paquete codificado hay un preámbulo. Esto permite que el receptor determine el nivel de ganancia y el fondo. También hay protocolos sin preámbulo, como Sharp.

A continuación, se transmiten los datos. La estructura, el preámbulo y el método de codificación de bits los determina el protocolo específico.

El **protocolo IR NEC** contiene un comando corto y un código de repetición, que se envía mientras se mantiene pulsado el botón. Tanto el comando como el código de repetición tienen el mismo preámbulo al principio.

El **comando** NEC, además del preámbulo, consta de un byte de dirección y un byte de número de comando, con los que el dispositivo entiende qué debe ejecutar. Los bytes de dirección y de número de comando se duplican con valores invertidos para comprobar la integridad de la transmisión. Al final del comando hay un bit de parada adicional.

El **código de repetición** tiene un «1» después del preámbulo, que es un bit de parada.

Para los **lógicos «0» y «1»**, NEC utiliza la codificación por distancia de pulso: primero se transmite una ráfaga de pulsos, seguida de una pausa cuya duración determina el valor del bit.

### Aires acondicionados

A diferencia de otros mandos, **los aires acondicionados no transmiten únicamente el código del botón pulsado**. También **transmiten toda la información** al pulsar un botón para garantizar que **el aparato de aire acondicionado y el mando estén sincronizados**.\
Esto evita que un aparato configurado a 20 ºC suba a 21 ºC con un mando y que, al usar otro mando que todavía tiene configurados 20 ºC para volver a subir la temperatura, esta «suba» a 21 ºC (en lugar de a 22 ºC, al pensar que está a 21 ºC).<sup>[[1]](#references)</sup>

---

## Ataques e investigación ofensiva <a href="#attacks" id="attacks"></a>

Puedes atacar el infrarrojo con Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Secuestro de Smart-TV / set-top box (EvilScreen)

Un trabajo académico reciente (EvilScreen, 2022) demostró que **los mandos multicanal que combinan infrarrojos con Bluetooth o Wi-Fi pueden utilizarse para secuestrar por completo smart-TVs modernas**. El ataque encadena códigos de servicio IR de alto privilegio con paquetes Bluetooth autenticados, evita el aislamiento entre canales y permite iniciar aplicaciones arbitrarias, activar el micrófono o restablecer la configuración de fábrica sin acceso físico. Se confirmó que ocho televisores convencionales de distintos proveedores —incluido un modelo Samsung que afirmaba cumplir con ISO/IEC 27001— eran vulnerables. La mitigación requiere actualizaciones de firmware del proveedor o desactivar por completo los receptores IR que no se utilicen.<sup>[[2]](#references)</sup>

### Exfiltración de datos de sistemas aislados mediante LED IR (familia aIR-Jumper)

Las cámaras de seguridad suelen incluir **LED IR de visión nocturna**. El prototipo aIR-Jumper mostró que el malware que controla esos LED podía **exfiltrar secretos a través de ventanas** hacia una cámara externa a una velocidad de hasta **20 bit/s por cámara de vigilancia** a lo largo de decenas de metros. En la dirección inversa, los investigadores demostraron una infiltración de más de **100 bit/s** a distancias de cientos de metros a kilómetros.<sup>[[3]](#references)</sup> Como la luz está fuera del espectro visible, es posible que los operadores no la detecten. Entre las contramedidas se incluyen:

* Proteger físicamente o retirar los LED IR de las zonas sensibles
* Supervisar el ciclo de trabajo de los LED de las cámaras y la integridad del firmware
* Instalar filtros de bloqueo de IR en ventanas y cámaras de vigilancia

Un atacante también puede usar proyectores IR potentes para **infiltrar** comandos en la red, transmitiendo datos a cámaras vulnerables. 

### Fuerza bruta de largo alcance y protocolos extendidos con Flipper Zero 1.0

El firmware 1.0 (septiembre de 2024) amplió la biblioteca de mandos universales y añadió la carga dinámica de archivos de recursos infrarrojos desde microSD.<sup>[[4]](#references)</sup> Sus funciones de aprendizaje y mando universal pueden reproducir comandos conocidos o probarlos en televisores y aires acondicionados cercanos. El alcance depende en gran medida del emisor, la óptica, la luz ambiental y el receptor; el hardware IR externo puede ampliarlo, pero no se debe asumir una distancia fija.

---

## Herramientas y ejemplos prácticos <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – transceptor portátil con modos de aprendizaje, reproducción y fuerza bruta mediante diccionario (véase más arriba).
* **Arduino / ESP32** + LED IR / receptor TSOP38xx – analizador/transmisor DIY económico. Combínalo con la biblioteca `Arduino-IRremote` (la v4.x admite más de 40 protocolos).
* **Analizadores lógicos** (Saleae/FX2) – capturan temporizaciones sin procesar cuando se desconoce el protocolo.
* **Smartphones con emisor IR** (p. ej., Xiaomi) – prueba rápida en terreno, pero con alcance limitado.

### Software

* **`Arduino-IRremote`** – biblioteca C++ con mantenimiento activo:<sup>[[5]](#references)</sup>
  ```cpp
  #include <IRremote.hpp>
  void setup(){ IrSender.begin(3); }
  void loop(){
    IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
    delay(5000);
  }
  ```
* **IRscrutinizer / AnalysIR** – decodificadores con GUI que importan capturas sin procesar, identifican automáticamente el protocolo y generan código Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – recibir e inyectar IR desde la línea de comandos:
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## Medidas defensivas <a href="#defense" id="defense"></a>

* Desactiva o cubre los receptores IR de los dispositivos instalados en espacios públicos cuando no sean necesarios.
* Exige *emparejamiento* o verificaciones criptográficas entre los Smart TV y los mandos a distancia; aísla los códigos de «servicio» privilegiados.
* Instala filtros de corte IR o detectores de onda continua alrededor de áreas clasificadas para interrumpir los canales encubiertos ópticos.
* Supervisa la integridad del firmware de las cámaras y los dispositivos IoT que exponen LED IR controlables.

## References

- [1] [Publicación del blog de infrarrojos de Flipper Zero](https://blog.flipperzero.one/infrared/)
- [2] [Ataque EvilScreen: secuestro de Smart TV mediante imitación de control remoto multicanal (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: exfiltración/infiltración encubierta de un espacio aislado mediante cámaras de seguridad e infrarrojos (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Blog de Flipper Zero - Publicación del firmware 1.0](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - documentación de uso y protocolos](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
