# iButton

{{#include ../../banners/hacktricks-training.md}}

## Introducción

iButton es un nombre genérico para una llave de identificación electrónica alojada en un **contenedor metálico con forma de moneda**. También se denomina memoria **Dallas Touch** o memoria de contacto. Aunque a menudo se la llama incorrectamente llave “magnética”, en su interior **no hay nada magnético**. De hecho, dentro se encuentra oculto un **microchip** completo que funciona mediante un protocolo digital.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### ¿Qué es iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

El nombre iButton describe el paquete resistente con forma de moneda y la disposición de los contactos. Entre sus soportes se incluyen llaveros de plástico, anillos y colgantes.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Cuando ambos contactos tocan el lector, el dispositivo recibe alimentación e intercambia datos. Si la geometría del contacto empotrado impide que los contactos de tierra exteriores hagan contacto, inclinar la llave contra la pared del lector puede restablecer la conexión.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocolo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Las llaves Dallas/Maxim utilizan el protocolo 1-Wire: un contacto de datos transporta tráfico bidireccional y también puede proporcionar alimentación parasitaria, mientras que la carcasa metálica es el contacto de retorno. El controlador inicia las transacciones y el dispositivo responde.<sup>[[2]](#references)</sup>

Cuando la llave (Slave) entra en contacto con el interfono (Master), el chip situado dentro de la llave se enciende, alimentado por el interfono, y la llave se inicializa. A continuación, el interfono solicita el ID de la llave. Ahora veremos este proceso con más detalle.

Flipper puede actuar como controlador al leer una llave y como dispositivo emulado al presentar un identificador almacenado a un lector.<sup>[[1]](#references)</sup>

### Llaves Dallas, Cyfral y Metakom

Para obtener información sobre cómo funcionan estas llaves, consulta la página [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Ataques

Los iButton pueden atacarse con Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Dominar iButton con Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — Comunicación 1-Wire mediante software](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
