# iButton

{{#include ../../banners/hacktricks-training.md}}

## Introducción

iButton es un nombre genérico para una llave de identificación electrónica alojada en un **contenedor metálico con forma de moneda**. También se conoce como memoria Dallas Touch o memoria de contacto. Aunque a menudo se la llama erróneamente llave «magnética», **no tiene nada magnético**. De hecho, en su interior se oculta un **microchip** completo que funciona mediante un protocolo digital.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### ¿Qué es iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

El nombre iButton describe el resistente encapsulado con forma de moneda y la disposición de sus contactos. Los soportes incluyen llaveros de plástico, anillos y colgantes.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Cuando ambos contactos se acoplan al lector, el dispositivo recibe alimentación e intercambia datos. Si la geometría de los contactos hundidos impide que los contactos exteriores de tierra hagan contacto, inclinar la llave contra la pared del lector puede restablecer la conexión.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocolo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Las llaves Dallas/Maxim utilizan el protocolo 1-Wire: un contacto de datos transporta la comunicación bidireccional y también puede proporcionar alimentación parasitaria, mientras que la carcasa metálica sirve como contacto de retorno. El controlador inicia las transacciones y el dispositivo responde.<sup>[[2]](#references)</sup>

Cuando la llave (esclavo) hace contacto con el intercomunicador (maestro), el chip dentro de la llave se enciende, alimentado por el intercomunicador, y la llave se inicializa. A continuación, el intercomunicador solicita el ID de la llave. Ahora veremos este proceso con más detalle.

Flipper puede actuar como controlador al leer una llave y como dispositivo emulado al presentar un identificador almacenado a un lector.<sup>[[1]](#references)</sup>

### Llaves Dallas, Cyfral y Metakom

Para obtener información sobre cómo funcionan estas llaves, consulta la página [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Ataques

Se pueden atacar los iButton con Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Domar iButton con Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — Comunicación 1-Wire mediante software](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
