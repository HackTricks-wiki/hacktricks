# iButton

{{#include ../../banners/hacktricks-training.md}}

## Introducción

iButton es un nombre genérico para una llave de identificación electrónica empaquetada en un **contenedor metálico con forma de moneda**. También se denomina memoria **Dallas Touch** o memoria de contacto. Aunque a menudo se la llama erróneamente llave “magnética”, no contiene **nada magnético**. En realidad, en su interior se oculta un **microchip** completo que funciona mediante un protocolo digital.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### ¿Qué es iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Normalmente, iButton hace referencia a la forma física de la llave y del lector: una moneda redonda con dos contactos. En cuanto al armazón que la rodea, existen muchas variaciones, desde el soporte de plástico más común con un agujero hasta anillos, colgantes, etc.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Cuando la llave llega al lector, los **contactos entran en contacto** y la llave recibe alimentación para **transmitir** su ID. A veces la llave **no se lee** inmediatamente porque el **PSD de contacto del interfono es más grande** de lo debido. Por lo tanto, los contornos exteriores de la llave y del lector no pueden tocarse. Si ese es el caso, tendrás que presionar la llave contra una de las paredes del lector.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocolo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Las llaves Dallas intercambian datos mediante el protocolo 1-Wire, con un único contacto para la transferencia de datos (!!) en ambas direcciones: del Master al Slave y viceversa. El protocolo 1-Wire funciona según el modelo Master-Slave. En esta topología, el Master siempre inicia la comunicación y el Slave sigue sus instrucciones.

Cuando la llave (Slave) entra en contacto con el interfono (Master), el chip situado en el interior de la llave se enciende, alimentado por el interfono, y la llave se inicializa. A continuación, el interfono solicita el ID de la llave. Seguidamente, analizaremos este proceso con más detalle.

Flipper puede funcionar tanto en modo Master como en modo Slave. En el modo de lectura de llaves, Flipper actúa como lector; es decir, funciona como Master. En el modo de emulación de llaves, Flipper simula ser una llave y funciona en modo Slave.

### Llaves Dallas, Cyfral y Metakom

Para obtener información sobre cómo funcionan estas llaves, consulta la página [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Ataques

Los iButtons pueden atacarse con Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Referencias

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
