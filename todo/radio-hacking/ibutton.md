# iButton

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción

iButton es un nombre genérico para una llave de identificación electrónica empaquetada en un **contenedor metálico en forma de moneda**. También se le llama **Memoria táctil Dallas** o memoria de contacto. Aunque a menudo se le llama erróneamente una llave "magnética", en realidad no tiene **nada magnético** en su interior. De hecho, en su interior se encuentra un **microchip** completo que opera con un protocolo digital.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### ¿Qué es iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Por lo general, iButton implica la forma física de la llave y el lector: una moneda redonda con dos contactos. Para el marco que lo rodea, hay muchas variaciones desde el soporte de plástico más común con un agujero hasta anillos, colgantes, etc.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Cuando la llave alcanza el lector, los **contactos se tocan** y la llave se alimenta para **transmitir** su ID. A veces la llave **no se lee** inmediatamente porque el **PSD de contacto de un intercomunicador es más grande** de lo que debería ser. En ese caso, tendrás que presionar la llave sobre una de las paredes del lector.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocolo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Las llaves Dallas intercambian datos utilizando el protocolo 1-Wire. Con un solo contacto para la transferencia de datos (!!) en ambas direcciones, desde el maestro al esclavo y viceversa. El protocolo 1-Wire funciona según el modelo Maestro-Esclavo. En esta topología, el Maestro siempre inicia la comunicación y el Esclavo sigue sus instrucciones.

Cuando la llave (Esclavo) contacta al intercomunicador (Maestro), el chip dentro de la llave se enciende, alimentado por el intercomunicador, y la llave se inicializa. A continuación, el intercomunicador solicita el ID de la llave. A continuación, veremos este proceso con más detalle.

Flipper puede funcionar tanto en modos Maestro como Esclavo. En el modo de lectura de llave, Flipper actúa como un lector, es decir, funciona como un Maestro. Y en el modo de emulación de llave, Flipper finge ser una llave, está en modo Esclavo.

### Llaves Dallas, Cyfral y Metakom

Para obtener información sobre cómo funcionan estas llaves, consulta la página [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Ataques

Las iButtons pueden ser atacadas con Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Referencias

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)
