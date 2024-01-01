# iButton

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción

iButton es un nombre genérico para una llave de identificación electrónica empaquetada en un **contenedor metálico con forma de moneda**. También se le llama **Dallas Touch** Memory o memoria de contacto. Aunque a menudo se le llama erróneamente "llave magnética", no hay **nada magnético** en ella. De hecho, dentro se esconde un **microchip** completo que opera bajo un protocolo digital.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### ¿Qué es iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Normalmente, iButton implica la forma física de la llave y el lector - una moneda redonda con dos contactos. Para el marco que la rodea, hay muchas variaciones desde el soporte de plástico más común con un agujero hasta anillos, colgantes, etc.

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

Cuando la llave alcanza el lector, los **contactos se tocan** y la llave se alimenta para **transmitir** su ID. A veces la llave **no se lee** inmediatamente porque el **PSD de contacto de un intercomunicador es más grande** de lo que debería ser. Entonces, los contornos exteriores de la llave y el lector no podrían tocarse. Si ese es el caso, tendrás que presionar la llave sobre una de las paredes del lector.

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **Protocolo 1-Wire** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Las llaves Dallas intercambian datos utilizando el protocolo 1-Wire. Con solo un contacto para la transferencia de datos (!!) en ambas direcciones, del maestro al esclavo y viceversa. El protocolo 1-Wire funciona según el modelo Maestro-Esclavo. En esta topología, el Maestro siempre inicia la comunicación y el Esclavo sigue sus instrucciones.

Cuando la llave (Esclavo) contacta con el intercomunicador (Maestro), el chip dentro de la llave se enciende, alimentado por el intercomunicador, y la llave se inicializa. A continuación, el intercomunicador solicita el ID de la llave. Más adelante, examinaremos este proceso con más detalle.

Flipper puede trabajar tanto en modos Maestro como Esclavo. En el modo de lectura de llaves, Flipper actúa como un lector, es decir, funciona como un Maestro. Y en el modo de emulación de llave, Flipper finge ser una llave, está en modo Esclavo.

### Llaves Dallas, Cyfral & Metakom

Para información sobre cómo funcionan estas llaves consulta la página [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Ataques

Los iButtons pueden ser atacados con Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Referencias

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
