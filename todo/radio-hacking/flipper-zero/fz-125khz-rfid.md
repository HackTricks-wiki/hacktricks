# FZ - RFID de 125kHz

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción

Para más información sobre cómo funcionan las etiquetas de 125kHz revisa:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Acciones

Para más información sobre estos tipos de etiquetas [**lee esta introducción**](../../../radio-hacking/pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Leer

Intenta **leer** la información de la tarjeta. Luego puede **emularlas**.

{% hint style="warning" %}
Ten en cuenta que algunos intercomunicadores intentan protegerse de la duplicación de llaves enviando un comando de escritura antes de leer. Si la escritura tiene éxito, esa etiqueta se considera falsa. Cuando Flipper emula RFID, no hay forma de que el lector lo distinga del original, por lo que no ocurren tales problemas.
{% endhint %}

### Añadir Manualmente

Puedes crear **tarjetas falsas en Flipper Zero indicando los datos** que ingreses manualmente y luego emularla.

#### IDs en tarjetas

A veces, cuando obtienes una tarjeta encontrarás el ID (o parte de él) escrito visiblemente en la tarjeta.

* **EM Marin**

Por ejemplo, en esta tarjeta EM-Marin en la tarjeta física es posible **leer los últimos 3 de 5 bytes claramente**.\
Los otros 2 pueden ser forzados a la bruta si no puedes leerlos de la tarjeta.

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

* **HID**

Lo mismo ocurre en esta tarjeta HID donde solo se pueden encontrar 2 de 3 bytes impresos en la tarjeta

<figure><img src="../../../.gitbook/assets/image (15) (3).png" alt=""><figcaption></figcaption></figure>

### Emular/Escribir

Después de **copiar** una tarjeta o **ingresar** el ID **manualmente** es posible **emularla** con Flipper Zero o **escribirla** en una tarjeta real.

## Referencias

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
