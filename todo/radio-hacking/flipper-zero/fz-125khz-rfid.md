# FZ - 125kHz RFID

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**productos oficiales de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Introducción

Para obtener más información sobre cómo funcionan las etiquetas de 125kHz, consulta:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Acciones

Para obtener más información sobre estos tipos de etiquetas, [**lee esta introducción**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Leer

Intenta **leer** la información de la tarjeta. Luego puedes **emular** la tarjeta.

{% hint style="warning" %}
Ten en cuenta que algunos intercomunicadores intentan protegerse contra la duplicación de llaves enviando un comando de escritura antes de la lectura. Si la escritura tiene éxito, esa etiqueta se considera falsa. Cuando Flipper emula RFID, no hay forma de que el lector lo distinga del original, por lo que no se producen tales problemas.
{% endhint %}

### Agregar Manualmente

Puedes crear **tarjetas falsas en Flipper Zero indicando los datos** manualmente y luego emularlas.

#### IDs en tarjetas

A veces, al obtener una tarjeta, encontrarás el ID (o parte de él) escrito en la tarjeta visible.

* **EM Marin**

Por ejemplo, en esta tarjeta EM-Marin es posible **leer los últimos 3 de 5 bytes en claro** en la tarjeta física.\
Los otros 2 se pueden forzar si no puedes leerlos en la tarjeta.

<figure><img src="../../../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

* **HID**

Lo mismo ocurre en esta tarjeta HID donde solo 2 de 3 bytes se pueden encontrar impresos en la tarjeta

<figure><img src="../../../.gitbook/assets/image (1011).png" alt=""><figcaption></figcaption></figure>

### Emular/Escribir

Después de **copiar** una tarjeta o **ingresar** el ID **manualmente**, es posible **emularla** con Flipper Zero o **escribirla** en una tarjeta real.

## Referencias

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**productos oficiales de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
