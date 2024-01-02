# FZ - iButton

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

Para más información sobre qué es un iButton consulta:

{% content-ref url="../ibutton.md" %}
[ibutton.md](../ibutton.md)
{% endcontent-ref %}

## Diseño

La parte **azul** de la siguiente imagen muestra cómo necesitas **colocar el iButton real** para que el Flipper pueda **leerlo.** La parte **verde** es cómo necesitas **tocar el lector** con el Flipper Zero para **emular correctamente un iButton**.

<figure><img src="../../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

## Acciones

### Leer

En el Modo Lectura, Flipper espera que la llave iButton toque y es capaz de procesar cualquiera de los tres tipos de llaves: **Dallas, Cyfral y Metakom**. Flipper **determinará el tipo de llave por sí mismo**. El nombre del protocolo de la llave se mostrará en la pantalla sobre el número de identificación.

### Añadir manualmente

Es posible **añadir manualmente** un iButton de tipo: **Dallas, Cyfral y Metakom**

### **Emular**

Es posible **emular** iButtons guardados (leídos o añadidos manualmente).

{% hint style="info" %}
Si no puedes hacer que los contactos esperados del Flipper Zero toquen el lector, puedes **usar el GPIO externo:**
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (24) (1).png" alt=""><figcaption></figcaption></figure>

## Referencias

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
