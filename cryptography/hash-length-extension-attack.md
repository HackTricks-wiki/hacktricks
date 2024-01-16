<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Resumen del ataque

Imagina un servidor que está **firmando** algunos **datos** **añadiendo** un **secreto** a algunos datos de texto claro conocidos y luego hasheando esos datos. Si conoces:

* **La longitud del secreto** (esto también puede ser forzado bruscamente desde un rango de longitud dado)
* **Los datos de texto claro**
* **El algoritmo (y es vulnerable a este ataque)**
* **El padding es conocido**
* Usualmente se utiliza uno por defecto, así que si se cumplen los otros 3 requisitos, este también se cumple
* El padding varía dependiendo de la longitud del secreto+datos, por eso se necesita la longitud del secreto

Entonces, es posible para un **atacante** **añadir** **datos** y **generar** una **firma válida** para los **datos previos + datos añadidos**.

## ¿Cómo?

Básicamente los algoritmos vulnerables generan los hashes primero **hasheando un bloque de datos**, y luego, **desde** el **hash previamente** creado **(estado)**, **añaden el siguiente bloque de datos** y **lo hashean**.

Entonces, imagina que el secreto es "secret" y los datos son "data", el MD5 de "secretdata" es 6036708eba0d11f6ef52ad44e8b74d5b.\
Si un atacante quiere añadir la cadena "append", puede:

* Generar un MD5 de 64 "A"s
* Cambiar el estado del hash previamente inicializado a 6036708eba0d11f6ef52ad44e8b74d5b
* Añadir la cadena "append"
* Finalizar el hash y el hash resultante será un **válido para "secret" + "data" + "padding" + "append"**

## **Herramienta**

{% embed url="https://github.com/iagox86/hash_extender" %}

# Referencias

Puedes encontrar este ataque bien explicado en [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
