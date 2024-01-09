<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) es una herramienta que se puede usar con un Raspberry PI o un Arduino para intentar encontrar pines JTAG en un chip desconocido.\
En el **Arduino**, conecta los **pines del 2 al 11 a 10 pines que potencialmente pertenecen a un JTAG**. Carga el programa en el Arduino y este intentará forzar bruscamente todos los pines para encontrar si alguno pertenece a JTAG y cuál es cada uno.\
En el **Raspberry PI** solo puedes usar **pines del 1 al 6** (6 pines, por lo que irás más lento probando cada pin JTAG potencial).

## Arduino

En Arduino, después de conectar los cables (pin 2 al 11 a pines JTAG y GND de Arduino al GND de la base), **carga el programa JTAGenum en Arduino** y en el Monitor Serial envía un **`h`** (comando de ayuda) y deberías ver la ayuda:

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

Configura **"Sin fin de línea" y 115200baud**.\
Envía el comando s para comenzar el escaneo:

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

Si estás contactando un JTAG, encontrarás una o varias **líneas que comienzan con FOUND!** indicando los pines de JTAG.


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
