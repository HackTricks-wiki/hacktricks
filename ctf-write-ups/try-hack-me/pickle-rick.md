# Pickle Rick

## Pickle Rick

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](../../.gitbook/assets/picklerick.gif)

Esta máquina fue categorizada como fácil y realmente lo fue.

## Enumeración

Comencé **enumerando la máquina usando mi herramienta** [**Legion**](https://github.com/carlospolop/legion):

![](<../../.gitbook/assets/image (79) (2).png>)

Como puedes ver, hay 2 puertos abiertos: 80 (**HTTP**) y 22 (**SSH**)

Entonces, lancé legion para enumerar el servicio HTTP:

![](<../../.gitbook/assets/image (234).png>)

Nota que en la imagen puedes ver que `robots.txt` contiene la cadena `Wubbalubbadubdub`

Después de algunos segundos revisé lo que `disearch` ya había descubierto:

![](<../../.gitbook/assets/image (235).png>)

![](<../../.gitbook/assets/image (236).png>)

Y como puedes ver en la última imagen, se descubrió una página de **inicio de sesión**.

Revisando el código fuente de la página principal, se descubre un nombre de usuario: `R1ckRul3s`

![](<../../.gitbook/assets/image (237) (1).png>)

Por lo tanto, puedes iniciar sesión en la página de inicio de sesión usando las credenciales `R1ckRul3s:Wubbalubbadubdub`

## Usuario

Usando esas credenciales accederás a un portal donde puedes ejecutar comandos:

![](<../../.gitbook/assets/image (241).png>)

Algunos comandos como cat no están permitidos pero puedes leer el primer ingrediente (bandera) usando, por ejemplo, grep:

![](<../../.gitbook/assets/image (242).png>)

Luego utilicé:

![](<../../.gitbook/assets/image (243) (1).png>)

Para obtener una shell inversa:

![](<../../.gitbook/assets/image (239) (1).png>)

El **segundo ingrediente** se puede encontrar en `/home/rick`

![](<../../.gitbook/assets/image (240).png>)

## Root

El usuario **www-data puede ejecutar cualquier cosa como sudo**:

![](<../../.gitbook/assets/image (238).png>)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
