# Armando Distroless

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Qué es Distroless

Un contenedor distroless es un tipo de contenedor que **contiene solo las dependencias necesarias para ejecutar una aplicación específica**, sin ningún software o herramientas adicionales que no sean requeridos. Estos contenedores están diseñados para ser lo más **ligeros** y **seguros** posible, y su objetivo es **minimizar la superficie de ataque** eliminando cualquier componente innecesario.

Los contenedores distroless a menudo se utilizan en **entornos de producción donde la seguridad y la fiabilidad son primordiales**.

Algunos **ejemplos** de **contenedores distroless** son:

* Proporcionados por **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Proporcionados por **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Armando Distroless

El objetivo de armar un contenedor distroless es poder **ejecutar binarios y cargas arbitrarias incluso con las limitaciones** implicadas por **distroless** (falta de binarios comunes en el sistema) y también protecciones comúnmente encontradas en contenedores como **solo lectura** o **no ejecución** en `/dev/shm`.

### A través de la memoria

Llegará en algún momento de 2023...

### Mediante binarios existentes

#### openssl

****[**En este post,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) se explica que el binario **`openssl`** se encuentra frecuentemente en estos contenedores, posiblemente porque es **necesario** para el software que va a ejecutarse dentro del contenedor.

Abusar del binario **`openssl`** es posible para **ejecutar cosas arbitrarias**.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
