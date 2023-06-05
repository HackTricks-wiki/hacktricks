# Armando Distroless

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## ¿Qué es Distroless?

Un contenedor distroless es un tipo de contenedor que **contiene solo las dependencias necesarias para ejecutar una aplicación específica**, sin ningún software o herramienta adicional que no sea necesario. Estos contenedores están diseñados para ser lo más **ligeros** y **seguros** posible, y tienen como objetivo **minimizar la superficie de ataque** eliminando cualquier componente innecesario.

Los contenedores distroless se utilizan a menudo en **entornos de producción donde la seguridad y la fiabilidad son primordiales**.

Algunos **ejemplos** de **contenedores distroless** son:

* Proporcionados por **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Proporcionados por **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Armando Distroless

El objetivo de armar un contenedor distroless es poder **ejecutar binarios y cargas arbitrarias incluso con las limitaciones** implicadas por **distroless** (falta de binarios comunes en el sistema) y también protecciones comúnmente encontradas en contenedores como **solo lectura** o **no ejecución** en `/dev/shm`.

### A través de la memoria

Llegará en algún momento de 2023...

### A través de binarios existentes

#### openssl

En **[este post](https://www.form3.tech/engineering/content/exploiting-distroless-images)** se explica que el binario **`openssl`** se encuentra con frecuencia en estos contenedores, potencialmente porque es **necesario** para el software que se va a ejecutar dentro del contenedor.

Abusando del binario **`openssl`** es posible **ejecutar cosas arbitrarias**.
