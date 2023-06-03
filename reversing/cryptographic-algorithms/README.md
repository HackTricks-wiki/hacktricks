# Algoritmos Criptográficos/Compresión

## Algoritmos Criptográficos/Compresión

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Identificación de Algoritmos

Si te encuentras con un código que **usa desplazamientos a la derecha e izquierda, XOR y varias operaciones aritméticas**, es muy probable que sea la implementación de un **algoritmo criptográfico**. Aquí se mostrarán algunas formas de **identificar el algoritmo que se está utilizando sin necesidad de revertir cada paso**.

### Funciones de API

**CryptDeriveKey**

Si se utiliza esta función, se puede encontrar qué **algoritmo se está utilizando** comprobando el valor del segundo parámetro:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Comprueba aquí la tabla de posibles algoritmos y sus valores asignados: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime y descomprime un búfer de datos dado.

**CryptAcquireContext**

La función **CryptAcquireContext** se utiliza para adquirir un identificador para un contenedor de claves particular dentro de un proveedor de servicios criptográficos (CSP) particular. **Este identificador devuelto se utiliza en llamadas a funciones de CryptoAPI** que utilizan el CSP seleccionado.

**CryptCreateHash**

Inicia el hash de un flujo de datos. Si se utiliza esta función, se puede encontrar qué **algoritmo se está utilizando** comprobando el valor del segundo parámetro:

![](<../../.gitbook/assets/image (376).png>)

Comprueba aquí la tabla de posibles algoritmos y sus valores asignados: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Constantes de código

A veces es muy fácil identificar un algoritmo gracias al hecho de que necesita usar un valor especial y único.

![](<../../.gitbook/assets/image (370).png>)

Si buscas la primera constante en Google, esto es lo que obtienes:

![](<../../.gitbook/assets/image (371).png>)

Por lo tanto, se puede asumir que la función descompilada es un **calculador sha256**.\
