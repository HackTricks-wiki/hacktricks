# macOS Kernel Extensions

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

Las extensiones de kernel (Kexts) son **paquetes** con extensión **`.kext`** que se **cargan directamente en el espacio del kernel** de macOS, proporcionando funcionalidades adicionales al sistema operativo principal.

### Requisitos

Obviamente, esto es tan poderoso que es complicado cargar una extensión de kernel. Estos son los requisitos que debe cumplir una extensión de kernel para ser cargada:

* Al entrar en **modo de recuperación**, las extensiones de kernel deben estar **permitidas para ser cargadas**:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* La extensión de kernel debe estar **firmada con un certificado de firma de código de kernel**, que solo puede ser otorgado por **Apple**. Quien revisará en detalle la **empresa** y las **razones** por las que se necesita.
* La extensión de kernel también debe estar **notarizada**, Apple podrá verificarla en busca de malware.
* Luego, el **usuario root** es el que puede cargar la extensión de kernel y los archivos dentro del paquete deben pertenecer a root.
* Durante el proceso de carga, el paquete debe ser preparado en una ubicación protegida sin raíz: `/Library/StagedExtensions` (requiere la concesión `com.apple.rootless.storage.KernelExtensionManagement`)
* Finalmente, al intentar cargarlo, el [**usuario recibirá una solicitud de confirmación**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) y, si se acepta, la computadora debe **reiniciarse** para cargarlo.

### Proceso de carga

En Catalina era así: Es interesante destacar que el proceso de **verificación** ocurre en **userland**. Sin embargo, solo las aplicaciones con la concesión **`com.apple.private.security.kext-management`** pueden **solicitar al kernel** que **cargue una extensión:** kextcache, kextload, kextutil, kextd, syspolicyd

1. **`kextutil`** cli **inicia** el proceso de verificación para cargar una extensión

* Hablará con **`kextd`** enviando usando un servicio Mach

2. **`kextd`** comprobará varias cosas, como la firma

* Hablará con **`syspolicyd`** para comprobar si se puede cargar la extensión

3. **`syspolicyd`** **preguntará** al **usuario** si la extensión no se ha cargado previamente

* **`syspolicyd`** indicará el resultado a **`kextd`**

4. **`kextd`** finalmente podrá indicar al **kernel que cargue la extensión**

Si kextd no está disponible, kextutil puede realizar las mismas comprobaciones.

## Referencias

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
