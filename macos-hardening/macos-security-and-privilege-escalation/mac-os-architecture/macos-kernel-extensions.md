# Extensiones del Kernel de macOS

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

Las extensiones del kernel (Kexts) son **paquetes** con extensión **`.kext`** que se **cargan directamente en el espacio del kernel de macOS**, proporcionando funcionalidades adicionales al sistema operativo principal.

### Requisitos

Obviamente, esto es tan poderoso que es **complicado cargar una extensión del kernel**. Estos son los **requisitos** que una extensión del kernel debe cumplir para ser cargada:

* Cuando se **ingresa al modo de recuperación**, las **extensiones del kernel deben estar permitidas** para ser cargadas:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* La extensión del kernel debe estar **firmada con un certificado de firma de código de kernel**, que solo puede ser **concedido por Apple**. Quien revisará en detalle la empresa y las razones por las que se necesita.
* La extensión del kernel también debe estar **notarizada**, Apple podrá verificarla en busca de malware.
* Luego, el usuario **root** es el que puede **cargar la extensión del kernel** y los archivos dentro del paquete deben **pertenecer a root**.
* Durante el proceso de carga, el paquete debe estar preparado en una **ubicación protegida que no sea root**: `/Library/StagedExtensions` (requiere el permiso `com.apple.rootless.storage.KernelExtensionManagement`).
* Finalmente, al intentar cargarlo, el usuario recibirá una [**solicitud de confirmación**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) y, si se acepta, la computadora debe ser **reiniciada** para cargarla.

### Proceso de carga

En Catalina era así: Es interesante notar que el proceso de **verificación** ocurre en **userland**. Sin embargo, solo las aplicaciones con el permiso **`com.apple.private.security.kext-management`** pueden **solicitar al kernel que cargue una extensión**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **inicia** el proceso de **verificación** para cargar una extensión
* Se comunicará con **`kextd`** enviando un **servicio Mach**.
2. **`kextd`** verificará varias cosas, como la **firma**
* Se comunicará con **`syspolicyd`** para **verificar** si la extensión puede ser **cargada**.
3. **`syspolicyd`** **solicitará** al **usuario** si la extensión no ha sido cargada previamente.
* **`syspolicyd`** informará el resultado a **`kextd`**
4. **`kextd`** finalmente podrá **indicarle al kernel que cargue** la extensión

Si **`kextd`** no está disponible, **`kextutil`** puede realizar las mismas verificaciones.

## Referencias

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
