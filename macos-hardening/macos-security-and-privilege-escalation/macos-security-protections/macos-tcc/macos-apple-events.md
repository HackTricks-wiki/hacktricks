# macOS Eventos de Apple

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

Los **Eventos de Apple** son una característica en macOS de Apple que permite que las aplicaciones se comuniquen entre sí. Forman parte del **Gestor de Eventos de Apple**, que es un componente del sistema operativo macOS responsable de manejar la comunicación entre procesos. Este sistema permite que una aplicación envíe un mensaje a otra aplicación para solicitar que realice una operación específica, como abrir un archivo, recuperar datos o ejecutar un comando.

El demonio mina es `/System/Library/CoreServices/appleeventsd` que registra el servicio `com.apple.coreservices.appleevents`.

Cada aplicación que puede recibir eventos verificará con este demonio proporcionando su Puerto Mach de Eventos de Apple. Y cuando una aplicación desea enviar un evento a él, la aplicación solicitará este puerto al demonio.

Las aplicaciones con sandbox requieren privilegios como `allow appleevent-send` y `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` para poder enviar eventos. Ten en cuenta que los permisos como `com.apple.security.temporary-exception.apple-events` podrían restringir quién tiene acceso para enviar eventos, lo cual necesitará permisos como `com.apple.private.appleevents`.

{% hint style="success" %}
Es posible utilizar la variable de entorno **`AEDebugSends`** para registrar información sobre el mensaje enviado:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
