# Protecciones de Seguridad en macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Gatekeeper

Gatekeeper se utiliza generalmente para referirse a la combinación de **Quarantine + Gatekeeper + XProtect**, 3 módulos de seguridad de macOS que intentarán **prevenir que los usuarios ejecuten software potencialmente malicioso descargado**.

Más información en:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Limitaciones de Procesos

### SIP - Protección de Integridad del Sistema

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

Sandbox de MacOS **limita las aplicaciones** que se ejecutan dentro del sandbox a las **acciones permitidas especificadas en el perfil de Sandbox** con el que se está ejecutando la aplicación. Esto ayuda a asegurar que **la aplicación solo accederá a los recursos esperados**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparencia, Consentimiento y Control**

**TCC (Transparencia, Consentimiento y Control)** es un mecanismo en macOS para **limitar y controlar el acceso de las aplicaciones a ciertas características**, generalmente desde una perspectiva de privacidad. Esto puede incluir cosas como servicios de ubicación, contactos, fotos, micrófono, cámara, accesibilidad, acceso completo al disco y mucho más.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Restricciones de Lanzamiento/Ambiente & Trust Cache

Las restricciones de lanzamiento en macOS son una característica de seguridad para **regular la iniciación de procesos** definiendo **quién puede lanzar** un proceso, **cómo** y **desde dónde**. Introducidas en macOS Ventura, categorizan los binarios del sistema en categorías de restricciones dentro de un **trust cache**. Cada binario ejecutable tiene establecidas **reglas** para su **lanzamiento**, incluyendo restricciones de **sí mismo**, **padre** y **responsable**. Extendido a aplicaciones de terceros como Restricciones de **Ambiente** en macOS Sonoma, estas características ayudan a mitigar posibles explotaciones del sistema gobernando las condiciones de lanzamiento de procesos.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Herramienta de Eliminación de Malware

La Herramienta de Eliminación de Malware (MRT) es otra parte de la infraestructura de seguridad de macOS. Como su nombre indica, la función principal de MRT es **eliminar malware conocido de sistemas infectados**.

Una vez que se detecta malware en un Mac (ya sea por XProtect o por otros medios), MRT se puede utilizar para **eliminar automáticamente el malware**. MRT opera silenciosamente en segundo plano y generalmente se ejecuta cada vez que el sistema se actualiza o cuando se descarga una nueva definición de malware (parece que las reglas que MRT tiene para detectar malware están dentro del binario).

Mientras que tanto XProtect como MRT son parte de las medidas de seguridad de macOS, realizan funciones diferentes:

* **XProtect** es una herramienta preventiva. **Verifica los archivos a medida que se descargan** (a través de ciertas aplicaciones), y si detecta algún tipo conocido de malware, **impide que el archivo se abra**, evitando así que el malware infecte su sistema en primer lugar.
* **MRT**, por otro lado, es una herramienta **reactiva**. Opera después de que se ha detectado malware en un sistema, con el objetivo de eliminar el software ofensivo para limpiar el sistema.

La aplicación MRT se encuentra en **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gestión de Tareas en Segundo Plano

**macOS** ahora **alerta** cada vez que una herramienta utiliza una técnica bien conocida para **persistir la ejecución de código** (como Elementos de Inicio, Daemons...), para que el usuario sepa mejor **qué software está persistiendo**.

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

Esto se ejecuta con un **daemon** ubicado en `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` y el **agente** en `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

La forma en que **`backgroundtaskmanagementd`** sabe que algo está instalado en una carpeta persistente es **obteniendo los FSEvents** y creando algunos **manejadores** para esos.

Además, hay un archivo plist que contiene **aplicaciones bien conocidas** que frecuentemente persisten mantenidas por Apple ubicado en: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeración

Es posible **enumerar todos** los elementos de fondo configurados ejecutando la herramienta de línea de comandos de Apple:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Además, también es posible listar esta información con [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
### Manipulación de BTM

Cuando se encuentra una nueva persistencia, se genera un evento de tipo **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Por lo tanto, cualquier forma de **prevenir** que este **evento** sea enviado o que el **agente notifique** al usuario ayudará a un atacante a _**eludir**_ BTM.

* **Restablecer la base de datos**: Ejecutar el siguiente comando restablecerá la base de datos (debería reconstruirla desde cero), sin embargo, por alguna razón, después de ejecutar esto, **no se alertará de nuevas persistencias hasta que el sistema se reinicie**.
* Se requiere **root**.
```bash
# Reset the database
sfltool resettbtm
```
* **Detener el Agente**: Es posible enviar una señal de detención al agente para que **no alerte al usuario** cuando se encuentren nuevas detecciones.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Bug**: Si el **proceso que creó la persistencia se cierra rápidamente justo después de hacerlo**, el daemon intentará **obtener información** sobre él, **fallará** y **no podrá enviar el evento** que indica que algo nuevo está persistiendo.

Referencias y **más información sobre BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
