# Protecciones de seguridad de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper suele utilizarse para referirse a la combinación de **Quarantine + Gatekeeper + XProtect**, 3 módulos de seguridad de macOS que intentan **impedir que los usuarios ejecuten software potencialmente malicioso descargado**.

Más información en:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Limitaciones de procesos

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox **limita las aplicaciones** que se ejecutan dentro del sandbox a las **acciones permitidas especificadas en el perfil de Sandbox** con el que se ejecuta la aplicación. Esto ayuda a garantizar que **la aplicación solo acceda a los recursos esperados**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** es un framework de seguridad. Está diseñado para **gestionar los permisos** de las aplicaciones, regulando específicamente su acceso a funciones sensibles. Esto incluye elementos como **servicios de ubicación, contactos, fotos, micrófono, cámara, accesibilidad y acceso total al disco**. TCC garantiza que las aplicaciones solo puedan acceder a estas funciones después de obtener el consentimiento explícito del usuario, reforzando así la privacidad y el control sobre los datos personales.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Las restricciones de Launch en macOS son una función de seguridad para **regular el inicio de procesos**, definiendo **quién puede iniciar** un proceso, **cómo** y **desde dónde**. Introducidas en macOS Ventura, clasifican los binarios del sistema en categorías de restricciones dentro de una **trust cache**. Cada binario ejecutable tiene un conjunto de **reglas** para su **inicio**, incluidas las restricciones **self**, **parent** y **responsible**. Extendidas a aplicaciones de terceros como restricciones de **Environment** en macOS Sonoma, estas funciones ayudan a mitigar posibles explotaciones del sistema al controlar las condiciones de inicio de los procesos.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) es otra parte de la infraestructura de seguridad de macOS. Como su nombre indica, la función principal de MRT es **eliminar malware conocido de sistemas infectados**.

Una vez que se detecta malware en un Mac (ya sea mediante XProtect o por algún otro medio), MRT puede utilizarse para **eliminar automáticamente el malware**. MRT opera silenciosamente en segundo plano y normalmente se ejecuta cuando se actualiza el sistema o cuando se descarga una nueva definición de malware (parece que las reglas que MRT utiliza para detectar malware están dentro del binario).

Aunque XProtect y MRT forman parte de las medidas de seguridad de macOS, realizan funciones diferentes:

- **XProtect** es una herramienta preventiva. **Comprueba los archivos cuando se descargan** (mediante ciertas aplicaciones) y, si detecta algún tipo conocido de malware, **impide que el archivo se abra**, evitando así que el malware infecte el sistema.
- **MRT**, por otro lado, es una **herramienta reactiva**. Opera después de que se haya detectado malware en un sistema, con el objetivo de eliminar el software malicioso y limpiar el sistema.

La aplicación MRT se encuentra en **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gestión de tareas en segundo plano

**macOS** ahora **muestra una alerta** cada vez que una herramienta utiliza una **técnica conocida para persistir la ejecución de código** (como Login Items, Daemons...), para que el usuario sepa mejor **qué software está persistiendo**.<sup>[3]</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Esto se ejecuta mediante un **daemon** ubicado en `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` y el **agent** en `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[1]</sup>

La forma en que **`backgroundtaskmanagementd`** sabe que algo está instalado en una carpeta persistente es **obteniendo los FSEvents** y creando algunos **handlers** para ellos.<sup>[1]</sup>

Además, existe un archivo plist que contiene **aplicaciones conocidas** que persisten con frecuencia y que Apple mantiene, ubicado en: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[3]</sup>
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

Es posible **enumerar todos** los elementos en segundo plano configurados mediante la herramienta cli de Apple:<sup>[3]</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Además, también es posible listar esta información con [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[2]</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Esta información se almacena en **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** y Terminal necesita FDA.<sup>[2]</sup>

### Manipulando BTM

Cuando se encuentra una nueva persistence, se genera un evento de tipo **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Por lo tanto, cualquier forma de **impedir** que se envíe este **evento** o de **evitar que el agent alerte** al usuario ayudará a un atacante a _**bypassear**_ BTM.<sup>[1]</sup>

- **Restablecer la base de datos**: Ejecutar el siguiente comando restablecerá la base de datos (debería reconstruirla desde cero); sin embargo, por alguna razón, después de ejecutarlo, **no se alertará sobre ninguna nueva persistence hasta que se reinicie el sistema**.<sup>[1]</sup>
- Se requiere **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Detener el Agent**: Es posible enviar una señal de detención al agent para que **no alerte al usuario** cuando se encuentren nuevas detecciones.<sup>[1]</sup>
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
- **Bug**: Si el **proceso que creó la persistence sale rápidamente justo después**, el daemon intentará **obtener información** sobre él, **fallará** y **no podrá enviar el evento** que indica que algo nuevo está persisting.<sup>[1]</sup>

## Referencias

- [1] [OBTS v6.0: "Desmitificando (y evadiendo) la gestión de tareas en segundo plano de macOS" - Patrick Wardle y Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Nueva herramienta (para desarrolladores): "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Gestionar elementos de inicio de sesión y tareas en segundo plano en Mac - Implementación de plataformas de Apple](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
