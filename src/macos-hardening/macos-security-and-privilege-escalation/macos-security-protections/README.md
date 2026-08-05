# Protecciones de seguridad de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper suele utilizarse para referirse a la combinación de **Quarantine + Gatekeeper + XProtect**, 3 módulos de seguridad de macOS que intentarán **impedir que los usuarios ejecuten software potencialmente malicioso descargado**.

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

**TCC (Transparency, Consent, and Control)** es un framework de seguridad. Está diseñado para **gestionar los permisos** de las aplicaciones, regulando específicamente su acceso a funciones sensibles. Esto incluye elementos como **servicios de localización, contactos, fotos, micrófono, cámara, accesibilidad y acceso total al disco**. TCC garantiza que las aplicaciones solo puedan acceder a estas funciones después de obtener el consentimiento explícito del usuario, reforzando así la privacidad y el control sobre los datos personales.


{{#ref}}
macos-tcc/
{{#endref}}

### Restricciones de lanzamiento/entorno y Trust Cache

Las restricciones de lanzamiento en macOS son una función de seguridad que **regula el inicio de procesos** definiendo **quién puede lanzar** un proceso, **cómo** y **desde dónde**. Introducidas en macOS Ventura, clasifican los binarios del sistema en categorías de restricciones dentro de una **trust cache**. Cada binario ejecutable tiene un conjunto de **reglas** para su **lanzamiento**, incluidas las restricciones **self**, **parent** y **responsible**. Extendidas a aplicaciones de terceros como restricciones de **Environment** en macOS Sonoma, estas funciones ayudan a mitigar posibles explotaciones del sistema controlando las condiciones de lanzamiento de procesos.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) es otra parte de la infraestructura de seguridad de macOS. Como su nombre indica, la función principal de MRT es **eliminar malware conocido de sistemas infectados**.

Una vez detectado el malware en un Mac (ya sea mediante XProtect o por cualquier otro medio), MRT puede utilizarse para **eliminar automáticamente el malware**. MRT funciona silenciosamente en segundo plano y normalmente se ejecuta cada vez que se actualiza el sistema o cuando se descarga una nueva definición de malware (parece que las reglas que MRT utiliza para detectar malware se encuentran dentro del binario).

Aunque XProtect y MRT forman parte de las medidas de seguridad de macOS, realizan funciones diferentes:

- **XProtect** es una herramienta preventiva. **Comprueba los archivos cuando se descargan** (mediante determinadas aplicaciones) y, si detecta algún tipo conocido de malware, **impide que el archivo se abra**, evitando así que el malware infecte el sistema en primer lugar.
- **MRT**, por otro lado, es una **herramienta reactiva**. Funciona después de que se haya detectado malware en un sistema, con el objetivo de eliminar el software malicioso para limpiar el sistema.

La aplicación MRT se encuentra en **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gestión de tareas en segundo plano

**macOS** ahora **alerta** cada vez que una herramienta utiliza una **técnica conocida para persistir la ejecución de código** (como Login Items, Daemons...), para que el usuario sepa mejor **qué software está persistiendo**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Esto se ejecuta con un **daemon** ubicado en `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` y el **agent** en `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

La forma en que **`backgroundtaskmanagementd`** sabe que algo está instalado en una carpeta persistente es **obteniendo los FSEvents** y creando algunos **handlers** para ellos.<sup>[[1]](#references)</sup>

Además, existe un archivo plist que contiene **aplicaciones conocidas** que persisten con frecuencia, mantenido por Apple y ubicado en: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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

Es posible **enumerar todos** los elementos en segundo plano configurados ejecutando la herramienta cli de Apple:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Además, también es posible enumerar esta información con [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Esta información se almacena en **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** y Terminal necesita FDA.<sup>[[2]](#references)</sup>

### Manipulando BTM

Cuando se detecta una nueva persistence, se genera un event de tipo **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Por lo tanto, cualquier forma de **impedir** que se envíe este **event** o de **evitar que el agent genere una alerta** para el usuario ayudará a un atacante a _**bypassear**_ BTM.<sup>[[1]](#references)</sup>

- **Restablecer la base de datos**: Ejecutar el siguiente comando restablecerá la base de datos (debería reconstruirla desde cero); sin embargo, por alguna razón, después de ejecutarlo, **no se generarán alertas sobre nuevas persistences hasta que se reinicie el sistema**.<sup>[[1]](#references)</sup>
- Se requiere **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Detener el Agent**: Es posible enviar una señal de detención al agente para que **no avise al usuario** cuando se encuentren nuevas detecciones.<sup>[[1]](#references)</sup>
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
- **Bug**: If the **process that created the persistence exits soon after**, the daemon will try to **get information** about it, **fail**, and **won't be able to send the event** indicating that a new thing is persisting.<sup>[[1]](#references)</sup>

## Referencias

- [1] [OBTS v6.0: "Desmitificando (y eludiendo) la gestión de tareas en segundo plano de macOS" - Patrick Wardle y Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Nueva herramienta (para desarrolladores): "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Gestionar los elementos de inicio de sesión y las tareas en segundo plano en Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
