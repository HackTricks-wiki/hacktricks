# Protecciones de Seguridad de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper se utiliza generalmente para referirse a la combinación de **Quarantine + Gatekeeper + XProtect**, 3 módulos de seguridad de macOS que intentarán **prevenir que los usuarios ejecuten software potencialmente malicioso descargado**.

Más información en:

{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Límites de Procesos

### MACF

### SIP - Protección de Integridad del Sistema

{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

El Sandbox de macOS **limita las aplicaciones** que se ejecutan dentro del sandbox a las **acciones permitidas especificadas en el perfil de Sandbox** con el que se está ejecutando la aplicación. Esto ayuda a garantizar que **la aplicación solo acceda a los recursos esperados**.

{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparencia, Consentimiento y Control**

**TCC (Transparencia, Consentimiento y Control)** es un marco de seguridad. Está diseñado para **gestionar los permisos** de las aplicaciones, regulando específicamente su acceso a funciones sensibles. Esto incluye elementos como **servicios de ubicación, contactos, fotos, micrófono, cámara, accesibilidad y acceso completo al disco**. TCC asegura que las aplicaciones solo puedan acceder a estas funciones después de obtener el consentimiento explícito del usuario, fortaleciendo así la privacidad y el control sobre los datos personales.

{{#ref}}
macos-tcc/
{{#endref}}

### Restricciones de Lanzamiento/Entorno y Caché de Confianza

Las restricciones de lanzamiento en macOS son una característica de seguridad para **regular la iniciación de procesos** definiendo **quién puede lanzar** un proceso, **cómo** y **desde dónde**. Introducidas en macOS Ventura, categorizan los binarios del sistema en categorías de restricción dentro de una **caché de confianza**. Cada binario ejecutable tiene **reglas** establecidas para su **lanzamiento**, incluyendo restricciones de **auto**, **padre** y **responsable**. Ampliadas a aplicaciones de terceros como **Restricciones de Entorno** en macOS Sonoma, estas características ayudan a mitigar posibles explotaciones del sistema al gobernar las condiciones de lanzamiento de procesos.

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Herramienta de Eliminación de Malware

La Herramienta de Eliminación de Malware (MRT) es otra parte de la infraestructura de seguridad de macOS. Como su nombre indica, la función principal de MRT es **eliminar malware conocido de sistemas infectados**.

Una vez que se detecta malware en un Mac (ya sea por XProtect o por otros medios), se puede usar MRT para **eliminar automáticamente el malware**. MRT opera silenciosamente en segundo plano y generalmente se ejecuta cada vez que se actualiza el sistema o cuando se descarga una nueva definición de malware (parece que las reglas que MRT tiene para detectar malware están dentro del binario).

Mientras que tanto XProtect como MRT son parte de las medidas de seguridad de macOS, realizan funciones diferentes:

- **XProtect** es una herramienta preventiva. **Verifica archivos a medida que se descargan** (a través de ciertas aplicaciones), y si detecta algún tipo de malware conocido, **previene que el archivo se abra**, evitando así que el malware infecte su sistema en primer lugar.
- **MRT**, por otro lado, es una **herramienta reactiva**. Opera después de que se ha detectado malware en un sistema, con el objetivo de eliminar el software ofensivo para limpiar el sistema.

La aplicación MRT se encuentra en **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gestión de Tareas en Segundo Plano

**macOS** ahora **alerta** cada vez que una herramienta utiliza una **técnica bien conocida para persistir la ejecución de código** (como Elementos de Inicio de Sesión, Daemons...), para que el usuario sepa mejor **qué software está persistiendo**.

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Esto se ejecuta con un **daemon** ubicado en `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` y el **agente** en `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

La forma en que **`backgroundtaskmanagementd`** sabe que algo está instalado en una carpeta persistente es **obteniendo los FSEvents** y creando algunos **manejadores** para esos.

Además, hay un archivo plist que contiene **aplicaciones bien conocidas** que frecuentemente persisten mantenido por Apple ubicado en: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

Es posible **enumerar todos** los elementos de fondo configurados ejecutando la herramienta cli de Apple:
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
Esta información se está almacenando en **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** y el Terminal necesita FDA.

### Manipulando BTM

Cuando se encuentra una nueva persistencia, se genera un evento de tipo **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Por lo tanto, cualquier forma de **prevenir** que este **evento** sea enviado o que el **agente alerte** al usuario ayudará a un atacante a _**eludir**_ BTM.

- **Restableciendo la base de datos**: Ejecutar el siguiente comando restablecerá la base de datos (debería reconstruirse desde cero), sin embargo, por alguna razón, después de ejecutar esto, **no se alertará sobre ninguna nueva persistencia hasta que el sistema se reinicie**.
- Se requiere **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Detener el Agente**: Es posible enviar una señal de detención al agente para que **no alerte al usuario** cuando se encuentren nuevas detecciones.
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
- **Error**: Si el **proceso que creó la persistencia existe rápidamente después de él**, el daemon intentará **obtener información** sobre él, **fallará** y **no podrá enviar el evento** indicando que una nueva cosa está persistiendo.

Referencias y **más información sobre BTM**:

- [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
- [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
