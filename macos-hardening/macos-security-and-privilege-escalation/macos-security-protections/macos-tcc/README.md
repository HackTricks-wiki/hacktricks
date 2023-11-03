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
Los permisos se heredan de la aplicación padre y se rastrean según el ID de paquete y el ID de desarrollador.

### Bases de datos de TCC

Las selecciones se almacenan en la base de datos de TCC en todo el sistema en **`/Library/Application Support/com.apple.TCC/TCC.db`** o en **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** para las preferencias por usuario. Las bases de datos están protegidas contra la edición con SIP (Protección de Integridad del Sistema), pero se pueden leer.

{% hint style="danger" %}
La base de datos de TCC en **iOS** se encuentra en **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

Hay una tercera base de datos de TCC en **`/var/db/locationd/clients.plist`** para indicar los clientes permitidos para acceder a los servicios de ubicación.

Además, un proceso con **acceso completo al disco** puede editar la base de datos en modo de usuario. Ahora, una aplicación también necesita **FDA** para leer la base de datos.

{% hint style="info" %}
La **interfaz de usuario del centro de notificaciones** puede realizar cambios en la base de datos de TCC del sistema:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% tab title="Base de datos de usuario" %}
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
{% tab title="base de datos del sistema" %}
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
Al verificar ambas bases de datos, puedes verificar los permisos que una aplicación ha permitido, ha prohibido o no tiene (solicitará permiso).
{% endhint %}

* El **`auth_value`** puede tener diferentes valores: denied(0), unknown(1), allowed(2) o limited(3).
* El **`auth_reason`** puede tener los siguientes valores: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12).
* Para obtener más información sobre los **otros campos** de la tabla, [**consulta esta publicación en el blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

{% hint style="info" %}
Algunos permisos de TCC son: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... No hay una lista pública que defina todos ellos, pero puedes consultar esta [**lista de los conocidos**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

El acceso completo al disco se llama **`kTCCServiceSystemPolicyAllFiles`** y **`kTCCServiceAppleEvents`** permite que la aplicación envíe eventos a otras aplicaciones que se utilizan comúnmente para **automatizar tareas**. Además, **`kTCCServiceSystemPolicySysAdminFiles`** permite cambiar el atributo **`NFSHomeDirectory`** de un usuario, lo que cambia su carpeta de inicio y, por lo tanto, permite **burlar TCC**.
{% endhint %}

También puedes verificar los **permisos ya otorgados** a las aplicaciones en `Preferencias del Sistema --> Seguridad y Privacidad --> Privacidad --> Archivos y Carpetas`.

{% hint style="success" %}
Ten en cuenta que aunque una de las bases de datos esté dentro del directorio del usuario, **los usuarios no pueden modificar directamente estas bases de datos debido a SIP** (incluso si eres root). La única forma de configurar o modificar una nueva regla es a través del panel de Preferencias del Sistema o de las solicitudes en las que la aplicación pide permiso al usuario.

Sin embargo, recuerda que los usuarios _pueden_ **eliminar o consultar reglas** utilizando **`tccutil`**.
{% endhint %}

#### Restablecer
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Escalación de privilegios desde la base de datos de usuario TCC a FDA

Obtener **permisos de escritura** sobre la base de datos de usuario TCC no te permite otorgarte a ti mismo los permisos de **`FDA`**, solo la base de datos del sistema puede otorgar eso.

Pero puedes otorgarte a ti mismo los **derechos de automatización para Finder**, y dado que Finder tiene `FDA`, tú también los tendrás.

### De la omisión de SIP a la omisión de TCC

Las bases de datos de **TCC** están protegidas por **SIP**, por lo que solo los procesos con los **privilegios indicados podrán modificar** las bases de datos. Por lo tanto, si un atacante encuentra una **omisión de SIP** en un **archivo** (puede modificar un archivo restringido por SIP), podrá **eliminar la protección** de una base de datos de TCC y otorgarse todos los permisos de TCC.

Sin embargo, hay otra opción para abusar de esta **omisión de SIP para omitir TCC**: el archivo `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` es una lista de aplicaciones que requieren una excepción de TCC. Por lo tanto, si un atacante puede **eliminar la protección de SIP** de este archivo y agregar su **propia aplicación**, la aplicación podrá omitir TCC.
Por ejemplo, para agregar Terminal:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:

Este archivo es utilizado por el Mecanismo de Control de Transparencia (TCC) en macOS para determinar qué aplicaciones tienen permiso para acceder a ciertos recursos protegidos, como la cámara, el micrófono o los datos de ubicación. El archivo AllowApplicationsList.plist contiene una lista de las aplicaciones permitidas y sus identificadores de paquete.

Para agregar una aplicación a la lista de permitidas, debes editar este archivo y agregar una entrada con el identificador de paquete de la aplicación. Asegúrate de que el identificador de paquete sea correcto, ya que de lo contrario la aplicación no será reconocida.

Es importante tener en cuenta que modificar este archivo requiere privilegios de administrador y puede afectar la seguridad del sistema si se realizan cambios incorrectos. Se recomienda tener precaución al editar este archivo y realizar copias de seguridad regulares del mismo.

Aquí hay un ejemplo de cómo se ve el archivo AllowApplicationsList.plist:

```xml
<dict>
    <key>AllowedApplications</key>
    <array>
        <string>com.example.app1</string>
        <string>com.example.app2</string>
    </array>
</dict>
```

En este ejemplo, las aplicaciones "com.example.app1" y "com.example.app2" tienen permiso para acceder a los recursos protegidos por el TCC.

Recuerda que es importante mantener actualizado este archivo y revisar regularmente las aplicaciones permitidas para garantizar la seguridad de tu sistema.
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
### Verificación de firmas de TCC

La **base de datos** de TCC almacena el **ID del paquete** de la aplicación, pero también **almacena** **información** sobre la **firma** para **asegurarse** de que la aplicación que solicita usar un permiso sea la correcta.

{% code overflow="wrap" %}
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

{% hint style="warning" %}
Por lo tanto, otras aplicaciones que utilicen el mismo nombre y ID de paquete no podrán acceder a los permisos otorgados a otras aplicaciones.
{% endhint %}

### Entitlements

Las aplicaciones no solo necesitan solicitar y obtener acceso a algunos recursos, sino que también necesitan tener los permisos relevantes. Por ejemplo, Telegram tiene el permiso `com.apple.security.device.camera` para solicitar acceso a la cámara. Una aplicación que no tenga este permiso no podrá acceder a la cámara (y ni siquiera se le pedirá permiso al usuario).

Sin embargo, para que las aplicaciones accedan a ciertas carpetas del usuario, como `~/Desktop`, `~/Downloads` y `~/Documents`, no necesitan tener ningún permiso específico. El sistema manejará el acceso de forma transparente y solicitará permiso al usuario según sea necesario.

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

{% hint style="success" %}
Además de la documentación oficial sobre los permisos, también es posible encontrar **información interesante sobre los permisos en** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

### Lugares sensibles desprotegidos

* $HOME (en sí mismo)
* $HOME/.ssh, $HOME/.aws, etc
* /tmp

### Intención del usuario / com.apple.macl

Como se mencionó anteriormente, es posible **conceder acceso a una aplicación a un archivo arrastrándolo y soltándolo en ella**. Este acceso no se especificará en ninguna base de datos de TCC, sino como un **atributo extendido del archivo**. Este atributo **almacenará el UUID** de la aplicación permitida:
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

También hay que tener en cuenta que si mueves un archivo que permite el UUID de una aplicación en tu computadora a otra computadora, debido a que la misma aplicación tendrá diferentes UIDs, no otorgará acceso a esa aplicación.
{% endhint %}

El atributo extendido `com.apple.macl` **no se puede borrar** como otros atributos extendidos porque está **protegido por SIP**. Sin embargo, como [**se explica en esta publicación**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), es posible desactivarlo **comprimiendo** el archivo, **borrándolo** y **descomprimiéndolo**.

### Bypasses de TCC

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## Referencias

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
*   [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
