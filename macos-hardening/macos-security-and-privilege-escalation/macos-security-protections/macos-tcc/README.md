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
Sin embargo, los usuarios pueden **eliminar o consultar reglas** con la utilidad de línea de comandos **`tccutil`**. 
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Note that the **`tccutil`** command requires **root privileges** to modify the **kernel database**.
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

TCC se implementa mediante el uso de una base de datos SQLite3 que se encuentra en `/Library/Application Support/com.apple.TCC/TCC.db`. La base de datos contiene una tabla llamada `access` que almacena las reglas de acceso para cada servicio o dato del sistema.

Cada regla de acceso se almacena en la tabla `access` como una fila. Cada fila contiene los siguientes campos:

- `service`: El nombre del servicio o dato del sistema al que se aplica la regla de acceso.
- `client`: El identificador del cliente que solicita el acceso.
- `client_type`: El tipo de cliente que solicita el acceso (por ejemplo, una aplicación o un proceso).
- `allowed`: Un valor booleano que indica si se permite o no el acceso.
- `prompt_count`: El número de veces que se ha solicitado acceso para esta regla.
- `csreq`: Un valor hash que se utiliza para verificar la firma de la aplicación que solicita el acceso.

La tabla `access` se actualiza automáticamente por el sistema cuando se solicita acceso a un servicio o dato del sistema. Si se deniega el acceso, se crea una nueva fila en la tabla `access` con el campo `allowed` establecido en `0`.

## Escalada de privilegios de TCC

TCC es un componente crítico de la seguridad de macOS y se utiliza para controlar el acceso a los servicios y datos del sistema que pueden ser sensibles. Como tal, cualquier vulnerabilidad en TCC podría permitir a un atacante escalar sus privilegios en el sistema.

A continuación se presentan algunas técnicas comunes que se pueden utilizar para escalar los privilegios de TCC:

- **Inyección de código**: Un atacante podría inyectar código en una aplicación legítima que tiene permiso para acceder a un servicio o dato del sistema controlado por TCC. El código inyectado podría entonces utilizar el permiso de la aplicación legítima para acceder al servicio o dato del sistema.
- **Ataque de fuerza bruta**: Un atacante podría intentar adivinar el valor de `csreq` para una aplicación que no tiene permiso para acceder a un servicio o dato del sistema controlado por TCC. Si el atacante adivina correctamente el valor de `csreq`, podría utilizarlo para acceder al servicio o dato del sistema.
- **Ataque de suplantación de identidad**: Un atacante podría suplantar la identidad de una aplicación legítima que tiene permiso para acceder a un servicio o dato del sistema controlado por TCC. El atacante podría entonces utilizar el permiso de la aplicación legítima para acceder al servicio o dato del sistema.

## Mitigación de la escalada de privilegios de TCC

Para mitigar la escalada de privilegios de TCC, se recomienda lo siguiente:

- **Mantener actualizado el sistema operativo**: Apple ha corregido varias vulnerabilidades de TCC en versiones anteriores de macOS. Mantener actualizado el sistema operativo es una forma importante de protegerse contra las vulnerabilidades conocidas de TCC.
- **Limitar el acceso a la base de datos de TCC**: La base de datos de TCC se encuentra en `/Library/Application Support/com.apple.TCC/TCC.db`. Limitar el acceso a esta base de datos puede ayudar a prevenir la inyección de código y otros ataques contra TCC.
- **Utilizar aplicaciones de confianza**: Utilizar aplicaciones de confianza que han sido descargadas de fuentes confiables puede ayudar a prevenir la inyección de código y otros ataques contra TCC.
- **Utilizar una solución de seguridad**: Utilizar una solución de seguridad que incluya protección contra la escalada de privilegios puede ayudar a prevenir los ataques contra TCC.
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
* $HOME/.ssh, $HOME/.aws, etc.
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

El atributo extendido `com.apple.macl` **no se puede borrar** como otros atributos extendidos porque está **protegido por SIP**. Sin embargo, como [**se explica en esta publicación**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), es posible deshabilitarlo **comprimiendo** el archivo, **eliminándolo** y **descomprimiéndolo**.

## Referencias

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
