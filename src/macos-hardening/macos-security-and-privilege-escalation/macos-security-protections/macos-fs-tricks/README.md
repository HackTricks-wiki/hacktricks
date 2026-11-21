# Trucos de FS de macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Combinaciones de permisos POSIX

Para un **directorio**, los tres bits de permisos significan algo distinto que en un archivo normal. `chmod(1)` llama al bit de ejecución "**búsqueda**" cuando se aplica a un directorio:<sup>[[2]](#references)</sup>

> `0100` Para archivos, permite la ejecución por parte del propietario. Para directorios, permite al propietario **buscar** en el directorio.

- **lectura**: puedes **enumerar** las entradas del directorio (listar los nombres).
- **escritura**: puedes **crear, renombrar y eliminar entradas** en el directorio. Ten en cuenta que esto es una propiedad del directorio *contenedor*, no del archivo: puedes eliminar un archivo que no puedes leer ni modificar, siempre que tengas permiso de escritura en su directorio padre.
  - Para eliminar un **subdirectorio**, debe estar vacío, lo que a su vez requiere derechos suficientes para eliminar todo lo que contiene.
  - Si el directorio tiene el **sticky bit** (`S_ISVTX`, como `/tmp`), esto está restringido: POSIX establece que un proceso solo puede eliminar o renombrar archivos en él si es propietario del archivo, propietario del directorio o tiene los privilegios adecuados.<sup>[[1]](#references)</sup>
- **ejecución / búsqueda**: tienes **permiso para recorrer** el directorio. La resolución de nombres de ruta localiza cada componente "en el directorio especificado por su predecesor", por lo que **perder los permisos de búsqueda en cualquier componente de la ruta hace que todo lo que esté por debajo sea inaccesible por ruta**, aunque el archivo final sea legible por todo el mundo.<sup>[[1]](#references)</sup>

### Combinaciones peligrosas

**Cómo sobrescribir un archivo/carpeta propiedad de root**, cuando:

- El **propietario** de uno de los **directorios** padre de la ruta es el usuario
- El **propietario** de uno de los **directorios** padre de la ruta es un **grupo de usuarios** con **acceso de escritura**
- Un **grupo** de usuarios tiene acceso de **escritura** al **archivo**

Con cualquiera de las combinaciones anteriores, un atacante podría **inyectar** un **sym/hard link** en la ruta esperada para obtener escritura arbitraria con privilegios.

### Caso especial: carpeta root con R+X

Esto se desprende directamente de la regla de resolución de nombres de ruta anterior. Si un **directorio solo concede R+X a root**, los archivos que contiene son inaccesibles *por ruta* para todos los demás, pero los **bits de permiso de los propios archivos pueden seguir siendo permisivos**. El directorio es lo único que se interpone.

Por tanto, cualquier primitiva que permita sacar el archivo de ese directorio —un proceso con privilegios que **mueva/renombre/copie** una ruta elegida por el atacante a una ubicación que *sí puedas recorrer*— se convierte en una lectura arbitraria, sin necesidad de eludir nunca los permisos del propio archivo:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Busca procesos privilegiados que muevan archivos (instaladores, rotadores de logs, recolectores de fallos/diagnósticos, funciones de copia de seguridad y de «exportación») y que acepten una ruta de origen proporcionada por un usuario con menos privilegios.

## Enlace simbólico / enlace duro

### Archivo/carpeta con permisos permisivos

Si un proceso privilegiado escribe datos en un **archivo** que podría estar **controlado** por un **usuario con menos privilegios**, o que podría haber sido **creado previamente** por uno, el usuario podría simplemente **hacer que apunte a otro archivo** mediante un enlace simbólico o duro, y el proceso privilegiado escribirá en ese archivo.

Consulta las otras secciones para ver cómo un atacante podría **abusar de una escritura arbitraria para escalar privilegios**.

### `O_NOFOLLOW` en `open`

Según [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *«Si se usa `O_NOFOLLOW` en la máscara y el archivo de destino pasado a `open()` es un enlace simbólico, la llamada a `open()` fallará».* Solo se comprueba el componente **final**: todos los componentes **intermedios** siguen resolviéndose y siguiéndose. Así que un desarrollador que haya «protegido» una escritura con `O_NOFOLLOW` todavía puede ser atacado mediante la creación de un enlace simbólico en cualquier **directorio padre** de la ruta de destino.<sup>[[3]](#references)</sup>

La misma página del manual documenta los flags que sí cierran esa brecha:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *«si ... cualquier componente de la ruta pasada a `open()` es un enlace simbólico, la llamada a `open()` fallará».*
- **`O_RESOLVE_BENEATH`** — *«si ... la resolución de la ruta especificada escapa del directorio asociado al fd, la llamada a `openat()` fallará».*

De lo contrario, las opciones restantes para impedir cambios de enlaces simbólicos en rutas intermedias son usar `openat()` con un FD de directorio que ya hayas validado, o usar `realpath()` y volver a validar.

## .fileloc

Los archivos con la extensión **`.fileloc`** pueden apuntar a otras aplicaciones o binarios, de modo que, al abrirlos, se ejecutará la aplicación o el binario indicado.\
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

Si una llamada a `open` no tiene el flag `O_CLOEXEC`, el descriptor de archivo se heredará en el proceso hijo. Así que, si un proceso privilegiado abre un archivo privilegiado y ejecuta un proceso controlado por el atacante, el atacante **heredará el FD del archivo privilegiado**.

El ejemplo canónico es el **`DYLD_PRINT_TO_FILE` LPE en OS X 10.10** ([SektionEins](https://www.sektionseins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` respetaba `DYLD_PRINT_TO_FILE=/path` incluso en **binarios restringidos (suid root)**, porque esa variable en particular se analizaba fuera de `processDyldEnvironmentVariable()`.
- Ejecutaba `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, por lo que **creaba un archivo propiedad de root en una ruta arbitraria**.
- El FD **nunca se cerraba y no tenía el flag close-on-exec**, así que todos los procesos hijos del binario suid heredaban un **FD de escritura a un archivo propiedad de root**.
- Al ejecutar, por ejemplo, `DYLD_PRINT_TO_FILE=/etc/target suid_binary` y después leer el número del FD heredado en el proceso hijo, se podían realizar escrituras arbitrarias en archivos propiedad de root; `fcntl(fd, F_SETFL, 0)` incluso eliminaba `O_APPEND` para permitir sobrescribir en lugar de añadir.

El mismo patrón aparece siempre que un proceso privilegiado abre un archivo **antes de ejecutar con `exec` algo que controlas** (herramientas auxiliares, editores de tipo `crontab` invocados mediante `$EDITOR`, archivos de registro/depuración abiertos desde una ruta de variable de entorno...). Enumera los FDs que heredaste con:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

Cualquier cosa por encima de `2` que apunte a un archivo que no puedas abrir tú mismo es una primitiva de escritura arbitraria (o lectura arbitraria).

## Evita los trucos de quarantine xattrs

### Elimínalo

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### indicador uchg / uchange / uimmutable

Si un archivo/carpeta tiene este atributo inmutable, no será posible asignarle un xattr.

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### Sistemas de archivos sin compatibilidad con xattr

No todos los sistemas de archivos que macOS puede montar almacenan **atributos extendidos** de forma nativa. HFS+ y APFS sí lo hacen; **FAT32, exFAT y la mayoría de los montajes NFS no**: macOS los emula escribiendo un archivo auxiliar **AppleDouble** llamado `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Esto importa para quarantine, porque el xattr solo persiste si realmente se puede escribir **y volver a leer** desde el mismo volumen:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

Si el volumen se lee más adelante desde una ruta que ignora el archivo complementario `._` (o si este se elimina), el archivo llega **sin un flag de cuarentena**; y una `.app` sin cuarentena basta para escapar de App Sandbox, como se explica en [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### ACL writeextattr y comportamiento de cuarentena de AppleDouble

Para ver el ejemplo de ACL `writeextattr`, el mecanismo AppleDouble `com.apple.acl.text` y los pasos para crear y validar el archivo sidecar, consulta [AppleDouble/ACL quarantine bypass reproduction](macos-appledouble-acl-quarantine-bypass.md).

## Omitir las comprobaciones de firma

### Omitir las comprobaciones de binarios de plataforma

Algunas comprobaciones de seguridad verifican si el binario es un **binario de plataforma**, por ejemplo, para permitir la conexión a un servicio XPC. Sin embargo, como se muestra en https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, es posible omitir esta comprobación obteniendo un binario de plataforma (como `/bin/ls`) e inyectando el exploit mediante dyld con la variable de entorno `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Omitir los flags `CS_REQUIRE_LV` y `CS_FORCED_LV`

Es posible que un binario en ejecución modifique sus propios flags para omitir las comprobaciones con código como este:<sup>[[7]](#references)</sup>

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

Los bundles contienen el archivo **`_CodeSignature/CodeResources`**, que contiene el **hash** de cada **archivo** del **bundle**. Ten en cuenta que el hash de CodeResources también está **integrado en el ejecutable**, así que tampoco podemos modificarlo.

Sin embargo, hay algunos archivos cuya firma no se comprobará; estos tienen la clave omit en el plist, como:

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

Un usuario puede montar un dmg personalizado incluso encima de algunas carpetas existentes. Así puedes crear un paquete dmg personalizado con contenido personalizado:

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

Normalmente, macOS monta discos comunicándose con el servicio Mach `com.apple.DiskArbitrarion.diskarbitrariond` (proporcionado por `/usr/libexec/diskarbitrationd`). Si añades el parámetro `-d` al archivo plist de LaunchDaemons y lo reinicias, almacenará registros en `/var/log/diskarbitrationd.log`; almacenará registros en `/var/log/diskarbitrationd.log`.\
Sin embargo, es posible usar herramientas como `hdik` y `hdiutil` para comunicarse directamente con el kext `com.apple.driver.DiskImages`.

## Escrituras arbitrarias

### Scripts sh periódicos

Si tu script puede interpretarse como un **script de shell**, podrías sobrescribir el script de shell **`/etc/periodic/daily/999.local`**, que se ejecutará todos los días.

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

Genera simplemente el script `/Applications/Scripts/privesc.sh` con los **commands** que quieras ejecutar como root.

### Sudoers File

Si tienes **escritura arbitraria**, podrías crear un archivo dentro de la carpeta **`/etc/sudoers.d/`** para concederte privilegios de **sudo**.

### PATH files

El archivo **`/etc/paths`** es uno de los principales lugares que completan la variable de entorno PATH. Necesitas ser root para sobrescribirlo, pero si un script de un **proceso privilegiado** ejecuta algún **command sin la ruta completa**, podrías **secuestrarlo** modificando este archivo.

También puedes escribir archivos en **`/etc/paths.d`** para añadir nuevas carpetas a la variable de entorno `PATH`.

### cups-files.conf

Esta técnica se usó en [este writeup](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Crea el archivo `/etc/cups/cups-files.conf` con el siguiente contenido:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

Esto creará el archivo `/etc/sudoers.d/lpe` con permisos 777. El texto basura adicional al final sirve para provocar la creación del registro de errores.

Luego, escribe en `/etc/sudoers.d/lpe` la configuración necesaria para escalar privilegios, como `%staff ALL=(ALL) NOPASSWD:ALL`.

Después, modifica de nuevo el archivo `/etc/cups/cups-files.conf` para indicar `LogFilePerm 700`, de modo que el nuevo archivo sudoers sea válido al invocar `cupsctl`.

### Escape del sandbox

Es posible escapar del sandbox de macOS con una escritura arbitraria en el FS. Para ver algunos ejemplos, consulta la página [macOS Auto Start](../../../../macos-auto-start-locations.md), pero una opción común es escribir un archivo de preferencias de Terminal en `~/Library/Preferences/com.apple.Terminal.plist` que ejecute un comando al iniciarse y llamarlo usando `open`.

## Generar archivos escribibles como otros usuarios

Una primitiva de privesc muy común consiste en hacer que un **proceso privilegiado cree un archivo por ti** en un directorio que controlas y luego conservar **acceso de escritura** a ese archivo. Se necesitan dos ingredientes:

1. Un directorio de tu propiedad (o donde puedas establecer una **ACL heredable**), para que cualquier elemento creado dentro herede tus permisos.
2. Un proceso privilegiado/`suid` al que se le pueda indicar **dónde** crear un archivo, normalmente mediante una variable de entorno de depuración/registro, un archivo de configuración o la API XPC de un helper.

La parte de la **ACL heredable** es lo que hace que el archivo creado sea escribible por ti, aunque pertenezca a otro usuario. Los indicadores de herencia `file_inherit` / `directory_inherit` están documentados en [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Ahora, cualquier archivo que un proceso con privilegios cree dentro de `$DIRNAME` será **escribible por ti**. Si ese directorio también es una ubicación que posteriormente se **ejecuta como root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, un directorio de LaunchDaemon...), esto permite una escalada directa a root. Consulta las secciones [Sudoers File](#sudoers-file) y [cups-files.conf](#cups-filesconf) anteriores para saber qué escribir una vez que tengas el archivo.

Para ver un ejemplo completo y práctico de la cadena «una variable de entorno hace que un proceso root cree un archivo y el FD se filtra hasta ti», consulta [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) más arriba.

## Memoria compartida POSIX

La **memoria compartida POSIX** permite que los procesos de sistemas operativos compatibles con POSIX accedan a un área de memoria común, lo que facilita una comunicación más rápida que otros métodos de comunicación entre procesos. Consiste en crear o abrir un objeto de memoria compartida con `shm_open()`, establecer su tamaño con `ftruncate()` y asignarlo al espacio de direcciones del proceso mediante `mmap()`. Después, los procesos pueden leer y escribir directamente en esta área de memoria. Para administrar el acceso concurrente y evitar la corrupción de datos, suelen utilizarse mecanismos de sincronización como mutexes o semáforos. Por último, los procesos desasignan y cierran la memoria compartida con `munmap()` y `close()`, y pueden eliminar el objeto de memoria con `shm_unlink()`. Este sistema resulta especialmente eficaz para una IPC rápida y eficiente en entornos donde varios procesos necesitan acceder rápidamente a datos compartidos.

<details>

<summary>Ejemplo de código del productor</summary>

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

<summary>Ejemplo de código consumidor</summary>

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

## Descriptores protegidos de macOS

**Los descriptores protegidos de macOS** son una función de seguridad introducida en macOS para mejorar la seguridad y la fiabilidad de las **operaciones con descriptores de archivo** en aplicaciones de usuario. Estos descriptores protegidos permiten asociar restricciones específicas, o «protecciones», a los descriptores de archivo, que el kernel hace cumplir.

Esta función es especialmente útil para prevenir ciertas clases de vulnerabilidades de seguridad, como el **acceso no autorizado a archivos** o las **condiciones de carrera**. Estas vulnerabilidades se producen, por ejemplo, cuando un subproceso accede a una descripción de archivo y **permite que otro subproceso vulnerable acceda a ella**, o cuando un proceso hijo vulnerable **hereda** un descriptor de archivo. Algunas funciones relacionadas con esta funcionalidad son:

- `guarded_open_np`: Abre un descriptor de archivo con una protección
- `guarded_close_np`: Lo cierra
- `change_fdguard_np`: Cambia las marcas de protección de un descriptor (incluso elimina la protección)

## References

- [1] [POSIX.1-2024 — Definiciones base, cap. 4 (Permisos de acceso a archivos, protección de directorios, resolución de nombres de ruta)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - Escalada local de privilegios mediante DYLD_PRINT_TO_FILE en OS X 10.10](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - ¿Qué sistemas de archivos y servicios en la nube conservan los atributos extendidos?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - Una nueva era de escapes del sandbox de macOS](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Descubriendo vulnerabilidades de Apple: la auditoría de diskarbitrationd y storagekitd, parte 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
