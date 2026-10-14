# macOS aplikacije – inspekcija, debagovanje i fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Statička analiza

### otool & objdump & nm

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```

```bash
nm -m ./tccd # List of symbols
```

### Disarm (old jtool2)

Možete [**preuzeti disarm ovde**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Imajte na umu da **`disarm`** može da radi i sa komprimovanim IM4P datotekama (kao što je `kernelcache`) i da izdvoji samo potrebne delove ili čak analizira potrebni deo bez njegovog izdvajanja.

```bash
export JCOLOR=1
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled

disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache
JDEBUG=1 disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache with debug info
disarm -r "code signature" /bin/ps # Check code signature of a binary
disarm -e "code signature" /bin/ps # Extract code signature of a binary
```


### Codesign / ldid

> [!TIP]
> **`Codesign`** se može pronaći u **macOS-u**, dok se **`ldid`** može pronaći u **iOS-u**.

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```

### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) je alat koristan za pregled **.pkg** datoteka (instalacionih paketa) i proveru njihovog sadržaja pre instalacije.\
Ovi instalacioni paketi sadrže bash skripte `preinstall` i `postinstall` koje autori malware-a obično zloupotrebljavaju da bi **persist** **malware**.

### hdiutil

Ovaj alat **montira** Apple disk image (`.dmg`) datoteke kako bi mogle da se pregledaju pre pokretanja bilo čega:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Montiraće se u `/Volumes`

### Pakovani binarni fajlovi

- Proverite da li imaju visoku entropiju
- Proverite stringove (ako gotovo da nema razumljivih stringova, binarni fajl je pakovan)
- UPX packer za macOS generiše sekciju pod nazivom `__XHDR`.

## Statička Objective-C analiza

### Metapodaci

> [!CAUTION]
> Imajte na umu da programi napisani u Objective-C **zadržavaju** deklaracije svojih klasa i kada se **kompajliraju** u [Mach-O binarne fajlove](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Takve deklaracije klasa **obuhvataju** nazive i tipove sledećeg:

- Definisanih interfejsa
- Metoda interfejsa
- Promenljivih instance interfejsa
- Definisanih protokola

Imajte na umu da ovi nazivi mogu biti maskirani kako bi se otežala reverzna analiza binarnog fajla.

### Pozivanje funkcija

Kada se u binarnom fajlu koji koristi Objective-C pozove funkcija, kompajlirani kod umesto pozivanja te funkcije poziva **`objc_msgSend`**. Ona zatim poziva konačnu funkciju:

![Metadata - Function calling: When a function is called in a binary that uses objective-C, the compiled code instead of calling that function, it will call objc msgSend . Which will be...](<../../../images/image (305).png>)

Parametri koje ova funkcija očekuje su:

- Prvi parametar (**self**) je „pokazivač koji pokazuje na **instancu klase koja treba da primi poruku**“. Jednostavnije rečeno, to je objekat nad kojim se poziva metoda. Ako je metoda klasna metoda, ovo će biti instanca objekta klase (kao celine), dok će za metodu instance `self` pokazivati na instancu klase kreiranu kao objekat.
- Drugi parametar (**op**) je „selektor metode koja obrađuje poruku“. Jednostavnije rečeno, to je samo **naziv metode.**
- Preostali parametri su sve **vrednosti koje metoda zahteva** (op).

Pogledajte kako da lako **dobijete ove informacije pomoću `lldb` u ARM64** na ovoj stranici:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Registar**                                                    | **(za) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1. argument**  | **rdi**                                                         | **self: objekat nad kojim se poziva metoda** |
| **2. argument**  | **rsi**                                                         | **op: naziv metode**                             |
| **3. argument**  | **rdx**                                                         | **1. argument metode**                         |
| **4. argument**  | **rcx**                                                         | **2. argument metode**                         |
| **5. argument**  | **r8**                                                          | **3. argument metode**                         |
| **6. argument**  | **r9**                                                          | **4. argument metode**                         |
| **7. i naredni argumenti** | <p><strong>rsp+</strong><br><strong>(na steku)</strong></p> | **5. i naredni argumenti metode**                        |

### Izdvajanje ObjectiveC metapodataka

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) je alat za class-dump Objective-C binarnih fajlova. Na GitHub stranici se pominju dylib fajlovi, ali alat radi i sa izvršnim fajlovima.

```bash
./dynadump dump /path/to/bin
```

U vreme pisanja, ovo **trenutno najbolje funkcioniše**.

#### Uobičajeni alati

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) je originalni alat za generisanje deklaracija klasa, kategorija i protokola u formatiranom Objective-C kodu.

Star je i više se ne održava, pa verovatno neće raditi kako treba.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) je moderan, višeplatformski alat za ispisivanje Objective-C klasa. Za razliku od postojećih alata, iCDump može da radi nezavisno od Apple ekosistema i nudi Python bindings.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Statička analiza Swift-a

Kod Swift binarnih datoteka, zbog kompatibilnosti sa Objective-C, ponekad možete izdvojiti deklaracije pomoću [class-dump](https://github.com/nygard/class-dump/), ali ne uvek.

Pomoću komandnih linija **`jtool -l`** ili **`otool -l`** moguće je pronaći nekoliko sekcija koje počinju prefiksom **`__swift5`**:

```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
    [...]
    Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
    Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
    Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
    Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
    [...]
```

Dodatne informacije o [**informacijama sačuvanim u ovim odeljcima možete pronaći u ovom blog postu**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Pored toga, **Swift binarne datoteke mogu sadržati simbole** (na primer, biblioteke moraju da čuvaju simbole kako bi njihove funkcije mogle da se pozivaju). **Simboli obično sadrže informacije o nazivu funkcije** i atributima u nečitljivom obliku, pa su veoma korisni; postoje i „**demangler**“ alati koji mogu da pronađu izvorni naziv:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Dinamička analiza

> [!WARNING]
> **Nemojte podrazumevano isključivati SIP kao korak pri debagovanju.** Razvojne verzije sa `com.apple.security.get-task-allow` mogu da se debaguju dok je SIP omogućen. Proverite cilj pomoću komande `codesign -d --entitlements :- /path/to/binary` pre nego što pokušate da koristite LLDB. Samo debugger entitlement ne omogućava pristup ciljevima koje štiti SIP.<sup>[[15]](#references)</sup>
>
> Distribuirana aplikacija sa hardened runtime-om obično izostavlja `get-task-allow` i blokira povezivanje. Ako je moguće, koristite debug verziju koju je obezbedio developer; ponovno potpisivanje privremene kopije može da promeni ponašanje koje testirate. Ako je zaštićenom cilju neophodno isključiti SIP, koristite namensku test mašinu ili VM, a ne mašinu na koju se oslanjate.<sup>[[16]](#references)</sup>
>
> Ranija uputstva za zaštićeni cilj u izolovanom testnom okruženju navodila su sledeće alternative:
>
> Imajte na umu da je za debagovanje binarnih datoteka potrebno isključiti SIP (`csrutil disable` ili `csrutil enable --without debug`), ili kopirati binarne datoteke u privremenu fasciklu i ukloniti potpis pomoću komande `codesign --remove-signature <binary-path>`, ili omogućiti debagovanje binarne datoteke (možete da koristite [ovu skriptu](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
>
> Ovo nije opšti zahtev za SIP: prednost dajte debug verziji i imajte na umu da kopiranje ili promena potpisa može da izmeni ponašanje koje testirate.

> [!WARNING]
> Imajte na umu da SIP **mora biti isključen** da bi se instrumentirale **sistemske binarne datoteke** (kao što je `cloudconfigurationd`) na macOS-u. (Samo uklanjanje potpisa nije dovoljno.)

### API-ji

macOS izlaže neke zanimljive API-je koji pružaju informacije o procesima:

- `proc_info`: Glavni API koji pruža mnogo informacija o svakom procesu. Da biste dobili informacije o drugim procesima, morate biti root, ali nisu vam potrebni posebni entitlements ni mach portovi.
- `libsysmon.dylib`: Izlaže informacije o procesima putem XPC funkcija, ali pozivaocima je potreban entitlement `com.apple.sysmond.client`.

### Stackshot i microstackshots

**Stackshotting** je tehnika za snimanje stanja procesa, uključujući stekove poziva svih pokrenutih niti. Posebno je korisna za debagovanje, analizu performansi i razumevanje ponašanja sistema u određenom trenutku. Na iOS-u i macOS-u stackshotting može da se obavlja pomoću više alata i metoda, kao što su alati **`sample`** i **`spindump`**.

### Sysdiagnose

Ovaj alat (`/usr/bini/ysdiagnose`) prikuplja mnogo informacija sa računara izvršavanjem desetina različitih komandi, kao što su `ps`, `zprint`...

Mora se pokrenuti kao **root**, a daemon `/usr/libexec/sysdiagnosed` ima veoma zanimljive entitlements, kao što su `com.apple.system-task-ports` i `get-task-allow`.

Njegov plist se nalazi na putanji `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` i definiše 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Briše stare arhive u /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Specijalni port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Korisnički interfejs preko Obj-C klase `Libsysdiagnose`. Mogu se proslediti tri argumenta u dict-u (`compress`, `display`, `run`)

### Unified Logs

macOS generiše opširne logove koji su korisni pri analizi ponašanja aplikacije.

Neka polja logova sadrže oznaku `<private>` kako bi sakrila informacije koje mogu da identifikuju korisnika ili uređaj. Starija uputstva ponekad opisuju instaliranje sertifikata za prikaz ovih polja; savremena uputstva za debagovanje umesto toga koriste konfiguracioni profil sa eksplicitno ograničenim opsegom i opcijom `Enable-Private-Data`, ili `OSLogPreferences` za pojedinačnu aplikaciju. Ponašanje može da se razlikuje u zavisnosti od podsistema i verzije macOS-a. Starija diskusija o sertifikatima/profilima zadržana je u referencama. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Levi panel

U levom panelu Hopper-a mogu se videti simboli binarne datoteke (**Labels**), lista procedura i funkcija (**Proc**) i stringovi (**Str**). To nisu svi stringovi, već oni definisani u nekoliko delova Mac-O datoteke (kao što su _cstring ili_ `objc_methname`).

#### Srednji panel

U srednjem panelu možete da vidite **disasemblirani kod**. Možete ga prikazati kao **sirovi** disassembly, **graf**, **dekompilirani kod** ili **binarni kod** tako što ćete kliknuti na odgovarajuću ikonu:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Klikom desnim tasterom miša na objekat koda možete da vidite **reference ka tom objektu i od njega**, pa čak i da promenite njegov naziv (ovo ne funkcioniše u dekompiliranom pseudokodu):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Pored toga, **u donjem delu srednjeg panela možete da pišete Python komande**.

#### Desni panel

U desnom panelu možete da vidite zanimljive informacije, kao što su **istorija navigacije** (da biste znali kako ste došli do trenutnog prikaza), **graf poziva** u kom možete da vidite sve **funkcije koje pozivaju ovu funkciju** i sve funkcije koje **ova funkcija poziva**, kao i informacije o **lokalnim promenljivama**.

### dtrace

Korisnicima omogućava pristup aplikacijama na izuzetno **niskom nivou** i pruža način da **prate** **programe**, pa čak i da menjaju njihov tok izvršavanja. Dtrace koristi **probe** koje su **postavljene širom kernela** i nalaze se na mestima kao što su početak i kraj sistemskih poziva.

DTrace koristi funkciju **`dtrace_probe_create`** za kreiranje probe za svaki sistemski poziv. Ove probe mogu da se aktiviraju na **ulaznoj i izlaznoj tački svakog sistemskog poziva**. Interakcija sa DTrace-om odvija se preko /dev/dtrace, koji je dostupan samo root korisniku.<sup>[[1]](#references)</sup>

> [!TIP]
> Da biste omogućili Dtrace bez potpunog isključivanja SIP zaštite, u Recovery Mode-u možete da izvršite: `csrutil enable --without dtrace`
>
> Možete da koristite **`dtrace`** ili **`dtruss`** i nad binarnim datotekama koje ste **sami kompajlirali**.

Dostupne probe za dtrace mogu se prikazati pomoću:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Naziv probe se sastoji od četiri dela: provider, modul, funkcija i naziv (`fbt:mach_kernel:ptrace:entry`). Ako ne navedete neki deo naziva, Dtrace će taj deo tretirati kao džoker.

Da biste podesili DTrace tako da aktivira probe i naveli koje radnje treba da izvrši kada se one aktiviraju, potrebno je da koristite jezik D.

Detaljnije objašnjenje i dodatne primere možete pronaći na [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Primeri

Pokrenite `man -k dtrace` da biste prikazali **dostupne DTrace skripte**. Primer: `sudo dtruss -n binary`

- U liniji

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

- skripta

```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
    printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
        printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
        ;
}
syscall:::return
{
        printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```

### dtruss

```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```

### kdebug

To je mogućnost praćenja rada kernela. Dokumentovane kodove možete pronaći u **`/usr/share/misc/trace.codes`**.

Alati kao što su `latency`, `sc_usage`, `fs_usage` i `trace` koriste ga interno.

Za povezivanje sa `kdebug`-om koristi se `sysctl` preko prostora imena `kern.kdebug`, a MIB-ove koje treba koristiti možete pronaći u `sys/sysctl.h`. Funkcije su implementirane u `bsd/kern/kdebug.c`.

Za interakciju sa kdebug-om pomoću prilagođenog klijenta obično se prate ovi koraci:

- Uklonite postojeća podešavanja pomoću KERN_KDSETREMOVE
- Podesite praćenje pomoću KERN_KDSETBUF i KERN_KDSETUP
- Pomoću KERN_KDGETBUF utvrdite broj unosa u baferu
- Preuzmite sopstveni klijent iz praćenja pomoću KERN_KDPINDEX
- Omogućite praćenje pomoću KERN_KDENABLE
- Pročitajte bafer pozivanjem KERN_KDREADTR
- Da biste povezali svaku nit sa njenim procesom, pozovite KERN_KDTHRMAP.

Da biste dobili ove informacije, možete koristiti Apple alat **`trace`** ili prilagođeni alat [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.

**Imajte u vidu da je Kdebug dostupan samo jednom korisniku u datom trenutku.** Zato istovremeno može da se izvršava samo jedan alat koji koristi k-debug.

### ktrace

API-ji `ktrace_*` potiču iz `libktrace.dylib`, koja obavija API-je za `Kdebug`. Klijent može jednostavno da pozove `ktrace_session_create` i `ktrace_events_[single/class]` da bi postavio callback funkcije za određene kodove, a zatim da pokrene praćenje pomoću `ktrace_start`.

Ovaj alat možete koristiti i kada je **SIP aktiviran**.

Kao klijent možete koristiti uslužni program `ktrace`:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Or `tailspin`.

### kperf

Koristi se za profilisanje na nivou kernela i izgrađen je pomoću `Kdebug` poziva.

U osnovi, proverava se globalna promenljiva `kernel_debug_active`, a ako je postavljena, poziva se `kperf_kdebug_handler` sa `Kdebug` kodom i adresom kernel okvira koji poziva funkciju. Ako se `Kdebug` kod podudara sa jednim od izabranih kodova, primenjuju se „akcije“ konfigurisane kao bitmapa (pogledajte `osfmk/kperf/action.h` za dostupne opcije).

Kperf takođe ima sysctl MIB tabelu: (kao root) `sysctl kperf`. Ovaj kod možete pronaći u `osfmk/kperf/kperfbsd.c`.

Pored toga, podskup funkcionalnosti Kperf-a nalazi se u `kpc`, koji pruža informacije o brojačima performansi mašine.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) je veoma koristan alat za proveru radnji povezanih sa procesima koje proces obavlja (na primer, za praćenje novih procesa koje neki proces pokreće).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) je alat koji prikazuje odnose između procesa.\
Potrebno je da nadgledate svoj Mac komandom kao što je **`sudo eslogger fork exec rename create > cap.json`** (terminal koji pokreće ovu komandu mora imati FDA). Zatim možete učitati JSON u ovaj alat da biste videli sve odnose:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) nadgleda događaje nad datotekama, kao što su kreiranje, izmena i brisanje.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) je GUI alat čiji izgled i način rada mogu biti poznati Windows korisnicima iz Microsoftovog alata _Procmon_ iz paketa Sysinternals. Ovaj alat omogućava pokretanje i zaustavljanje snimanja različitih vrsta događaja, filtriranje tih događaja po kategorijama kao što su datoteke, procesi, mreža itd. i čuvanje snimljenih događaja u JSON formatu.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) deo su Xcode-ovih alata za programere — koriste se za nadgledanje performansi aplikacija, pronalaženje curenja memorije i praćenje aktivnosti u sistemu datoteka.

![Crescendo - Apple Instruments: Apple Instruments su deo Xcode-ovih alata za programere — koriste se za nadgledanje performansi aplikacija, pronalaženje curenja memorije i praćenje aktivnosti u sistemu datoteka](<../../../images/image (1138).png>)

### fs_usage

Omogućava praćenje radnji koje obavljaju procesi:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) je koristan za pregled **biblioteka** koje koristi binarni fajl, **datoteka** koje koristi i **mrežnih** veza.\
Takođe proverava procese binarnih fajlova pomoću **virustotal** i prikazuje informacije o binarnom fajlu.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

U [**ovom blog postu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) možete pronaći primer kako **debugovati pokrenuti daemon** koji je koristio **`PT_DENY_ATTACH`** da spreči debugging čak i kada je SIP bio onemogućen.<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` je Darwin-specifičan zahtev za `ptrace(2)` sa vrednošću **31** (`0x1f`); ostali argumenti se ignorišu. Proces može da ga pozove direktno, bez forka, kako bi odbio kasnije praćenje od strane roditeljskog procesa.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### XNU stanje i redosled poziva

Rezultat zavisi od toga koji `ptrace` zahtev prvi stigne do XNU:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB se prvi poveže:** `debugserver` koristi `PT_ATTACHEXC`; XNU ga konvertuje u `PT_ATTACH`, obavlja proveru ovlašćenja `KAUTH_PROCESS_CANTRACE` i postavlja `P_LTRACED` na ciljnom procesu. Naknadni `PT_DENY_ATTACH` nailazi na tu zastavicu i prekida ciljni proces sa `W_EXITCODE(ENOTSUP, 0)`, što LLDB obično prikazuje kao status **45** (`0x2d`).
- **Ciljni proces prvi zabrani povezivanje:** XNU postavlja `P_LNOATTACH`. Kasnije povezivanje se odbija tokom provere ovlašćenja za praćenje procesa; putanja za grešku pri povezivanju vidi `P_LNOATTACH` i šalje `SIGSEGV` procesu koji pokušava da se poveže, što se u LLDB-u može prikazati kao prekinuta veza sa `debugserver`-om.

Da biste razlikovali ove putanje, omogućite `debugserver` logovanje pre pokretanja ili povezivanja i pregledajte njegove `ptrace` zahteve:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### Statička identifikacija i zaobilaženje ARM64

Kod neofuskiranog ARM64 Mach-O-a pronađite uvezeni `_ptrace` stub i pregledajte mesta poziva. Prvi celobrojni argument prosleđuje se u `w0`, pa ovaj niz direktno otkriva anti-debug zahtev. Odsustvo uvoza nije konačan dokaz, jer kod može dinamički da razreši `ptrace`. Uvezeni `_sysctl` takođe može da ukazuje na anti-debug provere, mada se i on može dinamički razrešiti.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

U prikazanom primeru, promena immediate vrednosti sa `0x1f` na `0x0` menja zahtev u `PT_TRACE_ME` i omogućava programu da nastavi rad pod LLDB-om. Ovo je **zaobilazno rešenje specifično za ovaj primer**, a ne opšti no-op: pre nego što odlučite da li ćete promeniti zahtev, preskočiti poziv ili forsirati uspešan povratni rezultat, proverite kako pozivalac obrađuje povratne vrednosti i tok kontrole.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** je **de facto alat** za **otklanjanje grešaka** u **macOS** binarnim fajlovima.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Možete podesiti Intel sintaksu pri korišćenju lldb-a tako što ćete u svom home folderu napraviti datoteku pod nazivom **`.lldbinit`** sa sledećom linijom:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Unutar lldb-a, napravite dump procesa pomoću `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) komanda</strong></td><td><strong>Opis</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Pokreće izvršavanje, koje se nastavlja dok se ne aktivira breakpoint ili proces ne završi.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Pokreće izvršavanje i zaustavlja ga na ulaznoj tački.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Nastavlja izvršavanje procesa koji se debaguje.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Izvršava sledeću instrukciju. Ova komanda preskače pozive funkcija.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Izvršava sledeću instrukciju. Za razliku od komande <code>nexti</code>, ova komanda ulazi u pozive funkcija.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Izvršava preostale instrukcije u trenutnoj funkciji (frejmu), vraća se i zaustavlja izvršavanje.</td></tr>
<tr><td><strong>control + c</strong></td><td>Pauzira izvršavanje. Ako je proces pokrenut (<code>r</code>) ili nastavljen (<code>c</code>), ova komanda ga zaustavlja na mestu na kom se trenutno izvršava.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Bilo koja funkcija pod nazivom main</p>
<p><code>b &lt;binname&gt;`main</code> # Glavna funkcija binarne datoteke</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Glavna funkcija navedene binarne datoteke</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Bilo koja metoda NSFileManager</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Postavlja breakpoint u svim funkcijama te biblioteke</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Spisak breakpointa</p>
<p><code>br e/dis &lt;num&gt;</code> # Uključivanje/isključivanje breakpointa</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Prikazuje pomoć za komandu breakpoint</p>
<p><code>help memory write</code> # Prikazuje pomoć za upisivanje u memoriju</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Prikazuje memoriju kao string završen nulom.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Prikazuje memoriju kao instrukciju asemblera.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Prikazuje memoriju kao bajt.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Ova komanda ispisuje objekat na koji parametar upućuje.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>Većina Apple Objective-C API-ja ili metoda vraća objekte, pa ih treba prikazati komandom „print object” (<code>po</code>). Ako <code>po</code> ne daje smislen izlaz, koristite <code>x/b</code>.</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Upisuje AAAA na tu adresu<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Upisuje AAAA na tu adresu
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Disasemblira trenutnu funkciju</p>
<p><code>dis -n &lt;funcname&gt;</code> # Disasemblira funkciju</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Disasemblira funkciju<br>
<code>dis -c 6</code> # Disasemblira šest linija<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Disasemblira od jedne adrese do druge<br>
<code>dis -p -c 4</code> # Počinje disasembliranje na trenutnoj adresi</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Pregled niza od tri elementa u registru <code>x1</code></td></tr>
<tr><td><strong>image dump sections</strong></td><td>Ispisuje mapu memorije trenutnog procesa.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Prikazuje adresu svakog simbola iz CoreNLP-a</td></tr>
</tbody>
</table>

> [!TIP]
> Prilikom poziva funkcije **`objc_sendMsg`**, registar **rsi** sadrži **naziv metode** kao string završen nulom („C” string). Da biste naziv ispisali pomoću lldb-a, uradite sledeće:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-dinamička analiza

#### Detekcija VM-a

- Komanda **`sysctl hw.model`** obično vraća identifikator modela Mac računara na fizičkom hardveru, a u VM-u može vratiti drugačiju vrednost.<sup>[[3]](#references)</sup>
- Menjanjem vrednosti **`hw.logicalcpu`** i **`hw.physicalcpu`**, neki malware pokušava da otkrije da li se izvršava u VM-u.<sup>[[4]](#references)</sup>
- Loader može i da proveri `kern.hv_vmm_present` i `machdep.cpu.brand_string` pomoću `sysctl`-a kako bi utvrdio da li je u pitanju VM pre nego što raspakuje sledeću fazu. Ove provere dopunjuju, ali ne zamenjuju, proveru prikačenog debagera opisanu u nastavku.<sup>[[20]](#references)</sup>
- Neki malware može da **otkrije** da li je mašina zasnovana na **VMware-u** na osnovu MAC adrese (00:50:56).
- Moguće je i jednostavnom linijom koda proveriti **da li se proces debaguje**:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Može se pozvati i sistemski poziv `ptrace` sa zastavicom `PT_DENY_ATTACH`. Time se sprečava kačenje debagera i praćenje procesa. Pogledajte odeljak [PT_DENY_ATTACH](#page-title) za ponašanje XNU-a koje zavisi od redosleda, beleženje događaja u `debugserver`-u i postupak za patchovanje ARM64 koda.<sup>[[7]](#references)[[12]](#references)</sup>
- Može se pozvati i sistemski poziv **`ptrace`** sa zastavicom **`PT_DENY_ATTACH`**. Pogledajte odeljak [PT_DENY_ATTACH](#page-title) za ponašanje XNU-a koje zavisi od redosleda, beleženje događaja u `debugserver`-u i postupak za patchovanje ARM64 koda.<sup>[[7]](#references)[[12]](#references)</sup>
  - Možete proveriti da li su funkcije **`sysctl`** ili **`ptrace`** **uvezene** (ali malware ih može uvesti i dinamički).
  - Kao što je navedeno u ovom tekstu, „[Pobijanje tehnika protiv debagovanja: varijante macOS ptrace-a](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    „_Poruka Process # exited with **status = 45 (0x0000002d)** obično je jasan znak da cilj debagovanja koristi **PT_DENY_ATTACH**_”

#### Predaja procesa pomoću `fork()`

Proces može da izbegne debager koji je i dalje zakačen za originalni PID tako što će pozvati `fork()` ubrzo nakon pokretanja, prekinuti roditeljski proces (`fork()` vraća pozitivan PID deteta) i nastaviti zaštićenu logiku samo u detetu (`fork()` vraća `0`). Rezolucija funkcije `fork` pomoću `dlsym(RTLD_DEFAULT, "fork")` uklanja i direktno mesto poziva `_fork`, ali to predstavlja samo prepreku za analizu: string sa nazivom simbola i tok podataka za dinamičku rezoluciju i dalje su vidljivi u Mach-O binarnoj datoteci.<sup>[[13]](#references)[[14]](#references)</sup>

Na arm64, ovaj obrazac otkrijte praćenjem toka podataka, a ne fiksnih adresa: prva dva argumenta funkcije `dlsym` prosleđuju se kroz `x0` i `x1`, `RTLD_DEFAULT` se može pojaviti kao `-2` (na primer, `movn x0, #1`), a par instrukcija `adrp`/`add` često konstruiše adresu stringa `"fork"`. Nakon instrukcije `bl` ka stubu `dlsym`, pratite vraćeni pokazivač iz `x0` kroz proveru da li je nula i njegovo smeštanje, sve do kasnijeg indirektnog poziva `blr`. Zatim pratite rezultat `fork()` u `w0`: nula vodi do nastavka u detetu, dok pozitivna vrednost i `-1` vode do putanje roditeljskog procesa odnosno greške.<sup>[[13]](#references)[[14]](#references)</sup>

Jedan statički način zaobilaženja je da se potisne indirektni poziv i postojeća provera rezultata usmeri na putanju deteta. Na primer, ako je kompajler generisao sekvencu prikazanu u nastavku, patchujte `blr` i upis rezultata instrukcijom `nop`, postavite sintetički rezultat na nulu i sačuvajte logiku poređenja i grananja. Aplikacija će zatim nastaviti da se izvršava pod originalnim PID-om, bez kreiranja deteta; registre instrukcija i ciljeve grananja treba prilagoditi analiziranoj verziji programa.<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Core Dumps

Core dump fajlovi se kreiraju ako:

- je `kern.coredump` sysctl podešen na 1 (što je podrazumevano)
- proces nije bio suid/sgid ili je `kern.sugid_coredump` podešen na 1 (podrazumevano je 0)
- ograničenje `AS_CORE` dozvoljava ovu operaciju. Kreiranje core dump fajlova može da se onemogući pozivom `ulimit -c 0` i ponovo omogući pomoću `ulimit -c unlimited`.

U tim slučajevima, core dump fajlovi se generišu u skladu sa podešavanjem `kern.corefile` sysctl-a i obično se čuvaju u `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizira procese koji se ruše i čuva izveštaj o rušenju na disku**. Izveštaj o rušenju sadrži informacije koje mogu da **pomognu programeru da utvrdi** uzrok rušenja.\
Za aplikacije i druge procese **koji se izvršavaju u launchd kontekstu konkretnog korisnika**, ReportCrash se izvršava kao LaunchAgent i čuva izveštaje o rušenju u korisnikovom `~/Library/Logs/DiagnosticReports/`\
Za daemon-e, druge procese **koji se izvršavaju u sistemskom launchd kontekstu** i druge privilegovane procese, ReportCrash se izvršava kao LaunchDaemon i čuva izveštaje o rušenju u sistemskom `/Library/Logs/DiagnosticReports`

Ako vas brine da se izveštaji o rušenju **šalju kompaniji Apple**, možete da ih onemogućite. U suprotnom, izveštaji o rušenju mogu da budu korisni za **utvrđivanje načina na koji se server srušio**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Sprečavanje uspavljivanja

Tokom fuzzing-a na macOS-u sprečite Mac da pređe u stanje spavanja:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Prekid SSH veze

Ako fuzzing obavljate preko SSH veze, važno je da sprečite prekid sesije. Zato izmenite datoteku sshd_config:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Interni rukovaoci

**Pogledajte sledeću stranicu** da biste saznali kako da pronađete koja je aplikacija odgovorna za **rukovanje navedenom šemom ili protokolom:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Nabrajanje mrežnih procesa

Ovo je korisno za pronalaženje procesa koji upravljaju mrežnim podacima:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Ili upotrebite `netstat` ili `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Stateful fuzzing Mach IPC-a

Mach servisi koje izlažu privilegovani daemoni korisni su ciljevi za fuzzing kada neprivilegovani ili sandboxovani klijent može da dobije pravo slanja. Počnite od unosa `MachServices` za daemon u launchd-u i upotrebite [MIG workflow za analizu](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) da biste povezali ID-jeve poruka sa handlerima. Pre menjanja bajtova, postavite breakpoint na MIG serversku rutinu dok običan klijent koristi servis i sačuvajte validne poruke zahteva kao početne ulaze. Očuvajte obavezna polja zaglavlja, veličine poruka i raspored deskriptora kako bi mutacije stigle do handlera, umesto da odmah budu odbijene tokom dispatch-a.<sup>[[17]](#references)</sup>

Mnogi handleri zavise od prethodnih poziva. Neka harness inicijalizuje stanje servisa, a zatim neka svaki fuzz ulaz obrađuje kao niz **operacija i argumenata**: šaljite pripremne zahteve (kao što su open ili create), sačuvajte vraćene identifikatore i koristite ih u narednim zahtevima. Tako feedback o pokrivenosti može da istražuje promene stanja, umesto da stalno nailazi na proveru neinicijalizovanog objekta.<sup>[[17]](#references)</sup>

Za closed-source cilj, in-process harness koji poziva MIG dispatch rutinu može se instrumentirati pomoću Jackalope/TinyInst. [CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) je konkretna implementacija, a ne gotov harness za druge servise.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**Validirajte svaki crash preko stvarnog IPC puta.** Harness koji direktno poziva dispatch preskače validaciju Mach poruka u kernelu i može dati lažno pozitivne rezultate, naročito kada prosleđuje nevalidnu out-of-line (OOL) memoriju ili deskriptore portova. U harness-u alocirajte validnu OOL memoriju, a zatim ponovo reprodukujte redukovani testcase preko `mach_msg` iz klijenta sa originalnim pristupom servisu i proverite da li se daemon i dalje ruši.<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Radi za CLI alate

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

„**Jednostavno radi**“ sa mnogim macOS GUI alatima. Neke aplikacije imaju dodatne zahteve, kao što su jedinstvena imena datoteka, određena ekstenzija ili čitanje datoteka iz sandbox kontejnera (`~/Library/Containers/com.apple.Safari/Data`).

Neki primeri:

```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```

### Više informacija o macOS fuzzingu

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [Odgovor na incidente u OS X-u: skriptovanje i analiza](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Leto fuzzinga: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Umetnost Mac malware-a, tom I: analiza](https://taomm.org/)
- [4] [No Starch Press - Umetnost Mac malware-a: vodič za analizu zlonamernog softvera](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - informacije sačuvane u ovim sekcijama u ovom blog postu](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Otklanjanje grešaka u Apple binarnim datotekama koje koriste Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Zaobilaženje tehnika protiv otklanjanja grešaka: macOS ptrace varijante](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Strukturirani Xcode logovi i `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Prikazivanje privatnih podataka u macOS unified log-u](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Apple XNU `ptrace.h` definicije zahteva](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Apple XNU implementacija `ptrace` u `mach_process.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - Internals ptrace-a: kako sprečava povezivanje debaggera](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - primeri fork-a](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - Tehnika protiv otklanjanja grešaka pomoću dlsym i fork-a](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - Entitlement za alat za otklanjanje grešaka](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - Otklanjanje grešaka u ojačanoj aplikaciji treće strane](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - Probijanje zvučne barijere, I deo: Fuzzing CoreAudio-a pomoću Mach poruka](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Jackalope fuzzer](https://github.com/googleprojectzero/Jackalope)
- [20] [Kaspersky Securelist - Nova verzija MacSync macOS kradljivca cilja entuzijaste kriptovaluta i programere](https://securelist.com/macsync-new-version/121383/)
{{#include ../../../banners/hacktricks-training.md}}
