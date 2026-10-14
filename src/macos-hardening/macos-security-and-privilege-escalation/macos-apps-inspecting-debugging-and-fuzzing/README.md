# macOS aplikacije - pregledanje, debagovanje i Fuzzing

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
> Imajte na umu da **`disarm`** može da radi i sa kompresovanim IM4P datotekama (kao što je `kernelcache`) i da izdvoji samo potrebne delove ili čak analizira potreban deo bez njegovog izdvajanja.

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) je alat koristan za pregled **.pkg** datoteka (instalacionih programa) i proveru njihovog sadržaja pre instalacije.\
Ovi instalacioni programi sadrže bash skripte `preinstall` i `postinstall` koje autori malware-a obično zloupotrebljavaju da bi obezbedili **persistenciju** **malware-a**.

### hdiutil

Ovaj alat **mounts** Apple disk image (`.dmg`) datoteke kako bi se mogle pregledati pre pokretanja bilo čega:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Biće montiran u `/Volumes`

### Upakovani binarni fajlovi

- Proverite da li je entropija visoka
- Proverite strings (ako gotovo da nema razumljivih stringova, fajl je upakovan)
- UPX packer za macOS generiše sekciju pod nazivom `__XHDR`.

## Statička Objective-C analiza

### Metapodaci

> [!CAUTION]
> Imajte na umu da programi napisani u Objective-C **zadržavaju** svoje deklaracije klasa **kada se** **kompajliraju** u [Mach-O binarne fajlove](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Takve deklaracije klasa **uključuju** nazive i tipove sledećih elemenata:

- Definisani interfejsi
- Metode interfejsa
- Promenljive instanci interfejsa
- Definisani protokoli

Imajte na umu da ovi nazivi mogu biti obfuskirani kako bi se otežala analiza binarnog fajla.

### Pozivanje funkcija

Kada se pozove funkcija u binarnom fajlu koji koristi Objective-C, kompajlirani kod umesto direktnog poziva te funkcije poziva **`objc_msgSend`**. Ona zatim poziva konačnu funkciju:

![Metapodaci - Pozivanje funkcija: Kada se pozove funkcija u binarnom fajlu koji koristi Objective-C, kompajlirani kod umesto direktnog poziva te funkcije poziva objc msgSend. Ona zatim poziva...](<../../../images/image (305).png>)

Ova funkcija očekuje sledeće parametre:

- Prvi parametar (**self**) je „pokazivač koji pokazuje na **instancu klase koja treba da primi poruku**“. Jednostavnije rečeno, to je objekat nad kojim se poziva metoda. Ako je metoda klasna metoda, ovaj parametar će biti instanca objekta klase (kao celine), dok će kod metode instance `self` pokazivati na instancu klase kao objekat.
- Drugi parametar (**op**) je „selektor metode koja obrađuje poruku“. Jednostavnije rečeno, to je samo **naziv metode**.
- Preostali parametri su sve **vrednosti koje metoda zahteva** (op).

Pogledajte kako možete lako da **dobijete ove informacije pomoću `lldb` u ARM64** na ovoj stranici:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Registar**                                                    | **(za) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1. argument**   | **rdi**                                                         | **self: objekat nad kojim se poziva metoda** |
| **2. argument**   | **rsi**                                                         | **op: naziv metode**                             |
| **3. argument**   | **rdx**                                                         | **1. argument metode**                         |
| **4. argument**   | **rcx**                                                         | **2. argument metode**                         |
| **5. argument**   | **r8**                                                          | **3. argument metode**                         |
| **6. argument**   | **r9**                                                          | **4. argument metode**                         |
| **7. i naredni argumenti** | <p><strong>rsp+</strong><br><strong>(na steku)</strong></p> | **5. i naredni argumenti metode**                        |

### Izbacivanje Objective-C metapodataka

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) je alat za class-dump Objective-C binarnih fajlova. Na GitHub-u se navodi da radi sa dylib fajlovima, ali radi i sa izvršnim fajlovima.

```bash
./dynadump dump /path/to/bin
```

U trenutku pisanja, **ovo je trenutno alat koji najbolje funkcioniše**.

#### Uobičajeni alati

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) je originalni alat za generisanje deklaracija klasa, kategorija i protokola u formatiranom Objective-C kodu.

Star je i više se ne održava, pa verovatno neće raditi ispravno.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) je moderan, međuplatformski alat za ispis Objective-C klasa. U poređenju sa postojećim alatima, iCDump može da radi nezavisno od Apple ekosistema i pruža Python bindinge.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Statička Swift analiza

Kod Swift binarnih datoteka, zbog kompatibilnosti sa Objective-C-jem, ponekad možete izdvojiti deklaracije pomoću [class-dump](https://github.com/nygard/class-dump/), ali ne uvek.

Pomoću komandnih linija **`jtool -l`** ili **`otool -l`** možete pronaći nekoliko sekcija koje počinju prefiksom **`__swift5`**:

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

Dodatne informacije možete pronaći u ovom [**blog postu o informacijama koje se čuvaju u ovim sekcijama**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Pored toga, **Swift binarni fajlovi mogu da sadrže simbole** (na primer, biblioteke moraju da čuvaju simbole kako bi njihove funkcije mogle da se pozivaju). **Simboli obično sadrže informacije o nazivu funkcije** i atributima, ali u nečitljivom obliku, pa su veoma korisni; postoje i **„demanglers“** koji mogu da vrate originalni naziv:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Dinamička analiza

> [!WARNING]
> **Nemojte podrazumevano isključivati SIP kao korak pri otklanjanju grešaka.** Development build-ovi sa `com.apple.security.get-task-allow` mogu da se debaguju dok je SIP omogućen. Proverite cilj pomoću `codesign -d --entitlements :- /path/to/binary` pre nego što pokušate da koristite LLDB. Samo debugger entitlement ne omogućava pristup ciljevima zaštićenim SIP-om.<sup>[[15]](#references)</sup>
>
> Distribuirana aplikacija sa hardened runtime-om obično izostavlja `get-task-allow` i blokira povezivanje. Ako je moguće, koristite debug build koji je obezbedio developer; ponovno potpisivanje kopije za jednokratnu upotrebu može da promeni ponašanje koje testirate. Ako zaštićeni cilj zahteva isključivanje SIP-a, koristite namenski test računar ili VM, a ne računar na koji se oslanjate.<sup>[[16]](#references)</sup>

> [!WARNING]
> Imajte na umu da za **instrumentaciju sistemskih binarnih fajlova** (kao što je `cloudconfigurationd`) na macOS-u **SIP mora biti isključen** (samo uklanjanje potpisa neće biti dovoljno).

### APIs

macOS izlaže neke zanimljive API-je koji pružaju informacije o procesima:

- `proc_info`: Ovo je glavni API koji pruža mnogo informacija o svakom procesu. Da biste dobili informacije o drugim procesima, morate biti root, ali vam nisu potrebni posebni entitlements ni Mach portovi.
- `libsysmon.dylib`: Izlaže informacije o procesima putem XPC funkcija, ali pozivaocima je potreban entitlement `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** je tehnika koja se koristi za beleženje stanja procesa, uključujući call stack-ove svih aktivnih niti. Posebno je korisna za otklanjanje grešaka, analizu performansi i razumevanje ponašanja sistema u određenom trenutku. Na iOS-u i macOS-u, stackshotting se može obaviti pomoću nekoliko alata i metoda, kao što su alati **`sample`** i **`spindump`**.

### Sysdiagnose

Ovaj alat (`/usr/bini/ysdiagnose`) u suštini prikuplja mnogo informacija sa računara izvršavanjem desetina različitih komandi, kao što su `ps`, `zprint`...

Mora se pokrenuti kao **root**, a daemon `/usr/libexec/sysdiagnosed` ima veoma zanimljive entitlements, kao što su `com.apple.system-task-ports` i `get-task-allow`.

Njegov plist se nalazi na putanji `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` i definiše tri MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Briše stare arhive iz /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Specijalni port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Korisnički interfejs preko Obj-C klase `Libsysdiagnose`. Mogu se proslediti tri argumenta u dict-u (`compress`, `display`, `run`)

### Unified Logs

macOS generiše opsežne logove koji su korisni pri analizi ponašanja aplikacije.

Neka polja u logovima sadrže oznaku `<private>` kako bi sakrila informacije koje mogu da identifikuju korisnika ili uređaj. Starija uputstva ponekad opisuju instaliranje sertifikata radi prikazivanja ovih polja; aktuelna uputstva za otklanjanje grešaka umesto toga koriste konfiguracioni profil sa izričito ograničenim opsegom i opcijom `Enable-Private-Data`, ili `OSLogPreferences` za pojedinačne aplikacije. Ponašanje može da se razlikuje u zavisnosti od podsistema i izdanja macOS-a. Starija diskusija o sertifikatu/profilu sačuvana je u referencama. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Levi panel

U levom panelu Hopper-a mogu se videti simboli (**Labels**) binarnog fajla, lista procedura i funkcija (**Proc**) i stringovi (**Str**). To nisu svi stringovi, već oni definisani u nekoliko delova Mac-O fajla (kao što su _cstring ili_ `objc_methname`).

#### Srednji panel

U srednjem panelu možete videti **disasemblirani kod**. Možete ga prikazati kao **raw** disassembly, kao **graph**, kao **decompiled** prikaz ili kao **binary**, klikom na odgovarajuću ikonu:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Klikom desnim tasterom na objekat koda možete videti **reference ka tom objektu i iz njega**, pa čak i promeniti njegov naziv (ovo ne radi u decompiled pseudokodu):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Pored toga, u **donjem delu srednjeg panela možete unositi Python komande**.

#### Desni panel

U desnom panelu možete videti korisne informacije kao što su **istorija navigacije** (da biste znali kako ste došli do trenutnog prikaza), **call graph**, u kojem možete videti sve **funkcije koje pozivaju ovu funkciju** i sve funkcije **koje ova funkcija poziva**, kao i informacije o **lokalnim promenljivama**.

### dtrace

Omogućava korisnicima pristup aplikacijama na izuzetno **niskom nivou** i pruža način da **prate** **programe** i čak menjaju tok njihovog izvršavanja. DTrace koristi **probe** koje su **postavljene kroz kernel**, na lokacijama kao što su početak i kraj sistemskih poziva.

DTrace koristi funkciju **`dtrace_probe_create`** da kreira probe za svaki sistemski poziv. Ove probe mogu da se aktiviraju na **ulaznoj i izlaznoj tački svakog sistemskog poziva**. Interakcija sa DTrace-om odvija se preko /dev/dtrace, koji je dostupan samo root korisniku.<sup>[[1]](#references)</sup>

> [!TIP]
> Da biste omogućili Dtrace bez potpunog isključivanja SIP zaštite, u recovery režimu možete izvršiti: `csrutil enable --without dtrace`
>
> Možete koristiti **`dtrace`** ili **`dtruss`** binarne fajlove koje ste **sami kompajlirali**.

Dostupne probe za dtrace možete dobiti pomoću:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Naziv probe sastoji se od četiri dela: provajdera, modula, funkcije i naziva (`fbt:mach_kernel:ptrace:entry`). Ako ne navedete neki deo naziva, DTrace će ga tretirati kao džoker.

Da bismo podesili DTrace da aktivira probe i odredili koje radnje treba da izvrši kada se one aktiviraju, koristićemo jezik D.

Detaljnije objašnjenje i dodatne primere možete pronaći na [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Primeri

Pokrenite `man -k dtrace` da biste izlistali **dostupne DTrace skripte**. Primer: `sudo dtruss -n binary`

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

To je kernel facility za praćenje. Dokumentovane kodove možete pronaći u **`/usr/share/misc/trace.codes`**.

Alati kao što su `latency`, `sc_usage`, `fs_usage` i `trace` koriste ga interno.

Za povezivanje sa `kdebug` koristi se `sysctl` u prostoru imena `kern.kdebug`, a MIB-ove koje treba koristiti možete pronaći u `sys/sysctl.h`; funkcije su implementirane u `bsd/kern/kdebug.c`.

Za interakciju sa kdebug-om pomoću prilagođenog klijenta obično se slede ovi koraci:

- Uklonite postojeća podešavanja pomoću KERN_KDSETREMOVE
- Podesite trace pomoću KERN_KDSETBUF i KERN_KDSETUP
- Pomoću KERN_KDGETBUF saznajte broj unosa u baferu
- Pomoću KERN_KDPINDEX izdvojite sopstvenog klijenta iz trace-a
- Omogućite praćenje pomoću KERN_KDENABLE
- Pročitajte bafer pozivom KERN_KDREADTR
- Da biste povezali svaku nit sa njenim procesom, pozovite KERN_KDTHRMAP.

Da biste dobili ove informacije, možete koristiti Apple alat **`trace`** ili prilagođeni alat [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Imajte na umu da je Kdebug dostupan samo jednom korisniku u datom trenutku.** Zato istovremeno može da se pokrene samo jedan alat koji koristi k-debug.

### ktrace

API-ji `ktrace_*` dolaze iz `libktrace.dylib`, koja obavija API-je iz `Kdebug`. Klijent može jednostavno da pozove `ktrace_session_create` i `ktrace_events_[single/class]` da bi podesio callback-ove za određene kodove, a zatim da pokrene praćenje pomoću `ktrace_start`.

Ovaj alat možete koristiti i kada je **SIP aktiviran**.

Kao klijent možete koristiti uslužni program `ktrace`:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Ili `tailspin`.

### kperf

Koristi se za profilisanje na nivou kernela i izgrađen je pomoću `Kdebug` callbackova.

Ukratko, proverava se globalna promenljiva `kernel_debug_active`, a ako je postavljena, poziva se `kperf_kdebug_handler` sa `Kdebug` kodom i adresom kernel frame-a koji je poziva. Ako se `Kdebug` kod poklapa sa nekim od izabranih kodova, primenjuju se „actions“ konfigurisane kao bitmapa (pogledajte `osfmk/kperf/action.h` za dostupne opcije).

Kperf ima i sysctl MIB tabelu: (kao root) `sysctl kperf`. Ovaj kod se nalazi u `osfmk/kperf/kperfbsd.c`.

Pored toga, deo funkcionalnosti Kperf-a nalazi se u `kpc`, koji pruža informacije o mašinskim brojačima performansi.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) je veoma koristan alat za proveru radnji povezanih sa procesima koje neki proces obavlja (na primer, za praćenje novih procesa koje pokreće).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) je alat koji prikazuje odnose između procesa.\
Potrebno je da nadgledate svoj Mac komandom kao što je **`sudo eslogger fork exec rename create > cap.json`** (terminal iz kog se ova komanda pokreće mora imati FDA). Zatim možete da učitate JSON datoteku u ovaj alat da biste videli sve odnose:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) nadgleda događaje nad datotekama, kao što su njihovo kreiranje, izmena i brisanje.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) je GUI alat čiji izgled i osećaj korisnicima Windowsa mogu biti poznati iz Microsoft Sysinternal-ovog _Procmon_-a. Ovaj alat omogućava pokretanje i zaustavljanje snimanja različitih tipova događaja, filtriranje tih događaja po kategorijama kao što su datoteke, procesi, mreža itd. i čuvanje snimljenih događaja u JSON formatu.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) je deo Xcode-ovih Developer tools — koristi se za nadgledanje performansi aplikacija, prepoznavanje curenja memorije i praćenje aktivnosti filesystem-a.

![Crescendo - Apple Instruments: Apple Instruments je deo Xcode-ovih Developer tools — koristi se za nadgledanje performansi aplikacija, prepoznavanje curenja memorije i praćenje aktivnosti filesystem-a](<../../../images/image (1138).png>)

### fs_usage

Omogućava praćenje radnji koje obavljaju procesi:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) je koristan za pregled **biblioteka** koje koristi binarni fajl, **fajlova** koje koristi i **mrežnih** veza.\
Takođe proverava procese binarnih fajlova pomoću **virustotal** i prikazuje informacije o binarnom fajlu.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

U [**ovom blog postu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) možete pronaći primer kako da **debugujete pokrenuti daemon** koji je koristio **`PT_DENY_ATTACH`** da spreči debugovanje čak i kada je SIP bio onemogućen.<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` je Darwin-specifičan `ptrace(2)` zahtev sa vrednošću **31** (`0x1f`); ostali argumenti se ignorišu. Proces ga može pozvati direktno, bez fork-a, kako bi odbio kasnije praćenje od strane roditeljskog procesa.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### XNU stanje i redosled poziva

Rezultat zavisi od toga koji `ptrace` zahtev prvi stigne do XNU:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB se prvi poveže:** `debugserver` koristi `PT_ATTACHEXC`; XNU ga pretvara u `PT_ATTACH`, obavlja autorizaciju `KAUTH_PROCESS_CANTRACE` i postavlja `P_LTRACED` na ciljnom procesu. Naknadni `PT_DENY_ATTACH` nailazi na tu zastavicu i prekida ciljni proces pomoću `W_EXITCODE(ENOTSUP, 0)`, što LLDB obično prikazuje kao status **45** (`0x2d`).
- **Ciljni proces prvi zabrani povezivanje:** XNU postavlja `P_LNOATTACH`. Kasniji pokušaj povezivanja odbija se tokom autorizacije praćenja procesa; putanja greške pri povezivanju proverava `P_LNOATTACH` i šalje `SIGSEGV` procesu koji pokušava da se poveže, što u LLDB može izgledati kao izgubljena veza sa `debugserver`.

Da biste razlikovali ove putanje, omogućite `debugserver` logovanje pre pokretanja ili povezivanja i pregledajte njegove `ptrace` zahteve:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### ARM64 statička identifikacija i zaobilaženje

Za neobfusciran ARM64 Mach-O, pronađite uvezeni `_ptrace` stub i pregledajte mesta poziva. Prvi celobrojni argument prosleđuje se u `w0`, tako da ovaj niz direktno otkriva anti-debug zahtev. Odsustvo uvoza nije konačan dokaz, jer kod može dinamički da razreši `ptrace`. Uvezeni `_sysctl` takođe može da ukazuje na anti-debug provere, mada i on može biti dinamički razrešen.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

U prikazanom primeru, izmena immediate vrednosti sa `0x1f` na `0x0` menja zahtev u `PT_TRACE_ME` i omogućava programu da nastavi rad pod LLDB-om. Ovo je **bypass specifičan za dati primer**, a ne opšti no-op: pre nego što odlučite da li ćete promeniti zahtev, preskočiti poziv ili nametnuti uspešan povratni rezultat, proverite provere povratne vrednosti i kontrolni tok pozivaoca.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** je de **facto alat** za **macOS** binarni **debugging**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Možete podesiti Intel format prilikom korišćenja lldb-a tako što ćete u svom početnom direktorijumu napraviti datoteku **`.lldbinit`** sa sledećim redom:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Unutar lldb, izbacite proces u datoteku pomoću komande `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>Opis</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Pokrenite izvršavanje; nastaviće se dok se ne pogodi breakpoint ili proces ne završi.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Pokrenite izvršavanje i zaustavite ga na ulaznoj tački.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Nastavite izvršavanje procesa koji se debaguje.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Izvršite sledeću instrukciju. Ova komanda preskače pozive funkcija.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Izvršite sledeću instrukciju. Za razliku od komande <code>nexti</code>, ova komanda ulazi u pozive funkcija.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Izvršite preostale instrukcije u trenutnoj funkciji (frejmu), vratite se i zaustavite izvršavanje.</td></tr>
<tr><td><strong>control + c</strong></td><td>Pauzirajte izvršavanje. Ako je proces pokrenut (<code>r</code>) ili je izvršavanje nastavljeno (<code>c</code>), proces će se zaustaviti na mestu na kom se trenutno izvršava.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Bilo koja funkcija koja se zove main</p>
<p><code>b &lt;binname&gt;`main</code> # Glavna funkcija binarne datoteke</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Glavna funkcija navedene binarne datoteke</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Bilo koja metoda NSFileManager</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Zaustavite se u svim funkcijama te biblioteke</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Lista breakpointa</p>
<p><code>br e/dis &lt;num&gt;</code> # Omogućite/onemogućite breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Prikažite pomoć za komandu breakpoint</p>
<p><code>help memory write</code> # Prikažite pomoć za upisivanje u memoriju</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Prikažite memoriju kao string završen null znakom.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Prikažite memoriju kao instrukciju asemblerskog jezika.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Prikažite memoriju kao bajt.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Ova komanda ispisuje objekat na koji pokazuje parametar.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Upišite AAAA na tu adresu<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Upišite AAAA na tu adresu
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Disasemblirajte trenutnu funkciju</p>
<p><code>dis -n &lt;funcname&gt;</code> # Disasemblirajte funkciju</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Disasemblirajte funkciju<br>
<code>dis -c 6</code> # Disasemblirajte šest linija<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Disasemblirajte od jedne adrese do druge<br>
<code>dis -p -c 4</code> # Počnite disasembliranje na trenutnoj adresi</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Pregledajte niz od tri elementa u registru <code>x1</code></td></tr>
<tr><td><strong>image dump sections</strong></td><td>Ispišite mapu memorije trenutnog procesa.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Prikažite adresu svakog simbola iz CoreNLP</td></tr>
</tbody>
</table>

Većina Apple Objective-C API-ja ili metoda vraća objekte, pa ih treba prikazati komandom „print object” (<code>po</code>). Ako <code>po</code> ne daje smislen izlaz, upotrebite <code>x/b</code>.

> [!TIP]
> Prilikom poziva funkcije **`objc_sendMsg`**, registar **rsi** sadrži **ime metode** kao string završen null znakom („C” string). Da biste ispisali ime pomoću lldb, uradite sledeće:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-dinamička analiza

#### Detekcija VM-a

- Komanda **`sysctl hw.model`** obično vraća identifikator Mac modela na fizičkom hardveru, a u VM-u može vratiti drugu vrednost.<sup>[[3]](#references)</sup>
- Menjanjem vrednosti **`hw.logicalcpu`** i **`hw.physicalcpu`**, neki malveri pokušavaju da otkriju da li se izvršavaju u VM-u.<sup>[[4]](#references)</sup>
- Neki malveri mogu i da **otkriju** da je mašina zasnovana na **VMware-u** na osnovu MAC adrese (00:50:56).
- Jednostavnim kodom moguće je utvrditi i **da li se proces debaguje**:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Može se pozvati i sistemski poziv **`ptrace`** sa zastavicom **`PT_DENY_ATTACH`**. Pogledajte odeljak [PT_DENY_ATTACH section](#page-title) za ponašanje XNU-a koje zavisi od redosleda, evidentiranje u `debugserver` i postupak patchovanja za ARM64.<sup>[[7]](#references)[[12]](#references)</sup>

- Može se pozvati i sistemski poziv **`ptrace`** sa zastavicom **`PT_DENY_ATTACH`**. Time se **sprečava** da se deb**u**gger prikači na proces i prati ga.
  - Možete proveriti da li se funkcija **`sysctl`** ili **`ptrace`** **uvozi** (ali malver bi mogao da je uveze dinamički).
  - Kao što je navedeno u ovom tekstu, „[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    „_Poruka Process # exited with **status = 45 (0x0000002d)** obično je jasan znak da cilj debagovanja koristi **PT_DENY_ATTACH**_”

#### Predaja procesa putem `fork()`

Proces može izbeći debugger koji je i dalje prikačen za prvobitni PID tako što će pri pokretanju pozvati `fork()`, prekinuti roditeljski proces (`fork()` vraća pozitivan PID deteta) i nastaviti zaštićenu logiku samo u detetu (`fork()` vraća `0`). Razrešavanje funkcije `fork` pomoću `dlsym(RTLD_DEFAULT, "fork")` uklanja i direktno pozivno mesto `_fork`, ali to je samo prepreka analizi: string sa imenom simbola i tok podataka za dinamičko razrešavanje i dalje su vidljivi u Mach-O binarnoj datoteci.<sup>[[13]](#references)[[14]](#references)</sup>

Na arm64, ovaj obrazac otkrijte praćenjem toka podataka, a ne fiksnih adresa: prva dva argumenta funkcije `dlsym` prosleđuju se u `x0` i `x1`, `RTLD_DEFAULT` se može pojaviti kao `-2` (na primer, `movn x0, #1`), a par `adrp`/`add` obično konstruiše adresu stringa `"fork"`. Nakon `bl` poziva ka stubu `dlsym`, pratite pokazivač koji je vraćen u `x0` kroz proveru da li je null i njegovo čuvanje, sve do kasnijeg indirektnog poziva `blr`. Zatim pratite rezultat funkcije `fork()` u `w0`: nula vodi ka nastavku deteta, dok pozitivne vrednosti i `-1` vode ka putanji roditelja ili greške.<sup>[[13]](#references)[[14]](#references)</sup>

Jedan statički način zaobilaženja jeste da potisnete indirektni poziv i naterate postojeću proveru rezultata da izabere putanju deteta. Na primer, ako je kompajler generisao niz prikazan ispod, patchujte `blr` i upisivanje rezultata instrukcijom `nop`, postavite sintetički rezultat na nulu i zadržite logiku poređenja i grananja. Aplikacija će zatim nastaviti pod prvobitnim PID-om, bez kreiranja deteta; registre instrukcija i odredišta grananja treba prilagoditi analiziranoj verziji.<sup>[[13]](#references)[[14]](#references)</sup>

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

Core dumps se kreiraju ako:

- je `kern.coredump` sysctl postavljen na 1 (podrazumevano)
- proces nije bio suid/sgid ili je `kern.sugid_coredump` postavljen na 1 (podrazumevano je 0)
- ograničenje `AS_CORE` dozvoljava ovu operaciju. Kreiranje core dump-ova može da se spreči pozivanjem komande `ulimit -c 0` i ponovo omogući komandom `ulimit -c unlimited`.

U tim slučajevima, core dump-ovi se generišu u skladu sa sysctl-om `kern.corefile` i obično se čuvaju u `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizira procese koji se ruše i čuva izveštaj o padu na disku**. Izveštaj o padu sadrži informacije koje mogu **pomoći programeru da utvrdi uzrok pada**.\
Za aplikacije i druge procese **koji rade u launchd kontekstu pojedinačnog korisnika**, ReportCrash radi kao LaunchAgent i čuva izveštaje o padu u direktorijumu `~/Library/Logs/DiagnosticReports/` tog korisnika.\
Za demone, druge procese **koji rade u sistemskom launchd kontekstu** i druge privilegovane procese, ReportCrash radi kao LaunchDaemon i čuva izveštaje o padu u sistemskom direktorijumu `/Library/Logs/DiagnosticReports`.

Ako ste zabrinuti da se izveštaji o padu **šalju kompaniji Apple**, možete da ih onemogućite. U suprotnom, izveštaji o padu mogu biti korisni za **utvrđivanje uzroka pada servera**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Spavanje

Tokom fuzzing-a na macOS-u sprečite Mac da pređe u stanje mirovanja:

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

**Pogledajte sledeću stranicu** da biste saznali kako da utvrdite koja je aplikacija zadužena za **rukovanje navedenom šemom ili protokolom:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerisanje mrežnih procesa

Ovo je korisno za pronalaženje procesa koji obrađuju mrežne podatke:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Ili koristite `netstat` ili `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Fuzzing Mach IPC-a sa očuvanjem stanja

Mach servisi koje izlažu privilegovani demoni korisne su mete za fuzzing ako neprivilegovani ili sandboxovani klijent može da dobije send pravo. Počnite od unosa `MachServices` u launchd konfiguraciji demona i koristite [MIG workflow za analizu](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) da biste povezali ID-jeve poruka sa handlerima. Pre nego što menjate bajtove, postavite breakpoint na MIG server rutinu dok običan klijent koristi servis i sačuvajte validne poruke zahteva kao početne ulaze. Sačuvajte obavezna polja zaglavlja, veličine poruka i raspored deskriptora kako bi mutacije stigle do handlera umesto da odmah padnu pri obradi zahteva.<sup>[[17]](#references)</sup>

Mnogi handleri zavise od prethodnih poziva. Neka harness inicijalizuje stanje servisa, a zatim obradite svaki fuzz ulaz kao niz **operacija i argumenata**: pošaljite zahteve za podešavanje (kao što su open ili create), sačuvajte vraćene identifikatore i upotrebite ih u narednim zahtevima. Tako povratne informacije o pokrivenosti mogu da istražuju promene stanja umesto da stalno nailaze na proveru neinicijalizovanog objekta.<sup>[[17]](#references)</sup>

Za cilj zatvorenog koda, harness u istom procesu koji poziva MIG dispatch rutinu može da se instrumentira pomoću Jackalope/TinyInst. [CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) konkretna je implementacija, a ne gotov harness za druge servise.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**Svaki crash proverite kroz stvarni IPC put.** Harness koji direktno poziva dispatch rutinu preskače validaciju Mach poruka u kernelu i može da proizvede lažno pozitivne rezultate, naročito kada prosledi nevalidnu out-of-line (OOL) memoriju ili deskriptore portova. U harness-u alocirajte validnu pozadinsku OOL memoriju, a zatim ponovo reprodukujte redukovani testcase preko `mach_msg` iz klijenta sa originalnim pristupom servisu i proverite da li se demon i dalje ruši.<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Radi sa CLI alatima

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

„**Jednostavno radi**“ sa mnogim macOS GUI alatima. Neke aplikacije imaju dodatne zahteve, kao što su jedinstveni nazivi datoteka, određena ekstenzija ili čitanje datoteka iz sandbox kontejnera (`~/Library/Containers/com.apple.Safari/Data`).

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

### Više informacija o fuzzingu za macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)



## References

- [1] [Reagovanje na incidente u OS X-u: skriptovanje i analiza](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Leto fuzzinga: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Umetnost Mac malware-a, prvi tom: analiza](https://taomm.org/)
- [4] [No Starch Press - Umetnost Mac malware-a: vodič za analizu zlonamernog softvera](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - informacije sačuvane u ovim odeljcima u ovom blog postu](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - otklanjanje grešaka u Apple binarnim datotekama koje koriste Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - zaobilaženje tehnika za sprečavanje otklanjanja grešaka: macOS ptrace varijante](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - strukturisani Xcode logovi i `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - prikazivanje privatnih podataka u objedinjenom macOS logu](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Apple XNU `ptrace.h` definicije zahteva](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Apple XNU implementacija `ptrace` u `mach_process.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - interni detalji ptrace-a: kako sprečava povezivanje debugger-a](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - primeri fork-a](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - tehnika sprečavanja otklanjanja grešaka pomoću dlsym i fork-a](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - pravo za alat za otklanjanje grešaka](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - otklanjanje grešaka u aplikaciji treće strane sa pojačanom zaštitom](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - probijanje zvučne barijere, prvi deo: fuzzing CoreAudio-a pomoću Mach poruka](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Jackalope fuzzer](https://github.com/googleprojectzero/Jackalope)
{{#include ../../../banners/hacktricks-training.md}}
