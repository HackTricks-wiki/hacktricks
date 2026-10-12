# macOS Apps - Ispitivanje, debugging i Fuzzing

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
> Imajte na umu da **`disarm`** može da radi i sa kompresovanim IM4P datotekama (kao što je `kernelcache`) i da izdvoji samo potrebne delove ili čak analizira potrebni deo bez izdvajanja.

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) je alat koristan za pregled **.pkg** datoteka (instalacionih paketa) i proveru njihovog sadržaja pre instaliranja.\
Ovi instalacioni paketi sadrže bash skripte `preinstall` i `postinstall` koje autori malware-a obično zloupotrebljavaju da bi obezbedili **postojanost** **malware-a**.

### hdiutil

Ovaj alat **montira** Apple disk image (`.dmg`) datoteke kako bi mogle da se pregledaju pre pokretanja bilo čega:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Биће монтиран у `/Volumes`

### Паковани бинарни фајлови

- Проверите да ли имају високу ентропију
- Проверите стрингове (ако готово да нема разумљивих стрингова, бинарни фајл је пакован)
- UPX пакер за macOS генерише секцију под називом `__XHDR`.

## Статичка анализа Objective-C-а

### Метаподаци

> [!CAUTION]
> Имајте на уму да програми написани у Objective-C-у **задржавају** своје декларације класа **када се** **компајлирају** у [Mach-O бинарне фајлове](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Такве декларације класа **обухватају** називе и типове следећег:

- Дефинисаних интерфејса
- Метода интерфејса
- Променљивих инстанце интерфејса
- Дефинисаних протокола

Имајте на уму да ови називи могу бити обфусковани како би се отежала реверзна анализа бинарног фајла.

### Позивање функција

Када се у бинарном фајлу који користи Objective-C позове функција, компајлирани код уместо те функције позива **`objc_msgSend`**, која ће позвати коначну функцију:

![Метаподаци - Позивање функција: Када се у бинарном фајлу који користи Objective-C позове функција, компајлирани код уместо те функције позива objc msgSend . Која ће...](<../../../images/image (305).png>)

Ова функција очекује следеће параметре:

- Први параметар (**self**) је „показивач који показује на **инстанцу класе која треба да прими поруку**“. Једноставније речено, то је објекат над којим се позива метода. Ако је метода метода класе, ово ће бити инстанца објекта класе (као целине), док ће код методе инстанце `self` показивати на инстанцирану инстанцу класе као објекат.
- Други параметар (**op**) је „селектор методе која обрађује поруку“. Једноставније речено, то је само **назив методе.**
- Преостали параметри су све **вредности које метода захтева** (op).

Погледајте како да лако **добијете ове информације помоћу `lldb`-а у ARM64** на овој страници:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Аргумент**      | **Регистар**                                                    | **(за) objc_msgSend**                                  |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1. аргумент**   | **rdi**                                                         | **self: објекат над којим се позива метода**           |
| **2. аргумент**   | **rsi**                                                         | **op: назив методе**                                   |
| **3. аргумент**   | **rdx**                                                         | **1. аргумент методе**                                 |
| **4. аргумент**   | **rcx**                                                         | **2. аргумент методе**                                 |
| **5. аргумент**   | **r8**                                                          | **3. аргумент методе**                                 |
| **6. аргумент**   | **r9**                                                          | **4. аргумент методе**                                 |
| **7. и наредни аргументи** | <p><strong>rsp+</strong><br><strong>(на стеку)</strong></p> | **5. и наредни аргументи методе**              |

### Избацивање Objective-C метаподатака

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) је алат за class-dump Objective-C бинарних фајлова. На GitHub-у се наводи да је намењен dylib фајловима, али ради и са извршним фајловима.

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

Star je i više se ne održava, pa verovatno neće ispravno raditi.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) je moderan, multiplatformski alat za dump Objective-C klasa. U poređenju sa postojećim alatima, iCDump može da radi nezavisno od Apple ekosistema i nudi Python bindinge.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Statička Swift analiza

Kod Swift binarnih fajlova, zbog kompatibilnosti sa Objective-C-jem, ponekad možete izdvojiti deklaracije pomoću alata [class-dump](https://github.com/nygard/class-dump/), ali ne uvek.

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

Dodatne informacije o [**informacijama sačuvanim u ovim odeljcima možete pronaći u ovom blog postu**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Štaviše, **Swift binarni fajlovi mogu da sadrže simbole** (na primer, biblioteke moraju da čuvaju simbole kako bi njihove funkcije mogle da se pozivaju). **Simboli obično sadrže informacije o nazivu funkcije** i atributima u teško čitljivom obliku, pa su veoma korisni. Postoje i „**demanglers**“ koji mogu da otkriju originalni naziv:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Dinamička analiza

> [!WARNING]
> Imajte na umu da je za otklanjanje grešaka u binarnim datotekama potrebno onemogućiti **SIP** (`csrutil disable` ili `csrutil enable --without debug`), ili kopirati binarne datoteke u privremenu fasciklu i **ukloniti potpis** pomoću `codesign --remove-signature <binary-path>`, ili dozvoliti otklanjanje grešaka u binarnoj datoteci (možete koristiti [ovu skriptu](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Imajte na umu da za **instrumentaciju sistemskih binarnih datoteka** (kao što je `cloudconfigurationd`) u macOS-u **SIP mora biti onemogućen** (samo uklanjanje potpisa nije dovoljno).

### API-ji

macOS pruža neke zanimljive API-je koji daju informacije o procesima:

- `proc_info`: Glavni API koji pruža mnogo informacija o svakom procesu. Potrebna su root prava za dobijanje informacija o drugim procesima, ali nisu potrebna posebna ovlašćenja ni mach portovi.
- `libsysmon.dylib`: Pruža informacije o procesima preko XPC funkcija, ali pozivaocima je potrebno ovlašćenje `com.apple.sysmond.client`.

### Stackshot i microstackshots

**Stackshotting** je tehnika koja se koristi za snimanje stanja procesa, uključujući stekove poziva svih aktivnih niti. Posebno je korisna za otklanjanje grešaka, analizu performansi i razumevanje ponašanja sistema u određenom trenutku. Na iOS-u i macOS-u stackshotting se može obavljati pomoću različitih alata i metoda, kao što su alati **`sample`** i **`spindump`**.

### Sysdiagnose

Ovaj alat (`/usr/bini/ysdiagnose`) u osnovi prikuplja mnogo informacija sa računara izvršavanjem desetina različitih komandi, kao što su `ps`, `zprint`...

Mora se pokrenuti kao **root**, a daemon `/usr/libexec/sysdiagnosed` ima veoma zanimljiva ovlašćenja, kao što su `com.apple.system-task-ports` i `get-task-allow`.

Njegov plist se nalazi na putanji `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` i deklariše 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Briše stare arhive iz /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Poseban port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Korisnički interfejs preko Obj-C klase `Libsysdiagnose`. Mogu se proslediti tri argumenta u dict-u (`compress`, `display`, `run`)

### Unified Logs

macOS generiše opširne logove koji su korisni pri analizi ponašanja aplikacije.

Neka polja logova sadrže oznaku `<private>` da bi se sakrile informacije koje mogu identifikovati korisnika ili uređaj. Starija uputstva ponekad opisuju instaliranje sertifikata radi otkrivanja tih polja; aktuelna uputstva za otklanjanje grešaka umesto toga koriste konfiguracioni profil sa izričito ograničenim opsegom i opcijom `Enable-Private-Data`, ili `OSLogPreferences` za pojedinačnu aplikaciju. Ponašanje se može razlikovati u zavisnosti od podsistema i izdanja macOS-a. Starija diskusija o sertifikatu/profilu zadržana je u referencama. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Levi panel

U levom panelu Hopper-a moguće je videti simbole (**Labels**) binarne datoteke, listu procedura i funkcija (**Proc**) i stringove (**Str**). To nisu svi stringovi, već oni definisani u različitim delovima Mac-O datoteke (kao što su _cstring ili_ `objc_methname`).

#### Središnji panel

U središnjem panelu možete videti **disasemblirani kod**. Možete ga prikazati kao **raw** disasemblirani kod, kao **graph**, kao **decompiled** ili kao **binary** klikom na odgovarajuću ikonu:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Klikom desnim tasterom miša na objekat koda možete videti **reference ka tom objektu i od njega**, pa čak i promeniti njegov naziv (ovo ne funkcioniše u dekompiliranom pseudokodu):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Osim toga, **u donjem delu središnjeg panela možete pisati python komande**.

#### Desni panel

U desnom panelu možete videti korisne informacije, kao što su **istorija navigacije** (da biste znali kako ste došli do trenutnog mesta), **graf poziva** koji prikazuje sve **funkcije koje pozivaju ovu funkciju** i sve funkcije koje **ova funkcija poziva**, kao i informacije o **lokalnim promenljivama**.

### dtrace

Omogućava korisnicima pristup aplikacijama na izuzetno **niskom nivou** i pruža način za **praćenje** **programa**, pa čak i za promenu toka njihovog izvršavanja. Dtrace koristi **probe** koje su **postavljene širom kernela** na mestima kao što su početak i kraj sistemskih poziva.

DTrace koristi funkciju **`dtrace_probe_create`** za kreiranje probe za svaki sistemski poziv. Te probe mogu se aktivirati na **ulaznoj i izlaznoj tački svakog sistemskog poziva**. Interakcija sa DTrace-om odvija se preko /dev/dtrace, koji je dostupan samo root korisniku.<sup>[[1]](#references)</sup>

> [!TIP]
> Da biste omogućili Dtrace bez potpunog isključivanja SIP zaštite, možete u režimu oporavka izvršiti: `csrutil enable --without dtrace`
>
> Takođe možete koristiti **`dtrace`** ili **`dtruss`** nad binarnim datotekama koje ste **sami kompajlirali**.

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

Naziv probe sastoji se od četiri dela: provajdera, modula, funkcije i naziva (`fbt:mach_kernel:ptrace:entry`). Ako ne navedete neki deo naziva, DTrace će taj deo tretirati kao džoker.

Da bismo podesili DTrace da aktivira probe i odredili koje radnje treba da izvrši kada se one aktiviraju, koristićemo jezik D.

Detaljnije objašnjenje i više primera možete pronaći na adresi [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

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

Za interakciju sa `kdebug`-om koristi se `sysctl` preko prostora imena `kern.kdebug`, a MIB-ove možete pronaći u `sys/sysctl.h`, dok su funkcije implementirane u `bsd/kern/kdebug.c`.

Za interakciju sa kdebug-om pomoću prilagođenog klijenta obično se koriste sledeći koraci:

- Uklonite postojeća podešavanja pomoću KERN_KDSETREMOVE
- Podesite praćenje pomoću KERN_KDSETBUF i KERN_KDSETUP
- Koristite KERN_KDGETBUF da biste dobili broj unosa u baferu
- Izdvojite sopstveni klijent iz praćenja pomoću KERN_KDPINDEX
- Omogućite praćenje pomoću KERN_KDENABLE
- Pročitajte bafer pozivanjem KERN_KDREADTR
- Da biste uparili svaku nit sa njenim procesom, pozovite KERN_KDTHRMAP.

Za pribavljanje ovih informacija možete koristiti Apple alat **`trace`** ili prilagođeni alat [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Imajte na umu da je Kdebug dostupan samo jednom korisniku istovremeno.** Dakle, istovremeno može da se pokrene samo jedan alat koji koristi k-debug.

### ktrace

API-ji `ktrace_*` potiču iz `libktrace.dylib`, koja obavija API-je iz `Kdebug`-a. Zatim klijent može samo da pozove `ktrace_session_create` i `ktrace_events_[single/class]` da bi postavio callback-ove za određene kodove, a potom da pokrene praćenje pomoću `ktrace_start`.

Ovo možete da koristite i kada je **SIP aktiviran**.

Kao klijent možete da koristite uslužni program `ktrace`:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Ili `tailspin`.

### kperf

Ovo se koristi za profilisanje na nivou kernela i izgrađeno je pomoću `Kdebug` poziva.

Ukratko, proverava se globalna promenljiva `kernel_debug_active`; ako je postavljena, poziva se `kperf_kdebug_handler` sa `Kdebug` kodom i adresom kernel frame-a koji poziva. Ako se `Kdebug` kod poklapa sa jednim od izabranih kodova, primenjuju se konfigurisane „actions“ predstavljene bitmapom (pogledajte `osfmk/kperf/action.h` za dostupne opcije).

Kperf ima i sysctl MIB tabelu: (kao root) `sysctl kperf`. Ovaj kod se nalazi u `osfmk/kperf/kperfbsd.c`.

Pored toga, deo Kperf funkcionalnosti nalazi se u `kpc`, koji pruža informacije o mašinskim brojačima performansi.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) je veoma koristan alat za proveru radnji povezanih sa procesima koje neki proces obavlja (na primer, za praćenje novih procesa koje proces pokreće).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) je alat koji prikazuje odnose između procesa.\
Potrebno je da nadgledate svoj Mac komandom kao što je **`sudo eslogger fork exec rename create > cap.json`** (terminal iz kog se pokreće ova komanda mora imati FDA). Zatim možete da učitate JSON u ovaj alat i prikažete sve odnose:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) nadgleda događaje nad datotekama, kao što su kreiranje, izmena i brisanje.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) je GUI alat čiji izgled i način rada mogu biti poznati korisnicima Windows-a iz Microsoft Sysinternal-ovog _Procmon_-a. Ovaj alat omogućava pokretanje i zaustavljanje snimanja različitih tipova događaja, filtriranje tih događaja po kategorijama kao što su datoteke, procesi, mreža itd. i čuvanje snimljenih događaja u JSON formatu.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) su deo Xcode-ovih Developer tools-a i koriste se za nadgledanje performansi aplikacija, otkrivanje curenja memorije i praćenje aktivnosti u sistemu datoteka.

![Crescendo - Apple Instruments: Apple Instruments su deo Xcode-ovih Developer tools-a i koriste se za nadgledanje performansi aplikacija, otkrivanje curenja memorije i praćenje aktivnosti u sistemu datoteka](<../../../images/image (1138).png>)

### fs_usage

Omogućava praćenje radnji koje obavljaju procesi:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) je koristan za pregled **biblioteka** koje koristi binarna datoteka, **fajlova** koje koristi i **mrežnih** veza.\
Takođe proverava procese binarne datoteke pomoću **virustotal** i prikazuje informacije o binarnoj datoteci.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

U [**ovom blog postu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) možete pronaći primer kako **debugovati pokrenuti daemon** koji je koristio **`PT_DENY_ATTACH`** da spreči debugging, čak i kada je SIP bio onemogućen.<sup>[[6]](#references)</sup>

### lldb

**lldb** je **de facto alat** za **debugging** binarnih datoteka na **macOS**-u.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Možete da podesite Intel format dok koristite lldb tako što ćete u svojoj početnoj fascikli napraviti datoteku pod nazivom **`.lldbinit`** sa sledećim redom:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Unutar lldb-a, sačuvajte dump procesa pomoću `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>Opis</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Pokreće izvršavanje, koje se nastavlja dok se ne aktivira breakpoint ili se proces ne završi.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Pokreće izvršavanje i zaustavlja ga na ulaznoj tački.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Nastavlja izvršavanje procesa koji se debaguje.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Izvršava sledeću instrukciju. Ova komanda preskače pozive funkcija.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Izvršava sledeću instrukciju. Za razliku od komande <code>nexti</code>, ova komanda ulazi u pozive funkcija.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Izvršava preostale instrukcije u trenutnoj funkciji (frejmu), vraća se i zaustavlja izvršavanje.</td></tr>
<tr><td><strong>control + c</strong></td><td>Pauzira izvršavanje. Ako je proces pokrenut (<code>r</code>) ili je nastavljeno njegovo izvršavanje (<code>c</code>), ova komanda ga zaustavlja na trenutnom mestu izvršavanja.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Bilo koja funkcija pod nazivom main</p>
<p><code>b &lt;binname&gt;`main</code> # Glavna funkcija binarne datoteke</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Glavna funkcija navedene binarne datoteke</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Bilo koja metoda NSFileManager</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Zaustavljanje u svim funkcijama te biblioteke</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Lista breakpoint-a</p>
<p><code>br e/dis &lt;num&gt;</code> # Uključivanje/isključivanje breakpoint-a</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Prikazuje pomoć za komandu breakpoint</p>
<p><code>help memory write</code> # Prikazuje pomoć za upis u memoriju</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Prikazuje memoriju kao string završen nul-terminatorom.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Prikazuje memoriju kao asembler instrukciju.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Prikazuje memoriju kao bajt.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Ova komanda ispisuje objekat na koji se parametar odnosi.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>Većina Apple Objective-C API-ja ili metoda vraća objekte, pa ih treba prikazati komandom „print object” (<code>po</code>). Ako <code>po</code> ne prikaže smislen izlaz, upotrebite <code>x/b</code>.</p>
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
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Dohvata adresu svakog simbola iz CoreNLP-a</td></tr>
</tbody>
</table>

> [!TIP]
> Pri pozivanju funkcije **`objc_sendMsg`**, registar **rsi** sadrži **naziv metode** kao string završen nul-terminatorom („C” string). Da biste ispisali naziv pomoću lldb-a, uradite sledeće:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-dinamička analiza

#### Detekcija VM-a

- Komanda **`sysctl hw.model`** obično vraća identifikator modela Mac-a na fizičkom hardveru, a u VM-u može vratiti drugu vrednost.<sup>[[3]](#references)</sup>
- Menjanjem vrednosti **`hw.logicalcpu`** i **`hw.physicalcpu`**, neki malveri pokušavaju da otkriju da li se izvršavaju u VM-u.<sup>[[4]](#references)</sup>
- Neki malveri mogu da **otkriju** da je mašina zasnovana na **VMware-u** na osnovu MAC adrese (00:50:56).
- Moguće je i jednostavnim kodom utvrditi **da li se proces debaguje**:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Može da pozove i sistemski poziv **`ptrace`** sa zastavicom **`PT_DENY_ATTACH`**. Time se **sprečava** da se deb**u**ger prikači na proces i prati ga.
  - Možete proveriti da li se funkcija **`sysctl`** ili **`ptrace`** **uvozi** (ali malver može da je uveze dinamički)
  - Kao što je navedeno u ovom tekstu, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_Poruka Process # exited with **status = 45 (0x0000002d)** obično je jasan znak da debug target koristi **PT_DENY_ATTACH**_”

#### Prebacivanje procesa pomoću `fork()`

Proces može da izbegne debugger koji je i dalje prikačen na originalni PID tako što će pri pokretanju pozvati `fork()`, prekinuti roditeljski proces (`fork()` vraća pozitivan PID deteta), a zaštićenu logiku nastaviti samo u detetu (`fork()` vraća `0`). Razrešavanje `fork`-a pomoću `dlsym(RTLD_DEFAULT, "fork")` uklanja i direktno mesto poziva `_fork`, ali je to samo prepreka za analizu: string sa nazivom simbola i tok podataka dinamičkog razrešavanja i dalje su vidljivi u Mach-O binarnoj datoteci.<sup>[[10]](#references)[[11]](#references)</sup>

Na arm64, ovaj obrazac otkrijte praćenjem toka podataka, a ne fiksnih adresa: prva dva argumenta za `dlsym` prosleđuju se u `x0` i `x1`, `RTLD_DEFAULT` se može pojaviti kao `-2` (na primer, `movn x0, #1`), a par `adrp`/`add` obično formira adresu stringa `"fork"`. Nakon `bl` poziva `dlsym` stub-a, pratite vraćeni pokazivač od `x0`, kroz proveru da li je null i njegovo skladištenje, do kasnijeg indirektnog poziva `blr`. Zatim pratite rezultat poziva `fork()` u `w0`: nula vodi do nastavka deteta, dok pozitivne vrednosti i `-1` vode do putanje roditelja/greške.<sup>[[10]](#references)[[11]](#references)</sup>

Jedan statički način zaobilaženja jeste da sprečite indirektni poziv i primorate postojeću proveru rezultata da izabere putanju deteta. Na primer, ako je kompajler generisao niz prikazan ispod, zamenite `blr` i upis rezultata sa `nop`, postavite sintetički rezultat na nulu i zadržite logiku poređenja/grananja. Aplikacija zatim nastavlja da radi pod originalnim PID-om, bez kreiranja deteta; registre instrukcija i odredišta grananja treba prilagoditi analiziranoj verziji programa.<sup>[[10]](#references)[[11]](#references)</sup>

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

- je sysctl `kern.coredump` podešen na 1 (podrazumevano)
- proces nije bio suid/sgid ili je `kern.sugid_coredump` podešen na 1 (podrazumevano je 0)
- limit `AS_CORE` dozvoljava ovu operaciju. Kreiranje core dumpova moguće je onemogućiti pozivom `ulimit -c 0`, a ponovo omogućiti pomoću `ulimit -c unlimited`.

U tim slučajevima, core dumpovi se generišu u skladu sa sysctl parametrom `kern.corefile` i obično se čuvaju u `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizira procese koji se ruše i čuva izveštaj o padu na disku**. Izveštaj o padu sadrži informacije koje mogu **pomoći programeru da dijagnostikuje** uzrok pada.\
Za aplikacije i druge procese **koji rade u launchd kontekstu pojedinačnog korisnika**, ReportCrash radi kao LaunchAgent i čuva izveštaje o padu u korisnikovom direktorijumu `~/Library/Logs/DiagnosticReports/`\
Za demone, druge procese **koji rade u sistemskom launchd kontekstu** i druge privilegovane procese, ReportCrash radi kao LaunchDaemon i čuva izveštaje o padu u sistemskom direktorijumu `/Library/Logs/DiagnosticReports`

Ako ste zabrinuti da se izveštaji o padu **šalju kompaniji Apple**, možete ih onemogućiti. U suprotnom, izveštaji o padu mogu biti korisni za **utvrđivanje uzroka pada servera**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Spavanje

Tokom fuzzing-a na macOS-u, sprečite Mac da pređe u režim spavanja:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Prekid SSH veze

Ako radite fuzzing preko SSH veze, važno je da sprečite prekid sesije. Zato izmenite datoteku sshd_config tako da sadrži:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Interni obrađivači

**Pogledajte sledeću stranicu** da biste saznali kako da pronađete koja je aplikacija odgovorna za **obradu navedene šeme ili protokola:**


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

Ili koristite `netstat` ili `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Fuzzeri

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Radi sa CLI alatima

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

„**jednostavno radi**“ sa mnogim macOS GUI alatima. Neke aplikacije imaju dodatne zahteve, kao što su jedinstvena imena datoteka, određena ekstenzija ili čitanje datoteka iz svog sandbox kontejnera (`~/Library/Containers/com.apple.Safari/Data`).

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

### Više informacija o macOS fuzzing-u

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [Odgovor na incidente u OS X-u: skriptovanje i analiza](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Leto fuzzinga: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Umetnost Mac malware-a, tom I: analiza](https://taomm.org/)
- [4] [No Starch Press - Umetnost Mac malware-a: vodič za analizu zlonamernog softvera](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - informacije sačuvane u ovom odeljku ovog blog posta](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Otklanjanje grešaka u Apple binarnim datotekama koje koriste Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Zaobilaženje anti-debug tehnika: macOS ptrace varijante](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcode strukturisani logovi i `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Prikaz privatnih podataka u objedinjenom macOS logu](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [tony-go/antidebug-examples - primeri fork-a](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [11] [Reverse Society - Anti-debugging tehnika koja koristi dlsym i fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
{{#include ../../../banners/hacktricks-training.md}}
