# macOS aplikacije - Inspecting, debugging i Fuzzing

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
> Imajte na umu da **`disarm`** može da radi i sa kompresovanim IM4P datotekama (kao što je `kernelcache`) i da izdvoji samo potrebne delove ili čak analizira potrebni deo bez njegovog izdvajanja.
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
> **`Codesign`** se može naći u **macOS-u**, dok se **`ldid`** može naći u **iOS-u**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) je alat koristan za pregled **.pkg** fajlova (instalacionih paketa) i proveru njihovog sadržaja pre instalacije.\
Ovi instalacioni paketi sadrže `preinstall` i `postinstall` bash skripte koje autori malware-a obično zloupotrebljavaju da bi **obezbedili** **persistenciju** **malware-a**.

### hdiutil

Ovaj alat omogućava da **montirate** Apple disk image (**.dmg**) fajlove i pregledate ih pre pokretanja bilo čega:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Biće montiran u `/Volumes`

### Pakovani binarni fajlovi

- Proverite visoku entropiju
- Proverite stringove (ako gotovo da nema razumljivih stringova, fajl je pakovan)
- UPX packer za MacOS generiše sekciju pod nazivom "\_\_XHDR"

## Statička Objective-C analiza

### Metapodaci

> [!CAUTION]
> Imajte na umu da programi napisani u Objective-C **zadržavaju** svoje deklaracije klasa kada se **kompajliraju** u [Mach-O binarne fajlove](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Takve deklaracije klasa **uključuju** naziv i tip sledećeg:

- Definisani interfejsi
- Metode interfejsa
- Promenljive instanci interfejsa
- Definisani protokoli

Imajte na umu da ovi nazivi mogu biti obfuskirani kako bi se otežala reverzna analiza binarnog fajla.

### Pozivanje funkcija

Kada se pozove funkcija u binarnom fajlu koji koristi Objective-C, kompajlirani kod umesto pozivanja te funkcije poziva **`objc_msgSend`**, koji zatim poziva konačnu funkciju:

![Metapodaci - Pozivanje funkcija: Kada se pozove funkcija u binarnom fajlu koji koristi Objective-C, kompajlirani kod umesto pozivanja te funkcije poziva objc msgSend. Koji će pozvati...](<../../../images/image (305).png>)

Parametri koje ova funkcija očekuje su:

- Prvi parametar (**self**) je „pokazivač koji pokazuje na **instancu klase koja treba da primi poruku**“. Jednostavnije rečeno, to je objekat nad kojim se metoda poziva. Ako je metoda klasna metoda, ovo će biti instanca objekta klase (u celini), dok će kod metode instance `self` pokazivati na instancu klase kreiranu kao objekat.
- Drugi parametar, (**op**), jeste „selektor metode koja obrađuje poruku“. Jednostavnije rečeno, ovo je samo **naziv metode**.
- Preostali parametri su sve **vrednosti koje metoda zahteva** (`op`).

Pogledajte kako da lako **dobijete ove informacije pomoću `lldb` na ARM64** na ovoj stranici:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**       | **Registar**                                                   | **(za) objc_msgSend**                                  |
| ------------------ | -------------------------------------------------------------- | ------------------------------------------------------ |
| **1. argument**    | **rdi**                                                        | **self: objekat nad kojim se metoda poziva**           |
| **2. argument**    | **rsi**                                                        | **op: naziv metode**                                    |
| **3. argument**    | **rdx**                                                        | **1. argument metode**                                 |
| **4. argument**    | **rcx**                                                        | **2. argument metode**                                 |
| **5. argument**    | **r8**                                                         | **3. argument metode**                                 |
| **6. argument**    | **r9**                                                         | **4. argument metode**                                 |
| **7. i naredni argumenti** | <p><strong>rsp+</strong><br><strong>(na steku)</strong></p> | **5. i naredni argumenti metode**                     |

### Izvoz Objective-C metapodataka

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) je alat za class-dump Objective-C binarnih fajlova. github navodi dylib fajlove, ali ovo takođe funkcioniše i sa izvršnim fajlovima.
```bash
./dynadump dump /path/to/bin
```
U trenutku pisanja, **ovo je trenutno ono što najbolje funkcioniše**.

#### Standardni alati
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) je originalni alat za generisanje deklaracija klasa, kategorija i protokola u formatiranom Objective-C kodu.

Star je i više se ne održava, tako da verovatno neće raditi ispravno.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) je moderan i multiplatformski alat za class dump u Objective-C-u. U poređenju sa postojećim alatima, iCDump može da radi nezavisno od Apple ekosistema i pruža Python bindings.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Statička Swift analiza

Kod Swift binarnih datoteka, pošto postoji Objective-C kompatibilnost, ponekad možete izdvojiti deklaracije pomoću alata [class-dump](https://github.com/nygard/class-dump/), ali ne uvek.

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
Dodatne informacije o [**informacijama sačuvanim u ovim odeljcima možete pronaći u ovom blog postu**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Pored toga, **Swift binarni fajlovi mogu sadržati symbols** (na primer, biblioteke moraju da čuvaju symbols kako bi njihove funkcije mogle da budu pozvane). **Symbols obično sadrže informacije o nazivu funkcije** i atributima na nezgodan način, zbog čega su veoma korisni, a postoje i "**demanglers**" koji mogu da dobiju originalni naziv:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dinamička analiza

> [!WARNING]
> Imajte na umu da, da biste debagovali binaries, **SIP mora biti onemogućen** (`csrutil disable` ili `csrutil enable --without debug`), ili je potrebno kopirati binaries u privremeni folder i **ukloniti potpis** pomoću `codesign --remove-signature <binary-path>`, ili dozvoliti debagovanje binary-ja (možete koristiti [ovu skriptu](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Imajte na umu da, da biste **instrumentovali sistemske binaries**, kao što je `cloudconfigurationd`, na macOS-u, **SIP mora biti onemogućen** (samo uklanjanje potpisa neće raditi).

### APIs

macOS izlaže neke zanimljive APIs koji pružaju informacije o procesima:

- `proc_info`: Ovo je glavni API koji pruža mnogo informacija o svakom procesu. Morate biti root da biste dobili informacije o drugim procesima, ali nisu vam potrebni posebni entitlements ili mach portovi.
- `libsysmon.dylib`: Omogućava dobijanje informacija o procesima putem funkcija izloženih kroz XPC, međutim, potrebno je imati entitlement `com.apple.sysmond.client`.

### Stackshot i microstackshots

**Stackshotting** je tehnika koja se koristi za beleženje stanja procesa, uključujući call stackove svih pokrenutih threadova. Ovo je naročito korisno za debugging, analizu performansi i razumevanje ponašanja sistema u određenom trenutku. Na iOS-u i macOS-u, stackshotting se može obaviti pomoću nekoliko alata i metoda, kao što su alati **`sample`** i **`spindump`**.

### Sysdiagnose

Ovaj alat (`/usr/bini/ysdiagnose`) u osnovi prikuplja mnogo informacija sa vašeg računara izvršavanjem desetina različitih komandi, kao što su `ps`, `zprint`...

Mora se pokrenuti kao **root**, a daemon `/usr/libexec/sysdiagnosed` ima veoma zanimljive entitlements, kao što su `com.apple.system-task-ports` i `get-task-allow`.

Njegov plist se nalazi na lokaciji `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` i definiše 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Briše stare arhive iz /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Special port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: User mode interfejs kroz Obj-C klasu `Libsysdiagnose`. Mogu se proslediti tri argumenta u dict-u (`compress`, `display`, `run`)

### Unified Logs

macOS generiše mnogo logova koji mogu biti veoma korisni prilikom pokretanja aplikacije i pokušaja da se razume **šta ona radi**.

Pored toga, neki logovi sadrže oznaku `<private>` kako bi **sakrili** određene informacije koje mogu identifikovati **korisnika** ili **računar**. Međutim, moguće je **instalirati certificate kako bi se otkrile ove informacije**. Pratite objašnjenja [ovde](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Levi panel

U levom panelu Hopper-a moguće je videti simbole (**Labels**) binary-ja, listu procedura i funkcija (**Proc**) i stringove (**Str**). To nisu svi stringovi, već oni definisani u nekoliko delova Mac-O fajla, kao što su _cstring ili `objc_methname`.

#### Središnji panel

U središnjem panelu možete videti **disasemblirani kod**. Takođe možete videti **sirovi** disassemble, kao **graf**, kao **dekompilovani** i kao **binary** prikaz klikom na odgovarajuću ikonu:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Desnim klikom na code object možete videti **reference ka tom object-u i iz njega** ili čak promeniti njegovo ime (ovo ne radi u dekompilovanom pseudokodu):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Pored toga, **dole u središnjem panelu možete pisati Python komande**.

#### Desni panel

U desnom panelu možete videti zanimljive informacije, kao što su **istorija navigacije** (kako biste znali kako ste došli do trenutne situacije), **graf poziva**, gde možete videti sve **funkcije koje pozivaju ovu funkciju** i sve funkcije **koje ova funkcija poziva**, kao i informacije o **lokalnim promenljivama**.

### dtrace

Omogućava korisnicima pristup aplikacijama na izuzetno **niskom nivou** i pruža način za **praćenje** **programa**, pa čak i promenu njihovog toka izvršavanja. Dtrace koristi **probes** koji su **postavljeni širom kernela**, na lokacijama kao što su početak i kraj sistemskih poziva.

DTrace koristi funkciju **`dtrace_probe_create`** za kreiranje probe-a za svaki sistemski poziv. Ovi probe-ovi mogu biti aktivirani na **ulaznoj i izlaznoj tački svakog sistemskog poziva**. Interakcija sa DTrace-om odvija se kroz /dev/dtrace, koji je dostupan samo root korisniku.

> [!TIP]
> Da biste omogućili Dtrace bez potpunog onemogućavanja SIP zaštite, možete u recovery mode-u izvršiti: `csrutil enable --without dtrace`
>
> Takođe možete koristiti **`dtrace`** ili **`dtruss`** binaries koje ste **sami kompajlirali**.

Dostupne probe-ove dtrace-a možete dobiti pomoću:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Naziv probe sastoji se od četiri dela: provider, module, function i name (`fbt:mach_kernel:ptrace:entry`). Ako ne navedete neki deo naziva, Dtrace će taj deo tretirati kao wildcard.

Da bismo konfigurisali DTrace za aktiviranje probe-ova i naveli koje radnje treba izvršiti kada se aktiviraju, potrebno je da koristimo D language.

Detaljnije objašnjenje i više primera možete pronaći na [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Primeri

Pokrenite `man -k dtrace` da biste izlistali **dostupne DTrace skripte**. Primer: `sudo dtruss -n binary`

- U liniji
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
- script
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

To je mehanizam za praćenje kernela. Dokumentovani kodovi mogu se pronaći u **`/usr/share/misc/trace.codes`**.

Alati kao što su `latency`, `sc_usage`, `fs_usage` i `trace` interno ga koriste.

Za interfejs sa `kdebug` koristi se `sysctl` preko prostora imena `kern.kdebug`, a MIB-ovi koji se koriste mogu se pronaći u `sys/sysctl.h`, dok su funkcije implementirane u `bsd/kern/kdebug.c`.

Za interakciju sa kdebug pomoću prilagođenog klijenta obično se prate sledeći koraci:

- Ukloniti postojeća podešavanja pomoću KERN_KDSETREMOVE
- Podesiti trace pomoću KERN_KDSETBUF i KERN_KDSETUP
- Koristiti KERN_KDGETBUF za dobijanje broja unosa u bufferu
- Izbaciti sopstveni klijent iz trace-a pomoću KERN_KDPINDEX
- Omogućiti tracing pomoću KERN_KDENABLE
- Pročitati buffer pozivanjem KERN_KDREADTR
- Upariti svaku nit sa njenim procesom pomoću KERN_KDTHRMAP.

Za dobijanje ovih informacija moguće je koristiti Apple alat **`trace`** ili prilagođeni alat [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Imajte na umu da je Kdebug dostupan samo jednom korisniku istovremeno.** Dakle, istovremeno može da se izvršava samo jedan alat koji koristi k-debug.

### ktrace

`ktrace_*` API-ji potiču iz `libktrace.dylib`, koja obuhvata API-je za `Kdebug`. Klijent zatim može jednostavno da pozove `ktrace_session_create` i `ktrace_events_[single/class]` kako bi podesio callback funkcije za određene kodove, a zatim pokrene tracing pomoću `ktrace_start`.

Ovo možete koristiti čak i kada je **SIP aktiviran**

Kao klijenta možete koristiti uslužni program `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Ili `tailspin`.

### kperf

Ovo se koristi za profiling na nivou kernela i izgrađeno je pomoću `Kdebug` poziva.

U osnovi, proverava se globalna promenljiva `kernel_debug_active` i, ako je postavljena, poziva se `kperf_kdebug_handler` sa `Kdebug` kodom i adresom kernel frame-a koji poziva. Ako se `Kdebug` kod podudara sa jednim od izabranih, dobijaju se konfigurisane „actions“ u obliku bitmap-e (pogledajte `osfmk/kperf/action.h` za dostupne opcije).

Kperf takođe ima sysctl MIB tabelu: (kao root) `sysctl kperf`. Ovaj kod se može pronaći u `osfmk/kperf/kperfbsd.c`.

Pored toga, podskup funkcionalnosti Kperf-a nalazi se u `kpc`, koji pruža informacije o performance counters mašine.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) je veoma koristan alat za proveru radnji povezanih sa procesima koje proces izvršava (na primer, praćenje procesa koje neki proces kreira).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) je alat koji ispisuje odnose između procesa.\
Potrebno je da nadgledate svoj Mac pomoću komande kao što je **`sudo eslogger fork exec rename create > cap.json`** (terminal iz kog se ovo pokreće zahteva FDA). Zatim možete učitati json u ovaj alat da biste videli sve odnose:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) omogućava praćenje događaja nad datotekama (kao što su kreiranje, izmene i brisanje), uz pružanje detaljnih informacija o tim događajima.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) je GUI alat čiji izgled i način rada mogu biti poznati Windows korisnicima iz Microsoft Sysinternal-ovog alata _Procmon_. Ovaj alat omogućava pokretanje i zaustavljanje snimanja različitih tipova događaja, filtriranje tih događaja po kategorijama kao što su datoteke, procesi, mreža itd. i čuvanje snimljenih događaja u json formatu.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) je deo Xcode-ovih Developer tools — koristi se za praćenje performansi aplikacija, prepoznavanje memory leak-ova i praćenje aktivnosti filesystem-a.

![Crescendo - Apple Instruments: Apple Instruments je deo Xcode-ovih Developer tools — koristi se za praćenje performansi aplikacija, prepoznavanje memory leak-ova i praćenje aktivnosti filesystem-a](<../../../images/image (1138).png>)

### fs_usage

Omogućava praćenje radnji koje izvršavaju procesi:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) je koristan za pregled **libraries** koje koristi binary, **files** koje koristi i **network** konekcija.\
Takođe proverava procese binary-ja pomoću **virustotal**-a i prikazuje informacije o binary-ju.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

U [**ovom postu na blogu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) možete pronaći primer kako **debug-ovati pokrenuti daemon** koji je koristio **`PT_DENY_ATTACH`** da spreči debugging čak i kada je SIP bio onemogućen.

### lldb

**lldb** je de facto alat za **macOS** binary **debugging**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Možete podesiti Intel sintaksu prilikom korišćenja lldb-a tako što ćete u svom početnom direktorijumu napraviti datoteku **`.lldbinit`** sa sledećom linijom:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Unutar lldb-a, sačuvajte dump procesa pomoću `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>Opis</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Pokretanje izvršavanja, koje će se nesmetano nastaviti sve dok se ne dosegne breakpoint ili se proces ne završi.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Pokretanje izvršavanja sa zaustavljanjem na entry point-u</td></tr><tr><td><strong>continue (c)</strong></td><td>Nastavljanje izvršavanja debugovanog procesa.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Izvršava sledeću instrukciju. Ova komanda preskače pozive funkcija.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Izvršava sledeću instrukciju. Za razliku od komande nexti, ova komanda ulazi u pozive funkcija.</td></tr><tr><td><strong>finish (f)</strong></td><td>Izvršava preostale instrukcije u trenutnoj funkciji („frame“), vraća se i zaustavlja.</td></tr><tr><td><strong>control + c</strong></td><td>Pauzira izvršavanje. Ako je proces pokrenut pomoću (r) ili nastavljeno pomoću (c), proces će se zaustaviti ...gde god se trenutno izvršava.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Any func called main</p><p><code>b <binname>`main</code> #Main func of the bin</p><p><code>b set -n main --shlib <lib_name></code> #Main func of the indicated bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Any NSFileManager method</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint list</p><p><code>br e/dis <num></code> #Enable/Disable breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Prikazuje memoriju kao null-terminated string.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Prikazuje memoriju kao assembly instrukciju.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Prikazuje memoriju kao bajt.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Ovo će ispisati objekat na koji parametar upućuje</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Imajte na umu da većina Apple-ovih Objective-C API-ja ili metoda vraća objekte, pa ih zato treba prikazati pomoću komande „print object“ (po). Ako po ne proizvede smislen izlaz, koristite <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Prikazuje mapu memorije trenutnog procesa</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Get the address of all the symbols from CoreNLP</td></tr></tbody></table>

> [!TIP]
> Prilikom pozivanja funkcije **`objc_sendMsg`**, registar **rsi** sadrži **naziv metode** kao null-terminated („C“) string. Da biste ispisali naziv pomoću lldb-a, uradite sledeće:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- Komanda **`sysctl hw.model`** vraća „Mac“ kada je **host MacOS**, ali vraća nešto drugačije kada je u pitanju VM.
- Menjanjem vrednosti **`hw.logicalcpu`** i **`hw.physicalcpu`**, neki malware pokušava da utvrdi da li se nalazi u VM-u.
- Neki malware takođe može da **detektuje** da je sistem **VMware** na osnovu MAC adrese (00:50:56).
- Takođe je moguće utvrditi **da li se proces debug-uje** pomoću jednostavnog koda, kao što je:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Takođe može da pozove sistemski poziv **`ptrace`** sa flagom **`PT_DENY_ATTACH`**. Ovo **sprečava** debugger da se zakači na proces i prati ga.
- Možete proveriti da li su funkcije **`sysctl`** ili **`ptrace`** **importovane** (ali malware ih može importovati dinamički)
- Kao što je navedeno u ovom writeup-u, „[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)“ :\
„_Poruka Process # exited with **status = 45 (0x0000002d)** obično je jasan znak da debug target koristi **PT_DENY_ATTACH**_“

## Core Dumps

Core dumps se kreiraju ako:

- je `kern.coredump` sysctl podešen na 1 (podrazumevano)
- proces nije bio suid/sgid ili je `kern.sugid_coredump` podešen na 1 (podrazumevano je 0)
- `AS_CORE` limit dozvoljava operaciju. Kreiranje core dump-ova moguće je onemogućiti pozivom `ulimit -c 0`, a ponovo ih omogućiti pomoću `ulimit -c unlimited`.

U tim slučajevima core dump se generiše u skladu sa `kern.corefile` sysctl-om i obično se čuva u `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizira procese koji su se srušili i čuva crash report na disku**. Crash report sadrži informacije koje mogu **pomoći developeru da dijagnostikuje** uzrok pada.\
Za aplikacije i druge procese **koji rade u per-user launchd kontekstu**, ReportCrash se izvršava kao LaunchAgent i čuva crash report-ove u korisničkom direktorijumu `~/Library/Logs/DiagnosticReports/`\
Za daemon-e, druge procese **koji rade u system launchd kontekstu** i druge privilegovane procese, ReportCrash se izvršava kao LaunchDaemon i čuva crash report-ove u sistemskom direktorijumu `/Library/Logs/DiagnosticReports`

Ako ste zabrinuti da se crash report-ovi **šalju Apple-u**, možete ih onemogućiti. U suprotnom, crash report-ovi mogu biti korisni za **utvrđivanje kako se server srušio**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sleep

Tokom fuzzing-a na MacOS-u važno je sprečiti Mac da pređe u stanje mirovanja:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Disconnect

Ako fuzzing obavljate putem SSH konekcije, važno je osigurati da sesija neće biti prekinuta. Zato izmenite fajl sshd_config pomoću sledećih postavki:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Interni rukovaoci

**Pogledajte sledeću stranicu** da biste saznali kako možete pronaći koja je aplikacija odgovorna za **rukovanje navedenom šemom ili protokolom:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumeracija mrežnih procesa

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
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Radi za CLI alate

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

**„jednostavno radi“** sa macOS GUI alatima. Imajte na umu da neke macOS aplikacije imaju posebne zahteve, kao što su jedinstvena imena datoteka, odgovarajuća ekstenzija ili potreba da čitaju datoteke iz sandbox-a (`~/Library/Containers/com.apple.Safari/Data`)...

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
### Još informacija o Fuzzing-u za MacOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Reference

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Volume I: Analysis](https://taomm.org/vol1/analysis.html)
- [4] [The Art of Mac Malware: The Guide to Analyzing Malicious Software](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
