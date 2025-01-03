# macOS Aplikacije - Istraživanje, debagovanje i Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Statistička Analiza

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
### jtool2 & Disarm

Možete [**preuzeti disarm отсуда**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
Možete [**preuzeti jtool2 ovde**](http://www.newosxbook.com/tools/jtool.html) ili ga instalirati pomoću `brew`.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
> [!CAUTION] > **jtool je zastareo u korist disarm**

### Codesign / ldid

> [!TIP] > **`Codesign`** se može naći u **macOS**, dok se **`ldid`** može naći u **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) је алат користан за инспекцију **.pkg** фајлова (инсталатера) и за преглед садржаја пре инсталирања.\
Ови инсталатери имају `preinstall` и `postinstall` bash скрипте које аутори малвера обично злоупотребљавају да **постигну** **упорност** **малвера**.

### hdiutil

Овај алат омогућава **монтирање** Apple слика дискова (**.dmg**) за инспекцију пре покретања било чега:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Biće montiran u `/Volumes`

### Pakovani binarni fajlovi

- Proverite visoku entropiju
- Proverite stringove (ako gotovo da nema razumljivih stringova, pakovano)
- UPX pakera za MacOS generiše sekciju pod nazivom "\_\_XHDR"

## Staticka analiza Objective-C

### Metapodaci

> [!CAUTION]
> Imajte na umu da programi napisani u Objective-C **zadržavaju** svoje deklaracije klasa **kada** su **kompilirani** u [Mach-O binarne fajlove](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Takve deklaracije klasa **uključuju** ime i tip:

- Definisani interfejsi
- Metode interfejsa
- Varijable instanci interfejsa
- Definisani protokoli

Imajte na umu da bi ova imena mogla biti obfuskovana kako bi se otežalo obrnuto inženjerstvo binarnog fajla.

### Pozivanje funkcija

Kada se funkcija poziva u binarnom fajlu koji koristi Objective-C, kompajlirani kod umesto pozivanja te funkcije, poziva **`objc_msgSend`**. Koji će pozvati konačnu funkciju:

![](<../../../images/image (305).png>)

Parametri koje ova funkcija očekuje su:

- Prvi parametar (**self**) je "pokazivač koji pokazuje na **instancu klase koja treba da primi poruku**". Ili jednostavnije rečeno, to je objekat na kojem se metoda poziva. Ako je metoda metoda klase, ovo će biti instanca objekta klase (kao celina), dok će za metodu instance, self pokazivati na instanciranu instancu klase kao objekat.
- Drugi parametar, (**op**), je "selektor metode koja obrađuje poruku". Ponovo, jednostavnije rečeno, ovo je samo **ime metode.**
- Preostali parametri su bilo koji **vrednosti koje su potrebne metodi** (op).

Pogledajte kako da **dobijete ove informacije lako sa `lldb` u ARM64** na ovoj stranici:

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Registar**                                                  | **(za) objc_msgSend**                                 |
| ----------------- | ------------------------------------------------------------- | ------------------------------------------------------ |
| **1. argument**   | **rdi**                                                       | **self: objekat na kojem se metoda poziva**           |
| **2. argument**   | **rsi**                                                       | **op: ime metode**                                    |
| **3. argument**   | **rdx**                                                       | **1. argument za metodu**                             |
| **4. argument**   | **rcx**                                                       | **2. argument za metodu**                             |
| **5. argument**   | **r8**                                                        | **3. argument za metodu**                             |
| **6. argument**   | **r9**                                                        | **4. argument za metodu**                             |
| **7. i više**     | <p><strong>rsp+</strong><br><strong>(na steku)</strong></p> | **5. i više argumenata za metodu**                   |

### Dump ObjectiveC metapodataka

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) je alat za dumpovanje klasa Objective-C binarnih fajlova. Github specificira dylibs, ali ovo takođe funkcioniše sa izvršnim fajlovima.
```bash
./dynadump dump /path/to/bin
```
U vreme pisanja, ovo je **trenutno ono što najbolje funkcioniše**.

#### Redovni alati
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) je originalni alat koji generiše deklaracije za klase, kategorije i protokole u kodu formatiranom u ObjetiveC.

Stari je i nije održavan, tako da verovatno neće raditi ispravno.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) je moderan i multiplatformski Objective-C dump. U poređenju sa postojećim alatima, iCDump može da radi nezavisno od Apple ekosistema i izlaže Python vezivanja.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Staticka analiza Swifta

Sa Swift binarnim datotekama, pošto postoji kompatibilnost sa Objective-C, ponekad možete izvući deklaracije koristeći [class-dump](https://github.com/nygard/class-dump/) ali ne uvek.

Sa **`jtool -l`** ili **`otool -l`** komandama moguće je pronaći nekoliko sekcija koje počinju sa **`__swift5`** prefiksom:
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
Možete pronaći dodatne informacije o [**informacijama pohranjenim u ovoj sekciji u ovom blog postu**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Pored toga, **Swift binarni fajlovi mogu imati simbole** (na primer, biblioteke treba da čuvaju simbole kako bi se njihove funkcije mogle pozivati). **Simboli obično imaju informacije o imenu funkcije** i atributima na ružan način, tako da su veoma korisni i postoje "**demangleri"** koji mogu dobiti originalno ime:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dinamička Analiza

> [!WARNING]
> Imajte na umu da da biste debagovali binarne datoteke, **SIP mora biti onemogućen** (`csrutil disable` ili `csrutil enable --without debug`) ili da kopirate binarne datoteke u privremenu fasciklu i **uklonite potpis** sa `codesign --remove-signature <binary-path>` ili dozvolite debagovanje binarne datoteke (možete koristiti [ovaj skript](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Imajte na umu da da biste **instrumentovali sistemske binarne datoteke**, (kao što je `cloudconfigurationd`) na macOS-u, **SIP mora biti onemogućen** (samo uklanjanje potpisa neće raditi).

### API-ji

macOS izlaže neke zanimljive API-je koji daju informacije o procesima:

- `proc_info`: Ovo je glavni koji daje mnogo informacija o svakom procesu. Potrebno je biti root da biste dobili informacije o drugim procesima, ali vam nisu potrebna posebna ovlašćenja ili mach portovi.
- `libsysmon.dylib`: Omogućava dobijanje informacija o procesima putem XPC izloženih funkcija, međutim, potrebno je imati ovlašćenje `com.apple.sysmond.client`.

### Stackshot & mikrostackshotovi

**Stackshotting** je tehnika koja se koristi za hvatanje stanja procesa, uključujući pozivne stekove svih aktivnih niti. Ovo je posebno korisno za debagovanje, analizu performansi i razumevanje ponašanja sistema u određenom trenutku. Na iOS-u i macOS-u, stackshotting se može izvesti korišćenjem nekoliko alata i metoda kao što su alati **`sample`** i **`spindump`**.

### Sysdiagnose

Ovaj alat (`/usr/bini/ysdiagnose`) u suštini prikuplja mnogo informacija sa vašeg računara izvršavajući desetine različitih komandi kao što su `ps`, `zprint`...

Mora se pokrenuti kao **root** i demon `/usr/libexec/sysdiagnosed` ima veoma zanimljiva ovlašćenja kao što su `com.apple.system-task-ports` i `get-task-allow`.

Njegov plist se nalazi u `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` koji deklarira 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Briše stare arhive u /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Poseban port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Interfejs korisničkog moda kroz `Libsysdiagnose` Obj-C klasu. Tri argumenta u dict-u mogu biti prosleđena (`compress`, `display`, `run`)

### Unified Logs

MacOS generiše mnogo logova koji mogu biti veoma korisni kada se pokreće aplikacija koja pokušava da razume **šta radi**.

Štaviše, postoje neki logovi koji će sadržati oznaku `<private>` da **sakriju** neke **korisničke** ili **računarske** **identifikacione** informacije. Međutim, moguće je **instalirati sertifikat da bi se otkrile ove informacije**. Pratite objašnjenja [**ovde**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Leva panel

Na levoj panelu Hoper-a moguće je videti simbole (**Labels**) binarne datoteke, listu procedura i funkcija (**Proc**) i stringove (**Str**). To nisu svi stringovi, već oni definisani u nekoliko delova Mac-O datoteke (kao što su _cstring ili_ `objc_methname`).

#### Srednja panel

Na srednjoj panelu možete videti **disasemblirani kod**. I možete ga videti kao **sirov** disasembler, kao **graf**, kao **dekompajliran** i kao **binarni** klikom na odgovarajuću ikonu:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Desnim klikom na objekat koda možete videti **reference na/iz tog objekta** ili čak promeniti njegovo ime (ovo ne funkcioniše u dekompajliranom pseudokodu):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Štaviše, u **srednjem donjem delu možete pisati python komande**.

#### Desna panel

Na desnoj panelu možete videti zanimljive informacije kao što su **istorija navigacije** (tako da znate kako ste došli do trenutne situacije), **call graf** gde možete videti sve **funkcije koje pozivaju ovu funkciju** i sve funkcije koje **ova funkcija poziva**, i informacije o **lokalnim varijablama**.

### dtrace

Omogućava korisnicima pristup aplikacijama na ekstremno **niskom nivou** i pruža način za korisnike da **prate** **programe** i čak promene njihov tok izvršenja. Dtrace koristi **probes** koje su **postavljene širom kernela** i nalaze se na mestima kao što su početak i kraj sistemskih poziva.

DTrace koristi funkciju **`dtrace_probe_create`** za kreiranje probe za svaki sistemski poziv. Ove probe mogu biti aktivirane u **ulaznoj i izlaznoj tački svakog sistemskog poziva**. Interakcija sa DTrace se odvija kroz /dev/dtrace koji je dostupan samo za root korisnika.

> [!TIP]
> Da omogućite Dtrace bez potpunog onemogućavanja SIP zaštite, možete izvršiti u režimu oporavka: `csrutil enable --without dtrace`
>
> Takođe možete **`dtrace`** ili **`dtruss`** binarne datoteke koje **ste sami kompajlirali**.

Dostupne probe dtrace-a mogu se dobiti sa:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Ime probe se sastoji od četiri dela: provajder, modul, funkcija i ime (`fbt:mach_kernel:ptrace:entry`). Ako ne navedete neki deo imena, Dtrace će taj deo primeniti kao džoker.

Da bismo konfigurisali DTrace da aktivira probe i da odredimo koje akcije da izvršimo kada se aktiviraju, moraćemo da koristimo D jezik.

Detaljnije objašnjenje i više primera možete pronaći u [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Primeri

Pokrenite `man -k dtrace` da biste prikazali **DTrace skripte koje su dostupne**. Primer: `sudo dtruss -n binary`
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
- скрипт
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

To je funkcija za praćenje jezgra. Dokumentovani kodovi se mogu naći u **`/usr/share/misc/trace.codes`**.

Alati kao što su `latency`, `sc_usage`, `fs_usage` i `trace` koriste je interno.

Za interakciju sa `kdebug` koristi se `sysctl` preko `kern.kdebug` imenskog prostora, a MIB-ovi koji se koriste mogu se naći u `sys/sysctl.h` gde su funkcije implementirane u `bsd/kern/kdebug.c`.

Da bi se interagovalo sa kdebug-om sa prilagođenim klijentom, obično su to koraci:

- Uklonite postojeće postavke sa KERN_KDSETREMOVE
- Postavite praćenje sa KERN_KDSETBUF i KERN_KDSETUP
- Koristite KERN_KDGETBUF da dobijete broj unosa u baferu
- Izvucite vlastiti klijent iz praćenja sa KERN_KDPINDEX
- Omogućite praćenje sa KERN_KDENABLE
- Pročitajte bafer pozivajući KERN_KDREADTR
- Da biste povezali svaku nit sa njenim procesom, pozovite KERN_KDTHRMAP.

Da biste dobili ove informacije, moguće je koristiti Apple alat **`trace`** ili prilagođeni alat [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Napomena: Kdebug je dostupan samo za 1 korisnika u isto vreme.** Dakle, samo jedan alat sa k-debug podrškom može se izvršavati u isto vreme.

### ktrace

`ktrace_*` API-ji dolaze iz `libktrace.dylib` koji obavijaju one iz `Kdebug`. Tada klijent može jednostavno pozvati `ktrace_session_create` i `ktrace_events_[single/class]` da postavi povratne pozive na specifične kodove i zatim ga pokrenuti sa `ktrace_start`.

Možete koristiti ovo čak i sa **SIP aktiviranim**

Možete koristiti kao klijente alat `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Ili `tailspin`.

### kperf

Ovo se koristi za profilisanje na nivou kernela i izgrađeno je koristeći `Kdebug` pozive.

U suštini, globalna promenljiva `kernel_debug_active` se proverava i ako je postavljena, poziva `kperf_kdebug_handler` sa `Kdebug` kodom i adresom kernel okvira koji poziva. Ako se `Kdebug` kod poklapa sa jednim od odabranih, dobijaju se "akcije" konfigurirane kao bitmapa (proverite `osfmk/kperf/action.h` za opcije).

Kperf takođe ima sysctl MIB tabelu: (kao root) `sysctl kperf`. Ovi kodovi se mogu naći u `osfmk/kperf/kperfbsd.c`.

Štaviše, podskup funkcionalnosti Kperfa se nalazi u `kpc`, koji pruža informacije o brojačima performansi mašine.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) je veoma koristan alat za proveru akcija vezanih za procese koje proces izvršava (na primer, prati koje nove procese proces kreira).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) je alat koji štampa odnose između procesa.\
Morate pratiti vaš mac sa komandom kao **`sudo eslogger fork exec rename create > cap.json`** (terminal koji pokreće ovo zahteva FDA). A zatim možete učitati json u ovaj alat da biste videli sve odnose:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) omogućava praćenje događaja vezanih za fajlove (kao što su kreiranje, modifikacije i brisanja) pružajući detaljne informacije o tim događajima.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) je GUI alat sa izgledom i osećajem koji korisnici Windows-a možda poznaju iz Microsoft Sysinternal’s _Procmon_. Ovaj alat omogućava snimanje različitih tipova događaja koji se mogu započeti i zaustaviti, omogućava filtriranje ovih događaja po kategorijama kao što su fajl, proces, mreža, itd., i pruža funkcionalnost za čuvanje snimljenih događaja u json formatu.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) su deo Xcode-ovih razvojnog alata – koriste se za praćenje performansi aplikacija, identifikovanje curenja memorije i praćenje aktivnosti na datotečnom sistemu.

![](<../../../images/image (1138).png>)

### fs_usage

Omogućava praćenje akcija koje izvode procesi:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) je koristan za pregled **biblioteka** koje koristi binarni fajl, **fajlova** koje koristi i **mrežnih** konekcija.\
Takođe proverava binarne procese protiv **virustotal** i prikazuje informacije o binarnom fajlu.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

U [**ovom blog postu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) možete pronaći primer o tome kako **debug-ovati pokrenuti daemon** koji koristi **`PT_DENY_ATTACH`** da spreči debagovanje čak i ako je SIP bio onemogućen.

### lldb

**lldb** je de **facto alat** za **macOS** binarno **debugovanje**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Možete postaviti intel varijantu kada koristite lldb kreiranjem datoteke pod nazivom **`.lldbinit`** u vašem domaćem folderu sa sledećom linijom:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Unutar lldb, dump-ujte proces sa `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Komanda</strong></td><td><strong>Opis</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Pokreće izvršavanje, koje će se nastaviti bez prekida dok se ne dostigne breakpoint ili proces ne završi.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Pokreće izvršavanje zaustavljajući se na ulaznoj tački</td></tr><tr><td><strong>continue (c)</strong></td><td>Nastavlja izvršavanje debagovanog procesa.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Izvršava sledeću instrukciju. Ova komanda će preskočiti pozive funkcija.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Izvršava sledeću instrukciju. Za razliku od nexti komande, ova komanda će ući u pozive funkcija.</td></tr><tr><td><strong>finish (f)</strong></td><td>Izvršava ostatak instrukcija u trenutnoj funkciji (“frame”) i vraća se i zaustavlja.</td></tr><tr><td><strong>control + c</strong></td><td>Pauzira izvršavanje. Ako je proces pokrenut (r) ili nastavljen (c), ovo će uzrokovati da proces stane ...gde god trenutno izvršava.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Svaka funkcija koja se zove main</p><p><code>b &#x3C;binname>`main</code> #Glavna funkcija binarija</p><p><code>b set -n main --shlib &#x3C;lib_name></code> #Glavna funkcija označenog binarija</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Svaka NSFileManager metoda</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Prekini u svim funkcijama te biblioteke</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Lista breakpointova</p><p><code>br e/dis &#x3C;num></code> #Omogući/Onemogući breakpoint</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Dobijte pomoć za breakpoint komandu</p><p>help memory write #Dobijte pomoć za pisanje u memoriju</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/adresa u memoriji></strong></td><td>Prikazuje memoriju kao string koji se završava nulom.</td></tr><tr><td><strong>x/i &#x3C;reg/adresa u memoriji></strong></td><td>Prikazuje memoriju kao instrukciju asemblera.</td></tr><tr><td><strong>x/b &#x3C;reg/adresa u memoriji></strong></td><td>Prikazuje memoriju kao bajt.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Ovo će odštampati objekat na koji se poziva parametar</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Napomena da većina Apple-ovih Objective-C API-ja ili metoda vraća objekte, i stoga bi trebali biti prikazani putem komande “print object” (po). Ako po ne daje smislen izlaz, koristite <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Upiši AAAA na tu adresu<br>memory write -f s $rip+0x11f+7 "AAAA" #Upiši AAAA na adresu</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas trenutnu funkciju</p><p>dis -n &#x3C;funcname> #Disas funkciju</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Disas funkciju<br>dis -c 6 #Disas 6 linija<br>dis -c 0x100003764 -e 0x100003768 # Od jedne adrese do druge<br>dis -p -c 4 # Počni u trenutnoj adresi disasembli</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Proveri niz od 3 komponente u x1 registru</td></tr><tr><td><strong>image dump sections</strong></td><td>Štampa mapu trenutne memorije procesa</td></tr><tr><td><strong>image dump symtab &#x3C;library></strong></td><td><code>image dump symtab CoreNLP</code> #Dobij adresu svih simbola iz CoreNLP</td></tr></tbody></table>

> [!NOTE]
> Kada se poziva funkcija **`objc_sendMsg`**, registar **rsi** sadrži **ime metode** kao string koji se završava nulom (“C”). Da biste odštampali ime putem lldb, uradite:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detekcija

- Komanda **`sysctl hw.model`** vraća "Mac" kada je **host MacOS**, ali nešto drugo kada je VM.
- Igrajući se sa vrednostima **`hw.logicalcpu`** i **`hw.physicalcpu`**, neki malveri pokušavaju da detektuju da li je u pitanju VM.
- Neki malveri takođe mogu **detektovati** da li je mašina **VMware** na osnovu MAC adrese (00:50:56).
- Takođe je moguće otkriti **da li se proces debaguje** jednostavnim kodom kao što je:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //proces se debaguje }`
- Takođe može pozvati **`ptrace`** sistemski poziv sa **`PT_DENY_ATTACH`** flagom. Ovo **sprečava** deb**u**gger da se priključi i prati.
- Možete proveriti da li je funkcija **`sysctl`** ili **`ptrace`** **importovana** (ali malver bi mogao da je importuje dinamički)
- Kao što je navedeno u ovom izveštaju, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Poruka Process # exited with **status = 45 (0x0000002d)** obično je znak da je cilj debagovanja koristio **PT_DENY_ATTACH**_”

## Core Dumps

Core dumps se kreiraju ako:

- `kern.coredump` sysctl je postavljen na 1 (po defaultu)
- Ako proces nije suid/sgid ili `kern.sugid_coredump` je 1 (po defaultu je 0)
- `AS_CORE` limit dozvoljava operaciju. Moguće je suprimirati kreiranje core dump-ova pozivom `ulimit -c 0` i ponovo ih omogućiti sa `ulimit -c unlimited`.

U tim slučajevima, core dump se generiše prema `kern.corefile` sysctl i obično se čuva u `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizira procese koji se ruše i čuva izveštaj o padu na disk**. Izveštaj o padu sadrži informacije koje mogu **pomoći programeru da dijagnostikuje** uzrok pada.\
Za aplikacije i druge procese **koji se izvršavaju u kontekstu per-user launchd**, ReportCrash se pokreće kao LaunchAgent i čuva izveštaje o padu u korisnikovom `~/Library/Logs/DiagnosticReports/`\
Za daemone, druge procese **koji se izvršavaju u kontekstu sistemskog launchd** i druge privilegovane procese, ReportCrash se pokreće kao LaunchDaemon i čuva izveštaje o padu u sistemskom `/Library/Logs/DiagnosticReports`

Ako ste zabrinuti zbog izveštaja o padu **koji se šalju Apple-u**, možete ih onemogućiti. Ako ne, izveštaji o padu mogu biti korisni za **utvrđivanje kako je server pao**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Spavanje

Dok fuzzujete na MacOS-u, važno je ne dozvoliti Mac-u da spava:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Isključenje

Ako fuzzujete putem SSH veze, važno je osigurati da sesija ne isključi. Tako da promenite sshd_config datoteku sa:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Interni Handleri

**Pogledajte sledeću stranicu** da saznate kako možete pronaći koja aplikacija je odgovorna za **rukovanje određenim shemama ili protokolima:**

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumeracija Mrežnih Procesa

Ovo je zanimljivo za pronalaženje procesa koji upravljaju mrežnim podacima:
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

Prosto radi sa macOS GUI alatima. Imajte na umu da neke macOS aplikacije imaju specifične zahteve kao što su jedinstvena imena datoteka, prava ekstenzija, potreba da se datoteke čitaju iz sandboxes (`~/Library/Containers/com.apple.Safari/Data`)...

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
### Više informacija o Fuzzingu na MacOS-u

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Reference

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
