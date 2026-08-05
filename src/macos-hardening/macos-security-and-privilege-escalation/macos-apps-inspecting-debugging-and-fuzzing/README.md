# macOS-toepassings - inspekteer, debugging en Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Statiese Analise

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
### Disarm (ou jtool2)

Jy kan [**disarm hier aflaai**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Let daarop dat **`disarm`** ook met saamgeperste IM4P-lêers (soos `kernelcache`) kan werk en slegs die nodige dele kan onttrek, of selfs die nodige deel kan ontleed sonder om dit te onttrek.
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
> **`Codesign`** kan in **macOS** gevind word, terwyl **`ldid`** in **iOS** gevind kan word.
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) is ’n tool wat nuttig is om **.pkg**-lêers (installers) te inspekteer en te sien wat daarin is voordat dit geïnstalleer word.\
Hierdie installers het `preinstall`- en `postinstall`-bash-skripte wat malware-outeurs gewoonlik misbruik om **persist** **die** **malware**.

### hdiutil

Hierdie tool laat jou toe om Apple-skyfbeelde (**.dmg**)-lêers te **mount** om hulle te inspekteer voordat enigiets uitgevoer word:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Dit sal in `/Volumes` gemount word

### Packed binaries

- Kontroleer vir hoë entropie
- Kontroleer die strings (as daar byna geen verstaanbare string is nie, is dit gepak)
- Die UPX packer vir MacOS genereer ’n seksie genaamd "\_\_XHDR"

## Statiese Objective-C-analise

### Metadata

> [!CAUTION]
> Let daarop dat programme wat in Objective-C geskryf is, hul **class declarations** behou **wanneer** hulle in [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) **gecompileer** word. Sulke **class declarations** **sluit die naam en tipe in van:**

- Die gedefinieerde interfaces
- Die interface-metodes
- Die interface-instansieveranderlikes
- Die gedefinieerde protocols

Let daarop dat hierdie name geobfuskeer kan word om die reversing van die binary moeiliker te maak.

### Funksie-aanroeping

Wanneer ’n funksie in ’n binary aangeroep word wat Objective-C gebruik, sal die gecompileerde kode, eerder as om daardie funksie aan te roep, **`objc_msgSend`** aanroep. Dit sal die finale funksie aanroep:

![Metadata - Funksie-aanroeping: Wanneer ’n funksie in ’n binary aangeroep word wat Objective-C gebruik, sal die gecompileerde kode, eerder as om daardie funksie aan te roep, objc msgSend aanroep. Dit sal...](<../../../images/image (305).png>)

Die params wat hierdie funksie verwag, is:

- Die eerste parameter (**self**) is "’n pointer wat na die **instansie van die klas wys wat die boodskap moet ontvang**". Eenvoudiger gestel, dit is die objek waarop die metode aangeroep word. As die metode ’n klasmetode is, sal dit ’n instansie van die klasobjek (as geheel) wees, terwyl self, vir ’n instansiemetode, na ’n geïnstansieerde instansie van die klas as ’n objek sal wys.
- Die tweede parameter, (**op**), is "die selector van die metode wat die boodskap hanteer". Weereens, eenvoudiger gestel, dit is bloot die **naam van die metode.**
- Die oorblywende parameters is enige **waardes wat deur die metode vereis word** (op).

Kyk op hierdie bladsy hoe om hierdie inligting maklik met `lldb` in **ARM64** te **verkry**:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(vir) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1ste argument**  | **rdi**                                                         | **self: objek waarop die metode aangeroep word** |
| **2de argument**  | **rsi**                                                         | **op: naam van die metode**                             |
| **3de argument**  | **rdx**                                                         | **1ste argument vir die metode**                         |
| **4de argument**  | **rcx**                                                         | **2de argument vir die metode**                         |
| **5de argument**  | **r8**                                                          | **3de argument vir die metode**                         |
| **6de argument**  | **r9**                                                          | **4de argument vir die metode**                         |
| **7de+ argument** | <p><strong>rsp+</strong><br><strong>(op die stack)</strong></p> | **5de+ argument vir die metode**                        |

### Dump ObjectiveC-metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) is ’n tool om Objective-C binaries te class-dump. Die github spesifiseer dylibs, maar dit werk ook met executables.
```bash
./dynadump dump /path/to/bin
```
Ten tyde van skrywe is dit **tans die een wat die beste werk**.

#### Algemene tools
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) is die oorspronklike tool om deklarasies vir die klasse, categories en protocols in Objective-C-geformateerde kode te genereer.

Dit is oud en word nie meer onderhou nie, dus sal dit waarskynlik nie behoorlik werk nie.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) is ’n moderne en kruisplatform Objective-C class dump. In vergelyking met bestaande tools kan iCDump onafhanklik van die Apple-ekosisteem loop, en dit stel Python bindings bloot.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Statiese Swift-analise

Met Swift-binaries, aangesien daar Objective-C-versoenbaarheid is, kan jy soms verklarings met [class-dump](https://github.com/nygard/class-dump/) onttrek, maar nie altyd nie.

Met die **`jtool -l`**- of **`otool -l`**-opdragreëls is dit moontlik om verskeie afdelings te vind wat met die **`__swift5`**-voorvoegsel begin:
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
Jy kan verdere inligting oor die [**inligting wat in hierdie afdelings gestoor word in hierdie blogplasing**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html) vind.

Boonop kan **Swift binaries symbols bevat** (biblioteke moet byvoorbeeld symbols stoor sodat hul functions geroep kan word). Die **symbols bevat gewoonlik die inligting oor die function se naam** en attr op ’n lelike manier, dus is hulle baie nuttig, en daar is "**demanglers"** wat die oorspronklike naam kan kry:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dinamiese Analise

> [!WARNING]
> Let daarop dat, om binaries te debug, **SIP gedeaktiveer moet wees** (`csrutil disable` of `csrutil enable --without debug`), of dat die binaries na ’n tydelike vouer gekopieer en die **signature verwyder** moet word met `codesign --remove-signature <binary-path>`, of debugging van die binary toegelaat moet word (jy kan [hierdie script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) gebruik)

> [!WARNING]
> Let daarop dat, om **system binaries te instrument**, (soos `cloudconfigurationd`) op macOS, **SIP gedeaktiveer moet wees** (slegs die signature verwyder sal nie werk nie).

### APIs

macOS stel ’n paar interessante APIs bloot wat inligting oor die prosesse gee:

- `proc_info`: Dit is die belangrikste een en gee baie inligting oor elke proses. Jy moet root wees om inligting oor ander prosesse te kry, maar jy het nie spesiale entitlements of mach ports nodig nie.
- `libsysmon.dylib`: Dit laat jou toe om inligting oor prosesse te kry via blootgestelde XPC-funksies; dit is egter nodig om die entitlement `com.apple.sysmond.client` te hê.

### Stackshot & microstackshots

**Stackshotting** is ’n tegniek wat gebruik word om die toestand van die prosesse vas te lê, insluitend die call stacks van alle lopende threads. Dit is besonder nuttig vir debugging, performance analysis en om die gedrag van die stelsel op ’n spesifieke tydstip te verstaan. Op iOS en macOS kan stackshotting met verskeie tools en metodes uitgevoer word, soos die tools **`sample`** en **`spindump`**.

### Sysdiagnose

Hierdie tool (`/usr/bini/ysdiagnose`) versamel basies baie inligting vanaf jou rekenaar deur tientalle verskillende commands uit te voer, soos `ps`, `zprint`...

Dit moet as **root** uitgevoer word en die daemon `/usr/libexec/sysdiagnosed` het baie interessante entitlements, soos `com.apple.system-task-ports` en `get-task-allow`.

Die plist is geleë by `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, wat 3 MachServices verklaar:

- `com.apple.sysdiagnose.CacheDelete`: Verwyder ou archives in /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Special port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: User mode-interface deur die `Libsysdiagnose` Obj-C-klas. Drie arguments in ’n dict kan deurgegee word (`compress`, `display`, `run`)

### Unified Logs

MacOS genereer baie logs wat baie nuttig kan wees wanneer ’n application uitgevoer word en jy probeer verstaan **wat dit doen**.

Daarbenewens is daar sommige logs wat die tag `<private>` bevat om sekere **user**- of **computer**-**identifiable** inligting te **verberg**. Dit is egter moontlik om ’n **certificate te installeer om hierdie inligting bekend te maak**. Volg die verduidelikings [hier](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Linker paneel

In Hopper se linker paneel is dit moontlik om die symbols (**Labels**) van die binary, die lys van procedures en functions (**Proc**) en die strings (**Str**) te sien. Dit is nie al die strings nie, maar dié wat in verskeie dele van die Mac-O-lêer gedefinieer is (soos _cstring of_ `objc_methname`).

#### Middelste paneel

In die middelste paneel kan jy die **gedisassembleerde code** sien. Jy kan dit as ’n **raw** disassembly, as ’n **graph**, as **decompiled** en as **binary** sien deur op die onderskeie ikoon te klik:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Deur regs te klik op ’n code object kan jy **references na/van daardie object** sien of selfs sy naam verander (dit werk nie in decompiled pseudocode nie):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Daarbenewens kan jy **onder in die middel python commands skryf**.

#### Regter paneel

In die regter paneel kan jy interessante inligting sien, soos die **navigation history** (sodat jy weet hoe jy by die huidige situasie uitgekom het), die **call grap**h waar jy al die **functions wat hierdie function call** en al die functions wat **hierdie function call**, sowel as inligting oor **local variables**, kan sien.

### dtrace

Dit gee users toegang tot applications op ’n uiters **lae vlak** en bied ’n manier vir users om **programs te trace** en selfs hul execution flow te verander. Dtrace gebruik **probes** wat **deur die kernel geplaas word** en op plekke voorkom soos die begin en einde van system calls.

DTrace gebruik die **`dtrace_probe_create`**-function om ’n probe vir elke system call te skep. Hierdie probes kan by die **entry- en exit point van elke system call** afgevuur word. Die interaksie met DTrace vind plaas deur /dev/dtrace, wat slegs vir die root user beskikbaar is.

> [!TIP]
> Om Dtrace te aktiveer sonder om SIP-beskerming volledig te deaktiveer, kan jy in recovery mode uitvoer: `csrutil enable --without dtrace`
>
> Jy kan ook **`dtrace`**- of **`dtruss`**-binaries gebruik wat **jy self compiled** het.

Die beskikbare probes van dtrace kan verkry word met:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Die probe-naam bestaan uit vier dele: die provider, module, funksie en naam (`fbt:mach_kernel:ptrace:entry`). As jy nie ’n deel van die naam spesifiseer nie, sal Dtrace daardie deel as ’n wildcard toepas.

Om DTrace op te stel om probes te aktiveer en te spesifiseer watter aksies uitgevoer moet word wanneer hulle geaktiveer word, sal ons die D-taal moet gebruik.

’n Meer gedetailleerde verduideliking en meer voorbeelde kan gevind word by [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Voorbeelde

Voer `man -k dtrace` uit om die **DTrace-skripte wat beskikbaar is** te lys. Voorbeeld: `sudo dtruss -n binary`

- In lyn
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

Dit is 'n kernelnasporingsfasiliteit. Die gedokumenteerde kodes kan in **`/usr/share/misc/trace.codes`** gevind word.

Tools soos `latency`, `sc_usage`, `fs_usage` en `trace` gebruik dit intern.

Om met `kdebug` te kommunikeer, word `sysctl` oor die `kern.kdebug`-namespace gebruik, en die MIBs wat gebruik moet word, kan gevind word in `sys/sysctl.h`, met die funksies geïmplementeer in `bsd/kern/kdebug.c`.

Om met kdebug deur middel van 'n custom client te kommunikeer, is die volgende gewoonlik die stappe:

- Verwyder bestaande settings met KERN_KDSETREMOVE
- Stel trace op met KERN_KDSETBUF en KERN_KDSETUP
- Gebruik KERN_KDGETBUF om die aantal buffer-inskrywings te kry
- Kry die eie client uit die trace met KERN_KDPINDEX
- Aktiveer tracing met KERN_KDENABLE
- Lees die buffer deur KERN_KDREADTR aan te roep
- Om elke thread met sy proses te koppel, roep KERN_KDTHRMAP aan.

Om hierdie inligting te verkry, is dit moontlik om die Apple-tool **`trace`** of die custom tool [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** te gebruik.**

**Let daarop dat Kdebug slegs vir 1 kliënt op 'n slag beskikbaar is.** Dus kan slegs een k-debug-aangedrewe tool op dieselfde tyd uitgevoer word.

### ktrace

Die `ktrace_*`-APIs kom van `libktrace.dylib`, wat dié van `Kdebug` omvou. 'n Client kan dan eenvoudig `ktrace_session_create` en `ktrace_events_[single/class]` aanroep om callbacks op spesifieke kodes te stel, en dit daarna met `ktrace_start` begin.

Jy kan hierdie een selfs met **SIP geaktiveer** gebruik.

Jy kan die `ktrace`-utility as client gebruik:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Of `tailspin`.

### kperf

Dit word gebruik om profilering op kernvlak uit te voer en is gebou met `Kdebug`-aanroepe.

Basies word die globale veranderlike `kernel_debug_active` nagegaan en, indien dit gestel is, roep dit `kperf_kdebug_handler` aan met die `Kdebug`-kode en adres van die kernraamwerk wat die oproep doen. Indien die `Kdebug`-kode met een van die geselekteerde kodes ooreenstem, kry dit die "actions" wat as ’n bitmap gekonfigureer is (sien `osfmk/kperf/action.h` vir die opsies).

Kperf het ook ’n sysctl MIB-tabel: (as root) `sysctl kperf`. Hierdie kode kan in `osfmk/kperf/kperfbsd.c` gevind word.

Daarbenewens is ’n subset van Kperf se funksionaliteit in `kpc` geleë, wat inligting oor masjienwerkverrigtingstellers verskaf.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) is ’n baie nuttige hulpmiddel om die prosesverwante aksies wat ’n proses uitvoer, na te gaan (byvoorbeeld om te monitor watter nuwe prosesse ’n proses skep).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) is ’n hulpmiddel wat die verhoudings tussen prosesse druk.\
Jy moet jou Mac monitor met ’n opdrag soos **`sudo eslogger fork exec rename create > cap.json`** (die terminale wat dit begin, benodig FDA). Daarna kan jy die json in hierdie hulpmiddel laai om al die verhoudings te sien:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) laat jou toe om lêergebeurtenisse (soos skepping, wysigings en uitvee) te monitor en verskaf gedetailleerde inligting oor sulke gebeurtenisse.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) is ’n GUI-hulpmiddel met die voorkoms en gevoel waarmee Windows-gebruikers moontlik vertroud is vanuit Microsoft Sysinternal se _Procmon_. Hierdie hulpmiddel laat toe dat die opname van verskeie gebeurtenistipes begin en gestop word, laat filtering van hierdie gebeurtenisse volgens kategorieë soos lêer, proses, netwerk, ensovoorts toe, en bied die funksionaliteit om die opgeneemde gebeurtenisse in ’n json-formaat te stoor.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) is deel van Xcode se Developer tools – dit word gebruik om toepassingswerkverrigting te monitor, memory leaks te identifiseer en lêerstelselaktiwiteit na te spoor.

![Crescendo - Apple Instruments: Apple Instruments is deel van Xcode se Developer tools – dit word gebruik om toepassingswerkverrigting te monitor, memory leaks te identifiseer en lêerstelselaktiwiteit na te spoor](<../../../images/image (1138).png>)

### fs_usage

Laat jou toe om aksies wat deur prosesse uitgevoer word, te volg:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) is nuttig om die **biblioteke** wat deur 'n binary gebruik word, die **lêers** wat dit gebruik en die **netwerk**-verbindings te sien.\
Dit kontroleer ook die binary-prosesse teen **virustotal** en wys inligting oor die binary.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

In [**hierdie blogplasing**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) kan jy 'n voorbeeld vind van hoe om 'n **lopende daemon te debug** wat **`PT_DENY_ATTACH`** gebruik het om debugging te voorkom, selfs al was SIP gedeaktiveer.

### lldb

**lldb** is die de facto hulpmiddel vir **macOS** binary-**debugging**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Jy kan die Intel flavour instel wanneer jy lldb gebruik deur ’n lêer genaamd **`.lldbinit`** in jou tuisvouer te skep met die volgende reël:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Binne lldb, dump ’n proses met `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Opdrag</strong></td><td><strong>Beskrywing</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Begin uitvoering, wat ononderbroke voortgaan totdat ’n breakpoint getref word of die proses beëindig.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Begin uitvoering en stop by die entry point</td></tr><tr><td><strong>continue (c)</strong></td><td>Gaan voort met die uitvoering van die debugde proses.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Voer die volgende instruksie uit. Hierdie opdrag slaan funksie-aanroepe oor.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Voer die volgende instruksie uit. Anders as die nexti-opdrag, tree hierdie opdrag binne funksie-aanroepe in.</td></tr><tr><td><strong>finish (f)</strong></td><td>Voer die res van die instruksies in die huidige funksie (“frame”) uit, keer terug en stop.</td></tr><tr><td><strong>control + c</strong></td><td>Laat uitvoering wag. As die proses met (r) uitgevoer of met (c) voortgesit is, sal dit veroorsaak dat die proses stop ...waar dit tans uitgevoer word.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Any func called main</p><p><code>b <binname>`main</code> #Main func of the bin</p><p><code>b set -n main --shlib <lib_name></code> #Main func of the indicated bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Any NSFileManager method</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint list</p><p><code>br e/dis <num></code> #Enable/Disable breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Vertoon die geheue as ’n nulbeëindigde string.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Vertoon die geheue as ’n assembly-instruksie.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Vertoon die geheue as ’n byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Dit druk die objek waarna die parameter verwys</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Let daarop dat die meeste van Apple se Objective-C APIs of metodes objekte terugstuur en dus met die “print object”- (po-)opdrag vertoon moet word. As po nie betekenisvolle uitvoer lewer nie, gebruik <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Druk ’n kaart van die huidige proses se geheue</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Get the address of all the symbols from CoreNLP</td></tr></tbody></table>

> [!TIP]
> Wanneer die **`objc_sendMsg`**-funksie aangeroep word, bevat die **rsi**-register die **naam van die metode** as ’n nulbeëindigde (“C”)-string. Om die naam via lldb te druk, doen:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-dinamiese analise

#### VM-opsporing

- Die opdrag **`sysctl hw.model`** gee "Mac" terug wanneer die **host ’n MacOS** is, maar iets anders wanneer dit ’n VM is.
- Deur met die waardes van **`hw.logicalcpu`** en **`hw.physicalcpu`** te speel, probeer sommige malware vasstel of dit ’n VM is.
- Sommige malware kan ook vasstel of die masjien **VMware** is op grond van die MAC-adres (00:50:56).
- Dit is ook moontlik om vas te stel **of ’n proses gedebug word** met eenvoudige kode soos:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Dit kan ook die **`ptrace`**-stelseloproep met die **`PT_DENY_ATTACH`**-vlag aanroep. Dit **verhoed** dat ’n deb**u**gger attach en tracing uitvoer.
- Jy kan kyk of die **`sysctl`**- of **`ptrace`**-funksie **ingevoer** word (maar die malware kan dit dinamies invoer)
- Soos in hierdie writeup aangedui, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Die boodskap Process # exited with **status = 45 (0x0000002d)** is gewoonlik ’n duidelike aanduiding dat die debug-teiken **`PT_DENY_ATTACH`** gebruik_”

## Core dumps

Core dumps word geskep indien:

- `kern.coredump` sysctl op 1 gestel is (by verstek)
- Indien die proses nie suid/sgid was nie, of `kern.sugid_coredump` 1 is (by verstek is dit 0)
- Die `AS_CORE`-limiet die operasie toelaat. Dit is moontlik om die skep van core dumps te onderdruk deur `ulimit -c 0` aan te roep en dit weer met `ulimit -c unlimited` te aktiveer.

In daardie gevalle word die core dump volgens die `kern.corefile`-sysctl gegenereer en gewoonlik in `/cores/core/.%P` gestoor.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **ontleed prosesse wat crash en stoor ’n crash report op skyf**. ’n Crash report bevat inligting wat ’n **developer kan help om** die oorsaak van ’n crash **te diagnoseer**.\
Vir toepassings en ander prosesse **wat in die per-user launchd-konteks loop**, loop ReportCrash as ’n LaunchAgent en stoor dit crash reports in die gebruiker se `~/Library/Logs/DiagnosticReports/`\
Vir daemons, ander prosesse **wat in die system launchd-konteks loop** en ander geprivilegieerde prosesse, loop ReportCrash as ’n LaunchDaemon en stoor dit crash reports in die stelsel se `/Library/Logs/DiagnosticReports`

As jy bekommerd is dat crash reports **na Apple gestuur word**, kan jy dit deaktiveer. Indien nie, kan crash reports nuttig wees om **uit te vind hoe ’n server gecrash het**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Slaap

Wanneer jy op ’n MacOS fuzzing uitvoer, is dit belangrik om nie toe te laat dat die Mac slaap nie:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH-ontkoppeling

As jy fuzzing via ’n SSH-verbinding uitvoer, is dit belangrik om seker te maak dat die sessie nie gaan ontkoppel nie. Verander dus die sshd_config-lêer met:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Interne Handlers

**Kyk na die volgende bladsy** om uit te vind hoe jy kan bepaal watter app verantwoordelik is vir die **hantering van die gespesifiseerde skema of protokol:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Opsomming van netwerkprosesse

Dit is nuttig om prosesse te vind wat netwerkdata bestuur:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Of gebruik `netstat` of `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Werk vir CLI tools

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Dit "**werk net"** met macOS GUI tools. Let daarop dat sommige macOS apps spesifieke vereistes het, soos unieke lêername, die regte uitbreiding, of dat die lêers vanaf die sandbox (`~/Library/Containers/com.apple.Safari/Data`) gelees moet word...

Enkele voorbeelde:
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
### Meer Fuzzing MacOS-inligting

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Verwysings

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Volume I: Analysis](https://taomm.org/vol1/analysis.html)
- [4] [The Art of Mac Malware: The Guide to Analyzing Malicious Software](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
