# macOS-toepassings - Inspeksie, debugging en Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Statiese analise

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

Jy kan [**disarm hier aflaai**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Let daarop dat **`disarm`** ook met saamgeperste IM4P-lêers (soos `kernelcache`) kan werk en slegs die vereiste dele kan onttrek, of selfs die vereiste deel kan ontleed sonder om dit te onttrek.

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) is ’n nuttige hulpmiddel om **.pkg**-lêers (installeerders) te inspekteer en te sien wat daarin is voordat dit geïnstalleer word.\
Hierdie installeerders het `preinstall`- en `postinstall`-bash-skripte wat malware-outeurs gewoonlik misbruik om die malware te **persist**.

### hdiutil

Hierdie hulpmiddel **mounts** Apple-skyfbeeldlêers (`.dmg`), sodat hulle geïnspekteer kan word voordat enigiets uitgevoer word:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Dit sal in `/Volumes` gemonteer word

### Gepakte binaries

- Kyk vir hoë entropie
- Kyk na die strings (is daar byna geen verstaanbare string nie, is dit gepak)
- Die UPX-packer vir macOS genereer ’n section genaamd `__XHDR`.

## Statiese Objective-C-analise

### Metadata

> [!CAUTION]
> Let daarop dat programme wat in Objective-C geskryf is, hul klasverklarings **behou** wanneer hulle in [Mach-O-binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) **gecompileer** word. Sulke klasverklarings **sluit** die name en tipes in van:

- Die gedefinieerde interfaces
- Die interfacemetodes
- Die interface-instance variables
- Die gedefinieerde protocols

Let daarop dat hierdie name geobfuskeer kan word om die reverse engineering van die binary moeiliker te maak.

### Funksie-oproepe

Wanneer ’n funksie in ’n binary wat Objective-C gebruik, aangeroep word, sal die gecompileerde kode eerder **`objc_msgSend`** aanroep. Dit sal die finale funksie aanroep:

![Metadata - Funksie-oproepe: Wanneer ’n funksie in ’n binary wat Objective-C gebruik, aangeroep word, sal die gecompileerde kode eerder objc msgSend aanroep. Dit sal...](<../../../images/image (305).png>)

Die parameters wat hierdie funksie verwag, is:

- Die eerste parameter (**self**) is "'n pointer wat wys na die **instansie van die klas wat die boodskap moet ontvang**". Of eenvoudiger gestel, dit is die object waarop die metode aangeroep word. As die metode ’n klasmetode is, sal dit ’n instansie van die klasobject (as geheel) wees; vir ’n instansiemetode sal self na ’n geïnstansieerde instansie van die klas as ’n object wys.
- Die tweede parameter, (**op**), is "die selector van die metode wat die boodskap hanteer". Weer eens, eenvoudiger gestel, dit is bloot die **naam van die metode.**
- Die oorblywende parameters is enige **waardes wat deur die metode vereis word** (op).

Kyk op hierdie bladsy hoe om hierdie **inligting maklik met `lldb` in ARM64 te kry**:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(vir) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1ste argument** | **rdi**                                                         | **self: object waarop die metode aangeroep word**      |
| **2de argument**  | **rsi**                                                         | **op: naam van die metode**                            |
| **3de argument**  | **rdx**                                                         | **1ste argument aan die metode**                       |
| **4de argument**  | **rcx**                                                         | **2de argument aan die metode**                        |
| **5de argument**  | **r8**                                                          | **3de argument aan die metode**                        |
| **6de argument**  | **r9**                                                          | **4de argument aan die metode**                        |
| **7de+ argument** | <p><strong>rsp+</strong><br><strong>(op die stack)</strong></p> | **5de+ argument aan die metode**                       |

### Dump ObjectiveC-metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) is ’n tool om Objective-C-binaries met class-dump te ondersoek. Die GitHub-beskrywing spesifiseer dylibs, maar dit werk ook met executables.

```bash
./dynadump dump /path/to/bin
```

Ten tyde van die skryf hiervan is dit tans die beste werkende een.

#### Standaardnutsgoed

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) is die oorspronklike hulpmiddel om verklarings vir die klasse, kategorieë en protokolle in ObjectiveC-geformateerde kode te genereer.

Dit is oud en word nie onderhou nie, so dit sal waarskynlik nie behoorlik werk nie.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) is ’n moderne, kruisplatform Objective-C-klasdump. In vergelyking met bestaande hulpmiddels kan iCDump onafhanklik van die Apple-ekosisteem loop en bied dit Python-bindings.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Statiese Swift-analise

Met Swift-binaries kan jy soms verklarings met [class-dump](https://github.com/nygard/class-dump/) onttrek, aangesien daar Objective-C-versoenbaarheid is, maar nie altyd nie.

Met die **`jtool -l`**- of **`otool -l`**-opdragreëls is dit moontlik om verskeie seksies te vind wat met die **`__swift5`**-voorvoegsel begin:

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

Jy kan verdere inligting vind oor die [**inligting wat in hierdie afdelings gestoor word, in hierdie blogplasing**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Verder **kan Swift-binaries symbols bevat** (biblioteke moet byvoorbeeld symbols stoor sodat hul funksies opgeroep kan word). Die **symbols bevat gewoonlik inligting oor die funksienaam** en attributes op ’n lelike manier, dus is hulle baie nuttig, en daar is **"demanglers"** wat die oorspronklike naam kan herwin:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Dinamiese analise

> [!WARNING]
> Let daarop dat **SIP gedeaktiveer moet wees** (`csrutil disable` or `csrutil enable --without debug`) om binaries te debug, of kopieer die binaries na ’n tydelike vouer en **verwyder die handtekening** met `codesign --remove-signature <binary-path>`, of laat die binary toe om gedebug te word (jy kan [this script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) gebruik)

> [!WARNING]
> Let daarop dat **SIP gedeaktiveer moet wees** om **system binaries** (soos `cloudconfigurationd`) op macOS te **instrumenteer** (om net die handtekening te verwyder, sal nie werk nie).

### APIs

macOS stel ’n paar interessante APIs beskikbaar wat inligting oor prosesse verskaf:

- `proc_info`: Dit is die belangrikste API en verskaf baie inligting oor elke proses. Jy moet root wees om inligting oor ander prosesse te kry, maar jy het nie spesiale entitlements of mach ports nodig nie.
- `libsysmon.dylib`: Stel prosesinligting deur XPC-funksies beskikbaar, maar oproepers benodig die `com.apple.sysmond.client` entitlement.

### Stackshot & microstackshots

**Stackshotting** is ’n tegniek waarmee die toestand van prosesse vasgelê word, insluitend die call stacks van alle lopende threads. Dit is veral nuttig vir debugging, prestasie-analise en om die gedrag van die stelsel op ’n spesifieke tydstip te verstaan. Op iOS en macOS kan stackshotting met verskeie nutsgoed en metodes gedoen word, soos die nutsgoed **`sample`** en **`spindump`**.

### Sysdiagnose

Hierdie nutsding (`/usr/bini/ysdiagnose`) versamel basies baie inligting van jou rekenaar deur tientalle verskillende opdragte uit te voer, soos `ps`, `zprint`...

Dit moet as **root** uitgevoer word, en die daemon `/usr/libexec/sysdiagnosed` het baie interessante entitlements, soos `com.apple.system-task-ports` en `get-task-allow`.

Die plist is geleë by `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, wat 3 MachServices verklaar:

- `com.apple.sysdiagnose.CacheDelete`: Verwyder ou argiewe in /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Spesiale poort 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Gebruikersmodus-koppelvlak deur die `Libsysdiagnose` Obj-C-klas. Drie argumente kan in ’n dict deurgegee word (`compress`, `display`, `run`)

### Unified Logs

macOS genereer uitgebreide logs wat nuttig is wanneer ’n toepassing se gedrag ontleed word.

Sommige logvelde bevat die merker `<private>` om inligting wat die gebruiker of toestel identifiseer, te versteek. Ouer instruksies beskryf soms hoe om ’n sertifikaat te installeer om hierdie velde te wys; huidige debugging-riglyne gebruik eerder ’n uitdruklik beperkte konfigurasieprofiel met `Enable-Private-Data`, of `OSLogPreferences` per toepassing. Die gedrag kan per subsisteem en macOS-weergawe verskil. Die bespreking van die ouer sertifikaat/profiel word in die verwysings behou. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Linkerpaneel

In Hopper se linkerpaneel kan jy die binary se simbole (**Labels**), die lys prosedures en funksies (**Proc**) en die stringe (**Str**) sien. Dit is nie al die stringe nie, maar dié wat in verskeie dele van die Mac-O-lêer gedefinieer is (soos _cstring of_ `objc_methname`).

#### Middelpaneel

In die middelste paneel kan jy die **gedisassembleerde kode** sien. Jy kan dit as ’n **raw** disassembly, as ’n **graph**, as **decompiled** en as **binary** bekyk deur op die ooreenstemmende ikoon te klik:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

As jy met die regtermuisknoppie op ’n kodeobjek klik, kan jy **verwysings na/van daardie objek** sien of selfs die naam daarvan verander (dit werk nie in gedecompileerde pseudokode nie):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Daarbenewens kan jy **python-opdragte in die middel onderaan skryf**.

#### Regterpaneel

In die regterpaneel kan jy interessante inligting sien, soos die **navigasiegeskiedenis** (sodat jy weet hoe jy by die huidige situasie uitgekom het), die **call graph**, waar jy al die **funksies kan sien wat hierdie funksie aanroep** en al die funksies wat **deur hierdie funksie aangeroep word**, en inligting oor **local variables**.

### dtrace

Dit gee gebruikers toegang tot toepassings op ’n uiters **lae vlak** en bied ’n manier om **programme te trace** en selfs hul uitvoeringsvloei te verander. Dtrace gebruik **probes** wat **regdeur die kernel geplaas is**, op plekke soos die begin en einde van system calls.

DTrace gebruik die funksie **`dtrace_probe_create`** om ’n probe vir elke system call te skep. Hierdie probes kan by die **begin- en eindpunt van elke system call** afgaan. Interaksie met DTrace vind deur /dev/dtrace plaas, wat slegs vir die root-gebruiker beskikbaar is.<sup>[[1]](#references)</sup>

> [!TIP]
> Om Dtrace te aktiveer sonder om SIP-beskerming heeltemal te deaktiveer, kan jy in recovery mode die volgende uitvoer: `csrutil enable --without dtrace`
>
> Jy kan ook binaries **wat jy self saamgestel het**, met **`dtrace`** of **`dtruss`** ondersoek.

Die beskikbare probes van dtrace kan soos volg verkry word:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Die probenaam bestaan uit vier dele: die verskaffer, module, funksie en naam (`fbt:mach_kernel:ptrace:entry`). As jy nie ’n deel van die naam spesifiseer nie, sal DTrace daardie deel as ’n jokerteken toepas.

Om DTrace in te stel om probes te aktiveer en te spesifiseer watter aksies uitgevoer moet word wanneer hulle aktiveer, moet ons die D-taal gebruik.

’n Meer gedetailleerde verduideliking en meer voorbeelde kan gevind word by [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Voorbeelde

Voer `man -k dtrace` uit om die **beskikbare DTrace-skripte** te lys. Voorbeeld: `sudo dtruss -n binary`

- Inlyn

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

Dit is ’n kernel-nasporingsfasiliteit. Die gedokumenteerde kodes is in **`/usr/share/misc/trace.codes`**.

Gereedskap soos `latency`, `sc_usage`, `fs_usage` en `trace` gebruik dit intern.

Om met `kdebug` te koppel, word `sysctl` oor die `kern.kdebug`-namespace gebruik. Die MIB’s wat gebruik moet word, is in `sys/sysctl.h`; die funksies word in `bsd/kern/kdebug.c` geïmplementeer.

Om met ’n pasgemaakte kliënt met kdebug te kommunikeer, is die stappe gewoonlik:

- Verwyder bestaande instellings met KERN_KDSETREMOVE
- Stel trace op met KERN_KDSETBUF en KERN_KDSETUP
- Gebruik KERN_KDGETBUF om die aantal bufferinskrywings te kry
- Haal jou eie kliënt uit die trace met KERN_KDPINDEX
- Aktiveer nasporing met KERN_KDENABLE
- Lees die buffer deur KERN_KDREADTR aan te roep
- Roep KERN_KDTHRMAP aan om elke thread met sy proses te koppel.

Om hierdie inligting te kry, kan jy die Apple-gereedskap **`trace`** of die pasgemaakte gereedskap [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** gebruik.

**Let daarop dat Kdebug net vir 1 gebruiker op ’n slag beskikbaar is.** Dus kan net een k-debug-aangedrewe gereedskap op dieselfde tyd loop.

### ktrace

Die `ktrace_*`-API’s kom van `libktrace.dylib`, wat dié van `Kdebug` omhul. ’n Kliënt kan dan eenvoudig `ktrace_session_create` en `ktrace_events_[single/class]` aanroep om terugroepe vir spesifieke kodes in te stel, en dit dan met `ktrace_start` begin.

Jy kan hierdie een selfs met **SIP geaktiveer** gebruik.

Jy kan die nutsprogram `ktrace` as kliënt gebruik:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Of `tailspin`.

### kperf

Dit word gebruik om profilering op kernvlak uit te voer en is gebou met `Kdebug`-terugroepe.

Basies word die globale veranderlike `kernel_debug_active` nagegaan, en as dit gestel is, roep dit `kperf_kdebug_handler` aan met die `Kdebug`-kode en die adres van die kernraamwerk wat die oproep doen. As die `Kdebug`-kode ooreenstem met een wat gekies is, kry dit die “actions” wat as ’n bitmap gekonfigureer is (kyk na `osfmk/kperf/action.h` vir die opsies).

Kperf het ook ’n sysctl MIB-tabel: (as root) `sysctl kperf`. Hierdie kode kan gevind word in `osfmk/kperf/kperfbsd.c`.

Daarbenewens is ’n subset van Kperf se funksionaliteit in `kpc`, wat inligting oor masjienwerkverrigtingtellers verskaf.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) is ’n baie nuttige hulpmiddel om die prosesverwante aksies na te gaan wat ’n proses uitvoer (byvoorbeeld, om te monitor watter nuwe prosesse ’n proses skep).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) is ’n hulpmiddel wat die verwantskappe tussen prosesse vertoon.\
Jy moet jou Mac monitor met ’n opdrag soos **`sudo eslogger fork exec rename create > cap.json`** (die terminaal wat dit begin, vereis FDA). Daarna kan jy die JSON in hierdie hulpmiddel laai om al die verwantskappe te sien:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) monitor lêergebeurtenisse soos skep, wysig en verwyder.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) is ’n GUI-hulpmiddel met die voorkoms en gevoel van Microsoft Sysinternal se _Procmon_, wat Windows-gebruikers dalk ken. Met hierdie hulpmiddel kan verskeie gebeurtenistipes opgeneem en die opname daarvan gestop word, kan hierdie gebeurtenisse volgens kategorieë soos lêer, proses, netwerk, ens. gefiltreer word, en kan die opgeneemde gebeurtenisse in JSON-formaat gestoor word.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) is deel van Xcode se Developer tools – dit word gebruik om toepassingwerkverrigting te monitor, geheuelekkasies te identifiseer en lêerstelselaktiwiteit na te spoor.

![Crescendo - Apple Instruments: Apple Instruments is deel van Xcode se Developer tools – dit word gebruik om toepassingwerkverrigting te monitor, geheuelekkasies te identifiseer en lêerstelselaktiwiteit na te spoor](<../../../images/image (1138).png>)

### fs_usage

Laat jou toe om aksies te volg wat deur prosesse uitgevoer word:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) is nuttig om die **libraries** te sien wat ’n binary gebruik, die **files** wat dit gebruik en die **network**-verbindings.\
Dit kontroleer ook die binary-prosesse teen **virustotal** en wys inligting oor die binary.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

In [**hierdie blogplasing**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) kan jy ’n voorbeeld vind van hoe om ’n lopende daemon te **debug** wat **`PT_DENY_ATTACH`** gebruik het om debugging te voorkom, selfs al was SIP gedeaktiveer.<sup>[[6]](#references)</sup>

### lldb

**lldb** is die de facto-instrument vir **macOS**-binary-**debugging**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Jy kan die Intel-flavour stel wanneer jy lldb gebruik deur ’n lêer genaamd **`.lldbinit`** in jou tuisvouer te skep met die volgende reël:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Dump 'n proses binne lldb met `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>Beskrywing</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Begin uitvoering. Dit gaan voort totdat 'n breakpoint getref word of die proses beëindig.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Begin uitvoering en stop by die toegangspunt.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Gaan voort met die uitvoering van die proses wat gedebug word.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Voer die volgende instruksie uit. Hierdie opdrag spring oor funksie-oproepe.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Voer die volgende instruksie uit. Anders as die <code>nexti</code>-opdrag, tree hierdie opdrag binne funksie-oproepe in.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Voer die oorblywende instruksies in die huidige funksie (raamwerk) uit, keer terug en stop.</td></tr>
<tr><td><strong>control + c</strong></td><td>Laat uitvoering wag. As die proses begin is (<code>r</code>) of voortgesit is (<code>c</code>), laat dit die proses stop waar dit tans uitvoer.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Any function called main</p>
<p><code>b &lt;binname&gt;`main</code> # Main function of the binary</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Main function of the indicated binary</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Any NSFileManager method</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Breakpoint list</p>
<p><code>br e/dis &lt;num&gt;</code> # Enable/disable breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Get help for the breakpoint command</p>
<p><code>help memory write</code> # Get help for writing to memory</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Vertoon geheue as 'n nul-beëindigde string.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Vertoon geheue as 'n assembly-instruksie.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Vertoon geheue as 'n greep.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Dit druk die objek uit waarna die parameter verwys.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
Die meeste Apple Objective-C-API's of -metodes gee objekte terug en moet dus met die “print object”-opdrag (<code>po</code>) vertoon word. As <code>po</code> nie betekenisvolle uitvoer lewer nie, gebruik <code>x/b</code>.
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Write AAAA at that address<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Write AAAA at the address
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Disassemble the current function</p>
<p><code>dis -n &lt;funcname&gt;</code> # Disassemble a function</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Disassemble a function<br>
<code>dis -c 6</code> # Disassemble six lines<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Disassemble from one address to the other<br>
<code>dis -p -c 4</code> # Start disassembling at the current address</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Inspect an array of three components in the <code>x1</code> register</td></tr>
<tr><td><strong>image dump sections</strong></td><td>Druk 'n kaart van die huidige proses se geheue af.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Get the address of every symbol from CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Wanneer die **`objc_sendMsg`**-funksie geroep word, bevat die **rsi**-register die **naam van die metode** as 'n nul-beëindigde (“C”)-string. Om die naam via lldb te druk, doen die volgende:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM-opsporing

- Die **`sysctl hw.model`**-opdrag gee gewoonlik 'n Mac-modelidentifiseerder op fisiese hardeware terug, en kan 'n ander waarde in 'n VM teruggee.<sup>[[3]](#references)</sup>
- Sommige malware probeer met die waardes van **`hw.logicalcpu`** en **`hw.physicalcpu`** vasstel of dit 'n VM is.<sup>[[4]](#references)</sup>
- Sommige malware kan ook **opspoor** of die masjien op **VMware** gebaseer is deur die MAC-adres (00:50:56) te gebruik.
- Dit is ook moontlik om met eenvoudige kode vas te stel **of 'n proses gedebug word**, soos:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Dit kan ook die **`ptrace`**-stelseloproep met die **`PT_DENY_ATTACH`**-vlag aanroep. Dit **verhoed** dat 'n debugger heg en opspoor.
  - Jy kan nagaan of die **`sysctl`**- of **`ptrace`**-funksie **ingevoer** word (maar die malware kan dit dinamies invoer)
  - Soos in hierdie skrywe vermeld, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_The message Process # exited with **status = 45 (0x0000002d)** is usually a tell-tale sign that the debug target is using **PT_DENY_ATTACH**_”

#### `fork()`-prosesoordrag

'n Proses kan 'n debugger ontduik wat aan die oorspronklike PID geheg bly deur kort ná opstart `fork()` aan te roep, die ouerproses te beëindig (`fork()` gee 'n positiewe kind-PID terug) en die beskermde logika slegs in die kindproses voort te sit (`fork()` gee `0` terug). As `fork` met `dlsym(RTLD_DEFAULT, "fork")` opgelos word, word die direkte `_fork`-aanroeppunt ook verwyder. Dit is egter net 'n struikelblok vir analise: die string met die simboolnaam en die datavloei vir dinamiese resolusie bly sigbaar in die Mach-O-binêre lêer.<sup>[[10]](#references)[[11]](#references)</sup>

Op arm64 kan jy hierdie patroon opspoor deur die datavloei te volg eerder as vaste adresse: die eerste twee argumente vir `dlsym` word in `x0` en `x1` deurgegee, `RTLD_DEFAULT` kan as `-2` verskyn (byvoorbeeld `movn x0, #1`), en 'n `adrp`/`add`-paar stel dikwels die adres van die `"fork"`-string saam. Ná die `bl` na die `dlsym`-stub, volg jy die teruggekeerde wyser vanaf `x0` deur die null-kontrole en berging tot by 'n latere indirekte `blr`. Volg daarna die `fork()`-resultaat in `w0`: nul kies die kind se voortsettingspad, terwyl positiewe en `-1`-waardes die ouer-/foutpad kies.<sup>[[10]](#references)[[11]](#references)</sup>

'n Statiese omseiling is om die indirekte aanroep te onderdruk en die bestaande resultaatkontrole te dwing om die kindpad te kies. As die samesteller byvoorbeeld die volgorde hieronder gegenereer het, patch die `blr` en resultaatberging na `nop`, verskaf 'n sintetiese nulresultaat en behou die vergelykings-/vertakkingslogika. Die toepassing gaan dan voort onder die oorspronklike PID sonder om 'n kindproses te skep; pas die instruksieregisters en vertakkings-teikens aan by die geanaliseerde bouweergawe.<sup>[[10]](#references)[[11]](#references)</sup>

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

Core dumps word geskep as:

- `kern.coredump`-sysctl op 1 gestel is (by verstek)
- As die proses nie suid/sgid was nie, of `kern.sugid_coredump` op 1 gestel is (by verstek is dit 0)
- Die `AS_CORE`-limiet die bewerking toelaat. Dit is moontlik om die skep van core dumps te onderdruk deur `ulimit -c 0` aan te roep en dit weer te aktiveer met `ulimit -c unlimited`.

In daardie gevalle word die core dumps volgens die `kern.corefile`-sysctl gegenereer en gewoonlik in `/cores/core/.%P` gestoor.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **ontleed prosesse wat omval en stoor 'n omvalverslag op skyf**. 'n Omvalverslag bevat inligting wat **'n ontwikkelaar kan help om die oorsaak van 'n omval te diagnoseer**.\
Vir toepassings en ander prosesse **wat in die per-gebruiker launchd-konteks loop**, loop ReportCrash as 'n LaunchAgent en stoor dit omvalverslae in die gebruiker se `~/Library/Logs/DiagnosticReports/`\
Vir daemone, ander prosesse **wat in die stelsel se launchd-konteks loop** en ander bevoorregte prosesse, loop ReportCrash as 'n LaunchDaemon en stoor dit omvalverslae in die stelsel se `/Library/Logs/DiagnosticReports`

As jy bekommerd is dat omvalverslae **na Apple gestuur word**, kan jy dit deaktiveer. Andersins kan omvalverslae nuttig wees om **uit te vind hoe 'n bediener omgeval het**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Slaap

Wanneer jy op macOS fuzzing uitvoer, voorkom dat die Mac gaan slaap:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH-verbinding verbreek

As jy fuzzing via ’n SSH-verbinding uitvoer, is dit belangrik om seker te maak dat die sessie nie gaan doodloop nie. Verander dus die sshd_config-lêer soos volg:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Interne hanteerders

**Kyk na die volgende bladsy** om uit te vind hoe jy kan bepaal watter app verantwoordelik is vir **die hantering van die gespesifiseerde skema of protokol:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Netwerkprosesse opnoem

Dit is interessant om prosesse te vind wat netwerkdata bestuur:

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

Werk vir CLI-nutsgoed

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Dit "**werk sommer**" met baie macOS-GUI-nutsgoed. Sommige toepassings het bykomende vereistes, soos unieke lêername, ’n spesifieke uitbreiding of om lêers uit hul sandbox-houer te lees (`~/Library/Containers/com.apple.Safari/Data`).

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

### Meer inligting oor macOS-fuzzing

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [OS X-voorvalreaksie: scripting en ontleding](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Somer van Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Die kuns van Mac-malware, Deel I: Ontleding](https://taomm.org/)
- [4] [No Starch Press - Die kuns van Mac-malware: Die gids vir die ontleding van kwaadwillige sagteware](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - inligting wat in hierdie afdeling in hierdie blogplasing gestoor is](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Ontfouting van Apple-binêre lêers wat Pt Deny Attach gebruik](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Om anti-ontfoutingstegnieke te verydel: macOS ptrace-variante](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcode-gestruktureerde logs en `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Wys private data in die macOS-eenvormige log](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [tony-go/antidebug-examples - fork-voorbeelde](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [11] [Reverse Society - Anti-ontfoutingstegniek wat dlsym en fork gebruik](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
{{#include ../../../banners/hacktricks-training.md}}
