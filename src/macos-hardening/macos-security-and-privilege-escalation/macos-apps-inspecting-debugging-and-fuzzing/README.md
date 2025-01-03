# macOS Apps - Inspekteer, debugg en Fuzzing

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
### jtool2 & Disarm

Jy kan [**disarm hier afgelaai**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
U kan [**jtool2 hier aflaai**](http://www.newosxbook.com/tools/jtool.html) of dit met `brew` installeer.
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
> [!CAUTION] > **jtool is verouderd ten gunste van disarm**

### Codesign / ldid

> [!TIP] > **`Codesign`** kan in **macOS** gevind word terwyl **`ldid`** in **iOS** gevind kan word
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) is 'n hulpmiddel wat nuttig is om **.pkg** lêers (installeerders) te inspekteer en te sien wat binne is voordat dit geïnstalleer word.\
Hierdie installeerders het `preinstall` en `postinstall` bash-skripte wat malware-skrywers gewoonlik misbruik om **die** **malware** **te** **hou**.

### hdiutil

Hierdie hulpmiddel laat jou toe om Apple skyfbeeldes (**.dmg**) lêers te **monteer** om dit te inspekteer voordat jy enigiets uitvoer:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Dit sal gemonteer word in `/Volumes`

### Gepakte binêre

- Kontroleer vir hoë entropie
- Kontroleer die strings (as daar amper geen verstaanbare string is, gepak)
- Die UPX-pakker vir MacOS genereer 'n afdeling genaamd "\_\_XHDR"

## Statiese Objective-C analise

### Metadata

> [!CAUTION]
> Let daarop dat programme geskryf in Objective-C **die** klasverklarings **behou** **wanneer** **gecompileer** in [Mach-O binêre](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Sulke klasverklarings **sluit** die naam en tipe van in:

- Die interfaces wat gedefinieer is
- Die interface metodes
- Die interface instansie veranderlikes
- Die protokolle wat gedefinieer is

Let daarop dat hierdie name dalk obfuskeer kan word om die omkering van die binêre moeiliker te maak.

### Funksie-aanroep

Wanneer 'n funksie in 'n binêre wat Objective-C gebruik, aangeroep word, sal die gecompileerde kode in plaas daarvan om daardie funksie aan te roep, **`objc_msgSend`** aanroep. Wat die finale funksie sal aanroep:

![](<../../../images/image (305).png>)

Die parameters wat hierdie funksie verwag is:

- Die eerste parameter (**self**) is "n aanwijser wat na die **instansie van die klas wat die boodskap moet ontvang** wys". Of eenvoudiger gestel, dit is die objek waarop die metode aangeroep word. As die metode 'n klasmetode is, sal dit 'n instansie van die klasobjek (as 'n geheel) wees, terwyl dit vir 'n instansiemetode, self na 'n geïnstantieerde instansie van die klas as 'n objek sal wys.
- Die tweede parameter, (**op**), is "die selektor van die metode wat die boodskap hanteer". Weer eens, eenvoudiger gestel, dit is net die **naam van die metode.**
- Die oorblywende parameters is enige **waardes wat deur die metode vereis word** (op).

Sien hoe om **hierdie inligting maklik te kry met `lldb` in ARM64** op hierdie bladsy:

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(vir) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1ste argument**  | **rdi**                                                         | **self: objek waarop die metode aangeroep word**       |
| **2de argument**  | **rsi**                                                         | **op: naam van die metode**                             |
| **3de argument**  | **rdx**                                                         | **1ste argument aan die metode**                        |
| **4de argument**  | **rcx**                                                         | **2de argument aan die metode**                        |
| **5de argument**  | **r8**                                                          | **3de argument aan die metode**                        |
| **6de argument**  | **r9**                                                          | **4de argument aan die metode**                        |
| **7de+ argument** | <p><strong>rsp+</strong><br><strong>(op die stapel)</strong></p> | **5de+ argument aan die metode**                        |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) is 'n hulpmiddel om Objective-C binêre te klasdump. Die github spesifiseer dylibs maar dit werk ook met uitvoerbare lêers.
```bash
./dynadump dump /path/to/bin
```
Tydens die skryf hiervan, is dit **huidiglik die een wat die beste werk**.

#### Gereelde gereedskap
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) is die oorspronklike hulpmiddel om verklarings te genereer vir die klasse, kategorieë en protokolle in ObjetiveC geformateerde kode.

Dit is oud en word nie meer onderhou nie, so dit sal waarskynlik nie behoorlik werk nie.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) is 'n moderne en kruis-platform Objective-C klas dump. In vergelyking met bestaande hulpmiddels, kan iCDump onafhanklik van die Apple-ekosisteem werk en dit stel Python-bindings bloot.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Statiese Swift analise

Met Swift binêre, aangesien daar Objective-C kompatibiliteit is, kan jy soms verklarings onttrek met behulp van [class-dump](https://github.com/nygard/class-dump/) maar nie altyd nie.

Met die **`jtool -l`** of **`otool -l`** opdraglyne is dit moontlik om verskeie afdelings te vind wat met die **`__swift5`** voorvoegsel begin:
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
Jy kan verdere inligting oor die [**inligting wat in hierdie afdeling gestoor is in hierdie blogpos**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html) vind.

Boonop **kan Swift-binaries simbole hê** (byvoorbeeld biblioteke moet simbole stoor sodat hul funksies aangeroep kan word). Die **simbole het gewoonlik die inligting oor die funksienaam** en attribuut op 'n lelike manier, so hulle is baie nuttig en daar is "**demanglers"** wat die oorspronklike naam kan kry:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Dinamiese Analise

> [!WARNING]
> Let daarop dat om binêre te debugeer, **SIP moet gedeaktiveer word** (`csrutil disable` of `csrutil enable --without debug`) of om die binêre na 'n tydelike gids te kopieer en **die handtekening te verwyder** met `codesign --remove-signature <binary-path>` of om die debuggings van die binêre toe te laat (jy kan [hierdie skrip](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) gebruik).

> [!WARNING]
> Let daarop dat om **stelselsbinêre te instrumenteer**, (soos `cloudconfigurationd`) op macOS, **SIP moet gedeaktiveer word** (net die handtekening verwyder sal nie werk nie).

### API's

macOS stel 'n paar interessante API's bloot wat inligting oor die prosesse gee:

- `proc_info`: Dit is die hoof een wat baie inligting oor elke proses gee. Jy moet root wees om inligting oor ander prosesse te kry, maar jy het nie spesiale regte of mach-poorte nodig nie.
- `libsysmon.dylib`: Dit maak dit moontlik om inligting oor prosesse te verkry via XPC blootgestelde funksies, egter, dit is nodig om die regte `com.apple.sysmond.client` te hê.

### Stackshot & mikrostackshots

**Stackshotting** is 'n tegniek wat gebruik word om die toestand van die prosesse vas te vang, insluitend die oproepstapels van alle lopende drade. Dit is veral nuttig vir debuggings, prestasieanalise, en om die gedrag van die stelsel op 'n spesifieke tydstip te verstaan. Op iOS en macOS kan stackshotting uitgevoer word met verskeie gereedskap en metodes soos die gereedskap **`sample`** en **`spindump`**.

### Sysdiagnose

Hierdie gereedskap (`/usr/bini/ysdiagnose`) versamel basies baie inligting van jou rekenaar deur tientalle verskillende opdragte soos `ps`, `zprint`...

Dit moet as **root** uitgevoer word en die daemon `/usr/libexec/sysdiagnosed` het baie interessante regte soos `com.apple.system-task-ports` en `get-task-allow`.

Sy plist is geleë in `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` wat 3 MachServices verklaar:

- `com.apple.sysdiagnose.CacheDelete`: Verwyder ou argiewe in /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Spesiale poort 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Gebruikersmodus-koppelvlak deur `Libsysdiagnose` Obj-C klas. Drie argumente in 'n dict kan oorgedra word (`compress`, `display`, `run`)

### Geünifiseerde Logs

MacOS genereer baie logs wat baie nuttig kan wees wanneer 'n toepassing uitgevoer word om te probeer verstaan **wat dit doen**.

Boonop is daar 'n paar logs wat die etiket `<private>` sal bevat om **te verberg** sommige **gebruikers** of **rekenaar** **identifiseerbare** inligting. Dit is egter moontlik om **'n sertifikaat te installeer om hierdie inligting bekend te maak**. Volg die verduidelikings van [**hier**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Linker paneel

In die linker paneel van hopper is dit moontlik om die simbole (**Labels**) van die binêre, die lys van prosedures en funksies (**Proc**) en die strings (**Str**) te sien. Dit is nie al die strings nie, maar diegene wat in verskeie dele van die Mac-O-lêer gedefinieer is (soos _cstring of_ `objc_methname`).

#### Middelpaneel

In die middelpaneel kan jy die **gedissasembelde kode** sien. En jy kan dit as 'n **rauwe** disassemble, as **grafiek**, as **gedekodeer** en as **binêr** sien deur op die onderskeie ikoon te klik:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Regsklik op 'n kode objek kan jy **verwysings na/vanaf daardie objek** sien of selfs sy naam verander (dit werk nie in gedekodeerde pseudokode nie):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Boonop kan jy in die **middel onder python-opdragte skryf**.

#### Regter paneel

In die regter paneel kan jy interessante inligting sien soos die **navigasiegeskiedenis** (sodat jy weet hoe jy by die huidige situasie gekom het), die **oproepgrafiek** waar jy al die **funksies wat hierdie funksie oproep** en al die funksies wat **hierdie funksie oproep**, en **lokale veranderlikes** inligting kan sien.

### dtrace

Dit stel gebruikers in staat om toegang tot toepassings op 'n uiters **lae vlak** te verkry en bied 'n manier vir gebruikers om **programmas** te **volg** en selfs hul uitvoeringsvloei te verander. Dtrace gebruik **probes** wat **oor die kernel geplaas is** en is op plekke soos die begin en einde van stelselsoproepen.

DTrace gebruik die **`dtrace_probe_create`** funksie om 'n probe vir elke stelselsoproep te skep. Hierdie probes kan in die **toegang en uitgangspunt van elke stelselsoproep** geaktiveer word. Die interaksie met DTrace vind plaas deur /dev/dtrace wat slegs beskikbaar is vir die root gebruiker.

> [!TIP]
> Om Dtrace in te skakel sonder om SIP-beskerming heeltemal te deaktiveer, kan jy in herstelmodus uitvoer: `csrutil enable --without dtrace`
>
> Jy kan ook **`dtrace`** of **`dtruss`** binêre wat **jy gecompileer het**.

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
Die proefnaam bestaan uit vier dele: die verskaffer, module, funksie, en naam (`fbt:mach_kernel:ptrace:entry`). As jy nie 'n deel van die naam spesifiseer nie, sal Dtrace daardie deel as 'n wildcard toepas.

Om DTrace te konfigureer om probes te aktiveer en om te spesifiseer watter aksies uitgevoer moet word wanneer hulle afgaan, sal ons die D-taal moet gebruik.

'n Meer gedetailleerde verduideliking en meer voorbeelde kan gevind word in [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Voorbeelde

Voer `man -k dtrace` uit om die **DTrace skripte beskikbaar** te lys. Voorbeeld: `sudo dtruss -n binary`
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
- skrif
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

Dit is 'n kern-tracing fasiliteit. Die gedokumenteerde kodes kan gevind word in **`/usr/share/misc/trace.codes`**.

Gereedskap soos `latency`, `sc_usage`, `fs_usage` en `trace` gebruik dit intern.

Om met `kdebug` te kommunikeer, word `sysctl` gebruik oor die `kern.kdebug` naamruimte en die MIBs wat gebruik kan word, kan gevind word in `sys/sysctl.h` met die funksies geïmplementeer in `bsd/kern/kdebug.c`.

Om met kdebug te interaksie met 'n pasgemaakte kliënt, is dit gewoonlik die stappe:

- Verwyder bestaande instellings met KERN_KDSETREMOVE
- Stel trace in met KERN_KDSETBUF en KERN_KDSETUP
- Gebruik KERN_KDGETBUF om die aantal buffer inskrywings te kry
- Kry die eie kliënt uit die trace met KERN_KDPINDEX
- Aktiveer tracing met KERN_KDENABLE
- Lees die buffer deur KERN_KDREADTR aan te roep
- Om elke draad met sy proses te pas, bel KERN_KDTHRMAP.

Om hierdie inligting te verkry, is dit moontlik om die Apple-gereedskap **`trace`** of die pasgemaakte gereedskap [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Let daarop dat Kdebug slegs vir 1 kliënt op 'n slag beskikbaar is.** Dus kan slegs een k-debug aangedrewe gereedskap terselfdertyd uitgevoer word.

### ktrace

Die `ktrace_*` APIs kom van `libktrace.dylib` wat dié van `Kdebug` omhul. Dan kan 'n kliënt eenvoudig `ktrace_session_create` en `ktrace_events_[single/class]` aanroep om callbacks op spesifieke kodes in te stel en dit dan te begin met `ktrace_start`.

Jy kan hierdie een selfs gebruik met **SIP geaktiveer**

Jy kan die nut `ktrace` as kliënte gebruik:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Of `tailspin`.

### kperf

Dit word gebruik om 'n kernvlak-profilerings te doen en dit is gebou met behulp van `Kdebug` oproepe.

Basies, die globale veranderlike `kernel_debug_active` word nagegaan en as dit ingestel is, roep dit `kperf_kdebug_handler` aan met die `Kdebug` kode en adres van die kernraam wat aanroep. As die `Kdebug` kode ooreenstem met een wat gekies is, kry dit die "aksies" wat as 'n bitmap geconfigureer is (kyk `osfmk/kperf/action.h` vir die opsies).

Kperf het ook 'n sysctl MIB tabel: (as root) `sysctl kperf`. Hierdie kode kan gevind word in `osfmk/kperf/kperfbsd.c`.

Boonop, 'n subset van Kperf se funksionaliteit woon in `kpc`, wat inligting verskaf oor masjienprestasie tellers.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) is 'n baie nuttige hulpmiddel om die prosesverwante aksies wat 'n proses uitvoer, na te gaan (byvoorbeeld, om te monitor watter nuwe prosesse 'n proses skep).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) is 'n hulpmiddel om die verhoudings tussen prosesse te druk.\
Jy moet jou mac monitor met 'n opdrag soos **`sudo eslogger fork exec rename create > cap.json`** (die terminal wat dit begin vereis FDA). En dan kan jy die json in hierdie hulpmiddel laai om al die verhoudings te sien:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) laat jou toe om lêer gebeurtenisse (soos skepping, wysigings, en verwyderings) te monitor en bied gedetailleerde inligting oor sulke gebeurtenisse.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) is 'n GUI-hulpmiddel met die voorkoms en gevoel wat Windows-gebruikers dalk van Microsoft Sysinternal se _Procmon_ ken. Hierdie hulpmiddel laat die opname van verskeie gebeurtenistipes toe om begin en gestop te word, laat die filtrering van hierdie gebeurtenisse deur kategorieë soos lêer, proses, netwerk, ens. toe, en bied die funksionaliteit om die opgeneemde gebeurtenisse in 'n json-formaat te stoor.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) is deel van Xcode se Ontwikkelaarshulpmiddels – gebruik vir die monitering van toepassingsprestasie, die identifisering van geheuelekke en die opsporing van lêerstelselsaktiwiteit.

![](<../../../images/image (1138).png>)

### fs_usage

Laat toe om aksies wat deur prosesse uitgevoer word, te volg:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) is nuttig om die **biblioteke** wat deur 'n binêre gebruik word, die **lêers** wat dit gebruik en die **netwerk** verbindings te sien.\
Dit kontroleer ook die binêre prosesse teen **virustotal** en wys inligting oor die binêre.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

In [**hierdie blogpos**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) kan jy 'n voorbeeld vind van hoe om 'n **lopende daemon** te **debug** wat **`PT_DENY_ATTACH`** gebruik het om debugging te voorkom selfs al was SIP gedeaktiveer.

### lldb

**lldb** is die de **facto tool** vir **macOS** binêre **debugging**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Jy kan die intel-smaak instel wanneer jy lldb gebruik deur 'n lêer genaamd **`.lldbinit`** in jou tuisgids te skep met die volgende lyn:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Binne lldb, dump 'n proses met `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Opdrag</strong></td><td><strong>Besonderheid</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Begin uitvoering, wat ononderbroke sal voortduur totdat 'n breekpunt bereik word of die proses beëindig.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Begin uitvoering wat by die ingangspunt stop</td></tr><tr><td><strong>continue (c)</strong></td><td>Voortgaan met die uitvoering van die gedebugde proses.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Voer die volgende instruksie uit. Hierdie opdrag sal funksie-oproepe oorslaan.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Voer die volgende instruksie uit. Anders as die nexti-opdrag, sal hierdie opdrag in funksie-oproepe stap.</td></tr><tr><td><strong>finish (f)</strong></td><td>Voer die res van die instruksies in die huidige funksie (“raam”) uit, keer terug en stop.</td></tr><tr><td><strong>control + c</strong></td><td>Pauzeer uitvoering. As die proses gedraai (r) of voortgegaan (c) is, sal dit die proses laat stop ... waar dit ook al tans uitvoer.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Enige funksie genoem main</p><p><code>b &#x3C;binname>`main</code> #Hoof funksie van die bin</p><p><code>b set -n main --shlib &#x3C;lib_name></code> #Hoof funksie van die aangeduide bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Enige NSFileManager metode</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Breek in alle funksies van daardie biblioteek</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint lys</p><p><code>br e/dis &#x3C;num></code> #Aktiveer/deaktiveer breekpunt</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Kry hulp van breekpunt opdrag</p><p>help memory write #Kry hulp om in die geheue te skryf</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">formaat</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/geheue adres></strong></td><td>Vertoon die geheue as 'n null-beëindigde string.</td></tr><tr><td><strong>x/i &#x3C;reg/geheue adres></strong></td><td>Vertoon die geheue as assembly instruksie.</td></tr><tr><td><strong>x/b &#x3C;reg/geheue adres></strong></td><td>Vertoon die geheue as byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Dit sal die objek verwys deur die param druk</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Let daarop dat die meeste van Apple se Objective-C APIs of metodes objekte teruggee, en dus via die “print object” (po) opdrag vertoon moet word. As po nie 'n betekenisvolle uitvoer lewer nie, gebruik <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Skryf AAAA in daardie adres<br>memory write -f s $rip+0x11f+7 "AAAA" #Skryf AAAA in die addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas huidige funksie</p><p>dis -n &#x3C;funcname> #Disas funksie</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Disas funksie<br>dis -c 6 #Disas 6 lyne<br>dis -c 0x100003764 -e 0x100003768 # Van een add tot die ander<br>dis -p -c 4 # Begin in huidige adres disassemble</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Kontroleer array van 3 komponente in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Druk kaart van die huidige proses geheue</td></tr><tr><td><strong>image dump symtab &#x3C;library></strong></td><td><code>image dump symtab CoreNLP</code> #Kry die adres van al die simbole van CoreNLP</td></tr></tbody></table>

> [!NOTE]
> Wanneer die **`objc_sendMsg`** funksie aangeroep word, hou die **rsi** register die **naam van die metode** as 'n null-beëindigde (“C”) string. Om die naam via lldb te druk, doen:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dinamiese Analise

#### VM opsporing

- Die opdrag **`sysctl hw.model`** gee "Mac" terug wanneer die **gasheer 'n MacOS** is, maar iets anders wanneer dit 'n VM is.
- Deur met die waardes van **`hw.logicalcpu`** en **`hw.physicalcpu`** te speel, probeer sommige malware om te detecteer of dit 'n VM is.
- Sommige malware kan ook **opspoor** of die masjien **VMware** gebaseer is op die MAC adres (00:50:56).
- Dit is ook moontlik om te vind **of 'n proses gedebug word** met 'n eenvoudige kode soos:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //proses wat gedebug word }`
- Dit kan ook die **`ptrace`** stelselaanroep met die **`PT_DENY_ATTACH`** vlag aanroep. Dit **verhoed** 'n deb**u**gger om aan te sluit en te volg.
- Jy kan nagaan of die **`sysctl`** of **`ptrace`** funksie **geïmporteer** word (maar die malware kan dit dinamies invoer)
- Soos opgemerk in hierdie skrywe, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Die boodskap Proses # het met **status = 45 (0x0000002d)** uitgegaan, is gewoonlik 'n duidelike teken dat die debug-teiken **PT_DENY_ATTACH** gebruik_”

## Kern Dumps

Kern dumps word geskep as:

- `kern.coredump` sysctl is op 1 gestel (per standaard)
- As die proses nie suid/sgid was nie of `kern.sugid_coredump` is 1 (per standaard is 0)
- Die `AS_CORE` limiet laat die operasie toe. Dit is moontlik om die skepping van kode dumps te onderdruk deur `ulimit -c 0` aan te roep en dit weer in te skakel met `ulimit -c unlimited`.

In daardie gevalle word die kern dumps gegenereer volgens `kern.corefile` sysctl en gewoonlik gestoor in `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analiseer neergestorte prosesse en stoor 'n neergestorte verslag op skyf**. 'n Neergestorte verslag bevat inligting wat kan **help 'n ontwikkelaar om** die oorsaak van 'n neergestorte te diagnoseer.\
Vir toepassings en ander prosesse **wat in die per-gebruiker launchd konteks loop**, loop ReportCrash as 'n LaunchAgent en stoor neergestorte verslae in die gebruiker se `~/Library/Logs/DiagnosticReports/`\
Vir daemons, ander prosesse **wat in die stelsel launchd konteks loop** en ander bevoorregte prosesse, loop ReportCrash as 'n LaunchDaemon en stoor neergestorte verslae in die stelsel se `/Library/Logs/DiagnosticReports`

As jy bekommerd is oor neergestorte verslae **wat na Apple gestuur word**, kan jy dit deaktiveer. As nie, kan neergestorte verslae nuttig wees om **uit te vind hoe 'n bediener neergestort het**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sliep

Terwyl jy fuzz in 'n MacOS, is dit belangrik om nie toe te laat dat die Mac slaap nie:

- systemsetup -setsleep Never
- pmset, Stelselsvoorkeure
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Ontkoppeling

As jy via 'n SSH-verbinding fuzz, is dit belangrik om te verseker dat die sessie nie gaan slaap nie. So verander die sshd_config-lêer met:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Interne Hanteerders

**Kyk na die volgende bladsy** om uit te vind hoe jy kan vind watter app verantwoordelik is vir **die hantering van die gespesifiseerde skema of protokol:**

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerering van Netwerkprosesse

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

Werk vir CLI gereedskap

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Dit "**werk net"** met macOS GUI gereedskap. Let daarop dat sommige macOS toepassings spesifieke vereistes het soos unieke lêername, die regte uitbreiding, en dat dit die lêers uit die sandbox moet lees (`~/Library/Containers/com.apple.Safari/Data`)...

Sommige voorbeelde:
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
### Meer Fuzzing MacOS Inligting

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Verwysings

- [**OS X Voorval Respons: Scripting en Analise**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**Die Kuns van Mac Malware: Die Gids om Kwaadaardige Sagteware te Analiseer**](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
