# macOS Apps - Inspeksie, debugging en Fuzzing

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
Hierdie installeerders het `preinstall`- en `postinstall`-bash-skripte wat malware-outeurs gewoonlik misbruik om **die** **malware** te **persist**.

### hdiutil

Hierdie hulpmiddel **koppel** Apple-skyfbeeldlêers (`.dmg`) aan sodat hulle geïnspekteer kan word voordat enigiets uitgevoer word:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Dit sal in `/Volumes` gemonteer word.

### Gepakte binaries

- Kyk vir hoë entropie
- Kyk na die strings (as daar byna geen verstaanbare string is nie, is dit gepak)
- Die UPX-pakker vir macOS genereer ’n afdeling genaamd `__XHDR`.

## Statiese Objective-C-analise

### Metadata

> [!CAUTION]
> Let daarop dat programme wat in Objective-C geskryf is, hul klasdeklasies **behou** wanneer hulle in [Mach-O-binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) **gecompileer** word. Sulke klasdeklasies **sluit** die name en tipes in van:

- Die gedefinieerde koppelvlakke
- Die koppelvlakmetodes
- Die koppelvlak-instansieveranderlikes
- Die gedefinieerde protokolle

Let daarop dat hierdie name verduister kan word om die omgekeerde ontleding van die binary moeiliker te maak.

### Funksie-aanroep

Wanneer ’n funksie in ’n binary wat Objective-C gebruik, aangeroep word, roep die gecompileerde kode eerder **`objc_msgSend`** aan as die funksie self. Dit sal dan die finale funksie aanroep:

![Metadata - Funksie-aanroep: Wanneer ’n funksie in ’n binary wat Objective-C gebruik, aangeroep word, roep die gecompileerde kode eerder objc msgSend aan as die funksie self. Dit sal dan...](<../../../images/image (305).png>)

Die parameters wat hierdie funksie verwag, is:

- Die eerste parameter (**self**) is "'n wyser wat wys na die **instansie van die klas wat die boodskap moet ontvang**". Eenvoudiger gestel, dit is die objek waarop die metode aangeroep word. As die metode ’n klasmetode is, sal dit ’n instansie van die klasobjek (as geheel) wees; vir ’n instansiemetode sal self na ’n objek wys wat ’n geïnstansieerde instansie van die klas is.
- Die tweede parameter, (**op**), is "die selector van die metode wat die boodskap hanteer". Eenvoudiger gestel, dit is bloot die **naam van die metode.**
- Die oorblywende parameters is enige **waardes wat deur die metode vereis word** (op).

Kyk op hierdie bladsy hoe om **hierdie inligting maklik met `lldb` in ARM64 te kry**:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**       | **Register**                                                    | **(vir) objc_msgSend**                                  |
| ------------------ | --------------------------------------------------------------- | ------------------------------------------------------- |
| **1ste argument**  | **rdi**                                                         | **self: objek waarop die metode aangeroep word**        |
| **2de argument**   | **rsi**                                                         | **op: naam van die metode**                             |
| **3de argument**   | **rdx**                                                         | **1ste argument vir die metode**                        |
| **4de argument**   | **rcx**                                                         | **2de argument vir die metode**                         |
| **5de argument**   | **r8**                                                          | **3de argument vir die metode**                         |
| **6de argument**   | **r9**                                                          | **4de argument vir die metode**                         |
| **7de+ argument**  | <p><strong>rsp+</strong><br><strong>(op die stack)</strong></p> | **5de+ argument vir die metode**                        |

### Dump Objective-C-metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) is ’n hulpmiddel om Objective-C-binaries met class-dump te ontleed. GitHub noem dylibs, maar dit werk ook met uitvoerbare lêers.

```bash
./dynadump dump /path/to/bin
```

Ten tyde van die skryf hiervan is dit die een wat tans die beste werk.

#### Standaardnutsgoed

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) is die oorspronklike hulpmiddel om verklarings vir die klasse, kategorieë en protokolle in Objective-C-geformateerde kode te genereer.

Dit is oud en word nie meer onderhou nie, dus sal dit waarskynlik nie behoorlik werk nie.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) is ’n moderne, kruisplatform Objective-C class dump. In vergelyking met bestaande hulpmiddels kan iCDump onafhanklik van die Apple-ekosisteem loop en bied dit Python-bindings.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Statiese Swift-ontleding

Met Swift-binêre lêers kan jy soms, danksy Objective-C-versoenbaarheid, verklarings met [class-dump](https://github.com/nygard/class-dump/) onttrek, maar nie altyd nie.

Met die **`jtool -l`**- of **`otool -l`**-opdragreëls kan jy verskeie afdelings vind wat met die **`__swift5`**-voorvoegsel begin:

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

Verder **kan Swift-binaries symbols bevat** (biblioteke moet byvoorbeeld symbols stoor sodat hul funksies opgeroep kan word). Die **symbols bevat gewoonlik inligting oor die funksienaam en eienskappe op ’n lelike manier**, daarom is hulle baie nuttig, en daar is “**demanglers**” wat die oorspronklike naam kan terugkry:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Dinamiese Analise

> [!WARNING]
> **Moenie SIP as ’n standaardontfoutingsstap deaktiveer nie.** Ontwikkelingsbouwe met `com.apple.security.get-task-allow` kan met SIP geaktiveer ontfout word. Kontroleer die teiken met `codesign -d --entitlements :- /path/to/binary` voordat jy LLDB probeer. ’n Ontfouter-entitlement alleen verleen nie toegang tot SIP-beskermde teikens nie.<sup>[[15]](#references)</sup>
>
> ’n Verspreide toepassing met die hardened runtime laat gewoonlik `get-task-allow` weg en blokkeer aanhegting. Gebruik, indien moontlik, ’n ontwikkelaar-verskafde ontfoutingsbou; die herondertekening van ’n weggooibare kopie kan die gedrag wat getoets word, verander. As ’n beskermde teiken vereis dat SIP gedeaktiveer word, gebruik ’n toegewyde toetsmasjien of VM eerder as ’n masjien waarop jy staatmaak.<sup>[[16]](#references)</sup>
>
> Vroeëre leiding vir ’n beskermde teiken in ’n geïsoleerde toetsomgewing het hierdie alternatiewe gelys:
>
> Let daarop dat SIP gedeaktiveer moet word om binaries te ontfout (`csrutil disable` of `csrutil enable --without debug`), of dat jy die binaries na ’n tydelike vouer moet kopieer en die handtekening moet verwyder met `codesign --remove-signature <binary-path>`, of ontfouting van die binary moet toelaat (jy kan [hierdie script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) gebruik)
>
> Dit is nie ’n algemene SIP-vereiste nie: verkies ’n ontfoutingsbou, en let daarop dat die kopiëring of verandering van ’n handtekening die gedrag wat getoets word, kan verander.

> [!WARNING]
> Let daarop dat SIP gedeaktiveer moet word om **stelselbinaries te instrumenteer** (soos `cloudconfigurationd`) op macOS (die verwydering van die handtekening alleen sal nie werk nie).

### APIs

macOS stel ’n paar interessante APIs beskikbaar wat inligting oor prosesse verskaf:

- `proc_info`: Dit is die belangrikste API en verskaf baie inligting oor elke proses. Jy moet root wees om inligting oor ander prosesse te kry, maar jy het nie spesiale entitlements of mach-poorte nodig nie.
- `libsysmon.dylib`: Stel prosesinligting deur XPC-funksies beskikbaar, maar bellers benodig die `com.apple.sysmond.client`-entitlement.

### Stackshot & microstackshots

**Stackshotting** is ’n tegniek wat gebruik word om die toestand van prosesse vas te vang, insluitend die oproepstapels van alle lopende drade. Dit is veral nuttig vir ontfouting, werkverrigtingontleding en om die gedrag van die stelsel op ’n spesifieke tydstip te verstaan. Op iOS en macOS kan stackshotting met verskeie nutsgoed en metodes uitgevoer word, soos die **`sample`**- en **`spindump`**-nutsgoed.

### Sysdiagnose

Hierdie nutsding (`/usr/bini/ysdiagnose`) versamel basies baie inligting van jou rekenaar deur tientalle verskillende opdragte uit te voer, soos `ps`, `zprint`...

Dit moet as **root** uitgevoer word, en die daemon `/usr/libexec/sysdiagnosed` het baie interessante entitlements, soos `com.apple.system-task-ports` en `get-task-allow`.

Sy plist is geleë by `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, wat 3 MachServices verklaar:

- `com.apple.sysdiagnose.CacheDelete`: Vee ou argiewe in /var/rmp uit
- `com.apple.sysdiagnose.kernel.ipc`: Spesiale poort 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Gebruikersmodus-koppelvlak deur die `Libsysdiagnose` Obj-C-klas. Drie argumente in ’n dict kan deurgegee word (`compress`, `display`, `run`)

### Unified Logs

macOS genereer uitgebreide logs wat nuttig is wanneer ’n toepassing se gedrag ontleed word.

Sommige logvelde bevat die merker `<private>` om inligting wat die gebruiker of toestel kan identifiseer, te verberg. Ouer instruksies beskryf soms die installering van ’n sertifikaat om hierdie velde te onthul; huidige ontfoutingsleiding gebruik eerder ’n uitdruklik begrensde konfigurasieprofiel met `Enable-Private-Data`, of `OSLogPreferences` vir ’n spesifieke toepassing. Die gedrag kan per substelsel en macOS-weergawe verskil. Die bespreking van die ouer sertifikaat/profiel word in die verwysings behou. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Linkerpaneel

In Hopper se linkerpaneel kan jy die binaries se simbole (**Labels**), die lys prosedures en funksies (**Proc**) en die strings (**Str**) sien. Dit is nie al die strings nie, maar dié wat in verskeie dele van die Mac-O-lêer gedefinieer is (soos _cstring of_ `objc_methname`).

#### Middelpaneel

In die middelste paneel kan jy die **gedisassembleerde kode** sien. Jy kan dit as ’n **rou** disassembly, as ’n **graph**, as **gedecompileerde** kode en as **binary** sien deur op die onderskeie ikoon te klik:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

As jy met die rechtermuisknop op ’n kode-objek klik, kan jy **verwysings na/van daardie objek** sien of selfs die naam daarvan verander (dit werk nie in gedecompileerde pseudokode nie):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Verder kan jy **python-opdragte onder in die middel skryf**.

#### Regterpaneel

In die regterpaneel kan jy interessante inligting sien, soos die **navigasiegeskiedenis** (sodat jy weet hoe jy by die huidige situasie uitgekom het), die **oproepgrafiek** waar jy al die **funksies kan sien wat hierdie funksie oproep** en al die funksies wat **hierdie funksie oproep**, en inligting oor **plaaslike veranderlikes**.

### dtrace

Dit gee gebruikers toegang tot toepassings op ’n uiters **lae vlak** en bied ’n manier om **programme** na te spoor en selfs hul uitvoeringsvloei te verander. Dtrace gebruik **probes** wat **deur die kernel versprei geplaas is**, op plekke soos die begin en einde van stelseloproepe.

DTrace gebruik die **`dtrace_probe_create`**-funksie om ’n probe vir elke stelseloproep te skep. Hierdie probes kan by die **inskrywings- en uittreepunte van elke stelseloproep** afgaan. Interaksie met DTrace vind plaas deur /dev/dtrace, wat slegs vir die root-gebruiker beskikbaar is.<sup>[[1]](#references)</sup>

> [!TIP]
> Om Dtrace te aktiveer sonder om SIP-beskerming heeltemal te deaktiveer, kan jy in herstelmodus die volgende uitvoer: `csrutil enable --without dtrace`
>
> Jy kan ook binaries wat **jy saamgestel het**, met **`dtrace`** of **`dtruss`** instrumenteer.

Die beskikbare dtrace-probes kan soos volg verkry word:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Die probe-naam bestaan uit vier dele: die verskaffer, module, funksie en naam (`fbt:mach_kernel:ptrace:entry`). As jy nie ’n deel van die naam spesifiseer nie, sal DTrace daardie deel as ’n jokerteken toepas.

Om DTrace op te stel om probes te aktiveer en te spesifiseer watter aksies uitgevoer moet word wanneer hulle afgaan, sal ons die D-taal moet gebruik.

’n Meer gedetailleerde verduideliking en meer voorbeelde is beskikbaar by [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Voorbeelde

Voer `man -k dtrace` uit om die **beskikbare DTrace-skripte** te lys. Voorbeeld: `sudo dtruss -n binary`

- In lyn

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

- skrip

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

Dit is ’n kernel-nasporingsfasiliteit. Die gedokumenteerde kodes kan gevind word in **`/usr/share/misc/trace.codes`**.

Gereedskap soos `latency`, `sc_usage`, `fs_usage` en `trace` gebruik dit intern.

Om met `kdebug` te koppel, word `sysctl` oor die `kern.kdebug`-naamruimte gebruik. Die MIB’s wat gebruik moet word, kan gevind word in `sys/sysctl.h`, met die funksies geïmplementeer in `bsd/kern/kdebug.c`.

Om met ’n pasgemaakte kliënt met kdebug te kommunikeer, is dit gewoonlik die stappe:

- Verwyder bestaande instellings met KERN_KDSETREMOVE
- Stel die nasporing op met KERN_KDSETBUF en KERN_KDSETUP
- Gebruik KERN_KDGETBUF om die aantal bufferinskrywings te kry
- Haal die eie kliënt uit die nasporing met KERN_KDPINDEX
- Aktiveer nasporing met KERN_KDENABLE
- Lees die buffer deur KERN_KDREADTR aan te roep
- Roep KERN_KDTHRMAP aan om elke thread met sy proses te koppel.

Om hierdie inligting te kry, kan jy Apple se **`trace`**-nutsding of die pasgemaakte nutsding [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** gebruik.

**Let daarop dat Kdebug op ’n slag net vir 1 kliënt beskikbaar is.** Daarom kan net een k-debug-aangedrewe nutsding op dieselfde tyd uitgevoer word.

### ktrace

Die `ktrace_*`-API’s kom van `libktrace.dylib`, wat dié van `Kdebug` omvou. ’n Kliënt kan dan eenvoudig `ktrace_session_create` en `ktrace_events_[single/class]` aanroep om terugroepe vir spesifieke kodes in te stel, en dit dan met `ktrace_start` begin.

Jy kan hierdie een selfs met **SIP geaktiveer** gebruik.

Jy kan die nutsding `ktrace` as kliënt gebruik:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Of `tailspin`.

### kperf

Dit word gebruik om profilering op kernvlak uit te voer en is met `Kdebug`-terugroepe gebou.

Basies word die globale veranderlike `kernel_debug_active` nagegaan. As dit ingestel is, roep dit `kperf_kdebug_handler` met die `Kdebug`-kode en die adres van die kernelraamwerk wat die oproep maak. As die `Kdebug`-kode ooreenstem met een wat gekies is, word die “aksies” toegepas wat as ’n bitmap gekonfigureer is (kyk na `osfmk/kperf/action.h` vir die opsies).

Kperf het ook ’n sysctl MIB-tabel: (as root) `sysctl kperf`. Hierdie kode kan in `osfmk/kperf/kperfbsd.c` gevind word.

Verder is ’n deelversameling van Kperf se funksionaliteit in `kpc`, wat inligting oor masjienwerkverrigtingtellers verskaf.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) is ’n baie nuttige hulpmiddel om die prosesverwante aksies wat ’n proses uitvoer, na te gaan (byvoorbeeld om te monitor watter nuwe prosesse ’n proses skep).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) is ’n hulpmiddel wat die verwantskappe tussen prosesse vertoon.\
Jy moet jou Mac monitor met ’n opdrag soos **`sudo eslogger fork exec rename create > cap.json`** (die terminaal wat dit begin, vereis FDA). Daarna kan jy die json-lêer in hierdie hulpmiddel laai om al die verwantskappe te sien:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) monitor lêergebeurtenisse soos die skep, wysiging en verwydering van lêers.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) is ’n GUI-hulpmiddel met die voorkoms en gevoel van Microsoft Sysinternal se _Procmon_, wat Windows-gebruikers dalk ken. Met hierdie hulpmiddel kan die opname van verskillende gebeurtenistipes begin en gestop word, kan hierdie gebeurtenisse volgens kategorieë soos lêer, proses, netwerk, ens. gefiltreer word, en kan die opgeneemde gebeurtenisse in json-formaat gestoor word.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) is deel van Xcode se Developer tools – dit word gebruik om toepassingwerkverrigting te monitor, geheuelekkasies te identifiseer en lêerstelselaktiwiteit na te spoor.

![Crescendo - Apple Instruments: Apple Instruments is deel van Xcode se Developer tools – dit word gebruik om toepassingwerkverrigting te monitor, geheuelekkasies te identifiseer en lêerstelselaktiwiteit na te spoor](<../../../images/image (1138).png>)

### fs_usage

Laat jou toe om aksies wat deur prosesse uitgevoer word, te volg:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) is nuttig om die **biblioteke** te sien wat deur ’n binary gebruik word, die **lêers** wat dit gebruik en die **netwerk**-verbindings.\
Dit kontroleer ook die binary-prosesse teen **virustotal** en wys inligting oor die binary.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

In [**hierdie blogplasing**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) kan jy ’n voorbeeld vind van hoe om ’n lopende daemon te **debug** wat **`PT_DENY_ATTACH`** gebruik het om debugging te voorkom, selfs wanneer SIP gedeaktiveer was.<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` is ’n Darwin-spesifieke `ptrace(2)`-versoek met waarde **31** (`0x1f`); die ander argumente word geïgnoreer. ’n Proses kan dit direk aanroep, sonder ’n fork, om latere tracing deur die ouerproses te weier.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### XNU-toestand en oproepvolgorde

Die resultaat hang af van watter `ptrace`-versoek XNU eerste bereik:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB heg eerste:** `debugserver` gebruik `PT_ATTACHEXC`; XNU skakel dit om na `PT_ATTACH`, voer `KAUTH_PROCESS_CANTRACE`-magtiging uit en stel `P_LTRACED` op die teiken. ’n Daaropvolgende `PT_DENY_ATTACH` bespeur daardie vlag en beëindig die teiken met `W_EXITCODE(ENOTSUP, 0)`, wat LLDB gewoonlik as status **45** (`0x2d`) vertoon.
- **Die teiken weier eerste:** XNU stel `P_LNOATTACH`. ’n Latere poging om te heg, word deur prosesnasporingsmagtiging afgekeur; die fouthanteringspad vir die hegaksie bespeur `P_LNOATTACH` en stuur `SIGSEGV` na die proses wat probeer heg, wat in LLDB as ’n verlore `debugserver`-verbinding kan verskyn.

Om hierdie paaie te onderskei, aktiveer `debugserver`-aantekening voordat jy dit begin of heg, en ondersoek sy `ptrace`-versoeke:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### ARM64 statiese identifikasie en omseiling

Vir ’n nie-geobfuskeerde ARM64 Mach-O, vind die ingevoerde `_ptrace`-stub en ondersoek die oproepterreine. Die eerste heelgetalargument word in `w0` deurgegee, dus wys hierdie volgorde die anti-debug-versoek direk. Die afwesigheid van die invoer is nie afdoende nie, omdat kode `ptrace` dinamies kan oplos. ’n Ingevoerde `_sysctl` kan ook op anti-debug-kontroles dui, hoewel dit ook dinamies opgelos kan word.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

In die gedemonstreerde voorbeeld verander die patch van die immediate van `0x1f` na `0x0` die versoek na `PT_TRACE_ME` en laat dit die program toe om onder LLDB voort te gaan. Dit is ’n **omseiling spesifiek vir hierdie voorbeeld**, nie ’n algemene no-op nie: ondersoek die aanroeper se terugkeerwaardetoetse en beheervloei voordat jy besluit of jy die versoek moet verander, die oproep moet oorslaan of ’n suksesvolle terugkeer moet afdwing.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** is die **de facto-hulpmiddel** vir **macOS**-binêre **ontfouting**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Jy kan die Intel-formaat instel wanneer jy lldb gebruik deur ’n lêer genaamd **`.lldbinit`** in jou tuisgids te skep met die volgende reël:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Binne lldb, dump 'n proses met `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Opdrag</strong></td><td><strong>Beskrywing</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Begin uitvoering, wat voortgaan totdat 'n breakpoint getref word of die proses eindig.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Begin uitvoering en stop by die toegangspunt.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Gaan voort met die uitvoering van die proses wat gedebug word.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Voer die volgende instruksie uit. Hierdie opdrag slaan oor funksie-oproepe.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Voer die volgende instruksie uit. Anders as die <code>nexti</code>-opdrag, stap hierdie opdrag in funksie-oproepe in.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Voer die oorblywende instruksies in die huidige funksie (raamwerk) uit, keer terug en stop.</td></tr>
<tr><td><strong>control + c</strong></td><td>Onderbreek uitvoering. As die proses begin is (<code>r</code>) of voortgesit is (<code>c</code>), laat dit die proses stop waar dit tans uitvoer.</td></tr>
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
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Vertoon geheue as 'n nulbeëindigde string.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Vertoon geheue as 'n assembly-instruksie.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Vertoon geheue as 'n byte.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Dit druk die objek waarna die parameter verwys.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>Die meeste Apple Objective-C API's of metodes gee objekte terug en moet dus met die “print object” (<code>po</code>)-opdrag vertoon word. As <code>po</code> nie betekenisvolle uitvoer lewer nie, gebruik <code>x/b</code>.</p>
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
> Wanneer die **`objc_sendMsg`**-funksie geroep word, bevat die **rsi**-register die **naam van die metode** as 'n nulbeëindigde (“C”)-string. Om die naam met lldb te druk, doen die volgende:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- Die opdrag **`sysctl hw.model`** gee normaalweg 'n Mac-modelidentifiseerder op fisiese hardeware terug, en kan 'n ander waarde in 'n VM gee.<sup>[[3]](#references)</sup>
- Sommige malware probeer met die waardes van **`hw.logicalcpu`** en **`hw.physicalcpu`** vasstel of dit 'n VM is.<sup>[[4]](#references)</sup>
- 'n Loader kan ook `kern.hv_vmm_present` en `machdep.cpu.brand_string` met `sysctl` navraag doen wanneer dit vir 'n VM toets voordat dit sy volgende stadium uitpak. Hierdie toetse vul die debugger-aanhegtingstoets hieronder aan, maar vervang dit nie.<sup>[[20]](#references)</sup>
- Sommige malware kan ook **bespeur** of die masjien op **VMware** gebaseer is deur die MAC-adres (00:50:56) te gebruik.
- Dit is ook moontlik om met eenvoudige kode vas te stel **of 'n proses gedebug word**, soos:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Dit kan ook die `ptrace`-stelseloproep met die `PT_DENY_ATTACH`-vlag aanroep. Dit verhoed dat 'n debugger aanheg en trace. Sien die [PT_DENY_ATTACH-afdeling](#page-title) vir die volgordeafhanklike XNU-gedrag, `debugserver`-logging en ARM64-patching-werkvloei.<sup>[[7]](#references)[[12]](#references)</sup>
- Dit kan ook die **`ptrace`**-stelseloproep met die **`PT_DENY_ATTACH`**-vlag aanroep. Sien die [PT_DENY_ATTACH-afdeling](#page-title) vir die volgordeafhanklike XNU-gedrag, `debugserver`-logging en ARM64-patching-werkvloei.<sup>[[7]](#references)[[12]](#references)</sup>
  - Jy kan nagaan of die **`sysctl`**- of **`ptrace`**-funksie **ingevoer** word (maar die malware kan dit dinamies invoer)
  - Soos in hierdie skrywe opgemerk: “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_Die boodskap Process # exited with **status = 45 (0x0000002d)** is gewoonlik 'n duidelike teken dat die debug-teiken **PT_DENY_ATTACH** gebruik_”
#### Prosesoorhandiging met `fork()`

'n Proses kan 'n debugger ontduik wat aan die oorspronklike PID geheg bly, deur naby die begin `fork()` aan te roep, die ouerproses te beëindig (`fork()` gee 'n positiewe child-PID terug) en die beskermde logika slegs in die child voort te sit (`fork()` gee `0` terug). Deur `fork` met `dlsym(RTLD_DEFAULT, "fork")` op te los, word die direkte `_fork`-oproepadres ook verwyder, maar dit is slegs 'n hindernis vir analysis: die string met die simboolnaam en die data-vloei vir dinamiese resolusie bly sigbaar in die Mach-O-binêre lêer.<sup>[[13]](#references)[[14]](#references)</sup>

Op arm64 kan jy hierdie patroon opspoor deur die data-vloei te volg eerder as vaste adresse: die eerste twee argumente vir `dlsym` word in `x0` en `x1` deurgegee, `RTLD_DEFAULT` kan as `-2` verskyn (byvoorbeeld, `movn x0, #1`), en 'n `adrp`/`add`-paar konstrueer gewoonlik die adres van die `"fork"`-string. Nadat die `bl` na die `dlsym`-stub uitgevoer is, volg die teruggekeerde wyser vanaf `x0` deur die null-kontrole en berging tot by 'n latere indirekte `blr`. Volg dan die `fork()`-resultaat in `w0`: nul kies die child-vervolgpad, terwyl positiewe en `-1`-waardes die ouer-/foutpad kies.<sup>[[13]](#references)[[14]](#references)</sup>

'n Statiese omseiling is om die indirekte oproep te onderdruk en die bestaande resultaatkontrole te dwing om die child-pad te kies. As die compiler byvoorbeeld die onderstaande volgorde gegenereer het, patch die `blr` en resultaatberging na `nop`, verskaf 'n sintetiese nulresultaat en behou die vergelykings-/vertakkingslogika. Die toepassing gaan dan voort onder die oorspronklike PID sonder om 'n child te skep; pas instruksieregisters en vertakkingsikens by die geanaliseerde bouweergawe aan.<sup>[[13]](#references)[[14]](#references)</sup>

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
- As die proses nie suid/sgid was nie, of as `kern.sugid_coredump` op 1 gestel is (by verstek is dit 0)
- Die `AS_CORE`-limiet die bewerking toelaat. Dit is moontlik om die skep van core dumps te onderdruk deur `ulimit -c 0` aan te roep en dit weer te aktiveer met `ulimit -c unlimited`.

In daardie gevalle word die core dumps volgens die `kern.corefile`-sysctl gegenereer en gewoonlik in `/cores/core/.%P` gestoor.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **ontleed prosesse wat omval en stoor 'n omvalverslag op skyf**. 'n Omvalverslag bevat inligting wat **'n ontwikkelaar kan help om die oorsaak van 'n omval te diagnoseer**.\
Vir toepassings en ander prosesse wat **in die per-gebruiker launchd-konteks loop**, loop ReportCrash as 'n LaunchAgent en stoor dit omvalverslae in die gebruiker se `~/Library/Logs/DiagnosticReports/`\
Vir daemons, ander prosesse wat **in die stelsel se launchd-konteks loop**, en ander bevoorregte prosesse, loop ReportCrash as 'n LaunchDaemon en stoor dit omvalverslae in die stelsel se `/Library/Logs/DiagnosticReports`

As jy bekommerd is dat omvalverslae **aan Apple gestuur word**, kan jy dit deaktiveer. Indien nie, kan omvalverslae nuttig wees om **uit te vind hoe 'n bediener omgeval het**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Slaap

Wanneer jy op macOS fuzzing doen, voorkom dat die Mac gaan slaap:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH-ontkoppeling

As jy via 'n SSH-verbinding fuzzing doen, is dit belangrik om seker te maak dat die sessie nie gaan sterf nie. Verander dus die sshd_config-lêer met:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Interne hanteerders

**Kyk na die volgende bladsy** om uit te vind hoe jy kan bepaal watter app verantwoordelik is vir die **hantering van die gespesifiseerde skema of protokol:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerering van netwerkprosesse

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

### Mach IPC-fuzzing met behoud van toestand

Mach-dienste wat deur bevoorregte daemons blootgestel word, is nuttige fuzz-teikens wanneer ’n onbevoorregte of sandboxed-kliënt ’n send right kan verkry. Begin by die daemon se `MachServices`-inskrywing in launchd en gebruik die [MIG-ontledingswerkvloei](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) om boodskap-ID’s aan handlers te koppel. Voordat jy grepe wysig, stel ’n breekpunt by die MIG-bedienerroetine terwyl ’n normale kliënt die diens gebruik, en stoor geldige versoekboodskappe as saad-insette. Behou die vereiste kopervelde, boodskapgroottes en beskryweruitleg sodat mutasies die handler bereik eerder as om onmiddellik tydens dispatch te faal.<sup>[[17]](#references)</sup>

Baie handlers is afhanklik van vorige oproepe. Laat die harness die diens se toestand inisialiseer, en verwerk dan elke fuzz-invoer as ’n reeks **bewerkings plus argumente**: stuur opstellingversoeke (soos open of create), behou teruggekeerde identifiseerders en gebruik hulle in latere versoeke. Só kan coverage-terugvoer toestandoorgange verken eerder as om herhaaldelik by ’n kontrole vir ’n ongeïnisialiseerde objek vas te haak.<sup>[[17]](#references)</sup>

Vir ’n geslotebron-teiken kan ’n in-process-harness wat die MIG-dispatch-roetine aanroep, met Jackalope/TinyInst geïnstrumenteer word. Die [CoreAudioFuzz-harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) is ’n konkrete implementering, nie ’n klaargemaakte harness vir ander dienste nie.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**Bevestig elke crash deur die werklike IPC-pad.** ’n Direct-dispatch-harness slaan die kern se validering van Mach-boodskappe oor en kan vals positiewe oplewer, veral wanneer dit ongeldige out-of-line (OOL)-geheue of port-beskrywers verskaf. Ken geldige OOL-rugsteungeheue in die harness toe, speel dan die verkleinde testcase weer deur `mach_msg` vanaf ’n kliënt met die oorspronklike dienstoegang af en bevestig dat die daemon steeds crash.<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Werk vir CLI-nutsmiddels

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Dit "**werk sommer**" met baie macOS-GUI-nutsmiddels. Sommige toepassings het bykomende vereistes, soos unieke lêername, ’n spesifieke lêeruitbreiding, of dat lêers uit hul sandbox-houer gelees word (`~/Library/Containers/com.apple.Safari/Data`).

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

- [1] [OS X-voorvalreaksie: scripting en analise](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Volume I: Analysis](https://taomm.org/)
- [4] [No Starch Press - The Art of Mac Malware: The Guide to Analyzing Malicious Software](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - inligting wat in hierdie afdeling in hierdie blogplasing gestoor is](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Apple-binaries ontfout wat Pt Deny Attach gebruik](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Anti-debug-tegnieke omseil: macOS ptrace-variante](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Xcode-gestruktureerde logs en `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Privaat data in die macOS unified log wys](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Apple XNU `ptrace.h`-versoekdefinisies](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Apple XNU `ptrace`-implementering in `mach_process.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - ptrace-internals: Hoe dit debugger-aanhegting voorkom](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - fork-voorbeelde](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - Anti-debug-tegniek met dlsym en fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - Debugging tool-regte](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - Ontfouting van 'n geharde derdeparty-toepassing](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - Breaking the Sound Barrier Part I: Fuzzing CoreAudio with Mach Messages](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - CoreAudioFuzz-harnas](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Jackalope-fuzzer](https://github.com/googleprojectzero/Jackalope)
- [20] [Kaspersky Securelist - 'n Nuwe weergawe van die MacSync macOS-dief teiken kripto-entoesiaste en ontwikkelaars](https://securelist.com/macsync-new-version/121383/)
{{#include ../../../banners/hacktricks-training.md}}
