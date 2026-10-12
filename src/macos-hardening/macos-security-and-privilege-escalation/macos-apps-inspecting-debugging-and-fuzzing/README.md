# Programu za macOS - Kukagua, kutatua hitilafu na Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Uchambuzi Tuli

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

Unaweza [**kupakua disarm hapa**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Kumbuka kwamba **`disarm`** inaweza pia kufanya kazi na faili za IM4P zilizobanwa (kama `kernelcache`) na kutoa sehemu zinazohitajika pekee, au hata kuchanganua sehemu inayohitajika bila kuitoa.

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
> **`Codesign`** inaweza kupatikana kwenye **macOS**, huku **`ldid`** ikipatikana kwenye **iOS**.

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) ni zana inayofaa kukagua faili za **.pkg** (visakinishi) na kuona vilivyomo kabla ya kuzisakinisha.\
Visakinishi hivi vina script za bash za `preinstall` na `postinstall` ambazo waandishi wa malware kwa kawaida huzitumia vibaya ili **persist** **the** **malware**.

### hdiutil

Zana hii **mounts** faili za Apple disk image (`.dmg`) ili ziweze kukaguliwa kabla ya chochote kuendeshwa:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Itamountwa kwenye `/Volumes`

### Packed binaries

- Angalia entropy ya juu
- Angalia strings (ikiwa karibu hakuna string zinazoeleweka, binary imepackiwa)
- UPX packer ya macOS hutengeneza section inayoitwa `__XHDR`.

## Uchambuzi tuli wa Objective-C

### Metadata

> [!CAUTION]
> Kumbuka kwamba programu zilizoandikwa kwa Objective-C **huhifadhi** matamko ya class **zinapokuwa** **zimecompiliwa** kuwa [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Matamko hayo ya class **hujumuisha** majina na aina za:

- Interfaces zilizobainishwa
- Methods za interface
- Instance variables za interface
- Protocols zilizobainishwa

Kumbuka kwamba majina haya yanaweza kufichwa ili kufanya reverse engineering ya binary kuwa ngumu zaidi.

### Kuitwa kwa function

Function inapoitwa katika binary inayotumia Objective-C, badala ya kuita function hiyo, code iliyocompiliwa itaita **`objc_msgSend`**, ambayo itaita function ya mwisho:

![Metadata - Kuitwa kwa function: Function inapoitwa katika binary inayotumia Objective-C, badala ya kuita function hiyo, code iliyocompiliwa itaita objc msgSend . Ambayo itakuwa ikiita...](<../../../images/image (305).png>)

Vigezo vinavyohitajika na function hii ni:

- Kigezo cha kwanza (**self**) ni "pointer inayoelekeza kwenye **instance ya class inayopaswa kupokea ujumbe**". Au kwa ufupi, ni object ambayo method inatekelezwa juu yake. Ikiwa method ni class method, hii itakuwa instance ya class object (kwa ujumla wake), ilhali kwa instance method, self itaelekeza kwenye instance iliyoundwa ya class kama object.
- Kigezo cha pili, (**op**), ni "selector ya method inayoshughulikia ujumbe". Kwa ufupi, hili ni **jina la method.**
- Vigezo vilivyobaki ni **thamani zozote zinazohitajika na method** (op).

Tazama jinsi ya **kupata taarifa hii kwa urahisi kwa `lldb` kwenye ARM64** kwenye ukurasa huu:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Kigezo**        | **Register**                                                     | **(kwa) objc_msgSend**                                  |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **Kigezo cha 1**  | **rdi**                                                         | **self: object ambayo method inatekelezwa juu yake** |
| **Kigezo cha 2**  | **rsi**                                                         | **op: jina la method**                             |
| **Kigezo cha 3**  | **rdx**                                                         | **Kigezo cha 1 cha method**                         |
| **Kigezo cha 4**  | **rcx**                                                         | **Kigezo cha 2 cha method**                         |
| **Kigezo cha 5**  | **r8**                                                          | **Kigezo cha 3 cha method**                         |
| **Kigezo cha 6**  | **r9**                                                          | **Kigezo cha 4 cha method**                         |
| **Kigezo cha 7+** | <p><strong>rsp+</strong><br><strong>(kwenye stack)</strong></p> | **Kigezo cha 5+ cha method**                        |

### Dump ya metadata ya ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) ni zana ya kufanya class-dump ya Objective-C binaries. GitHub inaeleza kuwa inatumika kwa dylibs, lakini inafanya kazi pia kwa executables.

```bash
./dynadump dump /path/to/bin
```

Wakati wa kuandika, hii **ndiyo inayofanya kazi vizuri zaidi kwa sasa**.

#### Zana za kawaida

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) ndiyo zana ya awali ya kutengeneza matamko ya classes, categories na protocols katika msimbo ulioumbizwa wa ObjectiveC.

Ni ya zamani na haidumishwi, kwa hivyo huenda isifanye kazi ipasavyo.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) ni zana ya kisasa na inayofanya kazi kwenye mifumo mbalimbali ya kutupa Objective-C class. Ikilinganishwa na zana zilizopo, iCDump inaweza kufanya kazi bila kutegemea mfumo ikolojia wa Apple na inatoa Python bindings.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Uchambuzi tuli wa Swift

Kwa binaries za Swift, kwa kuwa kuna uoanifu wa Objective-C, wakati mwingine unaweza kutoa matamko kwa kutumia [class-dump](https://github.com/nygard/class-dump/) lakini si kila wakati.

Kwa kutumia mistari ya amri **`jtool -l`** au **`otool -l`**, inawezekana kupata sehemu kadhaa zinazoanza na kiambishi awali **`__swift5`**:

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

Unaweza kupata maelezo zaidi kuhusu [**taarifa zilizohifadhiwa katika sehemu hizi kwenye chapisho hili la blogu**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Aidha, **Swift binaries zinaweza kuwa na symbols** (kwa mfano, libraries zinahitaji kuhifadhi symbols ili functions zake ziweze kuitwa). **Kwa kawaida, symbols huwa na taarifa kuhusu jina la function** na attr kwa namna isiyoeleweka, kwa hiyo zina manufaa sana. Kuna "**demanglers"** zinazoweza kupata jina asili:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Uchambuzi wa Dynamic

> [!WARNING]
> Kumbuka kwamba ili kufanya debugging ya binaries, **SIP inahitaji kuzimwa** (`csrutil disable` or `csrutil enable --without debug`), au kunakili binaries kwenye folda ya muda na **kuondoa signature** kwa `codesign --remove-signature <binary-path>`, au kuruhusu debugging ya binary (unaweza kutumia [script hii](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Kumbuka kwamba ili **ku-instrument system binaries**, (kama `cloudconfigurationd`) kwenye macOS, **SIP lazima izimwe** (kuondoa signature pekee hakutafanya kazi).

### APIs

macOS hutoa baadhi ya APIs za kuvutia zinazotoa taarifa kuhusu processes:

- `proc_info`: Hii ndiyo API kuu inayotoa taarifa nyingi kuhusu kila process. Unahitaji kuwa root ili kupata taarifa za processes nyingine, lakini huhitaji entitlements maalum au mach ports.
- `libsysmon.dylib`: Hutoa taarifa za processes kupitia functions za XPC, lakini wanaozitumia wanahitaji entitlement ya `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** ni mbinu inayotumiwa kunasa hali ya processes, ikijumuisha call stacks za threads zote zinazoendeshwa. Hii ni muhimu hasa kwa debugging, uchanganuzi wa utendaji na kuelewa tabia ya mfumo katika wakati fulani. Kwenye iOS na macOS, stackshotting inaweza kufanywa kwa kutumia zana na mbinu kadhaa, kama vile zana za **`sample`** na **`spindump`**.

### Sysdiagnose

Zana hii (`/usr/bini/ysdiagnose`) hukusanya taarifa nyingi kutoka kwenye kompyuta yako kwa kutekeleza commands nyingi tofauti kama `ps`, `zprint`...

Lazima iendeshwe kama **root**, na daemon `/usr/libexec/sysdiagnosed` ina entitlements za kuvutia sana kama `com.apple.system-task-ports` na `get-task-allow`.

Plist yake iko kwenye `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, ambayo hutangaza MachServices 3:

- `com.apple.sysdiagnose.CacheDelete`: Hufuta archives za zamani kwenye /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Special port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Kiolesura cha user mode kupitia class ya `Libsysdiagnose` Obj-C. Arguments tatu zinaweza kupitishwa kwenye dict (`compress`, `display`, `run`)

### Unified Logs

macOS huzalisha logs nyingi zinazosaidia kuchanganua tabia ya application.

Baadhi ya fields za log huwa na tag ya `<private>` ili kuficha taarifa zinazoweza kumtambulisha mtumiaji au kifaa. Maelekezo ya zamani wakati mwingine hueleza jinsi ya kusakinisha certificate ili kuonyesha fields hizi; mwongozo wa sasa wa debugging badala yake hutumia configuration profile yenye scope maalum na `Enable-Private-Data`, au `OSLogPreferences` kwa kila application. Tabia inaweza kutofautiana kulingana na subsystem na toleo la macOS. Maelezo ya zamani kuhusu certificate/profile yamehifadhiwa kwenye references. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Paneli ya kushoto

Kwenye paneli ya kushoto ya Hopper unaweza kuona symbols (**Labels**) za binary, orodha ya procedures na functions (**Proc**), na strings (**Str**). Hizi si strings zote, bali ni zile zilizoainishwa katika sehemu mbalimbali za faili la Mac-O (kama _cstring au_ `objc_methname`).

#### Paneli ya katikati

Kwenye paneli ya katikati unaweza kuona **code iliyodisassemble**. Unaweza kuiona kama disassembly **ghafi**, kama **graph**, kama **decompiled**, na kama **binary** kwa kubofya ikoni husika:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Ukibofya kulia kwenye code object unaweza kuona **references zinazoelekea au kutoka kwenye object hiyo**, au hata kubadilisha jina lake (hii haifanyi kazi kwenye pseudocode iliyodecompile):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Zaidi ya hayo, **katikati chini unaweza kuandika commands za python**.

#### Paneli ya kulia

Kwenye paneli ya kulia unaweza kuona taarifa muhimu kama **historia ya urambazaji** (ili ujue ulifikaje kwenye hali ya sasa), **call graph** inayoonyesha **functions zote zinazoita function hii** na functions zote **zinazoitwa na function hii**, pamoja na taarifa za **local variables**.

### dtrace

Huwapa watumiaji ufikiaji wa applications katika **kiwango cha chini sana**, na njia ya **kufuatilia** **programs** na hata kubadilisha mtiririko wa utekelezaji wake. Dtrace hutumia **probes** ambazo **huwekwa kote kwenye kernel**, katika maeneo kama mwanzo na mwisho wa system calls.

DTrace hutumia function ya **`dtrace_probe_create`** kuunda probe kwa kila system call. Probes hizi zinaweza kuwashwa kwenye **sehemu ya kuingia na kutoka ya kila system call**. Mawasiliano na DTrace hufanyika kupitia /dev/dtrace, ambayo inapatikana kwa root user pekee.<sup>[[1]](#references)</sup>

> [!TIP]
> Ili kuwezesha Dtrace bila kuzima kabisa ulinzi wa SIP, unaweza kutekeleza yafuatayo ukiwa kwenye recovery mode: `csrutil enable --without dtrace`
>
> Unaweza pia kutumia **`dtrace`** au **`dtruss`** kwenye binaries **ulizocompile**.

Probes zinazopatikana za dtrace zinaweza kupatikana kwa kutumia:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Jina la probe lina sehemu nne: provider, module, function, na name (`fbt:mach_kernel:ptrace:entry`). Usipobainisha sehemu fulani ya jina, Dtrace itatumia sehemu hiyo kama wildcard.

Ili kusanidi DTrace iwashe probes na kubainisha hatua za kutekeleza zinapowashwa, tutahitaji kutumia D language.

Maelezo ya kina zaidi na mifano mingine inapatikana katika [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Mifano

Tekeleza `man -k dtrace` ili kuorodhesha **scripts za DTrace zinazopatikana**. Mfano: `sudo dtruss -n binary`

- Ndani ya mstari

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

Ni kifaa cha kufuatilia kernel. Misimbo iliyoandikwa kwenye nyaraka inaweza kupatikana katika **`/usr/share/misc/trace.codes`**.

Zana kama `latency`, `sc_usage`, `fs_usage` na `trace` hukitumia ndani ya mfumo.

Ili kuwasiliana na `kdebug`, `sysctl` hutumiwa kupitia namespace ya `kern.kdebug`, na MIB zitakazotumika zinaweza kupatikana katika `sys/sysctl.h`, huku functions zake zikiwa zimetekelezwa katika `bsd/kern/kdebug.c`.

Kwa kawaida, hatua hizi hutumika kuwasiliana na kdebug kupitia client maalum:

- Ondoa mipangilio iliyopo kwa kutumia KERN_KDSETREMOVE
- Weka trace kwa kutumia KERN_KDSETBUF na KERN_KDSETUP
- Tumia KERN_KDGETBUF kupata idadi ya entries za buffer
- Ondoa client yako mwenyewe kwenye trace kwa kutumia KERN_KDPINDEX
- Washa tracing kwa kutumia KERN_KDENABLE
- Soma buffer kwa kuita KERN_KDREADTR
- Ili kulinganisha kila thread na process yake, ita KERN_KDTHRMAP.

Ili kupata taarifa hii, unaweza kutumia zana ya Apple **`trace`** au zana maalum [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Kumbuka kuwa Kdebug inapatikana kwa mteja 1 pekee kwa wakati mmoja.** Kwa hiyo, zana moja tu inayotumia k-debug inaweza kuendeshwa kwa wakati mmoja.

### ktrace

API za `ktrace_*` zinatoka kwenye `libktrace.dylib`, ambayo hufunika zile za `Kdebug`. Kisha, client anaweza kuita `ktrace_session_create` na `ktrace_events_[single/class]` ili kuweka callbacks kwenye misimbo maalum, kisha aanzishe kwa kutumia `ktrace_start`.

Unaweza kutumia hii hata **SIP ikiwa imewashwa**

Unaweza kutumia utility ya `ktrace` kama client:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Au `tailspin`.

### kperf

Hii hutumika kufanya profiling ya kiwango cha kernel na imejengwa kwa kutumia callout za `Kdebug`.

Kimsingi, kigezo cha kimataifa `kernel_debug_active` hukaguliwa. Ikiwa kimewashwa, `kperf_kdebug_handler` huitwa pamoja na code ya `Kdebug` na anwani ya kernel frame inayoita. Ikiwa code ya `Kdebug` inalingana na mojawapo ya zilizochaguliwa, hupokea "actions" zilizosanidiwa kama bitmap (angalia `osfmk/kperf/action.h` kwa chaguo).

Kperf pia ina jedwali la sysctl MIB: (kama root) `sysctl kperf`. Code hii inaweza kupatikana kwenye `osfmk/kperf/kperfbsd.c`.

Zaidi ya hayo, baadhi ya utendaji wa Kperf hupatikana kwenye `kpc`, ambayo hutoa maelezo kuhusu performance counters za mashine.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) ni zana muhimu sana ya kuangalia vitendo vinavyohusiana na process ambavyo process inatekeleza (kwa mfano, kufuatilia process mpya ambazo process inaunda).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) ni zana inayoonyesha uhusiano kati ya processes.\
Unahitaji kufuatilia mac yako kwa amri kama **`sudo eslogger fork exec rename create > cap.json`** (terminal inayoanzisha amri hii inahitaji FDA). Kisha unaweza kupakia json kwenye zana hii ili kuona uhusiano wote:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) hufuatilia matukio ya faili kama vile kuundwa, kurekebishwa na kufutwa.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) ni zana ya GUI yenye mwonekano na matumizi ambayo watumiaji wa Windows wanaweza kuyafahamu kutoka Microsoft Sysinternal’s _Procmon_. Zana hii huruhusu kurekodi aina mbalimbali za matukio kuanzishwa na kusimamishwa, kuchuja matukio haya kulingana na kategoria kama vile faili, process, mtandao, n.k., na kuhifadhi matukio yaliyorekodiwa katika umbizo la json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) ni sehemu ya zana za Developer za Xcode – hutumika kufuatilia utendaji wa programu, kutambua memory leaks na kufuatilia shughuli za filesystem.

![Crescendo - Apple Instruments: Apple Instruments ni sehemu ya zana za Developer za Xcode – hutumika kufuatilia utendaji wa programu, kutambua memory leaks na kufuatilia shughuli za filesystem](<../../../images/image (1138).png>)

### fs_usage

Hurahisisha kufuatilia vitendo vinavyotekelezwa na processes:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) ni muhimu kwa kuona **libraries** zinazotumiwa na binary, **files** inazotumia na miunganisho ya **network**.\
Pia hukagua michakato ya binary kwa kutumia **virustotal** na kuonyesha taarifa kuhusu binary.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Katika [**chapisho hili la blogu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) unaweza kupata mfano wa jinsi ya kufanya **debugging ya daemon inayoendesha** iliyotumia **`PT_DENY_ATTACH`** kuzuia debugging hata SIP ikiwa imezimwa.<sup>[[6]](#references)</sup>

### lldb

**lldb** ndiyo **zana inayotumika kwa kawaida** kwa **debugging** ya binary za **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Unaweza kuweka mtindo wa Intel unapotumia lldb kwa kuunda faili linaloitwa **`.lldbinit`** kwenye folda yako ya nyumbani, likiwa na mstari ufuatao:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Ndani ya lldb, hifadhi dump ya process kwa kutumia `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>Maelezo</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Anza utekelezaji; utaendelea hadi breakpoint ipatikane au process ikome.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Anza utekelezaji na usimame kwenye entry point.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Endelea na utekelezaji wa process inayofanyiwa debug.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Tekeleza instruction inayofuata. Command hii huruka juu ya function calls.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Tekeleza instruction inayofuata. Tofauti na command ya <code>nexti</code>, hii huingia ndani ya function calls.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Tekeleza instructions zilizobaki kwenye function (frame) ya sasa, rudi, kisha usimame.</td></tr>
<tr><td><strong>control + c</strong></td><td>Simamisha utekelezaji. Ikiwa process imeendeshwa (<code>r</code>) au imeendelezwa (<code>c</code>), hii huisimamisha mahali ilipo wakati huo.</td></tr>
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
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Onyesha memory kama string inayoishia kwa null.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Onyesha memory kama assembly instruction.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Onyesha memory kama byte.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Hii huchapisha object inayorejelewa na parameter.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
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
<tr><td><strong>image dump sections</strong></td><td>Chapisha ramani ya memory ya process ya sasa.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Get the address of every symbol from CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Unapopiga simu kwenye function ya **`objc_sendMsg`**, register ya **rsi** huwa na **jina la method** kama string inayoishia kwa null (“C”). Ili kuchapisha jina hilo kwa lldb:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Uchambuzi Dhidi ya Uchanganuzi wa Kihali

#### Kugundua VM

- Command ya **`sysctl hw.model`** kwa kawaida hurejesha kitambulisho cha modeli ya Mac kwenye hardware halisi, na inaweza kurejesha thamani tofauti kwenye VM.<sup>[[3]](#references)</sup>
- Kwa kuchezea thamani za **`hw.logicalcpu`** na **`hw.physicalcpu`**, baadhi ya malware hujaribu kugundua kama iko kwenye VM.<sup>[[4]](#references)</sup>
- Baadhi ya malware pia zinaweza **kugundua** kama mashine inatumia **VMware** kwa kutegemea MAC address (00:50:56).
- Inawezekana pia kugundua **ikiwa process inafanyiwa debug** kwa kutumia code rahisi kama hii:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Inaweza pia kuita system call ya **`ptrace`** kwa flag ya **`PT_DENY_ATTACH`**. Hii **huzuia** debugger kujifunga kwenye process na kuifuatilia.
  - Unaweza kuangalia ikiwa function ya **`sysctl`** au **`ptrace`** **imeingizwa** (lakini malware inaweza kuiingiza kwa njia ya dynamic)
  - Kama ilivyobainishwa kwenye writeup hii, “[Kushinda Mbinu za Kupinga Debug: vibadala vya macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_Ujumbe Process # exited with **status = 45 (0x0000002d)** kwa kawaida ni ishara ya wazi kuwa lengo la debug linatumia **PT_DENY_ATTACH**_”

#### Kukabidhi process kwa `fork()`

Process inaweza kuepuka debugger ambayo imeshikamana na PID ya awali kwa kuita `fork()` karibu na mwanzo, kusitisha parent (`fork()` hurejesha PID chanya ya child), kisha kuendeleza logic iliyolindwa kwenye child pekee (`fork()` hurejesha `0`). Kutatua `fork` kwa `dlsym(RTLD_DEFAULT, "fork")` pia huondoa sehemu ya moja kwa moja ya kuita `_fork`, lakini huu ni kikwazo cha uchanganuzi tu: string ya jina la symbol na data flow ya dynamic resolution bado vinaonekana kwenye binary ya Mach-O.<sup>[[10]](#references)[[11]](#references)</sup>

Kwenye arm64, gundua muundo huu kwa kufuatilia data flow badala ya anwani zisizobadilika: arguments mbili za kwanza za `dlsym` hupitishwa kwenye `x0` na `x1`, `RTLD_DEFAULT` inaweza kuonekana kama `-2` (kwa mfano, `movn x0, #1`), na jozi ya `adrp`/`add` kwa kawaida huunda anwani ya string ya `"fork"`. Baada ya `bl` kwenda kwenye stub ya `dlsym`, fuatilia pointer iliyorejeshwa kutoka `x0` kupitia ukaguzi wake wa null na uhifadhi wake hadi kwenye `blr` ya baadaye isiyo ya moja kwa moja. Kisha fuatilia matokeo ya `fork()` kwenye `w0`: sifuri huchagua mwendelezo wa child, huku thamani chanya na `-1` zikichagua njia ya parent/error.<sup>[[10]](#references)[[11]](#references)</sup>

Njia ya static bypass ni kukandamiza mwito usio wa moja kwa moja na kulazimisha ukaguzi wa matokeo uliopo uchague njia ya child. Kwa mfano, ikiwa compiler imetoa mfuatano ulioonyeshwa hapa chini, patch `blr` na uhifadhi wa matokeo kwa `nop`, weka matokeo ya kubuniwa ya sifuri, na uache logic ya ulinganishi/branch ibaki. Kisha application inaendelea chini ya PID ya awali bila kuunda child; registers za instruction na malengo ya branch lazima zilinganishwe na build iliyochanganuliwa.<sup>[[10]](#references)[[11]](#references)</sup>

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

Core dumps huundwa ikiwa:

- `kern.coredump` sysctl imewekwa kuwa 1 (kwa chaguo-msingi)
- Ikiwa mchakato haukuwa suid/sgid au `kern.sugid_coredump` ni 1 (kwa chaguo-msingi ni 0)
- Kikomo cha `AS_CORE` kinaruhusu operesheni hiyo. Inawezekana kuzuia uundaji wa core dumps kwa kuita `ulimit -c 0` na kuwasha tena kwa `ulimit -c unlimited`.

Katika hali hizo, core dumps huzalishwa kulingana na sysctl ya `kern.corefile` na kwa kawaida huhifadhiwa kwenye `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **huchanganua michakato inayocrash na kuhifadhi ripoti ya crash kwenye diski**. Ripoti ya crash ina taarifa zinazoweza **kumsaidia developer kutambua** chanzo cha crash.\
Kwa applications na michakato mingine **inayoendeshwa katika muktadha wa launchd wa kila mtumiaji**, ReportCrash huendeshwa kama LaunchAgent na kuhifadhi ripoti za crash kwenye `~/Library/Logs/DiagnosticReports/` ya mtumiaji.\
Kwa daemons, michakato mingine **inayoendeshwa katika muktadha wa launchd wa mfumo** na michakato mingine yenye privilege, ReportCrash huendeshwa kama LaunchDaemon na kuhifadhi ripoti za crash kwenye `/Library/Logs/DiagnosticReports` ya mfumo.

Ikiwa una wasiwasi kuhusu ripoti za crash **kutumwa kwa Apple**, unaweza kuzizima. La sivyo, ripoti za crash zinaweza kusaidia **kubaini jinsi server ilivyocrash**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Kulala

Unapofanya fuzzing kwenye macOS, zuia Mac isilale:

- systemsetup -setsleep Never
- pmset, Mapendeleo ya Mfumo
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Kukatika kwa SSH

Ikiwa unafanya fuzzing kupitia muunganisho wa SSH, ni muhimu kuhakikisha kuwa session haitakatika. Kwa hiyo, badilisha faili ya sshd_config kwa kuweka:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Internal Handlers

**Angalia ukurasa ufuatao** ili kujua jinsi ya kubaini ni app gani inayohusika na **kushughulikia scheme au protocol maalum:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerating Network Processes

Hii ni muhimu kwa kutafuta processes zinazodhibiti data ya mtandao:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Au tumia `netstat` au `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Hufanya kazi kwa zana za CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

"**Hufanya kazi tu**" na zana nyingi za macOS GUI. Baadhi ya programu zina mahitaji ya ziada, kama vile majina ya faili ya kipekee, kiendelezi maalum, au kusoma faili kutoka kwenye sandbox container yake (`~/Library/Containers/com.apple.Safari/Data`).

Baadhi ya mifano:

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

### Taarifa Zaidi kuhusu Fuzzing ya macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [Majibu kwa Matukio ya OS X: Uandishi wa Skripti na Uchambuzi](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Majira ya Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Sanaa ya Mac Malware, Juzuu ya I: Uchambuzi](https://taomm.org/)
- [4] [No Starch Press - Sanaa ya Mac Malware: Mwongozo wa Kuchambua Programu Hasidi](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - Taarifa iliyohifadhiwa katika sehemu hizi kwenye chapisho hili la blogu](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Kutatua hitilafu katika Apple Binaries Zinazotumia Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Kushinda Mbinu za Kuzuia Utatuzi wa Hitilafu: Vibadala vya macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Kumbukumbu zenye muundo za Xcode na `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Kuonyesha data ya faragha katika kumbukumbu iliyounganishwa ya macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [tony-go/antidebug-examples - Mifano ya fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [11] [Reverse Society - Mbinu ya kuzuia utatuzi wa hitilafu kwa kutumia dlsym na fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
{{#include ../../../banners/hacktricks-training.md}}
