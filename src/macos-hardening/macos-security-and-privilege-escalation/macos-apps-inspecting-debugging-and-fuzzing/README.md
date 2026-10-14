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
> **`Codesign`** hupatikana kwenye **macOS**, ilhali **`ldid`** hupatikana kwenye **iOS**.

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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) ni zana muhimu ya kukagua faili za **.pkg** (visakinishi) na kuona vilivyomo kabla ya kuzisakinisha.\
Visakinishi hivi vina script za bash za `preinstall` na `postinstall` ambazo waandishi wa malware kwa kawaida hutumia vibaya ili **persist** **hiyo** **malware**.

### hdiutil

Zana hii **mounts** faili za Apple disk image (`.dmg`) ili ziweze kukaguliwa kabla ya chochote kuendeshwa:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Itawekwa kwenye `/Volumes`

### Binaries zilizopakiwa

- Angalia kama entropy iko juu
- Angalia strings (kama karibu hakuna string zinazoeleweka, binary imepakiwa)
- UPX packer ya macOS hutengeneza section inayoitwa `__XHDR`.

## Uchambuzi wa Objective-C tuli

### Metadata

> [!CAUTION]
> Kumbuka kwamba programu zilizoandikwa kwa Objective-C **huhifadhi** matamko ya class **zinapokuwa** **compiled** kuwa [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Matamko hayo ya class **hujumuisha** jina na aina ya:

- Interfaces zilizofafanuliwa
- Methods za interface
- Instance variables za interface
- Protocols zilizofafanuliwa

Kumbuka kwamba majina haya yanaweza kufichwa ili kufanya reverse engineering ya binary kuwa ngumu zaidi.

### Kuitwa kwa function

Function inapoitwa kwenye binary inayotumia Objective-C, badala ya kuita function hiyo, code iliyocompile-itwa huita **`objc_msgSend`**. Ambayo itaita function ya mwisho:

![Metadata - Kuitwa kwa function: Function inapoitwa kwenye binary inayotumia Objective-C, badala ya kuita function hiyo, code iliyocompile-itwa huita objc msgSend . Ambayo itakuwa...](<../../../images/image (305).png>)

Vigezo vinavyotarajiwa na function hii ni:

- Kigezo cha kwanza (**self**) ni "pointer inayoelekeza kwenye **instance ya class inayopaswa kupokea ujumbe**". Au kwa ufupi zaidi, ni object ambayo method inaitwa juu yake. Ikiwa method ni class method, hiki kitakuwa instance ya class object (kwa ujumla wake), ilhali kwa instance method, self itaelekeza kwenye instance ya class iliyoundwa kama object.
- Kigezo cha pili, (**op**), ni "selector ya method inayoshughulikia ujumbe". Tena, kwa ufupi zaidi, hili ni **jina la method.**
- Vigezo vilivyosalia ni **thamani zozote zinazohitajika na method** (op).

Tazama jinsi ya **kupata taarifa hii kwa urahisi kwa kutumia `lldb` kwenye ARM64** katika ukurasa huu:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Kigezo**             | **Register**                                                   | **(kwa) objc_msgSend**                                      |
| ---------------------- | -------------------------------------------------------------- | ----------------------------------------------------------- |
| **Kigezo cha 1**       | **rdi**                                                        | **self: object ambayo method inaitwa juu yake**              |
| **Kigezo cha 2**       | **rsi**                                                        | **op: jina la method**                                       |
| **Kigezo cha 3**       | **rdx**                                                        | **Kigezo cha 1 cha method**                                 |
| **Kigezo cha 4**       | **rcx**                                                        | **Kigezo cha 2 cha method**                                 |
| **Kigezo cha 5**       | **r8**                                                         | **Kigezo cha 3 cha method**                                 |
| **Kigezo cha 6**       | **r9**                                                         | **Kigezo cha 4 cha method**                                 |
| **Kigezo cha 7 na zaidi** | <p><strong>rsp+</strong><br><strong>(kwenye stack)</strong></p> | **Kigezo cha 5 na zaidi cha method**                        |

### Dump ya metadata ya Objective-C

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) ni zana ya kufanya class-dump kwenye Objective-C binaries. GitHub inataja dylibs, lakini inafanya kazi pia na executables.

```bash
./dynadump dump /path/to/bin
```

Wakati wa kuandika, **hii ndiyo inayofanya kazi vizuri zaidi kwa sasa**.

#### Zana za kawaida

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) ndiyo zana ya awali ya kutengeneza matamko ya classes, categories na protocols katika code iliyoumbizwa kwa ObjectiveC.

Ni ya zamani na haidumishwi, kwa hivyo huenda isifanye kazi ipasavyo.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) ni zana ya kisasa na inayofanya kazi kwenye mifumo mbalimbali ya kutupa Objective-C class dump. Ikilinganishwa na zana zilizopo, iCDump inaweza kufanya kazi bila kutegemea mfumo wa Apple na inatoa Python bindings.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Uchambuzi tuli wa Swift

Kwa binary za Swift, kwa kuwa kuna uoanifu wa Objective-C, wakati mwingine unaweza kutoa matamko kwa kutumia [class-dump](https://github.com/nygard/class-dump/) lakini si kila wakati.

Kwa kutumia mistari ya amri **`jtool -l`** au **`otool -l`**, inawezekana kupata sehemu kadhaa zinazoanza na kiambishi **`__swift5`**:

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

Aidha, **Swift binaries zinaweza kuwa na symbols** (kwa mfano, maktaba zinahitaji kuhifadhi symbols ili functions zake ziweze kuitwa). Kwa kawaida, **symbols huwa na taarifa kuhusu jina la function** na sifa zake kwa namna isiyosomeka, kwa hiyo zina manufaa sana. Kuna **"demanglers"** zinazoweza kupata jina la awali:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Uchambuzi Tuli

> [!WARNING]
> **Usizime SIP kama hatua ya kawaida ya debugging.** Development builds zenye `com.apple.security.get-task-allow` zinaweza kufanyiwa debugging SIP ikiwa imewashwa. Kagua target kwa kutumia `codesign -d --entitlements :- /path/to/binary` kabla ya kujaribu LLDB. Debugger entitlement pekee haikupi ruhusa ya kufikia targets zinazolindwa na SIP.<sup>[[15]](#references)</sup>
>
> App inayosambazwa na hardened runtime kwa kawaida haijumuishi `get-task-allow` na huzuia kuunganisha debugger. Ikiwezekana, tumia debug build iliyotolewa na developer; kusaini upya nakala ya muda mfupi kunaweza kubadilisha tabia inayojaribiwa. Ikiwa target iliyolindwa inahitaji SIP izimwe, tumia mashine au VM maalumu ya majaribio badala ya mashine unayoitegemea.<sup>[[16]](#references)</sup>
>
> Mwongozo wa awali kuhusu target iliyolindwa katika mazingira ya majaribio yaliyotengwa ulitaja njia hizi mbadala:
>
> Kumbuka kwamba ili kufanyia binaries debugging, SIP lazima izimwe (`csrutil disable` au `csrutil enable --without debug`), au unakili binaries kwenye folda ya muda na uondoe signature kwa `codesign --remove-signature <binary-path>`, au uruhusu debugging ya binary (unaweza kutumia [script hii](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
>
> Hili si hitaji la jumla la SIP: pendelea debug build, na kumbuka kwamba kunakili au kubadilisha signature kunaweza kubadilisha tabia inayojaribiwa.

> [!WARNING]
> Kumbuka kwamba ili **kuweka instrumentation kwenye system binaries**, (kama `cloudconfigurationd`) kwenye macOS, **SIP lazima izimwe** (kuondoa signature pekee hakutatosha).

### APIs

macOS hutoa APIs za kuvutia zinazotoa taarifa kuhusu processes:

- `proc_info`: Hii ndiyo API kuu inayotoa taarifa nyingi kuhusu kila process. Unahitaji kuwa root ili kupata taarifa za processes nyingine, lakini huhitaji special entitlements au mach ports.
- `libsysmon.dylib`: Hutoa taarifa za process kupitia XPC functions, lakini wanaozitumia wanahitaji entitlement ya `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** ni mbinu ya kunasa hali ya processes, ikijumuisha call stacks za threads zote zinazoendesha. Hii ni muhimu hasa kwa debugging, uchanganuzi wa utendaji, na kuelewa tabia ya mfumo kwa wakati maalumu. Kwenye iOS na macOS, stackshotting inaweza kufanywa kwa kutumia zana na mbinu mbalimbali kama zana za **`sample`** na **`spindump`**.

### Sysdiagnose

Zana hii (`/usr/bini/ysdiagnose`) hukusanya taarifa nyingi kutoka kwenye kompyuta yako kwa kutekeleza makumi ya commands tofauti kama `ps`, `zprint`...

Lazima iendeshwe kama **root**, na daemon `/usr/libexec/sysdiagnosed` ina entitlements za kuvutia sana kama `com.apple.system-task-ports` na `get-task-allow`.

Plist yake iko kwenye `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, ambayo hutangaza MachServices 3:

- `com.apple.sysdiagnose.CacheDelete`: Hufuta archives za zamani ndani ya /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Special port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Kiolesura cha user mode kupitia class ya Obj-C `Libsysdiagnose`. Arguments tatu zinaweza kupitishwa kwenye dict (`compress`, `display`, `run`)

### Unified Logs

macOS hutengeneza logs nyingi zinazosaidia kuchanganua tabia ya app.

Baadhi ya fields za log zina tag ya `<private>` inayoficha taarifa zinazoweza kumtambua mtumiaji au kifaa. Maelekezo ya zamani wakati mwingine hueleza kusakinisha certificate ili kufichua fields hizi; mwongozo wa sasa wa debugging badala yake hutumia configuration profile yenye mipaka iliyoainishwa wazi na `Enable-Private-Data`, au `OSLogPreferences` kwa kila app, na tabia inaweza kutofautiana kulingana na subsystem na toleo la macOS. Majadiliano ya zamani kuhusu certificate/profile yamehifadhiwa kwenye marejeleo. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Paneli ya kushoto

Kwenye paneli ya kushoto ya Hopper unaweza kuona symbols (**Labels**) za binary, orodha ya procedures na functions (**Proc**), na strings (**Str**). Hizi si strings zote, bali zile zilizofafanuliwa katika sehemu mbalimbali za faili ya Mac-O (kama _cstring au `objc_methname`).

#### Paneli ya katikati

Kwenye paneli ya katikati unaweza kuona **disassembled code**. Unaweza kuiona kama disassembly **raw**, kama **graph**, kama **decompiled**, na kama **binary** kwa kubofya ikoni husika:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Ukibofya kulia kwenye code object unaweza kuona **references zinazoelekea au kutoka kwenye object hiyo**, au hata kubadilisha jina lake (hili halifanyi kazi kwenye decompiled pseudocode):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Zaidi ya hayo, **sehemu ya chini ya katikati unaweza kuandika commands za python**.

#### Paneli ya kulia

Kwenye paneli ya kulia unaweza kuona taarifa za kuvutia kama **historia ya urambazaji** (ili ujue jinsi ulivyofika kwenye hali ya sasa), **call graph** inayoonyesha **functions zote zinazoita function hii** na functions zote **zinazoitwa na function hii**, pamoja na taarifa za **local variables**.

### dtrace

Huwawezesha watumiaji kufikia apps kwa **kiwango cha chini sana** na huwapa njia ya **kufuatilia** **programs** na hata kubadilisha mtiririko wa utekelezaji wake. Dtrace hutumia **probes** ambazo **huwekwa kote kwenye kernel**, katika maeneo kama mwanzo na mwisho wa system calls.

DTrace hutumia function ya **`dtrace_probe_create`** kuunda probe kwa kila system call. Probes hizi zinaweza kuwashwa kwenye **entry na exit point za kila system call**. Mwingiliano na DTrace hufanyika kupitia /dev/dtrace, ambayo inapatikana kwa root user pekee.<sup>[[1]](#references)</sup>

> [!TIP]
> Ili kuwasha Dtrace bila kuzima kabisa ulinzi wa SIP, unaweza kutekeleza hili ukiwa kwenye recovery mode: `csrutil enable --without dtrace`
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

Jina la probe lina sehemu nne: provider, module, function, na name (`fbt:mach_kernel:ptrace:entry`). Ikiwa hutabainisha sehemu yoyote ya jina, Dtrace itatumia sehemu hiyo kama wildcard.

Ili kusanidi DTrace iwashe probes na kubainisha hatua za kutekeleza zinapowashwa, tutahitaji kutumia lugha ya D.

Maelezo ya kina zaidi na mifano zaidi yanaweza kupatikana kwenye [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Mifano

Tekeleza `man -k dtrace` ili kuorodhesha **scripts za DTrace zinazopatikana**. Mfano: `sudo dtruss -n binary`

- Katika mstari

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

Ni kifaa cha kufuatilia kernel. Nambari zilizoandikwa zinaweza kupatikana kwenye **`/usr/share/misc/trace.codes`**.

Zana kama `latency`, `sc_usage`, `fs_usage` na `trace` hukitumia ndani.

Ili kuwasiliana na `kdebug`, hutumika `sysctl` kupitia namespace ya `kern.kdebug`, na MIB za kutumia zinaweza kupatikana kwenye `sys/sysctl.h`; kazi zake zinatekelezwa kwenye `bsd/kern/kdebug.c`.

Kwa kawaida, hatua hizi hutumika kuwasiliana na kdebug kupitia client maalum:

- Ondoa mipangilio iliyopo kwa kutumia KERN_KDSETREMOVE
- Weka trace kwa kutumia KERN_KDSETBUF na KERN_KDSETUP
- Tumia KERN_KDGETBUF kupata idadi ya maingizo ya buffer
- Ondoa client yako mwenyewe kwenye trace kwa kutumia KERN_KDPINDEX
- Washa ufuatiliaji kwa kutumia KERN_KDENABLE
- Soma buffer kwa kuita KERN_KDREADTR
- Linganisha kila thread na process yake kwa kuita KERN_KDTHRMAP.

Ili kupata maelezo haya, unaweza kutumia zana ya Apple **`trace`** au zana maalum [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Kumbuka kuwa Kdebug inapatikana kwa mteja mmoja tu kwa wakati mmoja.** Kwa hiyo, zana moja tu inayotumia k-debug inaweza kuendeshwa kwa wakati mmoja.

### ktrace

API za `ktrace_*` zinatoka kwenye `libktrace.dylib`, ambayo hufunika zile za `Kdebug`. Kisha, client anaweza kuita `ktrace_session_create` na `ktrace_events_[single/class]` ili kuweka callbacks kwa misimbo maalum, kisha kuianzisha kwa `ktrace_start`.

Unaweza kuitumia hata **SIP ikiwa imewashwa**

Unaweza kutumia zana ya `ktrace` kama client:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Au `tailspin`.

### kperf

Hii hutumika kufanya profiling katika kiwango cha kernel, na imejengwa kwa kutumia callouts za `Kdebug`.

Kimsingi, kigezo cha kimataifa `kernel_debug_active` hukaguliwa na, kikiwa kimewekwa, huita `kperf_kdebug_handler` kwa kutumia code ya `Kdebug` na anwani ya kernel frame inayoita. Ikiwa code ya `Kdebug` inalingana na mojawapo ya zilizochaguliwa, hupata "actions" zilizosanidiwa kama bitmap (angalia `osfmk/kperf/action.h` kwa chaguo zilizopo).

Kperf pia ina jedwali la sysctl MIB: (kama root) `sysctl kperf`. Code hizi zinapatikana katika `osfmk/kperf/kperfbsd.c`.

Zaidi ya hayo, sehemu ya utendaji wa Kperf ipo ndani ya `kpc`, ambayo hutoa taarifa kuhusu performance counters za mashine.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) ni zana muhimu sana ya kuangalia vitendo vinavyohusiana na process ambavyo process inafanya (kwa mfano, kufuatilia process mpya ambazo process inaunda).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) ni zana inayochapisha mahusiano kati ya processes.\
Unahitaji kufuatilia mac yako kwa command kama **`sudo eslogger fork exec rename create > cap.json`** (terminal inayoizindua inahitaji FDA). Kisha unaweza kupakia json kwenye zana hii ili kuona mahusiano yote:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) hufuatilia matukio ya faili kama vile kuundwa, kurekebishwa na kufutwa.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) ni zana ya GUI yenye mwonekano na hisia ambayo watumiaji wa Windows wanaweza kuifahamu kutoka Microsoft Sysinternal’s _Procmon_. Zana hii huruhusu kurekodi aina mbalimbali za matukio kuanzishwa na kusimamishwa, kuchuja matukio haya kwa kategoria kama faili, process, network, n.k., na kuhifadhi matukio yaliyorekodiwa katika umbizo la json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) ni sehemu ya zana za Developer za Xcode – hutumika kufuatilia utendaji wa programu, kutambua memory leaks na kufuatilia shughuli za mfumo wa faili.

![Crescendo - Apple Instruments: Apple Instruments ni sehemu ya zana za Developer za Xcode – hutumika kufuatilia utendaji wa programu, kutambua memory leaks na kufuatilia shughuli za mfumo wa faili](<../../../images/image (1138).png>)

### fs_usage

Huruhusu kufuatilia vitendo vinavyofanywa na processes:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) ni muhimu kwa kuona **libraries** zinazotumiwa na binary, **files** inazotumia na miunganisho ya **network**.\
Pia hukagua michakato ya binary dhidi ya **virustotal** na kuonyesha maelezo kuhusu binary.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Katika [**chapisho hili la blogu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) unaweza kupata mfano wa jinsi ya **kudebug daemon inayoendesha** iliyotumia **`PT_DENY_ATTACH`** kuzuia debugging hata kama SIP ilikuwa imezimwa.<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` ni ombi la `ptrace(2)` mahususi kwa Darwin lenye thamani **31** (`0x1f`); hoja nyingine hazizingatiwi. Mchakato unaweza kuliita moja kwa moja, bila fork, ili kukataa ufuatiliaji wa baadaye na mchakato mzazi.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### Hali ya XNU na mpangilio wa miito

Matokeo hutegemea ombi la `ptrace` linalofika XNU kwanza:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB ina-attach kwanza:** `debugserver` hutumia `PT_ATTACHEXC`; XNU huibadilisha kuwa `PT_ATTACH`, hufanya uidhinishaji wa `KAUTH_PROCESS_CANTRACE` na kuweka `P_LTRACED` kwenye target. `PT_DENY_ATTACH` inayofuata huona flag hiyo na kusitisha target kwa `W_EXITCODE(ENOTSUP, 0)`, ambayo kwa kawaida huonyeshwa na LLDB kama status **45** (`0x2d`).
- **Target inakataa kwanza:** XNU huweka `P_LNOATTACH`. Attach inayofuata hukataliwa na uidhinishaji wa process-tracing; njia ya hitilafu ya attach huona `P_LNOATTACH` na kutuma `SIGSEGV` kwa process inayojaribu ku-attach, jambo linaloweza kuonekana kwenye LLDB kama muunganisho wa `debugserver` uliopotea.

Ili kutofautisha njia hizi, washa logging ya `debugserver` kabla ya kuzindua au ku-attach, kisha kagua maombi yake ya `ptrace`:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### Utambuzi tuli wa ARM64 na bypass

Kwa Mach-O ya ARM64 isiyofichwa, tafuta stub iliyoingizwa ya `_ptrace` na ukague maeneo ya miito. Hoja ya kwanza ya integer hupitishwa katika `w0`, kwa hivyo mfuatano huu hufichua moja kwa moja ombi la anti-debug. Kutokuwepo kwa import hii si uthibitisho kamili, kwa sababu code inaweza kutatua `ptrace` kwa njia ya dynamic. Import ya `_sysctl` pia inaweza kuashiria ukaguzi wa anti-debug, ingawa nayo inaweza kutatuliwa kwa njia ya dynamic.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

Katika mfano ulioonyeshwa, kubadilisha thamani ya immediate kutoka `0x1f` hadi `0x0` hubadilisha ombi kuwa `PT_TRACE_ME` na kuruhusu programu kuendelea chini ya LLDB. Hii ni **bypass maalum kwa mfano huu**, si no-op ya jumla: kagua ukaguzi wa thamani ya kurejesha ya caller na mtiririko wa udhibiti kabla ya kuchagua kubadilisha ombi, kuruka call, au kulazimisha kurejeshwa kwa mafanikio.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** ndiyo **zana inayotumika kwa kawaida** kwa **debugging** ya binary za **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Unaweza kuweka intel flavour unapotumia lldb kwa kuunda faili **`.lldbinit`** kwenye folda yako ya nyumbani kwa kutumia mstari ufuatao:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Ndani ya lldb, hifadhi dump ya process kwa `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>Maelezo</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Anza utekelezaji. Utaendelea hadi breakpoint ifikiwe au process ikome.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Anza utekelezaji na usimamishe kwenye entry point.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Endeleza utekelezaji wa process inayofanyiwa debug.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Tekeleza instruction inayofuata. Amri hii huruka juu ya function calls.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Tekeleza instruction inayofuata. Tofauti na amri ya <code>nexti</code>, amri hii huingia ndani ya function calls.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Tekeleza instructions zilizosalia kwenye function (frame) ya sasa, rudi, kisha usimame.</td></tr>
<tr><td><strong>control + c</strong></td><td>Simamisha utekelezaji. Ikiwa process imeendeshwa (<code>r</code>) au kuendelezwa (<code>c</code>), hii huifanya isimame mahali inapoendelea kutekelezwa kwa sasa.</td></tr>
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
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Onyesha memory kama string inayoishia na null.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Onyesha memory kama assembly instruction.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Onyesha memory kama byte.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Hii huchapisha object inayorejelewa na parameter.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
API au methods nyingi za Apple Objective-C hurejesha objects, hivyo zinapaswa kuonyeshwa kwa amri ya “print object” (<code>po</code>). Ikiwa <code>po</code> haitoi matokeo yenye maana, tumia <code>x/b</code>.
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
> Unapopiga simu ya function **`objc_sendMsg`**, register **rsi** huwa na **jina la method** kama string inayoishia na null (“C”). Ili kuchapisha jina hilo kupitia lldb, fanya hivi:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- Amri ya **`sysctl hw.model`** kwa kawaida hurejesha kitambulisho cha model ya Mac kwenye hardware halisi, na inaweza kurejesha thamani tofauti kwenye VM.<sup>[[3]](#references)</sup>
- Baadhi ya malware hujaribu kugundua ikiwa kifaa kiko kwenye VM kwa kuchezea thamani za **`hw.logicalcpu`** na **`hw.physicalcpu`**.<sup>[[4]](#references)</sup>
- Loader inaweza pia kuuliza `kern.hv_vmm_present` na `machdep.cpu.brand_string` kupitia `sysctl` inapokagua kama kuna VM kabla ya kufungua hatua inayofuata. Ukaguzi huu hukamilisha, badala ya kuchukua nafasi ya, ukaguzi wa debugger attachment ulioelezwa hapa chini.<sup>[[20]](#references)</sup>
- Baadhi ya malware zinaweza pia **kutambua** ikiwa mashine inatumia **VMware** kwa kutegemea anwani ya MAC (00:50:56).
- Pia inawezekana kujua **ikiwa process inafanyiwa debug** kwa code rahisi kama hii:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Inaweza pia kuita system call ya `ptrace` kwa flag ya `PT_DENY_ATTACH`. Hii huzuia debugger ku-attach na kufuatilia process. Angalia [sehemu ya PT_DENY_ATTACH](#page-title) kwa tabia ya XNU inayotegemea mpangilio wa matukio, logging ya `debugserver` na workflow ya ARM64 patching.<sup>[[7]](#references)[[12]](#references)</sup>
- Inaweza pia kuita system call ya **`ptrace`** kwa flag ya **`PT_DENY_ATTACH`**. Angalia [sehemu ya PT_DENY_ATTACH](#page-title) kwa tabia ya XNU inayotegemea mpangilio wa matukio, logging ya `debugserver` na workflow ya ARM64 patching.<sup>[[7]](#references)[[12]](#references)</sup>
  - Unaweza kuangalia ikiwa function ya **`sysctl`** au **`ptrace`** ina-**importiwa** (lakini malware inaweza kui-import kwa njia ya dynamic)
  - Kama ilivyoelezwa kwenye writeup hii, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_Ujumbe Process # exited with **status = 45 (0x0000002d)** kwa kawaida ni ishara dhahiri kwamba debug target inatumia **PT_DENY_ATTACH**_”
#### `fork()` process handoff

Process inaweza kukwepa debugger inayoendelea ku-attach kwa PID ya awali kwa kuita `fork()` karibu na mwanzo wa utekelezaji, kisha kukomesha parent (`fork()` hurejesha PID chanya ya child) na kuendelea na logic iliyolindwa kwenye child pekee (`fork()` hurejesha `0`). Kutumia `dlsym(RTLD_DEFAULT, "fork")` kutafuta `fork` pia huondoa call site ya moja kwa moja ya `_fork`, lakini hili ni kikwazo cha anti-analysis tu: string ya jina la symbol na data flow ya dynamic resolution bado vinaonekana kwenye binary ya Mach-O.<sup>[[13]](#references)[[14]](#references)</sup>

Kwenye arm64, tambua muundo huu kwa kufuatilia data flow badala ya anwani zisizobadilika: arguments mbili za kwanza za `dlsym` hupitishwa kwenye `x0` na `x1`, `RTLD_DEFAULT` inaweza kuonekana kama `-2` (kwa mfano, `movn x0, #1`), na jozi ya `adrp`/`add` kwa kawaida huunda anwani ya string ya `"fork"`. Baada ya `bl` kwenda kwenye stub ya `dlsym`, fuatilia pointer iliyorejeshwa kutoka `x0` kupitia ukaguzi wake wa null na uhifadhi wake hadi kwenye `blr` ya baadaye isiyo ya moja kwa moja. Kisha fuatilia matokeo ya `fork()` kwenye `w0`: thamani sifuri huchagua mwendelezo wa child, huku thamani chanya na `-1` zikichagua njia ya parent/error.<sup>[[13]](#references)[[14]](#references)</sup>

Njia ya static bypass ni kukandamiza indirect call na kulazimisha ukaguzi wa matokeo uliopo kuchagua njia ya child. Kwa mfano, ikiwa compiler imetengeneza mlolongo unaoonyeshwa hapa chini, patch `blr` na hifadhi ya matokeo ziwe `nop`, weka matokeo ya kubuniwa ya sifuri, na uache logic ya comparison/branch kama ilivyo. Kisha application huendelea chini ya PID ya awali bila kuunda child; registers za instruction na branch targets lazima zibadilishwe kulingana na build iliyochanganuliwa.<sup>[[13]](#references)[[14]](#references)</sup>

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

- `kern.coredump` sysctl imewekwa kuwa 1 (ndiyo hali ya kawaida)
- Mchakato haukuwa suid/sgid au `kern.sugid_coredump` ni 1 (hali ya kawaida ni 0)
- Kikomo cha `AS_CORE` kinaruhusu operesheni hiyo. Unaweza kuzuia uundaji wa core dumps kwa kutumia `ulimit -c 0` na kuziwasha tena kwa `ulimit -c unlimited`.

Katika hali hizo, core dumps hutengenezwa kulingana na sysctl ya `kern.corefile` na kwa kawaida huhifadhiwa kwenye `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **huchanganua michakato inayoharibika na kuhifadhi ripoti ya hitilafu kwenye diski**. Ripoti ya hitilafu huwa na maelezo yanayoweza **kumsaidia msanidi kubaini** chanzo cha hitilafu.\
Kwa programu na michakato mingine **inayoendeshwa katika muktadha wa launchd wa kila mtumiaji**, ReportCrash huendeshwa kama LaunchAgent na kuhifadhi ripoti za hitilafu kwenye `~/Library/Logs/DiagnosticReports/` ya mtumiaji.\
Kwa daemoni, michakato mingine **inayoendeshwa katika muktadha wa launchd wa mfumo**, na michakato mingine yenye upendeleo, ReportCrash huendeshwa kama LaunchDaemon na kuhifadhi ripoti za hitilafu kwenye `/Library/Logs/DiagnosticReports` ya mfumo.

Ikiwa una wasiwasi kuhusu ripoti za hitilafu **kutumwa kwa Apple**, unaweza kuzizima. La sivyo, ripoti za hitilafu zinaweza kusaidia **kubaini jinsi seva ilivyoharibika**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Kulala

Wakati wa kufanya fuzzing kwenye macOS, zuia Mac isilale:

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

### Handlers za Ndani

**Angalia ukurasa ufuatao** ili kujua jinsi ya kupata app inayohusika na **kushughulikia scheme au protocol iliyobainishwa:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Kuorodhesha Michakato ya Mtandao

Hii inafaa kwa kupata michakato inayodhibiti data ya mtandao:

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

### Stateful Mach IPC fuzzing

Mach services zinazofichuliwa na daemons zenye privileged ni malengo mazuri ya fuzzing wakati client asiye na privileged au aliyewekewa sandbox anaweza kupata send right. Anza na ingizo la `MachServices` la daemon kwenye launchd, kisha tumia [MIG analysis workflow](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) kuoanisha message IDs na handlers. Kabla ya kubadilisha bytes, weka breakpoint kwenye MIG server routine huku client wa kawaida akitumia service, kisha hifadhi request messages halali kama seed inputs. Hifadhi header fields zinazohitajika, ukubwa wa message na mpangilio wa descriptors ili mutations zifikie handler badala ya kushindwa mara moja kwenye dispatch.<sup>[[17]](#references)</sup>

Handlers wengi hutegemea calls zilizotangulia. Hakikisha harness inaanzisha state ya service, kisha itumie kila fuzz input kama mfululizo wa **operations pamoja na arguments**: tuma setup requests (kama open au create), hifadhi identifiers zinazorejeshwa, kisha uzitumie kwenye requests zinazofuata. Hii huruhusu coverage feedback kuchunguza state transitions badala ya kurudia kugonga ukaguzi wa object ambayo haijaanzishwa.<sup>[[17]](#references)</sup>

Kwa target ambayo source code yake haipatikani, harness ya in-process inayopiga MIG dispatch routine inaweza kuwekewa instrumentation kwa Jackalope/TinyInst. [CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) ni implementation halisi, si harness inayoweza kutumiwa moja kwa moja kwa services nyingine.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**Thibitisha kila crash kupitia njia halisi ya IPC.** Harness ya direct-dispatch huruka kernel validation ya Mach messages na inaweza kutoa false positives, hasa inapotoa memory au port descriptors za out-of-line (OOL) zisizo halali. Tenga backing memory halali ya OOL kwenye harness, kisha rudia testcase iliyopunguzwa kupitia `mach_msg` kutoka kwa client yenye access ileile ya awali ya service na uthibitishe kwamba daemon bado inapata crash.<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Hufanya kazi kwa CLI tools

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Hufanya kazi "**bila shida**" na macOS GUI tools nyingi. Baadhi ya applications zina mahitaji ya ziada, kama vile filenames za kipekee, extension maalum, au kusoma files kutoka kwenye sandbox container yake (`~/Library/Containers/com.apple.Safari/Data`).

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

- [1] [Majibu ya Tukio la OS X: Uandishi wa Script na Uchambuzi](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Majira ya Joto ya Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Sanaa ya Mac Malware, Juzuu ya I: Uchambuzi](https://taomm.org/)
- [4] [No Starch Press - Sanaa ya Mac Malware: Mwongozo wa Kuchambua Programu Hasidi](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - taarifa iliyohifadhiwa katika sehemu hizi kwenye chapisho hili la blogu](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Kutatua hitilafu za Apple Binaries zinazotumia Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Kushinda Mbinu za Anti-Debug: variants za macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - Kumbukumbu zilizopangwa za Xcode na `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Kuonyesha taarifa binafsi kwenye logi iliyounganishwa ya macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Ufafanuzi wa maombi ya Apple XNU `ptrace.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Utekelezaji wa Apple XNU `ptrace` katika `mach_process.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - Maelezo ya ndani ya ptrace: Jinsi inavyozuia debugger kuunganishwa](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - Mifano ya fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - Mbinu ya anti-debugging inayotumia dlsym na fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - Haki ya zana ya debugging](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - Debugging programu ngumu ya mtu mwingine](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - Kuvunja Kizuizi cha Sauti Sehemu ya I: Kufanya Fuzzing ya CoreAudio kwa Mach Messages](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - CoreAudioFuzz harness](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Jackalope fuzzer](https://github.com/googleprojectzero/Jackalope)
- [20] [Kaspersky Securelist - Toleo jipya la MacSync macOS stealer linalenga wapenda crypto na wasanidi programu](https://securelist.com/macsync-new-version/121383/)
{{#include ../../../banners/hacktricks-training.md}}
