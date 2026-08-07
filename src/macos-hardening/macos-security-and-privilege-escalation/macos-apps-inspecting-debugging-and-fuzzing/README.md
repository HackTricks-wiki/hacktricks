# Programu za macOS - Kukagua, debugging na Fuzzing

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
> Kumbuka kwamba **`disarm`** inaweza pia kufanya kazi na faili za IM4P zilizobanwa (kama vile `kernelcache`) na kutoa sehemu zinazohitajika pekee, au hata kuchanganua sehemu inayohitajika bila kuitoa.
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
> **`Codesign`** inapatikana kwenye **macOS**, huku **`ldid`** ikipatikana kwenye **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) ni zana inayofaa kukagua faili za **.pkg** (visakinishi) na kuona vilivyomo kabla ya kuvisakinisha.\
Visakinishi hivi vina scripts za `preinstall` na `postinstall` za bash ambazo waandishi wa malware kwa kawaida huzitumia vibaya ili **kuendeleza** **kuwepo kwa** **malware**.

### hdiutil

Zana hii inaruhusu **ku-mount** faili za picha za diski za Apple (**.dmg**) ili kuzikagua kabla ya kuendesha chochote:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
It will be mounted in `/Volumes`

### Binaries zilizopakiwa

- Angalia high entropy
- Angalia strings (ikiwa karibu hakuna string inayoweza kueleweka, imepakiwa)
- UPX packer ya MacOS hutengeneza section inayoitwa "\_\_XHDR"

## Uchambuzi tuli wa Objective-C

### Metadata

> [!CAUTION]
> Kumbuka kuwa programu zilizoandikwa katika Objective-C **huhifadhi** declarations za class **zinapokuwa** **compiled** kuwa [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Declarations hizo za class **hu include** jina na aina ya:

- Interfaces zilizofafanuliwa
- Interface methods
- Interface instance variables
- Protocols zilizofafanuliwa

Kumbuka kuwa majina haya yanaweza kuwa obfuscated ili kufanya reversing ya binary kuwa ngumu zaidi.

### Function calling

Function inapoitwa katika binary inayotumia Objective-C, badala ya code iliyocompile kuita function hiyo moja kwa moja, itaita **`objc_msgSend`**. Hii itaita final function:

![Metadata - Function calling: Function inapoitwa katika binary inayotumia Objective-C, badala ya code iliyocompile kuita function hiyo moja kwa moja, itaita objc msgSend. Hii itakuwa...](<../../../images/image (305).png>)

Params ambazo function hii inatarajia ni:

- Parameter ya kwanza (**self**) ni "pointer inayoelekeza kwenye **instance ya class ambayo itapokea message**". Kwa ufupi zaidi, ni object ambayo method inaitwa juu yake. Ikiwa method ni class method, hii itakuwa instance ya class object (kwa ujumla), ilhali kwa instance method, self itaelekeza kwenye instance iliyoinstantiate ya class kama object.
- Parameter ya pili, (**op**), ni "selector ya method inayoshughulikia message". Kwa ufupi zaidi, hii ni **jina la method.**
- Parameters zilizosalia ni **values zozote zinazohitajika na method** (op).

Angalia jinsi ya **kupata info hii kwa urahisi kwa kutumia `lldb` katika ARM64** kwenye ukurasa huu:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argument**      | **Register**                                                    | **(for) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1st argument**  | **rdi**                                                         | **self: object ambayo method inaitwa juu yake** |
| **2nd argument**  | **rsi**                                                         | **op: jina la method**                             |
| **3rd argument**  | **rdx**                                                         | **1st argument ya method**                         |
| **4th argument**  | **rcx**                                                         | **2nd argument ya method**                         |
| **5th argument**  | **r8**                                                          | **3rd argument ya method**                         |
| **6th argument**  | **r9**                                                          | **4th argument ya method**                         |
| **7th+ argument** | <p><strong>rsp+</strong><br><strong>(kwenye stack)</strong></p> | **5th+ argument ya method**                        |

### Dump ObjectiveC metadata

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) ni tool ya kufanya class-dump ya Objective-C binaries. Github inaeleza dylibs, lakini hii pia hufanya kazi na executables.
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

[**class-dump**](https://github.com/nygard/class-dump/) ni zana ya awali inayozalisha declarations za classes, categories na protocols katika code iliyoumbizwa kwa Objective-C.

Ni ya zamani na haidumishwi, kwa hiyo huenda isifanye kazi ipasavyo.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) ni class dump ya kisasa na inayofanya kazi kwenye platforms mbalimbali kwa Objective-C. Ikilinganishwa na zana zilizopo, iCDump inaweza kuendeshwa bila kutegemea Apple ecosystem na hutoa Python bindings.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Uchambuzi wa Static wa Swift

Kwa binary za Swift, kwa kuwa kuna compatibility ya Objective-C, wakati mwingine unaweza kutoa declarations kwa kutumia [class-dump](https://github.com/nygard/class-dump/) lakini si kila mara.

Kwa command lines za **`jtool -l`** au **`otool -l`**, inawezekana kupata sections kadhaa zinazoanza na prefix ya **`__swift5`**:
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

Zaidi ya hayo, **Swift binaries zinaweza kuwa na symbols** (kwa mfano, libraries zinahitaji kuhifadhi symbols ili functions zake ziweze kuitwa). **Kwa kawaida symbols huwa na taarifa kuhusu jina la function** na attr kwa njia isiyopendeza, kwa hiyo ni muhimu sana, na kuna "**demanglers"** zinazoweza kupata jina la awali:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Uchambuzi wa Dynamic

> [!WARNING]
> Kumbuka kwamba ili ku-debug binaries, **SIP inahitaji kuzimwa** (`csrutil disable` au `csrutil enable --without debug`) au kunakili binaries kwenye folder ya muda na **kuondoa signature** kwa `codesign --remove-signature <binary-path>` au kuruhusu debugging ya binary (unaweza kutumia [script hii](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Kumbuka kwamba ili **ku-instrument system binaries**, (kama `cloudconfigurationd`) kwenye macOS, **SIP lazima izimwe** (kuondoa signature pekee hakutafanya kazi).

### APIs

macOS inaweka wazi APIs kadhaa za kuvutia zinazotoa taarifa kuhusu processes:

- `proc_info`: Hii ndiyo kuu inayotoa taarifa nyingi kuhusu kila process. Unahitaji kuwa root ili kupata taarifa za processes nyingine, lakini huhitaji special entitlements au mach ports.
- `libsysmon.dylib`: Inaruhusu kupata taarifa kuhusu processes kupitia functions zilizo wazi za XPC, hata hivyo, inahitajika kuwa na entitlement `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** ni technique inayotumika kunasa hali ya processes, ikiwemo call stacks za threads zote zinazoendesha. Hii ni muhimu hasa kwa debugging, performance analysis, na kuelewa tabia ya system katika wakati fulani. Kwenye iOS na macOS, stackshotting inaweza kufanywa kwa kutumia tools na methods kadhaa kama tools **`sample`** na **`spindump`**.

### Sysdiagnose

Tool hii (`/usr/bini/ysdiagnose`) hukusanya taarifa nyingi kutoka kwenye computer yako kwa kutekeleza commands kadhaa tofauti kama `ps`, `zprint`...

Lazima iendeshwe kama **root** na daemon `/usr/libexec/sysdiagnosed` ina entitlements za kuvutia sana kama `com.apple.system-task-ports` na `get-task-allow`.

Plist yake iko kwenye `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, ambayo inatangaza MachServices 3:

- `com.apple.sysdiagnose.CacheDelete`: Hufuta archives za zamani katika /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Special port 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: User mode interface kupitia class ya Obj-C `Libsysdiagnose`. Arguments tatu kwenye dict zinaweza kutumwa (`compress`, `display`, `run`)

### Unified Logs

MacOS hutengeneza logs nyingi ambazo zinaweza kuwa muhimu sana unapoendesha application na kujaribu kuelewa **inafanya nini**.

Zaidi ya hayo, kuna logs ambazo zitakuwa na tag `<private>` ili **kuficha** taarifa fulani **zinazomtambulisha** **user** au **computer**. Hata hivyo, inawezekana **ku-install certificate ili kufichua taarifa hii**. Fuata maelezo kutoka [**hapa**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Paneli ya kushoto

Kwenye paneli ya kushoto ya Hopper inawezekana kuona symbols (**Labels**) za binary, orodha ya procedures na functions (**Proc**) pamoja na strings (**Str**). Hizi si strings zote, bali ni zile zilizofafanuliwa katika sehemu kadhaa za Mac-O file (kama _cstring au_ `objc_methname`).

#### Paneli ya katikati

Kwenye paneli ya katikati unaweza kuona **code iliyodissassemble**. Pia unaweza kuiona ikiwa **raw** disassemble, kama **graph**, kama **decompiled** na kama **binary** kwa kubofya icon husika:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Kwa kubofya kulia kwenye code object unaweza kuona **references zinazoelekea/kutoka kwenye object hiyo** au hata kubadilisha jina lake (hii haifanyi kazi kwenye decompiled pseudocode):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Zaidi ya hayo, kwenye **sehemu ya chini ya paneli ya katikati unaweza kuandika commands za python**.

#### Paneli ya kulia

Kwenye paneli ya kulia unaweza kuona taarifa za kuvutia kama **navigation history** (ili ujue ulivyofika kwenye hali ya sasa), **call graph** ambapo unaweza kuona **functions zote zinazoita function hii** na functions zote ambazo **function hii inaziita**, pamoja na taarifa za **local variables**.

### dtrace

Inawaruhusu users kufikia applications katika kiwango cha **chini sana** na hutoa njia kwa users **kufuatilia** **programs** na hata kubadilisha execution flow yake. Dtrace hutumia **probes** ambazo **zimewekwa kote kwenye kernel** na ziko katika maeneo kama mwanzo na mwisho wa system calls.

DTrace hutumia function ya **`dtrace_probe_create`** kuunda probe kwa kila system call. Probes hizi zinaweza ku-trigger kwenye **entry na exit point za kila system call**. Interaction na DTrace hufanyika kupitia /dev/dtrace, ambayo inapatikana kwa root user pekee.<sup>[[1]](#references)</sup>

> [!TIP]
> Ili kuwezesha Dtrace bila kuzima kabisa ulinzi wa SIP unaweza kutekeleza katika recovery mode: `csrutil enable --without dtrace`
>
> Unaweza pia kutumia **`dtrace`** au **`dtruss`** binaries ambazo **ume-compile**.

Probes zinazopatikana za dtrace zinaweza kupatikana kwa:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Jina la probe lina sehemu nne: provider, module, function, na name (`fbt:mach_kernel:ptrace:entry`). Ikiwa hutabainisha sehemu fulani ya jina, Dtrace itatumia sehemu hiyo kama wildcard.

Ili kusanidi DTrace iwashe probes na kubainisha hatua za kutekeleza zinapowashwa, tutahitaji kutumia lugha ya D.

Maelezo ya kina zaidi na mifano mingine yanaweza kupatikana kwenye [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

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

Ni kifaa cha kernel tracing. Codes zilizoandikwa zinaweza kupatikana katika **`/usr/share/misc/trace.codes`**.

Tools kama `latency`, `sc_usage`, `fs_usage` na `trace` hukitumia internally.

Ili kuwasiliana na `kdebug`, `sysctl` hutumika kupitia namespace ya `kern.kdebug`, na MIBs za kutumia zinaweza kupatikana katika `sys/sysctl.h`, huku functions zikiwa implemented katika `bsd/kern/kdebug.c`.

Ili kuingiliana na kdebug kwa custom client, kwa kawaida hizi ndizo hatua:

- Ondoa settings zilizopo kwa kutumia KERN_KDSETREMOVE
- Weka trace kwa kutumia KERN_KDSETBUF na KERN_KDSETUP
- Tumia KERN_KDGETBUF kupata idadi ya buffer entries
- Ondoa client yako mwenyewe kwenye trace kwa kutumia KERN_KDPINDEX
- Washa tracing kwa kutumia KERN_KDENABLE
- Soma buffer kwa kuita KERN_KDREADTR
- Ili kuhusisha kila thread na process yake, ita KERN_KDTHRMAP.

Ili kupata taarifa hii, unaweza kutumia Apple tool **`trace`** au custom tool [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Kumbuka kuwa Kdebug inapatikana kwa mteja 1 pekee kwa wakati mmoja.** Kwa hiyo ni tool moja tu inayotumia k-debug inayoweza kuendeshwa kwa wakati mmoja.

### ktrace

APIs za `ktrace_*` zinatoka katika `libktrace.dylib`, ambayo hufunika APIs za `Kdebug`. Kisha, client anaweza kuita tu `ktrace_session_create` na `ktrace_events_[single/class]` ili kuweka callbacks kwenye codes maalum, na kisha kuianzisha kwa `ktrace_start`.

Unaweza kutumia hii hata SIP ikiwa imewashwa

Unaweza kutumia utility `ktrace` kama client:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Au `tailspin`.

### kperf

Hii hutumika kufanya kernel level profiling na imejengwa kwa kutumia `Kdebug` callouts.

Kimsingi, global variable `kernel_debug_active` hukaguliwa, na ikiwa imewekwa, huita `kperf_kdebug_handler` pamoja na `Kdebug` code na address ya kernel frame inayoita. Ikiwa `Kdebug` code inalingana na mojawapo ya zilizochaguliwa, hupata "actions" zilizosanidiwa kama bitmap (angalia `osfmk/kperf/action.h` kwa chaguo).

Kperf pia ina sysctl MIB table: (kama root) `sysctl kperf`. Code hizi zinapatikana katika `osfmk/kperf/kperfbsd.c`.

Zaidi ya hayo, sehemu ya utendakazi wa Kperf inapatikana katika `kpc`, ambayo hutoa taarifa kuhusu machine performance counters.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) ni tool muhimu sana ya kuangalia actions zinazohusiana na process ambazo process inafanya (kwa mfano, kufuatilia ni process zipi mpya ambazo process inaunda).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) ni tool inayochapisha mahusiano kati ya process.\
Unahitaji kufuatilia mac yako kwa command kama **`sudo eslogger fork exec rename create > cap.json`** (terminal inayoanzisha hii inahitaji FDA). Kisha unaweza kupakia json katika tool hii ili kuona mahusiano yote:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) huruhusu kufuatilia file events (kama vile kuundwa, kurekebishwa na kufutwa) na kutoa taarifa za kina kuhusu events hizo.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) ni GUI tool yenye mwonekano na matumizi ambayo watumiaji wa Windows wanaweza kuuyafahamu kutoka Microsoft Sysinternal’s _Procmon_. Tool hii huruhusu kurekodi aina mbalimbali za events kuanzishwa na kusitishwa, huruhusu events hizi kuchujwa kwa categories kama file, process, network, na kadhalika, na hutoa uwezo wa kuhifadhi events zilizorekodiwa katika json format.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) ni sehemu ya Xcode’s Developer tools – hutumika kufuatilia application performance, kutambua memory leaks na kufuatilia filesystem activity.

![Crescendo - Apple Instruments: Apple Instruments ni sehemu ya Xcode’s Developer tools – hutumika kufuatilia application performance, kutambua memory leaks na kufuatilia filesystem activity](<../../../images/image (1138).png>)

### fs_usage

Huruhusu kufuatilia actions zinazofanywa na process:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) ni muhimu kwa kuona **libraries** zinazotumiwa na binary, **files** inayotumia na miunganisho ya **network**.\
Pia hukagua michakato ya binary dhidi ya **virustotal** na kuonyesha maelezo kuhusu binary.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Katika [**chapisho hili la blogu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) unaweza kupata mfano wa jinsi ya kufanya **debugging ya daemon inayoendelea** iliyotumia **`PT_DENY_ATTACH`** kuzuia debugging hata kama SIP ilikuwa imezimwa.<sup>[[6]](#references)</sup>

### lldb

**lldb** ni tool ya de **facto** kwa **debugging** ya binary za **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Unaweza kuweka intel flavour unapotumia lldb kwa kuunda faili linaloitwa **`.lldbinit`** katika folda yako ya nyumbani likiwa na mstari ufuatao:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Ndani ya lldb, dump mchakato kwa `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>Maelezo</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Kuanza utekelezaji, ambao utaendelea bila kukatizwa hadi breakpoint iguswe au mchakato ukome.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Anzisha utekelezaji na usimamishe kwenye entry point</td></tr><tr><td><strong>continue (c)</strong></td><td>Endeleza utekelezaji wa mchakato unao-debugiwa.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Tekeleza instruction inayofuata. Command hii itaruka function calls.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Tekeleza instruction inayofuata. Tofauti na command ya nexti, command hii itaingia ndani ya function calls.</td></tr><tr><td><strong>finish (f)</strong></td><td>Tekeleza instructions zilizobaki katika function (“frame”) ya sasa, irudi na isimame.</td></tr><tr><td><strong>control + c</strong></td><td>Sitisha utekelezaji. Ikiwa mchakato umeendeshwa (r) au umeendelezwa (c), hii itausababisha usimame ...popote unapotekelezwa kwa sasa.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Any func called main</p><p><code>b <binname>`main</code> #Main func of the bin</p><p><code>b set -n main --shlib <lib_name></code> #Main func of the indicated bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Any NSFileManager method</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint list</p><p><code>br e/dis <num></code> #Enable/Disable breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Onyesha memory kama string inayomalizika kwa null.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Onyesha memory kama assembly instruction.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Onyesha memory kama byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Hii ita-print object inayorejelewa na param</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Kumbuka kwamba Apple’s Objective-C APIs au methods nyingi hurudisha objects, hivyo zinapaswa kuonyeshwa kupitia command ya “print object” (po). Ikiwa po haitoi output yenye maana, tumia <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Print map ya memory ya mchakato wa sasa</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Get the address of all the symbols from CoreNLP</td></tr></tbody></table>

> [!TIP]
> Unapoiita function ya **`objc_sendMsg`**, register ya **rsi** huhifadhi **jina la method** kama string inayomalizika kwa null (“C”). Ili kuchapisha jina hilo kupitia lldb, fanya:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- Command **`sysctl hw.model`** hurudisha "Mac" wakati **host ni MacOS**, lakini hurudisha kitu tofauti ikiwa ni VM.<sup>[[3]](#references)</sup>
- Kwa kucheza na thamani za **`hw.logicalcpu`** na **`hw.physicalcpu`**, baadhi ya malwares hujaribu kugundua ikiwa ni VM.<sup>[[4]](#references)</sup>
- Baadhi ya malwares pia zinaweza **kutambua** ikiwa mashine ni **VMware** kulingana na MAC address (00:50:56).
- Pia inawezekana kujua **ikiwa mchakato una-debugiwa** kwa code rahisi kama hii:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Pia inaweza kuita system call ya **`ptrace`** ikiwa na flag ya **`PT_DENY_ATTACH`**. Hii **humzuia** deb**u**gger ku-attach na kufanya tracing.
- Unaweza kuangalia ikiwa function ya **`sysctl`** au **`ptrace`** ime-**importiwa** (lakini malware inaweza kui-import dynamically)
- Kama ilivyoelezwa katika writeup hii, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
“_Ujumbe Process # exited with **status = 45 (0x0000002d)** kwa kawaida ni ishara wazi kwamba debug target inatumia **PT_DENY_ATTACH**_”

## Core Dumps

Core dumps huundwa ikiwa:

- sysctl ya `kern.coredump` imewekwa kuwa 1 (kwa default)
- Ikiwa mchakato haukuwa suid/sgid au `kern.sugid_coredump` ni 1 (kwa default ni 0)
- Limit ya `AS_CORE` inaruhusu operesheni hiyo. Inawezekana kuzuia uundaji wa core dumps kwa kuita `ulimit -c 0` na kuziwezesha tena kwa `ulimit -c unlimited`.

Katika hali hizo, core dumps hutengenezwa kulingana na sysctl ya `kern.corefile` na kwa kawaida huhifadhiwa katika `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **huchanganua michakato inayocrash na kuhifadhi crash report kwenye disk**. Crash report huwa na taarifa zinazoweza **kumsaidia developer kutambua** chanzo cha crash.\
Kwa applications na michakato mingine **inayoendeshwa katika per-user launchd context**, ReportCrash huendeshwa kama LaunchAgent na huhifadhi crash reports katika `~/Library/Logs/DiagnosticReports/` ya mtumiaji.\
Kwa daemons, michakato mingine **inayoendeshwa katika system launchd context** na michakato mingine yenye privileges, ReportCrash huendeshwa kama LaunchDaemon na huhifadhi crash reports katika `/Library/Logs/DiagnosticReports` ya mfumo.

Ikiwa una wasiwasi kuhusu crash reports **kutumwa kwa Apple**, unaweza kuzizima. Vinginevyo, crash reports zinaweza kusaidia **kubaini jinsi server ilivyocrash**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Usingizi

Wakati wa kufanya fuzzing kwenye MacOS ni muhimu kutoruhusu Mac kulala:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Kukatika kwa SSH

Ikiwa unafanya fuzzing kupitia muunganisho wa SSH, ni muhimu kuhakikisha kuwa session haitakatika. Kwa hivyo badilisha faili ya sshd_config kwa:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Vishughulikiaji vya Ndani

**Angalia ukurasa ufuatao** ili kujua jinsi unavyoweza kupata ni app gani inayohusika na **kushughulikia scheme au protocol iliyobainishwa:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Kuhesabu Michakato ya Mtandao

Hii ni muhimu kwa kupata michakato inayodhibiti data ya mtandao:
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

**"Hufanya kazi tu"** na zana za GUI za macOS. Kumbuka kuwa baadhi ya apps za macOS zina mahitaji maalum kama vile majina ya faili ya kipekee, extension sahihi, au hitaji la kusoma faili kutoka kwenye sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

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
### Maelezo Zaidi kuhusu Fuzzing ya MacOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Marejeo

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [The Art of Mac Malware, Volume I: Analysis](https://taomm.org/vol1/analysis.html)
- [4] [The Art of Mac Malware: The Guide to Analyzing Malicious Software](https://taomm.org/)
- [5] [knight.sc - information stored in these section in this blog post](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Debugging Apple Binaries That Use Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)

{{#include ../../../banners/hacktricks-training.md}}
