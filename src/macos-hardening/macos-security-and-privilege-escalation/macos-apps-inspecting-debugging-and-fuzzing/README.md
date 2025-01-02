# macOS Apps - Kukagua, kujaribu na Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Uchambuzi wa Kijamii

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

Unaweza [**kupakua disarm kutoka hapa**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
Unaweza [**kupakua jtool2 hapa**](http://www.newosxbook.com/tools/jtool.html) au kuisakinisha kwa kutumia `brew`.
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
> [!CAUTION] > **jtool imeachwa kwa ajili ya disarm**

### Codesign / ldid

> [!TIP] > **`Codesign`** inaweza kupatikana katika **macOS** wakati **`ldid`** inaweza kupatikana katika **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) ni chombo muhimu kuchunguza **.pkg** faili (wawekaji) na kuona kilichomo ndani kabla ya kuisakinisha.\
Wawekaji hawa wana `preinstall` na `postinstall` bash scripts ambazo waandishi wa malware mara nyingi hutumia vibaya ili **kuendelea** **na** **malware**.

### hdiutil

Chombo hiki kinaruhusu **kuunganisha** picha za diski za Apple (**.dmg**) ili kuzichunguza kabla ya kuendesha chochote:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Itakuwa imewekwa katika `/Volumes`

### Binaries zilizopakizwa

- Angalia kwa entropy ya juu
- Angalia nyuzi (kama hakuna nyuzi zinazoweza kueleweka, zimepakizwa)
- Packer ya UPX kwa MacOS inazalisha sehemu inayoitwa "\_\_XHDR"

## Uchambuzi wa Static Objective-C

### Metadata

> [!CAUTION]
> Kumbuka kwamba programu zilizoandikwa kwa Objective-C **zinashikilia** matangazo yao ya darasa **wakati** **zinapokanzwa** katika [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Matangazo kama haya ya darasa **yanajumuisha** jina na aina ya:

- Interfaces zilizofafanuliwa
- Mbinu za interface
- Vigezo vya mfano wa interface
- Itifaki zilizofafanuliwa

Kumbuka kwamba majina haya yanaweza kufichwa ili kufanya kurudi nyuma kwa binary kuwa ngumu zaidi.

### Kuita kazi

Wakati kazi inaitwa katika binary inayotumia objective-C, msimbo uliokanzwa badala ya kuita kazi hiyo, itaita **`objc_msgSend`**. Ambayo itakuwa ikitafuta kazi ya mwisho:

![](<../../../images/image (305).png>)

Paramu ambazo kazi hii inatarajia ni:

- Paramu ya kwanza (**self**) ni "kiashiria kinachopointia **mfano wa darasa ambalo linapaswa kupokea ujumbe**". Au kwa kusema kwa urahisi, ni kitu ambacho mbinu inaitwa juu yake. Ikiwa mbinu ni mbinu ya darasa, hii itakuwa mfano wa kitu cha darasa (kama jumla), wakati kwa mbinu ya mfano, self itapointia mfano ulioanzishwa wa darasa kama kitu.
- Paramu ya pili, (**op**), ni "mchaguzi wa mbinu inayoshughulikia ujumbe". Tena, kwa kusema kwa urahisi, hii ni tu **jina la mbinu.**
- Paramu zilizobaki ni **thamani zozote zinazohitajika na mbinu** (op).

Tazama jinsi ya **kupata habari hii kwa urahisi na `lldb` katika ARM64** katika ukurasa huu:

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Hoja**         | **Register**                                                    | **(kwa) objc_msgSend**                                 |
| ---------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **hoja ya 1**    | **rdi**                                                         | **self: kitu ambacho mbinu inaitwa juu yake**        |
| **hoja ya 2**    | **rsi**                                                         | **op: jina la mbinu**                                 |
| **hoja ya 3**    | **rdx**                                                         | **hoja ya 1 kwa mbinu**                               |
| **hoja ya 4**    | **rcx**                                                         | **hoja ya 2 kwa mbinu**                               |
| **hoja ya 5**    | **r8**                                                          | **hoja ya 3 kwa mbinu**                               |
| **hoja ya 6**    | **r9**                                                          | **hoja ya 4 kwa mbinu**                               |
| **hoja ya 7+**   | <p><strong>rsp+</strong><br><strong>(katika stack)</strong></p> | **hoja ya 5+ kwa mbinu**                              |

### Dump Metadata ya ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) ni chombo cha kutupa darasa la binaries za Objective-C. Github inataja dylibs lakini hii pia inafanya kazi na executable.
```bash
./dynadump dump /path/to/bin
```
Wakati wa uandishi, hii ni **sasa ndiyo inafanya kazi vizuri zaidi**.

#### Zana za kawaida
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) ni chombo cha asili kinachozalisha matamko ya madarasa, makundi na itifaki katika msimbo wa muundo wa ObjetiveC.

Ni ya zamani na haina matengenezo hivyo huenda isifanye kazi vizuri.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) ni chombo cha kisasa na chenye uwezo wa kufanya kazi kwenye majukwaa mbalimbali cha Objective-C. Ikilinganishwa na zana zilizopo, iCDump inaweza kufanya kazi bila kutegemea mfumo wa Apple na inatoa viunganishi vya Python.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Uchambuzi wa Static Swift

Kwa binaries za Swift, kwa kuwa kuna ulinganifu wa Objective-C, wakati mwingine unaweza kutoa matamko kwa kutumia [class-dump](https://github.com/nygard/class-dump/) lakini si kila wakati.

Kwa kutumia amri za **`jtool -l`** au **`otool -l`** inawezekana kupata sehemu kadhaa zinazooanza na kiambishi **`__swift5`**:
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
Unaweza kupata taarifa zaidi kuhusu [**taarifa zilizohifadhiwa katika sehemu hizi katika chapisho hili la blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Zaidi ya hayo, **binaries za Swift zinaweza kuwa na alama** (kwa mfano maktaba zinahitaji kuhifadhi alama ili kazi zake ziweze kuitwa). **Alama hizo kwa kawaida zina taarifa kuhusu jina la kazi** na attr kwa njia isiyo ya kuvutia, hivyo ni muhimu sana na kuna "**demanglers"** ambazo zinaweza kupata jina la asili:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Uchambuzi wa Kinetiki

> [!WARNING]
> Kumbuka kwamba ili kufanyia kazi binaries, **SIP inahitaji kuzuiliwa** (`csrutil disable` au `csrutil enable --without debug`) au nakala ya binaries kwenye folda ya muda na **ondoa saini** kwa `codesign --remove-signature <binary-path>` au ruhusu ufanyaji kazi wa binary (unaweza kutumia [hii script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Kumbuka kwamba ili **kufanya kazi na binaries za mfumo**, (kama `cloudconfigurationd`) kwenye macOS, **SIP inapaswa kuzuiliwa** (kuondoa saini pekee hakutafanya kazi).

### APIs

macOS inatoa APIs kadhaa za kuvutia ambazo zinatoa habari kuhusu michakato:

- `proc_info`: Hii ndiyo muhimu zaidi inayoleta habari nyingi kuhusu kila mchakato. Unahitaji kuwa root ili kupata habari za michakato mingine lakini huhitaji ruhusa maalum au mach ports.
- `libsysmon.dylib`: Inaruhusu kupata habari kuhusu michakato kupitia kazi zilizofichwa za XPC, hata hivyo, inahitajika kuwa na ruhusa `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** ni mbinu inayotumika kukamata hali ya michakato, ikiwa ni pamoja na stacks za wito za nyuzi zote zinazofanya kazi. Hii ni muhimu sana kwa ajili ya ufanyaji kazi, uchambuzi wa utendaji, na kuelewa tabia ya mfumo katika wakati maalum. Kwenye iOS na macOS, stackshotting inaweza kufanywa kwa kutumia zana na mbinu kadhaa kama zana **`sample`** na **`spindump`**.

### Sysdiagnose

Zana hii (`/usr/bini/ysdiagnose`) kimsingi inakusanya habari nyingi kutoka kwa kompyuta yako ikitekeleza amri tofauti kama `ps`, `zprint`...

Inapaswa kufanywa kama **root** na daemon `/usr/libexec/sysdiagnosed` ina ruhusa za kuvutia kama `com.apple.system-task-ports` na `get-task-allow`.

Plist yake iko katika `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` ambayo inatangaza MachServices 3:

- `com.apple.sysdiagnose.CacheDelete`: Inafuta archives za zamani katika /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Bandari maalum 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Kiolesura cha hali ya mtumiaji kupitia `Libsysdiagnose` darasa la Obj-C. Hoja tatu katika dict zinaweza kupitishwa (`compress`, `display`, `run`)

### Magogo Yaliyounganishwa

MacOS inazalisha magogo mengi ambayo yanaweza kuwa ya manufaa wakati wa kuendesha programu ikijaribu kuelewa **kila inafanya**.

Zaidi ya hayo, kuna baadhi ya magogo ambayo yatakuwa na lebo `<private>` ili **kuficha** baadhi ya **mtumiaji** au **kompyuta** **inayoweza kutambulika** habari. Hata hivyo, inawezekana **kusanidi cheti kufichua habari hii**. Fuata maelezo kutoka [**hapa**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Paneli ya Kushoto

Katika paneli ya kushoto ya hopper inawezekana kuona alama (**Labels**) za binary, orodha ya taratibu na kazi (**Proc**) na nyuzi (**Str**). Hizi si nyuzi zote lakini zile zilizofafanuliwa katika sehemu kadhaa za faili la Mac-O (kama _cstring au_ `objc_methname`).

#### Paneli ya Kati

Katika paneli ya kati unaweza kuona **kanuni iliyovunjwa**. Na unaweza kuiona kama **raw** disassemble, kama **grafu**, kama **decompiled** na kama **binary** kwa kubofya kwenye ikoni husika:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Kubofya kulia kwenye kitu cha kanuni unaweza kuona **marejeleo kwa/kutoka kwa kitu hicho** au hata kubadilisha jina lake (hii haifanyi kazi katika pseudocode iliyotafsiriwa):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Zaidi ya hayo, katika **chini ya kati unaweza kuandika amri za python**.

#### Paneli ya Kulia

Katika paneli ya kulia unaweza kuona habari za kuvutia kama **historia ya urambazaji** (ili ujue jinsi ulivyofika katika hali ya sasa), **grafu ya wito** ambapo unaweza kuona **kazi zote zinazoiita kazi hii** na kazi zote ambazo **kazi hii inaziita**, na habari za **mabadiliko ya ndani**.

### dtrace

Inaruhusu watumiaji kufikia programu kwa kiwango cha **chini sana** na inatoa njia kwa watumiaji **kufuatilia** **programu** na hata kubadilisha mtiririko wa utekelezaji wao. Dtrace inatumia **probes** ambazo zimewekwa katika **kernel** na ziko katika maeneo kama mwanzo na mwisho wa wito wa mfumo.

DTrace inatumia **`dtrace_probe_create`** kazi kuunda probe kwa kila wito wa mfumo. Probes hizi zinaweza kuamshwa katika **kiingilio na kutoka kwa kila wito wa mfumo**. Maingiliano na DTrace yanatokea kupitia /dev/dtrace ambayo inapatikana tu kwa mtumiaji wa root.

> [!TIP]
> Ili kuwezesha Dtrace bila kuzima kabisa ulinzi wa SIP unaweza kutekeleza katika hali ya urejelezi: `csrutil enable --without dtrace`
>
> Unaweza pia **`dtrace`** au **`dtruss`** binaries ambazo **umeunda**.

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
Jina la probe linajumuisha sehemu nne: mtoa huduma, moduli, kazi, na jina (`fbt:mach_kernel:ptrace:entry`). Ikiwa hujatoa sehemu fulani ya jina, Dtrace itatumia sehemu hiyo kama wildcard.

Ili kuunda DTrace ili kuamsha probes na kubaini ni hatua zipi za kuchukua wakati zinapowaka, tutahitaji kutumia lugha ya D.

Maelezo ya kina zaidi na mifano zaidi yanaweza kupatikana katika [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Mifano

Kimbia `man -k dtrace` ili orodheshe **scripts za DTrace zinazopatikana**. Mfano: `sudo dtruss -n binary`
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
- skripti
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

Ni kituo cha kufuatilia kernel. M codes zilizoorodheshwa zinaweza kupatikana katika **`/usr/share/misc/trace.codes`**.

Zana kama `latency`, `sc_usage`, `fs_usage` na `trace` zinatumia ndani yake.

Ili kuingiliana na `kdebug`, `sysctl` inatumika juu ya nafasi ya jina `kern.kdebug` na MIBs zinazoweza kutumika zinaweza kupatikana katika `sys/sysctl.h` zikiwa na kazi zilizotekelezwa katika `bsd/kern/kdebug.c`.

Ili kuingiliana na kdebug na mteja maalum, hatua hizi kawaida hufuatwa:

- Ondoa mipangilio iliyopo kwa KERN_KDSETREMOVE
- Weka trace kwa KERN_KDSETBUF na KERN_KDSETUP
- Tumia KERN_KDGETBUF kupata idadi ya entries za buffer
- Pata mteja wako kutoka kwenye trace kwa KERN_KDPINDEX
- Washa kufuatilia kwa KERN_KDENABLE
- Soma buffer kwa kuita KERN_KDREADTR
- Ili kulinganisha kila thread na mchakato wake, piga KERN_KDTHRMAP.

Ili kupata habari hii, inawezekana kutumia zana ya Apple **`trace`** au zana maalum [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Kumbuka kwamba Kdebug inapatikana kwa mteja 1 tu kwa wakati mmoja.** Hivyo, zana moja iliyo na k-debug inaweza kutekelezwa kwa wakati mmoja.

### ktrace

APIs za `ktrace_*` zinatoka `libktrace.dylib` ambazo zinafungua zile za `Kdebug`. Kisha, mteja anaweza tu kuita `ktrace_session_create` na `ktrace_events_[single/class]` kuweka callbacks kwenye codes maalum na kisha kuanza nayo kwa `ktrace_start`.

Unaweza kutumia hii hata na **SIP imewashwa**

Unaweza kutumia kama wateja zana `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Or `tailspin`.

### kperf

Hii inatumika kufanya profiling ya kiwango cha kernel na imejengwa kwa kutumia `Kdebug` callouts.

Kimsingi, kigezo cha kimataifa `kernel_debug_active` kinakaguliwa na kinapowekwa kinaita `kperf_kdebug_handler` na `Kdebug` code na anwani ya kernel frame inayopiga simu. Ikiwa `Kdebug` code inalingana na moja iliyochaguliwa inapata "vitendo" vilivyowekwa kama bitmap (angalia `osfmk/kperf/action.h` kwa chaguo).

Kperf ina meza ya sysctl MIB pia: (kama root) `sysctl kperf`. Mifano hii inaweza kupatikana katika `osfmk/kperf/kperfbsd.c`.

Zaidi ya hayo, subset ya kazi za Kperf inapatikana katika `kpc`, ambayo inatoa habari kuhusu vigezo vya utendaji wa mashine.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) ni chombo muhimu sana kuangalia vitendo vinavyohusiana na mchakato ambao mchakato unatekeleza (kwa mfano, kufuatilia mchakato gani mpya mchakato unaunda).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) ni chombo kinachochapisha uhusiano kati ya michakato.\
Unahitaji kufuatilia mac yako kwa amri kama **`sudo eslogger fork exec rename create > cap.json`** (terminal inayozindua hii inahitaji FDA). Na kisha unaweza kupakia json katika chombo hiki ili kuona uhusiano wote:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) inaruhusu kufuatilia matukio ya faili (kama vile uundaji, marekebisho, na kufutwa) ikitoa habari za kina kuhusu matukio hayo.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) ni chombo cha GUI chenye muonekano na hisia ambazo watumiaji wa Windows wanaweza kujua kutoka Microsoft Sysinternal’s _Procmon_. Chombo hiki kinaruhusu kurekodi aina mbalimbali za matukio kuanzishwa na kusitishwa, kinaruhusu kuchuja matukio haya kwa makundi kama faili, mchakato, mtandao, nk., na kinatoa uwezo wa kuhifadhi matukio yaliyorekodiwa katika muundo wa json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) ni sehemu ya zana za Developer za Xcode – zinazotumika kwa kufuatilia utendaji wa programu, kubaini leaks za kumbukumbu na kufuatilia shughuli za mfumo wa faili.

![](<../../../images/image (1138).png>)

### fs_usage

Inaruhusu kufuatilia vitendo vinavyofanywa na michakato:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) ni muhimu kuona **maktaba** zinazotumiwa na binary, **faili** inazotumia na **michakato** ya mtandao.\
Pia inakagua michakato ya binary dhidi ya **virustotal** na kuonyesha taarifa kuhusu binary.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Katika [**hiki kipande cha blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) unaweza kupata mfano wa jinsi ya **kudebug daemon inayotembea** ambayo ilitumia **`PT_DENY_ATTACH`** kuzuia debugging hata kama SIP ilikuwa imezimwa.

### lldb

**lldb** ni chombo cha de **facto** kwa **macOS** binary **debugging**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Unaweza kuweka ladha ya intel unapotumia lldb kwa kuunda faili inayoitwa **`.lldbinit`** katika folda yako ya nyumbani na mstari ufuatao:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Ndani ya lldb, dump mchakato kwa `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Amri</strong></td><td><strong>Maelezo</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Kuanza utekelezaji, ambayo itaendelea bila kukatizwa hadi breakpoint ipatikane au mchakato uishe.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Kuanza utekelezaji ukisimama kwenye kiingilio</td></tr><tr><td><strong>continue (c)</strong></td><td>Endelea na utekelezaji wa mchakato unaoshughulikiwa.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Tekeleza amri inayofuata. Amri hii itakataa kupita kwenye wito wa kazi.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Tekeleza amri inayofuata. Tofauti na amri ya nexti, amri hii itachambua wito wa kazi.</td></tr><tr><td><strong>finish (f)</strong></td><td>Tekeleza amri zilizobaki katika kazi ya sasa (“frame”) rudisha na simama.</td></tr><tr><td><strong>control + c</strong></td><td>Simamisha utekelezaji. Ikiwa mchakato umekuwa ukikimbia (r) au umeendelea (c), hii itasababisha mchakato kusimama ... popote ulipo.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Kazi yoyote inayoitwa main</p><p><code>b &#x3C;binname>`main</code> #Kazi kuu ya bin</p><p><code>b set -n main --shlib &#x3C;lib_name></code> #Kazi kuu ya bin iliyoonyeshwa</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Njia yoyote ya NSFileManager</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Vunjia katika kazi zote za maktaba hiyo</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Orodha ya breakpoint</p><p><code>br e/dis &#x3C;num></code> #Washa/Zima breakpoint</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Pata msaada wa amri ya breakpoint</p><p>help memory write #Pata msaada wa kuandika kwenye kumbukumbu</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>Onyesha kumbukumbu kama mfuatano wa mwisho.</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>Onyesha kumbukumbu kama amri ya mkusanyiko.</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>Onyesha kumbukumbu kama byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Hii itachapisha kitu kinachorejelewa na param</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Kumbuka kwamba nyingi za API za Objective-C za Apple au mbinu hurudisha vitu, na hivyo zinapaswa kuonyeshwa kupitia amri ya “print object” (po). Ikiwa po haitoi matokeo yenye maana tumia <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Andika AAAA katika anwani hiyo<br>memory write -f s $rip+0x11f+7 "AAAA" #Andika AAAA katika anwani</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas kazi ya sasa</p><p>dis -n &#x3C;funcname> #Disas kazi</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Disas kazi<br>dis -c 6 #Disas mistari 6<br>dis -c 0x100003764 -e 0x100003768 # Kutoka moja hadi nyingine<br>dis -p -c 4 # Anza katika anwani ya sasa ukichambua</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Angalia array ya vipengele 3 katika reg x1</td></tr><tr><td><strong>image dump sections</strong></td><td>Chapisha ramani ya kumbukumbu ya mchakato wa sasa</td></tr><tr><td><strong>image dump symtab &#x3C;library></strong></td><td><code>image dump symtab CoreNLP</code> #Pata anwani ya alama zote kutoka CoreNLP</td></tr></tbody></table>

> [!NOTE]
> Wakati wa kuita kazi **`objc_sendMsg`**, register **rsi** ina **jina la mbinu** kama mfuatano wa mwisho (“C”). Ili kuchapisha jina kupitia lldb fanya:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Anti-Dynamic Analysis

#### VM detection

- Amri **`sysctl hw.model`** inarudisha "Mac" wakati **mwenyeji ni MacOS** lakini kitu tofauti wakati ni VM.
- Kucheza na thamani za **`hw.logicalcpu`** na **`hw.physicalcpu`** baadhi ya malware hujaribu kugundua ikiwa ni VM.
- Baadhi ya malware pia inaweza **gundua** ikiwa mashine ni **VMware** kulingana na anwani ya MAC (00:50:56).
- Pia inawezekana kupata **ikiwa mchakato unashughulikiwa** kwa kutumia msimbo rahisi kama:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //mchakato unashughulikiwa }`
- Inaweza pia kuita **`ptrace`** mfumo wa wito na bendera **`PT_DENY_ATTACH`**. Hii **inazuia** deb**u**gger kuungana na kufuatilia.
- Unaweza kuangalia ikiwa **`sysctl`** au **`ptrace`** kazi inapo **ingizwa** (lakini malware inaweza kuingiza kwa njia ya kidinamik).
- Kama ilivyotajwa katika andiko hili, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Ujumbe Mchakato # ulitoka na **hali = 45 (0x0000002d)** mara nyingi ni ishara ya wazi kwamba lengo la debug linatumia **PT_DENY_ATTACH**_”

## Core Dumps

Core dumps zinaundwa ikiwa:

- `kern.coredump` sysctl imewekwa kuwa 1 (kwa kawaida)
- Ikiwa mchakato haukuwa suid/sgid au `kern.sugid_coredump` ni 1 (kwa kawaida ni 0)
- Kiwango cha `AS_CORE` kinaruhusu operesheni. Inawezekana kuzuiya uundaji wa core dumps kwa kuita `ulimit -c 0` na kuziwezesha tena kwa `ulimit -c unlimited`.

Katika hali hizo core dumps inaundwa kulingana na `kern.corefile` sysctl na kuhifadhiwa kwa kawaida katika `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **inafanya uchambuzi wa michakato inayoshindwa na kuhifadhi ripoti ya ajali kwenye diski**. Ripoti ya ajali ina habari ambayo inaweza **kusaidia mendelezi kutambua** sababu ya ajali.\
Kwa programu na michakato mingine **inayoendesha katika muktadha wa per-user launchd**, ReportCrash inakimbia kama LaunchAgent na kuhifadhi ripoti za ajali katika `~/Library/Logs/DiagnosticReports/` ya mtumiaji\
Kwa daemons, michakato mingine **inayoendesha katika muktadha wa system launchd** na michakato mingine yenye mamlaka, ReportCrash inakimbia kama LaunchDaemon na kuhifadhi ripoti za ajali katika `/Library/Logs/DiagnosticReports` ya mfumo

Ikiwa unahofia ripoti za ajali **zinatumwa kwa Apple** unaweza kuzizima. Ikiwa la, ripoti za ajali zinaweza kuwa na manufaa katika **kugundua jinsi seva ilivyoshindwa**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Kulala

Wakati wa fuzzing katika MacOS ni muhimu kutoruhusu Mac kulala:

- systemsetup -setsleep Never
- pmset, Mipangilio ya Mfumo
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH Kutenganisha

Ikiwa unafuzzing kupitia muunganisho wa SSH ni muhimu kuhakikisha kuwa kikao hakitakufa. Hivyo badilisha faili ya sshd_config na:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Internal Handlers

**Angalia ukurasa ufuatao** ili kujua jinsi unavyoweza kupata ni programu ipi inayohusika na **kushughulikia mpango au itifaki iliyoainishwa:**

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerating Network Processes

Hii ni ya kuvutia kupata michakato inayosimamia data ya mtandao:
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

Inafanya kazi kwa zana za CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Inafanya kazi tu na zana za GUI za macOS. Kumbuka kwamba baadhi ya programu za macOS zina mahitaji maalum kama vile majina ya faili ya kipekee, kiendelezi sahihi, zinahitaji kusoma faili kutoka kwenye sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

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
### Taarifa Zaidi Za Fuzzing MacOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Marejeleo

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
