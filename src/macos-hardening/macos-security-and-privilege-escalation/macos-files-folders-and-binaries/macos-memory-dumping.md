# Memory Dumping kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap files, kama vile `/private/var/vm/swapfile0`, hutumika kama **caches wakati physical memory imejaa**. Wakati hakuna nafasi zaidi katika physical memory, data yake huhamishiwa kwenye swap file kisha kurudishwa kwenye physical memory inapohitajika. Swap files nyingi zinaweza kuwepo, zikiwa na majina kama swapfile0, swapfile1, na kadhalika.

### Hibernate Image

Faili iliyo kwenye `/private/var/vm/sleepimage` ni muhimu wakati wa **hibernation mode**. **Data kutoka kwenye memory huhifadhiwa kwenye faili hii OS X inapoweka mfumo kwenye hibernation**. Kompyuta inapoamka, mfumo hurejesha data ya memory kutoka kwenye faili hii, hivyo kumwezesha mtumiaji kuendelea pale alipoishia.

Ni muhimu kutambua kwamba kwenye mifumo ya kisasa ya MacOS, faili hii kwa kawaida huwa encrypted kwa sababu za usalama, jambo linalofanya recovery kuwa ngumu.

- Kuangalia ikiwa encryption imewezeshwa kwa sleepimage, unaweza kuendesha command `sysctl vm.swapusage`. Hii itaonyesha ikiwa faili ime-encryptiwa.

### Memory Pressure Logs

Faili nyingine muhimu inayohusiana na memory kwenye mifumo ya MacOS ni **memory pressure log**. Logs hizi ziko kwenye `/var/log` na zina maelezo ya kina kuhusu matumizi ya memory ya mfumo na matukio ya pressure. Zinaweza kuwa muhimu hasa kwa diagnosing matatizo yanayohusiana na memory au kuelewa jinsi mfumo unavyosimamia memory kwa muda.

## Dumping memory kwa kutumia osxpmem

Ili kudump memory kwenye MacOS machine, unaweza kutumia [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Kumbuka**: Hii kwa kiasi kikubwa ni **legacy workflow** kwa sasa. `osxpmem` inategemea kupakia kernel extension, project ya [Rekall](https://github.com/google/rekall) ime-archive, release ya mwisho ilitolewa mwaka **2017**, na binary iliyochapishwa inalenga **Intel Macs**. Kwenye macOS releases za sasa, hasa kwenye **Apple Silicon**, full-RAM acquisition inayotumia kext kwa kawaida huzuiwa na vikwazo vya kisasa vya kernel-extension, SIP, na mahitaji ya platform-signing. Kwa vitendo, kwenye mifumo ya kisasa mara nyingi utaishia kufanya **process-scoped dump** badala ya whole-RAM image.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Ukikumbana na hitilafu hii: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Unaweza kuirekebisha kwa kufanya:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Hitilafu nyingine** zinaweza kurekebishwa kwa **kuruhusu upakiaji wa kext** katika "Security & Privacy --> General"; bofya **Allow** tu.

Unaweza pia kutumia **oneliner** hii kupakua application, kupakia kext na kufanya memory dump:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumping mchakato unaoendelea kwa kutumia LLDB

Kwa **matoleo ya hivi karibuni ya macOS**, mbinu ya vitendo zaidi kwa kawaida ni kudump memory ya **mchakato mahususi** badala ya kujaribu kuunda image ya memory yote ya physical.

LLDB inaweza kuhifadhi faili ya core ya Mach-O kutoka kwa target inayoendelea:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Kwa chaguo-msingi, hii kwa kawaida huunda **skinny core**. Ili kulazimisha LLDB kujumuisha kumbukumbu yote ya mchakato iliyopangwa:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Amri muhimu za kufuatia kabla ya kufanya dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Hii kwa kawaida inatosha wakati lengo ni kurejesha:

- Decrypted configuration blobs
- Tokens, cookies, au credentials zilizo kwenye memory
- Plaintext secrets ambazo zinalindwa tu wakati wa kuhifadhiwa
- Decrypted Mach-O pages baada ya unpacking / JIT / runtime patching

Ikiwa target inalindwa na **hardened runtime**, au ikiwa `taskgated` inakataa attach, kwa kawaida unahitaji mojawapo ya masharti haya:

- Target ina **`get-task-allow`**
- Debugger yako imesainiwa kwa **debugger entitlement** inayofaa
- Wewe ni **root** na target ni third-party process isiyo na hardened runtime

Kwa maelezo zaidi kuhusu kupata task port na mambo yanayoweza kufanywa nayo:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Ukaguzi wa haraka kabla ya attach

Kabla ya kutumia muda kwenye LLDB/Frida, thibitisha haraka ikiwa target inaweza kweli kuwa **dumpable**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Kwa upande wa utekelezaji, kwa kawaida hii humaanisha:

- App ya third-party iliyo na **`get-task-allow`** mara nyingi inaweza kufanyiwa dump moja kwa moja kwa kutumia LLDB, na dump inayopatikana inaweza kufichua data iliyolindwa na TCC ambayo app ilikuwa tayari imefikia.
- Target **hardened** isiyo na `get-task-allow` kwa kawaida itakataa attach, hata ukiwa `root`, isipokuwa udhibiti entitlements husika za debugger au njia ya policy.
- Processes za third-party ambazo si hardened bado ndizo rahisi zaidi kutumia `lldb`, `vmmap`, Frida, au readers maalum za `task_for_pid`/`vm_read`.

### Tafuta nested helpers zinazoweza kufanyiwa dump

Utafiti wa hivi karibuni kuhusu apps za macOS zilizofanyiwa notarization unaendelea kugundua **`get-task-allow`** ndani ya nested helpers badala ya binary kuu ya GUI. App ya kiwango cha juu inapoonekana kuwa hardened, orodhesha **XPC services**, **login items**, **helper tools**, na CLIs zilizofungwa pamoja kabla ya kukata tamaa:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Executable iliyopachikwa yenye `get-task-allow` mara nyingi ndiyo sehemu rahisi zaidi ya kuambatisha kwa `lldb`, kutengeneza core dump, au kuvuta memory kwa kutumia custom `task_for_pid` client, hata wakati main app imeimarishwa zaidi kwa usalama.

## Selective dumps kwa Frida au userland readers

Wakati core nzima ina kelele nyingi, kudump **interesting readable ranges** pekee mara nyingi huwa haraka zaidi. Frida ni muhimu sana kwa sababu inafanya kazi vizuri kwa **targeted extraction** mara tu unapoweza kuambatisha kwenye process.

Mfano wa mbinu:

1. Orodhesha readable/writable ranges
2. Chuja kwa module, heap, stack, au anonymous memory
3. Dump maeneo pekee yenye candidate strings, keys, protobufs, plist/XML blobs, au decrypted code/data

Mfano mdogo wa Frida wa kudump anonymous ranges zote zinazoweza kusomwa:
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
Hii ni muhimu unapotaka kuepuka core files kubwa na kukusanya tu:

- App heap chunks zilizo na secrets
- Anonymous regions zilizoundwa na custom packers au loaders
- JIT / unpacked code pages baada ya kubadilisha protections

Wakati target inaendelea **allocating / freeing** unapofanya dump, pendelea primitive ya Frida ya **`readVolatile()`** badala ya **`readByteArray()`** kwa ranges zisizo thabiti. Ni ya polepole zaidi, lakini huepuka kuua target ikiwa page itakuwa unreadable katikati ya kusoma. Kwa acquisitions kubwa zaidi, inaweza pia kuwa safi zaidi ku-stream chunks kurudi kwa kutumia `send(..., data)` na kuzikandamiza upande wa controller badala ya kuunda maelfu ya files ndogo ndani ya target.

Zana za zamani za userland kama [`readmem`](https://github.com/gdbinit/readmem) pia zipo, lakini zinafaa zaidi kama **source references** za dumping ya moja kwa moja kwa mtindo wa `task_for_pid`/`vm_read` na hazitunzwe vizuri kwa workflows za kisasa za Apple Silicon.

## Heap / VM snapshots with `.memgraph`

Ikiwa unajali zaidi **heap objects**, **allocation provenance**, au snapshot inayoweza kuhamishwa hadi kwenye machine nyingine, `.memgraph` mara nyingi huwa ya vitendo zaidi kuliko Mach-O core kubwa. Zana za `leaks` zinaweza kuunda moja kutoka kwenye process inayoendelea:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Kisha ifanyie triage offline kwa kutumia zana za kawaida za Apple:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` ndiyo sababu kuu ya kuhifadhi capture ya `-fullContent`, kwa sababu labels zinazoeleza memory contents huondolewa kwenye `.memgraph` ndogo.

Hii ni muhimu hasa wakati:

- Unataka **snapshot ndogo inayoweza kushirikiwa** badala ya core kamili
- `MallocStackLogging` iliwezeshwa na unataka **allocation backtraces**
- Tayari unajua **heap address ya kuvutia** na unataka kuendelea nayo kwa `malloc_history`
- Unahitaji **uchanganuzi wa haraka wa VM/heap** kabla ya kuamua kama full dump inafaa noise hiyo

### Differential memgraph triage

Ikiwa unadhibiti jinsi target inavyoanzishwa, wezesha **historical allocation logging** kabla ya launch ili snapshots za baadaye zihifadhi allocation/free backtraces zenye manufaa:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Kisha capture snapshots kabla na baada ya kitendo cha kuvutia, na uzifanyie diff offline:
```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```
Hii ni njia ya vitendo ya kutenga **objects za baada ya authentication**, **large `CFData` buffers**, au **anonymous VM regions** zinazoonekana tu baada ya hatua ya decryption, unpacking, au secret-retrieval.

## Targets zinazotumia sana Swift: `swift-inspect`

Kwa applications zinazohifadhi data yenye thamani kubwa ndani ya **Swift runtime objects**, `swift-inspect` inaweza kuwa nyongeza nzuri kwa LLDB au Frida. Badala ya kudump kila kitu kwanza, unaweza ku-query miundo mahususi ya Swift runtime kutoka kwenye live process:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Hii ni muhimu kutambua:

- Swift arrays kubwa zinazohifadhi data ya kuvutia
- Metadata allocations zinazoonyesha types zilizopakiwa wakati wa runtime
- Hali ya Swift concurrency (`Task`, actor, uhusiano wa thread) kabla ya kufanya dump inayolenga zaidi

Kwa object-level runtime triage zaidi baada ya kuwa tayari unaweza kukagua process, angalia [ukurasa maalum kuhusu objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Vidokezo vya Quick triage

- `sysctl vm.swapusage` bado ni njia ya haraka ya kukagua **swap usage** na ikiwa swap **imesimbwa kwa njia fiche**.
- `sleepimage` bado ni muhimu hasa katika hali za **hibernate/safe sleep**, lakini mifumo ya kisasa kwa kawaida huilinda; kwa hiyo inapaswa kuchukuliwa kama **chanzo cha artifact cha kukagua**, si kama njia ya kuaminika ya acquisition.
- Kwenye matoleo ya hivi karibuni ya macOS, **process-level dumping** kwa ujumla ni ya uhalisia zaidi kuliko **full physical memory imaging**, isipokuwa udhibiti boot policy, hali ya SIP, na upakiaji wa kext.

## Marejeo

- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [https://keith.github.io/xcode-man-pages/leaks.1.html](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
