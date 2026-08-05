# Memory Dumping ya macOS

{{#include ../../../banners/hacktricks-training.md}}

## Artifacts za Memory

### Swap Files

Swap files, kama `/private/var/vm/swapfile0`, hutumika kama **caches wakati physical memory imejaa**. Wakati hakuna nafasi zaidi kwenye physical memory, data yake huhamishiwa kwenye swap file na kisha kurudishwa kwenye physical memory inapohitajika. Swap files nyingi zinaweza kuwepo, zikiwa na majina kama swapfile0, swapfile1, na kadhalika.

### Hibernate Image

Faili iliyo kwenye `/private/var/vm/sleepimage` ni muhimu wakati wa **hibernation mode**. **Data kutoka kwenye memory huhifadhiwa kwenye faili hii wakati OS X inaingia hibernation**. Kompyuta inapoamka, mfumo huchukua data ya memory kutoka kwenye faili hii, na kumruhusu mtumiaji kuendelea na kazi aliyokuwa ameacha.

Inafaa kutambua kwamba kwenye mifumo ya kisasa ya MacOS, faili hii kwa kawaida huwa encrypted kwa sababu za usalama, hivyo kufanya recovery kuwa ngumu.

- Ili kuangalia kama encryption imewezeshwa kwa sleepimage, amri `sysctl vm.swapusage` inaweza kutekelezwa. Hii itaonyesha kama faili imeencrypted.

### Memory Pressure Logs

Faili nyingine muhimu inayohusiana na memory kwenye mifumo ya MacOS ni **memory pressure log**. Logs hizi zinapatikana kwenye `/var/log` na zina taarifa za kina kuhusu matumizi ya memory ya mfumo na matukio ya memory pressure. Zinaweza kuwa muhimu hasa katika kuchunguza matatizo yanayohusiana na memory au kuelewa jinsi mfumo unavyodhibiti memory kwa muda.

## Kudump memory kwa kutumia osxpmem

Ili kudump memory kwenye mashine ya MacOS unaweza kutumia [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Kumbuka**: Hii kwa kiasi kikubwa ni **legacy workflow** kwa sasa. `osxpmem` inategemea kupakia kernel extension, mradi wa [Rekall](https://github.com/google/rekall) umeachwa, release ya hivi karibuni ni ya **2017**, na binary iliyochapishwa inalenga **Intel Macs**. Kwenye releases za sasa za macOS, hasa kwenye **Apple Silicon**, upatikanaji wa full-RAM kwa kutumia kext kwa kawaida huzuiwa na vizuizi vya kisasa vya kernel extension, SIP, na mahitaji ya platform-signing. Kwa vitendo, kwenye mifumo ya kisasa mara nyingi utaishia kufanya **process-scoped dump** badala ya image ya RAM nzima.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Ukikumbana na kosa hili: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Unaweza kulirekebisha kwa kufanya:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Makosa mengine** yanaweza kurekebishwa kwa **kuruhusu upakiaji wa kext** katika "Security & Privacy --> General", bofya **allow** tu.

Unaweza pia kutumia **oneliner** hii kupakua application, kupakia kext na kufanya memory dump:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumping kumbukumbu ya process inayoendelea kwa kutumia LLDB

Kwa **matoleo ya hivi karibuni ya macOS**, mbinu ya vitendo zaidi kwa kawaida ni kudump kumbukumbu ya **process mahususi** badala ya kujaribu kuunda image ya kumbukumbu yote ya kimwili.

LLDB inaweza kuhifadhi faili ya msingi ya Mach-O kutoka kwa target inayoendelea:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Kwa chaguo-msingi, hii kwa kawaida huunda **skinny core**. Ili kuilazimisha LLDB kujumuisha kumbukumbu yote ya mchakato iliyowekwa ramani:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Amri muhimu za kufuata kabla ya dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Hii kwa kawaida inatosha wakati lengo ni kurejesha:

- Blobs za configuration zilizodecryptiwa
- Tokens, cookies, au credentials zilizo kwenye memory
- Secrets za plaintext ambazo zimelindwa tu wakati wa kuhifadhiwa
- Kurasa za Mach-O zilizodecryptiwa baada ya unpacking / JIT / runtime patching

Ikiwa target imelindwa na **hardened runtime**, au ikiwa `taskgated` inakataa attach, kwa kawaida unahitaji mojawapo ya masharti haya:

- Target ina **`get-task-allow`**
- Debugger yako imesainiwa kwa **debugger entitlement** inayofaa
- Wewe ni **root** na target ni process ya third-party isiyo na hardened runtime

Kwa maelezo zaidi kuhusu kupata task port na mambo yanayoweza kufanywa nayo:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Ukaguzi wa haraka kabla ya attach

Kabla ya kutumia muda kwenye LLDB/Frida, thibitisha haraka ikiwa target inaweza realistically kuwa **dumpable**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Kwa upande wa utekelezaji, hii kwa kawaida humaanisha:

- App ya third-party iliyosafirishwa ikiwa na **`get-task-allow`** mara nyingi inaweza kufanyiwa dump moja kwa moja kwa LLDB, na dump inayotokana inaweza kufichua data iliyolindwa na TCC ambayo app ilikuwa tayari imeifikia.<sup>[1]</sup>
- Target **hardened** isiyo na `get-task-allow` kwa kawaida itakataa attaches, hata ukiwa `root`, isipokuwa udhibiti debugger entitlements / policy path husika.
- Michakato ya third-party isiyo **hardened** bado ndiyo mahali rahisi zaidi pa kutumia `lldb`, `vmmap`, Frida, au readers maalum za `task_for_pid`/`vm_read`.

### Tafuta dumpable nested helpers

Utafiti wa hivi karibuni kuhusu notarized macOS apps unaendelea kugundua **`get-task-allow`** katika nested helpers badala ya GUI binary kuu. App ya kiwango cha juu inapoonekana kuwa **hardened**, orodhesha **XPC services**, **login items**, **helper tools**, na CLIs zilizowekwa pamoja kabla ya kukata tamaa:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Executable ya nested yenye `get-task-allow` mara nyingi ndiyo sehemu rahisi zaidi ya ku-attach kwa `lldb`, ku-dump core, au kuvuta memory kwa custom `task_for_pid` client, hata wakati main app imeimarishwa zaidi.

## Selective dumps kwa kutumia Frida au userland readers

Wakati full core ina noise nyingi, ku-dump **readable ranges zenye kuvutia pekee** mara nyingi huwa haraka zaidi. Frida ni muhimu sana kwa sababu inafanya kazi vizuri kwa **targeted extraction** baada ya kuweza ku-attach kwenye process.

Njia ya mfano:

1. Enumerate readable/writable ranges
2. Filter kwa module, heap, stack, au anonymous memory
3. Dump regions pekee zenye candidate strings, keys, protobufs, plist/XML blobs, au decrypted code/data

Mfano mdogo wa Frida wa ku-dump anonymous ranges zote zinazosomeka:
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

Wakati target inaendelea **allocating / freeing** unapofanya dump, pendelea primitive ya Frida **`readVolatile()`** badala ya **`readByteArray()`** kwa ranges zisizo thabiti. Ni ya polepole zaidi, lakini huepusha kuangusha target ikiwa page inakuwa haisomeki katikati ya usomaji. Kwa acquisitions kubwa zaidi, inaweza pia kuwa safi zaidi ku-stream chunks kwa kutumia `send(..., data)` na kuzikandamiza upande wa controller badala ya kuunda maelfu ya files ndogo ndani ya target.

Userland tools za zamani kama [`readmem`](https://github.com/gdbinit/readmem) pia zipo, lakini zinafaa zaidi kama **source references** za dumping ya moja kwa moja kwa mtindo wa `task_for_pid`/`vm_read`, na hazitunzwe vizuri kwa workflows za kisasa za Apple Silicon.

## Heap / VM snapshots zenye `.memgraph`

Ikiwa unajali zaidi **heap objects**, **allocation provenance**, au snapshot inayoweza kuhamishwa hadi kwenye machine nyingine, `.memgraph` mara nyingi ni practical zaidi kuliko Mach-O core kubwa. Tooling ya `leaks` inaweza kuitengeneza kutoka kwenye process inayofanya kazi:
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
`stringdups` ndiyo sababu kuu ya kuhifadhi capture ya `-fullContent`, kwa sababu lebo zinazoeleza maudhui ya memory huondolewa kwenye `.memgraph` ndogo.

Hii ni muhimu hasa wakati:

- Unataka **snapshot ndogo inayoweza kushirikiwa** badala ya core kamili
- `MallocStackLogging` iliwezeshwa na unataka **allocation backtraces**
- Tayari unajua **heap address inayovutia** na unataka kuendelea na `malloc_history`
- Unahitaji **mgawanyo wa haraka wa VM/heap** kabla ya kuamua ikiwa full dump inafaa kelele hiyo

### Differential memgraph triage

Ikiwa unadhibiti jinsi target inavyoanza, wezesha **historical allocation logging** kabla ya launch ili snapshots za baadaye zihifadhi alloc/free backtraces muhimu:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Kisha nasa snapshots kabla na baada ya kitendo cha kuvutia, kisha uzifanyie diff offline:
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
Hii ni njia ya kiutendaji ya kutenga **post-authentication objects**, **large `CFData` buffers**, au **anonymous VM regions** zinazoonekana tu baada ya hatua ya decryption, unpacking, au secret-retrieval.

## Targets zenye Swift nyingi: `swift-inspect`

Kwa applications zinazohifadhi data yenye thamani kubwa ndani ya **Swift runtime objects**, `swift-inspect` inaweza kuwa nyongeza nzuri kwa LLDB au Frida. Badala ya kudump kila kitu kwanza, unaweza kuuliza Swift runtime structures maalum kutoka kwenye process inayofanya kazi:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Hii ni muhimu kwa kutambua:

- Swift arrays kubwa zinazohifadhi data ya kuvutia
- Metadata allocations zinazoonyesha types zilizopakiwa wakati wa runtime
- Hali ya Swift concurrency (`Task`, actor, na uhusiano wa thread) kabla ya kufanya dump yenye kulenga zaidi

Kwa runtime triage ya kiwango cha object baada ya kuwa tayari unaweza kukagua process, angalia [ukurasa maalum kuhusu objects kwenye memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Maelezo mafupi ya triage

- `sysctl vm.swapusage` bado ni njia ya haraka ya kuangalia **matumizi ya swap** na kama swap **imesimbwa kwa njia fiche**.
- `sleepimage` bado ni muhimu hasa katika hali za **hibernate/safe sleep**, lakini mifumo ya kisasa kwa kawaida huilinda, kwa hiyo inapaswa kuchukuliwa kama **chanzo cha artifacts cha kukagua**, si kama njia ya kuaminika ya acquisition.
- Kwenye matoleo ya hivi karibuni ya macOS, **process-level dumping** kwa ujumla ni halisi zaidi kuliko **full physical memory imaging**, isipokuwa udhibiti boot policy, hali ya SIP, na upakiaji wa kext.

## Marejeo

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
