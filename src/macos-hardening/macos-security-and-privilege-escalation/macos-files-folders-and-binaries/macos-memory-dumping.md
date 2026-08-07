# Memory Dumping ya macOS

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Faili za Swap

Faili za swap, kama vile `/private/var/vm/swapfile0`, hutumika kama **caches wakati memory ya kimwili imejaa**. Wakati hakuna nafasi zaidi katika memory ya kimwili, data yake huhamishiwa kwenye faili ya swap na kisha kurejeshwa kwenye memory ya kimwili inapohitajika. Faili nyingi za swap zinaweza kuwepo, zikiwa na majina kama swapfile0, swapfile1, na kadhalika.

### Picha ya Hibernate

Faili iliyo katika `/private/var/vm/sleepimage` ni muhimu wakati wa **hali ya hibernation**. **Data kutoka kwenye memory huhifadhiwa katika faili hii OS X inapofanya hibernation**. Kompyuta inapoamshwa, mfumo hurejesha data ya memory kutoka kwenye faili hii, na kumruhusu mtumiaji kuendelea na kazi aliyokuwa akifanya.

Inafaa kutambua kwamba kwenye mifumo ya kisasa ya MacOS, faili hii kwa kawaida husimbwa kwa encryption kwa sababu za usalama, hivyo kufanya recovery kuwa ngumu.

- Ili kuangalia kama encryption imewashwa kwa sleepimage, amri `sysctl vm.swapusage` inaweza kutekelezwa. Hii itaonyesha kama faili imesimbwa kwa encryption.

### Memory Pressure Logs

Faili nyingine muhimu inayohusiana na memory katika mifumo ya MacOS ni **memory pressure log**. Logs hizi zinapatikana katika `/var/log` na zina taarifa za kina kuhusu matumizi ya memory ya mfumo na matukio ya memory pressure. Zinaweza kuwa muhimu hasa kwa kutambua matatizo yanayohusiana na memory au kuelewa jinsi mfumo unavyodhibiti memory kwa muda.

## Kudump memory kwa kutumia osxpmem

Ili kudump memory katika mashine ya MacOS unaweza kutumia [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Kumbuka**: Hii kwa kiasi kikubwa ni **legacy workflow** sasa. `osxpmem` inategemea kupakia kernel extension, mradi wa [Rekall](https://github.com/google/rekall) umehifadhiwa, release ya hivi karibuni ni ya **2017**, na binary iliyochapishwa inalenga **Intel Macs**. Katika matoleo ya sasa ya macOS, hasa kwenye **Apple Silicon**, upatikanaji wa full-RAM kwa kutumia kext kwa kawaida huzuiwa na restrictions za kisasa za kernel extension, SIP, na mahitaji ya platform-signing. Kwa vitendo, kwenye mifumo ya kisasa mara nyingi utaishia kufanya **process-scoped dump** badala ya image ya RAM nzima.
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
**Other errors** zinaweza kurekebishwa kwa **kuruhusu upakiaji wa kext** katika "Security & Privacy --> General", bonyeza tu **allow**.

Unaweza pia kutumia **oneliner** hii kupakua application, kupakia kext na kufanya memory dump:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Kudump memory ya process inayoendelea kwa LLDB

Kwa **recent macOS versions**, mbinu inayofaa zaidi kwa kawaida ni kudump memory ya **process maalum** badala ya kujaribu ku-image physical memory yote.

LLDB inaweza kuhifadhi core file ya Mach-O kutoka kwa target inayoendelea:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Kwa chaguo-msingi, hii kwa kawaida huunda **skinny core**. Ili kulazimisha LLDB kujumuisha kumbukumbu yote ya mchakato iliyopangwa:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Amri muhimu za kufuatia kabla ya dumping:
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
- In-memory tokens, cookies, au credentials
- Plaintext secrets ambazo zinalindwa tu zikiwa kwenye storage
- Decrypted Mach-O pages baada ya unpacking / JIT / runtime patching

Ikiwa target inalindwa na **hardened runtime**, au ikiwa `taskgated` inakataa attach, kwa kawaida unahitaji mojawapo ya masharti haya:

- Target ina **`get-task-allow`**
- Debugger yako imesainiwa kwa **debugger entitlement** inayofaa
- Wewe ni **root** na target ni third-party process isiyo na hardened runtime

Kwa maelezo zaidi kuhusu kupata task port na kile kinachoweza kufanywa nayo:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Ukaguzi wa haraka kabla ya attach

Kabla ya kutumia muda kwenye LLDB/Frida, hakikisha haraka ikiwa target inaweza kweli kuwa **dumpable**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Kwa upande wa uendeshaji, hii kwa kawaida inamaanisha:

- App ya third-party iliyosafirishwa ikiwa na **`get-task-allow`** mara nyingi inaweza kudumpiwa moja kwa moja kwa LLDB, na dump inayopatikana inaweza kufichua data iliyolindwa na TCC ambayo app hiyo tayari ilikuwa imeifikia.<sup>[[1]](#references)</sup>
- Target **hardened** isiyo na `get-task-allow` kwa kawaida itakataa attaches, hata ukiwa `root`, isipokuwa udhibiti debugger entitlements / policy path husika.
- Third-party processes zisizo **hardened** bado ndizo rahisi zaidi kutumia `lldb`, `vmmap`, Frida, au custom `task_for_pid`/`vm_read` readers.

### Tafuta nested helpers zinazoweza kudumpiwa

Utafiti wa hivi karibuni kuhusu apps za macOS zilizotiwa notarization unaendelea kugundua **`get-task-allow`** katika nested helpers badala ya GUI binary kuu. App ya kiwango cha juu inapoonekana kuwa **hardened**, enumerate **XPC services**, **login items**, **helper tools**, na bundled CLIs zake kabla ya kukata tamaa:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Executable ya ndani yenye `get-task-allow` mara nyingi ndiyo mahali rahisi zaidi pa ku-attach kwa `lldb`, kufanya dump ya core, au kuvuta memory kwa kutumia custom `task_for_pid` client, hata wakati app kuu ime-hardened zaidi.

## Selective dumps kwa kutumia Frida au userland readers

Wakati core dump kamili ina kelele nyingi, kufanya dump ya **readable ranges zinazovutia pekee** mara nyingi huwa haraka zaidi. Frida ni muhimu hasa kwa sababu inafanya kazi vizuri kwa **targeted extraction** pindi unapoweza ku-attach kwenye process.

Mbinu ya mfano:

1. Orodhesha readable/writable ranges
2. Chuja kwa module, heap, stack, au anonymous memory
3. Fanya dump ya regions pekee zilizo na candidate strings, keys, protobufs, plist/XML blobs, au decrypted code/data

Mfano mdogo wa Frida wa kufanya dump ya anonymous ranges zote zinazosomeka:
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
Hii ni muhimu unapohitaji kuepuka core files kubwa sana na kukusanya tu:

- Vipande vya App heap vyenye secrets
- Anonymous regions zilizoundwa na custom packers au loaders
- Kurasa za JIT / unpacked code baada ya kubadilisha protections

Target inapoendelea **allocating / freeing** wakati wa dump, pendelea primitive ya Frida **`readVolatile()`** badala ya **`readByteArray()`** kwa ranges zisizo thabiti. Ni ya polepole zaidi, lakini huepuka kuua target ikiwa page itakuwa haiwezi kusomeka katikati ya usomaji. Kwa acquisitions kubwa, inaweza pia kuwa safi zaidi kusababisha chunks zirudishwe kwa kutumia `send(..., data)` na kuzicompress kwenye controller badala ya kuunda maelfu ya files ndogo ndani ya target.

Userland tools za zamani kama [`readmem`](https://github.com/gdbinit/readmem) pia zipo, lakini zinafaa zaidi kama **source references** za dumping ya moja kwa moja kwa mtindo wa `task_for_pid`/`vm_read`, na hazitunzwe vizuri kwa workflows za kisasa za Apple Silicon.

## Heap / VM snapshots zenye `.memgraph`

Ikiwa unajali zaidi **heap objects**, **allocation provenance**, au snapshot inayoweza kuhamishwa kwenda kwenye machine nyingine, `.memgraph` mara nyingi huwa ya vitendo zaidi kuliko Mach-O core kubwa sana. Tooling ya `leaks` inaweza kuitengeneza kutoka kwa process inayoendelea:<sup>[[2]](#references)</sup>
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
`stringdups` ndiyo sababu kuu ya kuhifadhi capture ya `-fullContent`, kwa sababu labels zinazoelezea memory contents huondolewa kwenye `.memgraph` ya minimal.

Hii ni muhimu hasa wakati:

- Unataka **snapshot ndogo inayoweza kushirikiwa** badala ya core kamili
- `MallocStackLogging` ilikuwa imewezeshwa na unataka **allocation backtraces**
- Tayari unajua **heap address ya kuvutia** na unataka kuendelea na `malloc_history`
- Unahitaji **mgawanyo wa haraka wa VM/heap** kabla ya kuamua kama full dump inafaa kelele hiyo

### Triage ya differential memgraph

Ikiwa unadhibiti jinsi target inavyoanzishwa, wezesha **historical allocation logging** kabla ya launch ili snapshots za baadaye zihifadhi alloc/free backtraces muhimu:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Kisha chukua snapshots kabla na baada ya action inayokuvutia, kisha uzilinganishe kwa kutumia diff offline:
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
Hii ni njia ya vitendo ya kutenga **post-authentication objects**, **large `CFData` buffers**, au **anonymous VM regions** zinazoonekana tu baada ya hatua ya decryption, unpacking, au secret-retrieval.

## Targets zenye matumizi makubwa ya Swift: `swift-inspect`

Kwa applications zinazohifadhi data yenye thamani kubwa ndani ya **Swift runtime objects**, `swift-inspect` inaweza kuwa nyongeza nzuri kwa LLDB au Frida. Badala ya kudump kila kitu kwanza, unaweza ku-query miundo mahususi ya Swift runtime kutoka kwenye process inayoendelea:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Hii ni muhimu kwa kutambua:

- Swift arrays kubwa zinazohifadhi data ya kuvutia
- Metadata allocations zinazoonyesha types zilizopakiwa wakati wa runtime
- Hali ya Swift concurrency (`Task`, uhusiano kati ya actor na thread) kabla ya kufanya dump yenye kulenga zaidi

Kwa object-level runtime triage zaidi mara tu unapoweza kukagua process, angalia [the dedicated page on objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Maelezo ya haraka ya triage

- `sysctl vm.swapusage` bado ni njia ya haraka ya kuangalia **matumizi ya swap** na ikiwa swap **imesimbwa kwa njia fiche**.
- `sleepimage` bado inahusika hasa katika hali za **hibernate/safe sleep**, lakini mifumo ya kisasa kwa kawaida huilinda, hivyo inapaswa kuchukuliwa kama **chanzo cha artifact cha kukagua**, si njia ya kuaminika ya acquisition.
- Kwenye matoleo ya hivi karibuni ya macOS, **dumping ya kiwango cha process** kwa ujumla ni rahisi zaidi kuliko **full physical memory imaging**, isipokuwa udhibiti boot policy, hali ya SIP, na upakiaji wa kext.

## References

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
