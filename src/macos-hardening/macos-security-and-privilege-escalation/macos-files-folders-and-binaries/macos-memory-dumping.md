# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap files, kama `/private/var/vm/swapfile0`, hutumika kama **caches wakati physical memory imejaa**. Wakati hakuna nafasi tena kwenye physical memory, data yake huhamishiwa kwenye swap file na kisha kurudishwa kwenye physical memory kadri inavyohitajika. Inaweza kuwepo swap file kadhaa, zikiwa na majina kama swapfile0, swapfile1, na kadhalika.

### Hibernate Image

Faili iliyo katika `/private/var/vm/sleepimage` ni muhimu wakati wa **hibernation mode**. **Data kutoka memory huhifadhiwa kwenye faili hii wakati OS X inahibernates**. Kompyuta inapowashwa tena, system huchukua data ya memory kutoka kwenye faili hii, hivyo kumwezesha user kuendelea alipoishia.

Inafaa kutambua kwamba kwenye modern MacOS systems, faili hii kwa kawaida huwa imesimbwa kwa sababu za usalama, jambo linalofanya recovery kuwa ngumu.

- Ili kuangalia kama encryption imewezeshwa kwa sleepimage, command `sysctl vm.swapusage` inaweza kuendeshwa. Hii itaonyesha kama faili imesimbwa.

### Memory Pressure Logs

Faili nyingine muhimu inayohusiana na memory kwenye MacOS systems ni **memory pressure log**. Logs hizi zipo katika `/var/log` na zina taarifa za kina kuhusu matumizi ya memory ya system na pressure events. Zinaweza kuwa muhimu sana kwa kugundua issues zinazohusiana na memory au kuelewa jinsi system inavyosimamia memory kwa muda.

## Dumping memory with osxpmem

Ili kufanya dump ya memory kwenye MacOS machine unaweza kutumia [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: Huu kwa sasa ni zaidi ya **legacy workflow**. `osxpmem` inategemea kupakia kernel extension, project ya [Rekall](https://github.com/google/rekall) imehifadhiwa kama archive, latest release ni ya **2017**, na published binary inalenga **Intel Macs**. Kwenye current macOS releases, hasa kwenye **Apple Silicon**, kext-based full-RAM acquisition mara nyingi huzuiwa na modern kernel-extension restrictions, SIP, na platform-signing requirements. Kwa vitendo, kwenye modern systems mara nyingi utaishia kufanya **process-scoped dump** badala ya whole-RAM image.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Ukipata kosa hili: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Unaweza kulirekebisha kwa kufanya hivi:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Makosa mengine** yanaweza kusahihishwa kwa **kuruhusu upakuaji wa kext** katika "Security & Privacy --> General", tu **ruhusu**.

Unaweza pia kutumia **oneliner** hii kupakua application, kupakia kext na kudump memory:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live process dumping with LLDB

Kwa **matoleo ya hivi karibuni ya macOS**, njia ya vitendo zaidi kawaida ni kudump memory ya **process maalum** badala ya kujaribu ku-image all physical memory.

LLDB inaweza kuhifadhi Mach-O core file kutoka kwa live target:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Kwa chaguo-msingi hii kwa kawaida huunda **skinny core**. Ili kulazimisha LLDB kujumuisha kumbukumbu yote ya process iliyopangwa:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Amri muhimu za kufuatilia kabla ya dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Hii kawaida inatosha wakati lengo ni kurejesha:

- Decrypted configuration blobs
- In-memory tokens, cookies, or credentials
- Plaintext secrets that are only protected at rest
- Decrypted Mach-O pages after unpacking / JIT / runtime patching

Ikiwa lengo linalindwa na **hardened runtime**, au ikiwa `taskgated` inakataa attach, kwa kawaida unahitaji mojawapo ya masharti haya:

- Lengo lina **`get-task-allow`**
- Debugger yako imesainiwa na **debugger entitlement** sahihi
- Wewe ni **root** na lengo ni non-hardened third-party process

Kwa maelezo zaidi kuhusu kupata task port na kile kinachoweza kufanywa nayo:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

Kabla ya kutumia muda kwenye LLDB/Frida, thibitisha haraka kama lengo linaweza kweli **dumpable**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Secara operesheni, hii kwa kawaida inamaanisha:

- App ya third-party iliyosafirishwa na **`get-task-allow`** mara nyingi inaweza kudumpiwa moja kwa moja kwa kutumia LLDB, na dump inayopatikana inaweza kufichua data iliyolindwa na TCC ambayo app tayari iliifikia.
- Lengo **hardened** bila `get-task-allow` kwa kawaida litakataa attaches, hata kama ni `root`, isipokuwa udhibiti entitlement / policy path husika ya debugger.
- Unhardened third-party processes bado ndizo mahali rahisi zaidi pa kutumia `lldb`, `vmmap`, Frida, au custom `task_for_pid`/`vm_read` readers.

## Selective dumps with Frida or userland readers

Wakati full core ni noisy sana, kudumpi **interesting readable ranges** pekee mara nyingi ni haraka zaidi. Frida ni muhimu sana kwa sababu inafanya kazi vizuri kwa **targeted extraction** mara tu unapoweza kuattach kwenye process.

Mfano wa approach:

1. Enumerate readable/writable ranges
2. Filter kwa module, heap, stack, au anonymous memory
3. Dump tu regions zinazobeba candidate strings, keys, protobufs, plist/XML blobs, au decrypted code/data

Minimal Frida example to dump all readable anonymous ranges:
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

- App heap chunks zenye secrets
- Anonymous regions zilizoundwa na custom packers au loaders
- JIT / unpacked code pages baada ya kubadilisha protections

Older userland tools kama [`readmem`](https://github.com/gdbinit/readmem) pia zipo, lakini kwa kawaida ni muhimu zaidi kama **source references** kwa direct `task_for_pid`/`vm_read` style dumping na hazitunzwi vizuri kwa modern Apple Silicon workflows.

## Heap / VM snapshots with `.memgraph`

Ikiwa unajali zaidi kuhusu **heap objects**, **allocation provenance**, au snapshot inayoweza kuhamishwa kwenda machine nyingine, `.memgraph` mara nyingi ni practical zaidi kuliko giant Mach-O core. The `leaks` tooling inaweza kutengeneza moja kutoka kwa live process:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Kisha ifanyie triage offline kwa kutumia Apple tooling ya kawaida:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` ndio sababu kuu ya kuweka `-fullContent` capture karibu, kwa sababu lebo zinazoelezea maudhui ya kumbukumbu huondolewa kutoka kwa `.memgraph` ya chini kabisa.

Hii ni muhimu hasa wakati:

- Unataka **snapshot ndogo, inayoweza kushirikiwa** badala ya core kamili
- `MallocStackLogging` ilikuwa imewezeshwa na unataka **allocation backtraces**
- Tayari unajua **interesting heap address** na unataka pivot kwa `malloc_history`
- Unahitaji **VM/heap breakdown** ya haraka kabla ya kuamua kama dump kamili inafaa kelele

## Swift-heavy targets: `swift-inspect`

Kwa applications zinazohifadhi data ya thamani kubwa ndani ya **Swift runtime objects**, `swift-inspect` inaweza kuwa nyongeza nzuri kwa LLDB au Frida. Badala ya kudump kila kitu kwanza, unaweza kuuliza specific Swift runtime structures kutoka kwa live process:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Hii ni muhimu kutambua:

- Arrays kubwa za Swift zinazohifadhi data ya kuvutia
- Metadata allocations zinazoonyesha types zilizopakiwa wakati wa runtime
- Swift concurrency state (`Task`, actor, thread relationships) kabla ya kufanya dump iliyolengwa zaidi

Kwa triage zaidi ya object-level runtime mara tu unapoweza tayari kuinspect process, angalia [the dedicated page on objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Quick triage notes

- `sysctl vm.swapusage` bado ni njia ya haraka ya kuangalia **swap usage** na kama swap ime**encrypted**.
- `sleepimage` bado ni muhimu hasa kwa hali za **hibernate/safe sleep**, lakini systems za kisasa mara nyingi huihifadhi, hivyo inapaswa kutazamwa kama **artifact source to check**, si kama acquisition path ya kuaminika.
- Kwenye releases za hivi karibuni za macOS, **process-level dumping** kwa ujumla ni halisi zaidi kuliko **full physical memory imaging** isipokuwa udhibiti boot policy, SIP state, na kext loading.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
