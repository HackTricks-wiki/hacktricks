# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap files, soos `/private/var/vm/swapfile0`, dien as **kasgeheue wanneer die fisiese geheue vol is**. Wanneer daar nie meer plek in fisiese geheue is nie, word die data daarvan na ’n swap file oorgedra en dan soos nodig teruggebring na fisiese geheue. Verskeie swap files kan teenwoordig wees, met name soos swapfile0, swapfile1, en so aan.

### Hibernate Image

Die file geleë by `/private/var/vm/sleepimage` is noodsaaklik tydens **hibernation mode**. **Data uit memory word in hierdie file gestoor wanneer OS X hibernate**. Wanneer die rekenaar wakker word, haal die system memory data uit hierdie file, wat die user toelaat om voort te gaan waar hulle opgehou het.

Dit is die moeite werd om daarop te let dat op moderne MacOS systems, hierdie file tipies vir security reasons encrypted is, wat recovery moeilik maak.

- Om te check of encryption enabled is vir die sleepimage, kan die command `sysctl vm.swapusage` run word. Dit sal wys of die file encrypted is.

### Memory Pressure Logs

Nog ’n belangrike memory-related file in MacOS systems is die **memory pressure log**. Hierdie logs is in `/var/log` geleë en bevat gedetailleerde inligting oor die system se memory usage en pressure events. Hulle kan veral nuttig wees vir die diagnose van memory-related issues of om te verstaan hoe die system memory oor tyd manage.

## Dumping memory with osxpmem

In order to dump the memory in a MacOS machine you can use [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: This is mostly a **legacy workflow** now. `osxpmem` depends on loading a kernel extension, the [Rekall](https://github.com/google/rekall) project is archived, the latest release is from **2017**, and the published binary targets **Intel Macs**. On current macOS releases, especially on **Apple Silicon**, kext-based full-RAM acquisition is usually blocked by modern kernel-extension restrictions, SIP, and platform-signing requirements. In practice, on modern systems you will more often end up doing a **process-scoped dump** instead of a whole-RAM image.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
As jy hierdie fout vind: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Jy kan dit regstel deur:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Ander foute** kan dalk reggestel word deur **die laai van die kext toe te laat** in "Security & Privacy --> General", just **allow** it.

Jy kan ook hierdie **oneliner** gebruik om die toepassing af te laai, die kext te laai en die geheue te dump:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live process dumping with LLDB

Vir **onlangse macOS-weergawes** is die mees praktiese benadering gewoonlik om die memory van ’n **spesifieke proses** te dump in plaas daarvan om alle fisiese memory te image.

LLDB kan ’n Mach-O core file van ’n live target stoor:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
By verstek skep dit gewoonlik ’n **skinny core**. Om LLDB te forseer om al die gemapte prosesgeheue in te sluit:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Nuttige opvolgopdragte voor dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Dit is gewoonlik genoeg wanneer die doel is om te herwin:

- Ontsleutelde konfigurasie-blobs
- In-memory tokens, cookies, of credentials
- Plaintext secrets wat net by rest beskerm word
- Ontsleutelde Mach-O-bladsye ná unpacking / JIT / runtime patching

As die teiken beskerm word deur die **hardened runtime**, of as `taskgated` die attach weier, het jy tipies een van hierdie toestande nodig:

- Die teiken dra **`get-task-allow`**
- Jou debugger is gesigned met die regte **debugger entitlement**
- Jy is **root** en die teiken is 'n nie-hardened derdeparty-proses

Vir meer agtergrond oor hoe om 'n task port te verkry en wat daarmee gedoen kan word:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

Voordat jy tyd aan LLDB/Frida bestee, verifieer vinnig of die teiken realisties **dumpable** is:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Operasioneel beteken dit gewoonlik:

- ’n Derdeparty-toepassing wat met **`get-task-allow`** gestuur is, is dikwels direk dumpable met LLDB, en die gevolglike dump kan TCC-beskermde data blootstel waartoe die toepassing reeds toegang gekry het.
- ’n **hardened** teiken sonder `get-task-allow` sal gewoonlik attaches weier, selfs as `root`, tensy jy die relevante debugger entitlements / policy path beheer.
- Unhardened derdeparty-prosesse is steeds die maklikste plek om `lldb`, `vmmap`, Frida, of custom `task_for_pid`/`vm_read` readers te gebruik.

## Selective dumps with Frida or userland readers

Wanneer ’n volledige core te raserig is, is dit dikwels vinniger om net **interesting readable ranges** te dump. Frida is veral nuttig omdat dit goed werk vir **targeted extraction** sodra jy aan die proses kan attach.

Voorbeeldbenadering:

1. Tel readable/writable ranges op
2. Filter volgens module, heap, stack, of anonymous memory
3. Dump net die regions wat kandidaat strings, keys, protobufs, plist/XML blobs, of decrypted code/data bevat

Minimale Frida-voorbeeld om alle readable anonymous ranges te dump:
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
Dit is nuttig wanneer jy reuse core files wil vermy en net die volgende wil versamel:

- App heap chunks wat secrets bevat
- Anonymous regions wat deur custom packers of loaders geskep is
- JIT / unpacked code pages nadat protections verander is

Ouer userland tools soos [`readmem`](https://github.com/gdbinit/readmem) bestaan ook, maar hulle is hoofsaaklik nuttig as **source references** vir direkte `task_for_pid`/`vm_read`-styl dumping en word nie goed onderhou vir moderne Apple Silicon workflows nie.

## Heap / VM snapshots met `.memgraph`

As jy hoofsaaklik omgee vir **heap objects**, **allocation provenance**, of 'n snapshot wat na 'n ander masjien geskuif kan word, is 'n `.memgraph` dikwels meer prakties as 'n reuse Mach-O core. Die `leaks` tooling kan een van 'n live process genereer:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Dan triage dit vanlyn met standaard Apple-gereedskap:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` is die hoofrede om `-fullContent` naby te hou, omdat die etikette wat geheue-inhoud beskryf, weggelaat word uit 'n minimale `.memgraph`.

Dit is veral nuttig wanneer:

- Jy 'n **kleiner, deelbare snapshot** wil hê in plaas van 'n volle core
- `MallocStackLogging` geaktiveer was en jy **allocation backtraces** wil hê
- Jy reeds 'n **interessante heap-adres** ken en met `malloc_history` wil pivot
- Jy 'n vinnige **VM/heap breakdown** nodig het voordat jy besluit of 'n volle dump die noise werd is

## Swift-heavy targets: `swift-inspect`

Vir toepassings wat hoëwaarde-data binne **Swift runtime objects** hou, kan `swift-inspect` 'n goeie aanvulling tot LLDB of Frida wees. In plaas daarvan om eers alles te dump, kan jy spesifieke Swift runtime structures vanaf 'n live process navraag doen:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Dit is handig om te identifiseer:

- Groot Swift arrays wat interessante data buffer
- Metadata-toewysings wat tipes openbaar wat tydens runtime gelaai is
- Swift concurrency state (`Task`, actor, thread relationships) voordat jy 'n meer geteikende dump doen

Vir meer object-level runtime triage sodra jy die process reeds kan inspekteer, kyk [the dedicated page on objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Quick triage notes

- `sysctl vm.swapusage` is steeds 'n vinnige manier om **swap usage** te nagaan en of swap **encrypted** is.
- `sleepimage` bly hoofsaaklik relevant vir **hibernate/safe sleep**-scenario's, maar moderne systems beskerm dit gewoonlik, so dit moet as 'n **artifact source to check** beskou word, nie as 'n betroubare acquisition path nie.
- Op onlangse macOS releases is **process-level dumping** oor die algemeen meer realisties as **full physical memory imaging** tensy jy boot policy, SIP state en kext loading beheer.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
