# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Geheue-artefakte

### Swap-lêers

Swap-lêers, soos `/private/var/vm/swapfile0`, dien as **caches wanneer die fisiese geheue vol is**. Wanneer daar nie meer plek in die fisiese geheue is nie, word die data daarvan na ’n swap-lêer oorgedra en daarna soos nodig na die fisiese geheue teruggebring. Daar kan verskeie swap-lêers teenwoordig wees, met name soos swapfile0, swapfile1, ensovoorts.

### Hibernasiebeeld

Die lêer by `/private/var/vm/sleepimage` is belangrik tydens **hibernasiemodus**. **Data uit die geheue word in hierdie lêer gestoor wanneer OS X hiberneer**. Wanneer die rekenaar wakker word, haal die stelsel geheuedata uit hierdie lêer, wat die gebruiker in staat stel om voort te gaan waar hulle opgehou het.

Dit is belangrik om daarop te let dat hierdie lêer op moderne MacOS-stelsels gewoonlik om sekuriteitsredes encrypted is, wat recovery moeilik maak.

- Om te kontroleer of encryption vir die sleepimage geaktiveer is, kan die command `sysctl vm.swapusage` uitgevoer word. Dit sal wys of die lêer encrypted is.

### Geheuedruk-logboeke

Nog ’n belangrike geheueverwante lêer in MacOS-stelsels is die **geheuedruk-logboek**. Hierdie logboeke is in `/var/log` geleë en bevat gedetailleerde inligting oor die stelsel se geheuegebruik en geheuedruk-gebeurtenisse. Hulle kan besonder nuttig wees om geheueverwante probleme te diagnoseer of te verstaan hoe die stelsel geheue met verloop van tyd bestuur.

## Dumping van geheue met osxpmem

Om die geheue op ’n MacOS-masjien te dump, kan jy [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) gebruik.

**Nota**: Dit is tans meestal ’n **legacy workflow**. `osxpmem` is afhanklik van die laai van ’n kernel extension, die [Rekall](https://github.com/google/rekall)-projek is archived, die jongste release is van **2017**, en die gepubliseerde binary teiken **Intel Macs**. Op huidige macOS-releases, veral op **Apple Silicon**, word kext-gebaseerde verkryging van volledige RAM gewoonlik deur moderne kernel-extension-beperkings, SIP en platform-signing-vereistes geblokkeer. In die praktyk sal jy op moderne stelsels eerder ’n **process-scoped dump** as ’n hele-RAM-beeld uitvoer.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
As jy hierdie fout teëkom: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Jy kan dit regstel deur:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Ander foute** kan moontlik reggestel word deur **die laai van die kext toe te laat** in "Sekuriteit & Privaatheid --> Algemeen"; **laat dit net toe**.

Jy kan ook hierdie **oneliner** gebruik om die application af te laai, die kext te laai en die memory te dump:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live proses-dumping met LLDB

Vir **onlangse macOS-weergawes** is die mees praktiese benadering gewoonlik om die geheue van ’n **spesifieke proses** te dump eerder as om die hele fisiese geheue te probeer image.

LLDB kan ’n Mach-O-kernlêer vanaf ’n lewendige teiken stoor:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
By verstek skep dit gewoonlik ’n **skinny core**. Om LLDB te dwing om alle gemapte prosesgeheue in te sluit:
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
Dit is gewoonlik genoeg wanneer die doel is om die volgende te herwin:

- Decrypted configuration blobs
- In-memory tokens, cookies, of credentials
- Plaintext secrets wat slegs at rest beskerm word
- Decrypted Mach-O pages ná unpacking / JIT / runtime patching

As die teiken deur die **hardened runtime** beskerm word, of as `taskgated` die attach weier, benodig jy tipies een van hierdie voorwaardes:

- Die teiken dra **`get-task-allow`**
- Jou debugger is met die korrekte **debugger entitlement** onderteken
- Jy is **root**, en die teiken is ’n non-hardened third-party process

Vir meer agtergrond oor die verkryging van ’n task port en wat daarmee gedoen kan word:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Vinnige kontroles voor attach

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
In die praktyk beteken dit gewoonlik:

- ’n Derdeparty-app wat met **`get-task-allow`** verskeep is, kan dikwels direk met LLDB gedump word, en die gevolglike dump kan TCC-beskermde data blootlê waartoe die app reeds toegang verkry het.<sup>[[1]](#references)</sup>
- ’n **hardened** teiken sonder `get-task-allow` sal aanhegsels gewoonlik weier, selfs as `root`, tensy jy die toepaslike debugger-entitlements / policy path beheer.
- Unhardened derdeparty-prosesse is steeds die maklikste plek om `lldb`, `vmmap`, Frida, of pasgemaakte `task_for_pid`/`vm_read`-lesers te gebruik.

### Soek dumpable geneste helpers

Onlangse navorsing oor genotariseerde macOS-apps vind steeds **`get-task-allow`** in geneste helpers in plaas van die hoof-GUI-binêre lêer. Wanneer ’n topvlak-app hardened lyk, lys sy **`XPC services`**, **`login items`**, **`helper tools`** en gebundelde CLI’s voordat jy tou opgooi:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
'n Geneste uitvoerbare lêer met `get-task-allow` is dikwels die maklikste plek om met `lldb` te attach, 'n core te dump, of geheue met 'n pasgemaakte `task_for_pid`-client te onttrek, selfs wanneer die hoofapp beter beveilig is.

## Selektiewe dumps met Frida of userland readers

Wanneer 'n volledige core te veel geraas bevat, is dit dikwels vinniger om slegs **interessante leesbare reekse** te dump. Frida is besonder nuttig omdat dit goed werk vir **geteikende ekstraksie** sodra jy aan die proses kan attach.

Voorbeeldbenadering:

1. Tel leesbare/skryfbare reekse op
2. Filter volgens module, heap, stack of anonieme geheue
3. Dump slegs die streke wat kandidaatstringe, sleutels, protobufs, plist/XML-blobs of gedekripteerde code/data bevat

Minimale Frida-voorbeeld om alle leesbare anonieme reekse te dump:
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
Dit is nuttig wanneer jy groot core files wil vermy en slegs die volgende wil versamel:

- App heap chunks wat secrets bevat
- Anonymous regions wat deur custom packers of loaders geskep is
- JIT- / unpacked code pages nadat protections verander is

Wanneer die target aanhou **allocating / freeing** terwyl jy dump, verkies Frida se **`readVolatile()`** primitive bo **`readByteArray()`** vir onstabiele ranges. Dit is stadiger, maar voorkom dat die target beëindig word as ’n page halfpad deur die read onleesbaar word. Vir groter acquisitions kan dit ook skoner wees om chunks met `send(..., data)` terug te stream en dit aan die controller-kant te compress, eerder as om duisende klein files binne die target te skep.

Ouer userland tools soos [`readmem`](https://github.com/gdbinit/readmem) bestaan ook, maar hulle is hoofsaaklik nuttig as **source references** vir direkte `task_for_pid`/`vm_read`-styl dumping en word nie goed vir moderne Apple Silicon-workflows onderhou nie.

## Heap / VM-snapshots met `.memgraph`

As jy hoofsaaklik omgee vir **heap objects**, **allocation provenance**, of ’n snapshot wat na ’n ander masjien verskuif kan word, is ’n `.memgraph` dikwels meer prakties as ’n reuse Mach-O core. Die `leaks`-tooling kan een vanaf ’n aktiewe proses genereer:<sup>[[2]](#references)</sup>
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Voer dan triage daarvan vanlyn uit met standaard Apple-nutsgoed:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` is die hoofrede om 'n `-fullContent`-capture te behou, omdat die labels wat memory-inhoud beskryf, uit 'n minimale `.memgraph` weggelaat word.

Dit is veral nuttig wanneer:

- Jy 'n **kleiner, deelbare snapshot** in plaas van 'n volledige core wil hê
- `MallocStackLogging` enabled was en jy **allocation backtraces** wil hê
- Jy reeds 'n **interessante heap-adres** ken en met `malloc_history` wil pivot
- Jy vinnig 'n **VM/heap-uiteensetting** nodig het voordat jy besluit of 'n volledige dump die geraas werd is

### Differential memgraph-triage

As jy beheer het oor hoe die target start, enable **historical allocation logging** voor launch sodat latere snapshots nuttige alloc/free backtraces behou:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Neem dan snapshots rondom die interessante aksie en vergelyk hulle offline:
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
Dit is ’n praktiese manier om **post-authentication objects**, groot `CFData`-buffers of **anonymous VM regions** te isoleer wat slegs ná ’n dekripsie-, unpacking- of secret-retrieval-stadium verskyn.

## Swift-heavy targets: `swift-inspect`

Vir toepassings wat waardevolle data binne **Swift runtime objects** hou, kan `swift-inspect` ’n goeie aanvulling tot LLDB of Frida wees. In plaas daarvan om eers alles te dump, kan jy spesifieke Swift runtime-strukture vanuit ’n lewendige proses navraag doen:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Dit is nuttig om die volgende te identifiseer:

- Groot Swift-skikkings wat interessante data buffer
- Metadata-allokasies wat tipes onthul wat tydens runtime gelaai is
- Swift-concurrency-toestand (`Task`, actor- en thread-verhoudings) voordat ’n meer geteikende dump uitgevoer word

Vir verdere object-level runtime-triage sodra jy reeds die proses kan inspekteer, kyk na [die toegewyde bladsy oor objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Vinnige triage-notas

- `sysctl vm.swapusage` is steeds ’n vinnige manier om **swap-gebruik** te kontroleer en te bepaal of swap **geënkripteer** is.
- `sleepimage` bly hoofsaaklik relevant vir **hibernate/safe sleep**-scenario’s, maar moderne stelsels beskerm dit gewoonlik, dus moet dit as ’n **artifact-bron om na te gaan** behandel word, nie as ’n betroubare verkrygingsmetode nie.
- Op onlangse macOS-vrystellings is **process-level dumping** oor die algemeen meer realisties as **full physical memory imaging**, tensy jy beheer het oor boot policy, SIP-status en kext-loading.

## Verwysings

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
