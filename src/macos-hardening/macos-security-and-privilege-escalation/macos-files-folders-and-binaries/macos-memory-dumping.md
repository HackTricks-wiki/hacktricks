# macOS-geheue-dumping

{{#include ../../../banners/hacktricks-training.md}}

## Geheue-artefakte

### Swap-lêers

Swap-lêers, soos `/private/var/vm/swapfile0`, dien as **caches wanneer die fisiese geheue vol is**. Wanneer daar nie meer plek in die fisiese geheue is nie, word die data daarvan na 'n swap-lêer oorgedra en dan soos nodig na die fisiese geheue teruggebring. Daar kan verskeie swap-lêers teenwoordig wees, met name soos swapfile0, swapfile1, ensovoorts.

### Hibernasiebeeld

Die lêer by `/private/var/vm/sleepimage` is belangrik tydens **hibernasiemodus**. **Data uit die geheue word in hierdie lêer gestoor wanneer OS X hiberneer**. Wanneer die rekenaar wakker word, haal die stelsel geheuedata uit hierdie lêer, sodat die gebruiker kan voortgaan waar hulle opgehou het.

Dit is belangrik om daarop te let dat hierdie lêer op moderne MacOS-stelsels gewoonlik om sekuriteitsredes geënkripteer is, wat herstel moeilik maak.

- Om te kontroleer of encryption vir die sleepimage geaktiveer is, kan die opdrag `sysctl vm.swapusage` uitgevoer word. Dit sal wys of die lêer geënkripteer is.

### Geheuedruk-logboeke

Nog 'n belangrike geheueverwante lêer in MacOS-stelsels is die **geheuedruk-logboek**. Hierdie logboeke is in `/var/log` geleë en bevat gedetailleerde inligting oor die stelsel se geheuegebruik en geheuedrukgebeurtenisse. Hulle kan besonder nuttig wees om geheueverwante probleme te diagnoseer of te verstaan hoe die stelsel geheue met verloop van tyd bestuur.

## Dumping van geheue met osxpmem

Om die geheue op 'n MacOS-masjien te dump, kan jy [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) gebruik.

**Nota**: Dit is nou hoofsaaklik 'n **legacy workflow**. `osxpmem` is afhanklik van die laai van 'n kernel extension, die [Rekall](https://github.com/google/rekall)-projek is geargiveer, die jongste release dateer uit **2017**, en die gepubliseerde binary teiken **Intel Macs**. Op huidige macOS-releases, veral op **Apple Silicon**, word kext-gebaseerde verkryging van volledige RAM gewoonlik deur moderne kernel-extension-beperkings, SIP en platform-signing-vereistes geblokkeer. In die praktyk sal jy op moderne stelsels meer dikwels met 'n **process-scoped dump** as met 'n volledige RAM-beeld eindig.
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
**Ander foute** kan moontlik reggestel word deur **die laai van die kext toe te laat** in "Security & Privacy --> General"; **laat dit eenvoudig toe**.

Jy kan ook hierdie **oneliner** gebruik om die toepassing af te laai, die kext te laai en die memory te dump:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumping van live prosesse met LLDB

Vir **onlangse macOS-weergawes** is die mees praktiese benadering gewoonlik om die geheue van ’n **spesifieke proses** te dump, eerder as om ’n beeld van alle fisiese geheue te probeer skep.

LLDB kan ’n Mach-O-kernlêer vanaf ’n live-teiken stoor:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
By verstek skep dit gewoonlik 'n **skinny core**. Om LLDB te dwing om alle gekarteerde prosesgeheue in te sluit:
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
Dit is gewoonlik genoeg wanneer die doelwit is om die volgende te herwin:

- Gedekripteerde konfigurasie-blobs
- Tokens, cookies of credentials in memory
- Plaintext-secrets wat slegs at rest beskerm word
- Gedekripteerde Mach-O-bladsye ná unpacking / JIT / runtime patching

As die doelwit deur die **hardened runtime** beskerm word, of as `taskgated` die attach weier, benodig jy tipies een van hierdie toestande:

- Die doelwit bevat **`get-task-allow`**
- Jou debugger is met die korrekte **debugger entitlement** gesign
- Jy is **root** en die doelwit is ’n nie-hardened third-party-process

Vir meer agtergrond oor die verkryging van ’n task port en wat daarmee gedoen kan word:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Vinnige pre-attach-kontroles

Voordat jy tyd aan LLDB/Frida bestee, verifieer vinnig of die doelwit realisties **dumpable** is:
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

- ’n Derdepartytoepassing wat met **`get-task-allow`** gelewer word, kan dikwels direk met LLDB gedump word, en die resulterende dump kan TCC-beskermde data blootlê waartoe die toepassing reeds toegang gehad het.<sup>[1]</sup>
- ’n **hardened** teiken sonder `get-task-allow` sal aanhegsels gewoonlik weier, selfs as `root`, tensy jy beheer het oor die relevante debugger entitlements / policy path.
- Ongeharde derdepartyprosesse is steeds die maklikste plek om `lldb`, `vmmap`, Frida, of pasgemaakte `task_for_pid`/`vm_read` readers te gebruik.

### Soek dumpbare geneste helpers

Onlangse navorsing oor genotariseerde macOS-toepassings vind steeds **`get-task-allow`** in geneste helpers eerder as in die hoof-GUI-binêre lêer. Wanneer ’n topvlaktoepassing hardened lyk, lys sy **XPC services**, **login items**, **helper tools**, en gebundelde CLIs voordat jy moed opgee:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
'n Geneste executable met `get-task-allow` is dikwels die maklikste plek om met `lldb` te attach, 'n core te dump, of geheue met 'n pasgemaakte `task_for_pid`-client te onttrek, selfs wanneer die hoofapp beter gehard is.

## Selective dumps with Frida or userland readers

Wanneer 'n volledige core te veel geraas bevat, is dit dikwels vinniger om slegs **interessante leesbare ranges** te dump. Frida is veral nuttig omdat dit goed werk vir **targeted extraction** sodra jy aan die proses kan attach.

Voorbeeldbenadering:

1. Enumerate leesbare/skryfbare ranges
2. Filter volgens module, heap, stack, of anonieme geheue
3. Dump slegs die streke wat kandidaatstringe, sleutels, protobufs, plist/XML-blobs, of gedekripteerde kode/data bevat

Minimale Frida-voorbeeld om alle leesbare anonieme ranges te dump:
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
Dit is nuttig wanneer jy groot core-lêers wil vermy en slegs die volgende wil versamel:

- App heap-blokke wat secrets bevat
- Anonymous regions wat deur custom packers of loaders geskep is
- JIT- / unpacked code pages nadat protections verander is

Wanneer die target aanhou **allocate / free** terwyl jy dump, verkies Frida se **`readVolatile()`** primitive bo **`readByteArray()`** vir onstabiele ranges. Dit is stadiger, maar voorkom dat die target beëindig word indien ’n page halfpad deur die read onleesbaar word. Vir groter acquisitions kan dit ook netjieser wees om chunks terug te stream met `send(..., data)` en dit aan die controller-kant te compress, eerder as om duisende klein files binne die target te skep.

Ouer userland-tools soos [`readmem`](https://github.com/gdbinit/readmem) bestaan ook, maar hulle is hoofsaaklik nuttig as **source references** vir direkte `task_for_pid`/`vm_read`-styl dumping en word nie goed onderhou vir moderne Apple Silicon-workflows nie.

## Heap / VM-snapshots met `.memgraph`

As jy hoofsaaklik omgee vir **heap objects**, **allocation provenance**, of ’n snapshot wat na ’n ander masjien geskuif kan word, is ’n `.memgraph` dikwels meer prakties as ’n reuse Mach-O core. Die `leaks`-tooling kan een vanaf ’n aktiewe proses genereer:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Doen dan triage daarvan vanlyn met standaard Apple tooling:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` is die hoofrede om ’n `-fullContent`-capture te behou, omdat die labels wat memory-inhoud beskryf, uit ’n minimale `.memgraph` weggelaat word.

Dit is veral nuttig wanneer:

- Jy ’n **kleiner, deelbare snapshot** in plaas van ’n volledige core wil hê
- `MallocStackLogging` geaktiveer was en jy **allocation backtraces** wil hê
- Jy reeds ’n **interessante heap-adres** ken en met `malloc_history` wil pivot
- Jy vinnig ’n **VM/heap-ontleding** nodig het voordat jy besluit of ’n volledige dump die geraas werd is

### Differential memgraph-triage

As jy beheer het oor hoe die target begin, aktiveer **historical allocation logging** voordat dit geloods word, sodat latere snapshots nuttige alloc/free backtraces behou:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Neem dan snapshots rondom die interessante aksie en diff hulle vanlyn:
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
Dit is 'n praktiese manier om **post-authentication-objekte**, **groot `CFData`-buffers** of **anonieme VM-gebiede** te isoleer wat slegs ná 'n dekripterings-, uitpak- of geheimherwinningstadium verskyn.

## Teikens met baie Swift: `swift-inspect`

Vir toepassings wat waardevolle data binne **Swift runtime-objekte** hou, kan `swift-inspect` 'n goeie aanvulling tot LLDB of Frida wees. In plaas daarvan om eers alles te dump, kan jy spesifieke Swift runtime-strukture vanuit 'n lewendige proses navraag doen:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Dit is nuttig om die volgende te identifiseer:

- Groot Swift-skikkings wat interessante data buffer
- Metadata-allokasies wat tipes onthul wat tydens runtime gelaai is
- Swift concurrency-toestand (`Task`, actor- en thread-verhoudings) voordat ’n meer geteikende dump gedoen word

Vir verdere object-level runtime-triage sodra jy reeds die proses kan inspekteer, kyk na [die toegewyde bladsy oor objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Vinnige triage-notas

- `sysctl vm.swapusage` is steeds ’n vinnige manier om **swap-gebruik** en of swap **encrypted** is, na te gaan.
- `sleepimage` bly hoofsaaklik relevant vir **hibernate/safe sleep**-scenario’s, maar moderne stelsels beskerm dit gewoonlik, dus moet dit as ’n **artifact source om na te gaan** behandel word, nie as ’n betroubare acquisition path nie.
- Op onlangse macOS-vrystellings is **process-level dumping** oor die algemeen meer realisties as **full physical memory imaging**, tensy jy boot policy, SIP-status en kext-loading beheer.

## Verwysings

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
