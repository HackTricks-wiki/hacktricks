# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap files, kao što je `/private/var/vm/swapfile0`, služe kao **keš kada je fizička memorija puna**. Kada više nema mesta u fizičkoj memoriji, njeni podaci se prebacuju u swap file i zatim vraćaju u fizičku memoriju po potrebi. Može postojati više swap file-ova, sa imenima kao što su swapfile0, swapfile1 i tako dalje.

### Hibernate Image

Fajl koji se nalazi na `/private/var/vm/sleepimage` je ključan tokom **hibernation mode**. **Podaci iz memorije se čuvaju u ovom fajlu kada OS X uđe u hibernaciju**. Kada se računar probudi, sistem preuzima podatke iz memorije iz ovog fajla, omogućavajući korisniku da nastavi gde je stao.

Vredi napomenuti da je na modernim MacOS sistemima ovaj fajl tipično enkriptovan iz sigurnosnih razloga, što otežava recovery.

- Da biste proverili da li je enkripcija omogućena za sleepimage, može se pokrenuti komanda `sysctl vm.swapusage`. Ona će pokazati da li je fajl enkriptovan.

### Memory Pressure Logs

Još jedan važan fajl vezan za memoriju na MacOS sistemima je **memory pressure log**. Ovi logovi se nalaze u `/var/log` i sadrže detaljne informacije o korišćenju memorije i događajima opterećenja sistema. Mogu biti posebno korisni za dijagnostikovanje problema vezanih za memoriju ili za razumevanje kako sistem upravlja memorijom tokom vremena.

## Dumping memory with osxpmem

Da biste dump-ovali memoriju na MacOS mašini možete koristiti [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: Ovo je uglavnom **legacy workflow** sada. `osxpmem` zavisi od učitavanja kernel extension-a, projekat [Rekall](https://github.com/google/rekall) je arhiviran, najnovije izdanje je iz **2017**, a objavljeni binary cilja **Intel Macs**. Na trenutnim macOS izdanjima, posebno na **Apple Silicon**, full-RAM acquisition baziran na kext-u je obično blokiran modernim ograničenjima kernel extension-a, SIP-om i zahtevima platform-signing-a. U praksi, na modernim sistemima ćete češće završiti sa **process-scoped dump** umesto sa whole-RAM image.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Ako pronađete ovu grešku: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` možete je popraviti ovako:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Ostale greške** mogu biti ispravljene **dozvoljavanjem učitavanja kext-a** u "Security & Privacy --> General", samo ga **dozvoli**.

Takođe možeš da koristiš ovaj **oneliner** da preuzmeš aplikaciju, učitaš kext i dump-uješ memoriju:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumpovanje live procesa pomoću LLDB

Za **novije verzije macOS-a**, najpraktičniji pristup je obično da se dumpuje memorija **određenog procesa** umesto da se pokušava slika kompletne fizičke memorije.

LLDB može da sačuva Mach-O core file iz live target-a:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Podrazumevano ovo obično kreira **skinny core**. Da biste naterali LLDB da uključi svu mapiranu memoriju procesa:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Korisne naredbe za nastavak pre dumpovanja:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Ovo je obično dovoljno kada je cilj da se povrati:

- Decrypted configuration blobs
- In-memory tokens, cookies, or credentials
- Plaintext secrets that are only protected at rest
- Decrypted Mach-O pages after unpacking / JIT / runtime patching

Ako je target zaštićen pomoću **hardened runtime**, ili ako `taskgated` odbije attach, obično su potrebni jedan od ovih uslova:

- Target ima **`get-task-allow`**
- Tvoj debugger je potpisan odgovarajućim **debugger entitlement**
- Ti si **root** i target je non-hardened third-party proces

Za više pozadine o dobijanju task porta i šta se sa njim može uraditi:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

Pre nego što potrošiš vreme na LLDB/Frida, brzo proveri da li je target realno **dumpable**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Operativno, ovo obično znači:

- Third-party app isporučen sa **`get-task-allow`** je često direktno dumpable sa LLDB, a rezultujući dump može otkriti TCC-protected podatke kojima je app već pristupio.
- **hardened** target bez `get-task-allow` će često odbiti attaches, čak i kao `root`, osim ako kontrolišeš relevantne debugger entitlements / policy path.
- Unhardened third-party procesi su i dalje najlakše mesto za korišćenje `lldb`, `vmmap`, Frida, ili custom `task_for_pid`/`vm_read` readers.

## Selective dumps with Frida or userland readers

Kada je full core previše noisy, dumpovanje samo **interesting readable ranges** je često brže. Frida je posebno korisna zato što dobro radi za **targeted extraction** jednom kada možeš da se attachuješ na proces.

Primer approach:

1. Enumerate readable/writable ranges
2. Filter by module, heap, stack, or anonymous memory
3. Dump only the regions that contain candidate strings, keys, protobufs, plist/XML blobs, or decrypted code/data

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
Ovo je korisno kada želiš da izbegneš ogromne core fajlove i prikupiš samo:

- App heap chunks koji sadrže secrets
- Anonymous region-e kreirane od strane custom packers ili loaders
- JIT / unpacked code page-ove nakon promene protections

Stariji userland alati kao što je [`readmem`](https://github.com/gdbinit/readmem) takođe postoje, ali su uglavnom korisni kao **source references** za direktno `task_for_pid`/`vm_read` style dumping i nisu dobro održavani za moderne Apple Silicon workflows.

## Heap / VM snapshots sa `.memgraph`

Ako ti je uglavnom stalo do **heap objekata**, **allocation provenance**, ili snapshot-a koji može da se premesti na drugu mašinu, `.memgraph` je često praktičniji od ogromnog Mach-O core-a. `leaks` tooling može da ga generiše iz live procesa:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Zatim ga offline triage-uj sa standardnim Apple tooling-om:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` je glavni razlog da se zadrži `-fullContent` capture, zato što se oznake koje opisuju sadržaj memorije izostavljaju iz minimalnog `.memgraph`.

Ovo je posebno korisno kada:

- Želiš **manji, deljiv snapshot** umesto celog core-a
- `MallocStackLogging` je bio omogućen i želiš **allocation backtraces**
- Već znaš **zanimljivu heap adresu** i želiš da pivotuješ pomoću `malloc_history`
- Treba ti brz **VM/heap breakdown** pre nego što odlučiš da li se full dump isplati zbog šuma

## Swift-heavy targets: `swift-inspect`

Za aplikacije koje drže podatke visoke vrednosti unutar **Swift runtime objects**, `swift-inspect` može biti dobar dodatak uz LLDB ili Frida. Umesto da prvo dump-uješ sve, možeš da postavljaš upite nad određenim Swift runtime strukturama iz live procesa:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Ovo je korisno za identifikaciju:

- Veliki Swift nizovi koji baferuju zanimljive podatke
- Metadata allocations koje otkrivaju tipove učitane tokom izvršavanja
- Swift concurrency state (`Task`, actor, thread relationships) pre nego što uradite ciljaniji dump

Za detaljniji object-level runtime triage kada već možete da pregledate process, pogledajte [the dedicated page on objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Quick triage notes

- `sysctl vm.swapusage` je i dalje brz način da proverite **swap usage** i da li je swap **encrypted**.
- `sleepimage` je i dalje relevantan uglavnom za scenarije **hibernate/safe sleep**, ali modern systems ga često štite, pa ga treba tretirati kao **artifact source to check**, a ne kao pouzdan acquisition path.
- Na novijim macOS verzijama, **process-level dumping** je uglavnom realističniji od **full physical memory imaging** osim ako kontrolišete boot policy, SIP state i kext loading.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
