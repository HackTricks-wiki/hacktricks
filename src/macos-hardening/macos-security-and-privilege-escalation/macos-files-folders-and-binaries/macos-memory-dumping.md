# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap files, such as `/private/var/vm/swapfile0`, serve as **caches when the physical memory is full**. When there's no more room in physical memory, its data is transferred to a swap file and then brought back to physical memory as needed. Multiple swap files might be present, with names like swapfile0, swapfile1, and so on.

### Hibernate Image

The file located at `/private/var/vm/sleepimage` is crucial during **hibernation mode**. **Data from memory is stored in this file when OS X hibernates**. Upon waking the computer, the system retrieves memory data from this file, allowing the user to continue where they left off.

It's worth noting that on modern MacOS systems, this file is typically encrypted for security reasons, making recovery difficult.

- To check if encryption is enabled for the sleepimage, the command `sysctl vm.swapusage` can be run. This will show if the file is encrypted.

### Memory Pressure Logs

Another important memory-related file in MacOS systems is the **memory pressure log**. These logs are located in `/var/log` and contain detailed information about the system's memory usage and pressure events. They can be particularly useful for diagnosing memory-related issues or understanding how the system manages memory over time.

## Dumping memory with osxpmem

In order to dump the memory in a MacOS machine you can use [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: This is mostly a **legacy workflow** now. `osxpmem` depends on loading a kernel extension, the [Rekall](https://github.com/google/rekall) project is archived, the latest release is from **2017**, and the published binary targets **Intel Macs**. On current macOS releases, especially on **Apple Silicon**, kext-based full-RAM acquisition is usually blocked by modern kernel-extension restrictions, SIP, and platform-signing requirements. In practice, on modern systems you will more often end up doing a **process-scoped dump** instead of a whole-RAM image.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Ako naiđete na ovu grešku: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Možete to popraviti tako što ćete:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Ostale greške** mogu se rešiti tako što ćete **dozvoliti učitavanje kext-a** u "Security & Privacy --> General", samo ga **dozvolite**.

Takođe možete koristiti ovaj **oneliner** da preuzmete aplikaciju, učitate kext i dump the memory:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumpovanje memorije pokrenutog procesa pomoću LLDB

Za **novije verzije macOS-a**, najpraktičniji pristup je obično da se dump-uje memorija **konkretnog procesa** umesto pokušaja da se napravi image cele fizičke memorije.

LLDB može sačuvati Mach-O core fajl iz aktivnog cilja:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Podrazumevano ovo obično kreira **skinny core**. Da biste primorali LLDB da uključi svu mapiranu memoriju procesa:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Korisne prateće naredbe pre dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Ovo je obično dovoljno kada je cilj da se oporave:

- Dekriptovani konfiguracioni blobovi
- Tokeni, cookies ili kredencijali u memoriji
- Tajne u običnom tekstu koje su zaštićene samo kada su u mirovanju
- Dekriptovane Mach-O stranice nakon unpacking / JIT / runtime patchinga

Ako je cilj zaštićen pomoću **hardened runtime**, ili ako `taskgated` odbije attach, obično vam treba jedan od sledećih uslova:

- Cilj nosi **`get-task-allow`**
- Vaš debugger je potpisan odgovarajućim **debugger entitlement**
- Vi ste **root** i cilj je third-party proces koji nije zaštićen hardened runtime-om

Za više informacija o dobijanju task porta i šta se može uraditi sa njim:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Selektivni dumpovi sa Frida ili userland readers

Kada je full core previše noisy, dumpovanje samo **interesting readable ranges** često je brže. Frida je posebno korisna jer dobro funkcioniše za **targeted extraction** čim se možete attach-ovati na proces.

Primer pristupa:

1. Enumerišite readable/writable opsege
2. Filtrirajte po module, heap, stack ili anonymous memoriji
3. Dump-ujte samo regione koji sadrže kandidat stringove, ključeve, protobufs, plist/XML blobove ili dekriptovani code/data

Minimalni Frida primer za dump svih readable anonymous opsega:
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
Ovo je korisno kada želite da izbegnete gigantske core fajlove i prikupite samo:

- heap blokovi aplikacije koji sadrže tajne
- anonimne regije kreirane od strane custom packers ili loaders
- JIT / unpacked code pages nakon promene zaštita

Older userland tools such as [`readmem`](https://github.com/gdbinit/readmem) also exist, but they are mainly useful as **referentni izvori** for direct `task_for_pid`/`vm_read` style dumping and are not well-maintained for modern Apple Silicon workflows.

## Brze napomene za trijažu

- `sysctl vm.swapusage` i dalje je brz način da se proveri **korišćenje swap-a** i da li je swap **šifrovan**.
- `sleepimage` ostaje relevantan uglavnom za **hibernacija/bezbedno spavanje** scenarije, ali moderni sistemi ga obično štite, tako da ga treba tretirati kao **izvor artefakata za proveru**, a ne kao pouzdan način pribavljanja.
- Na novijim izdanjima macOS-a, **dumpovanje na nivou procesa** je generalno realističnije nego **potpuno slikanje fizičke memorije** osim ako ne kontrolišete boot policy, SIP stanje i učitavanje kext-ova.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
