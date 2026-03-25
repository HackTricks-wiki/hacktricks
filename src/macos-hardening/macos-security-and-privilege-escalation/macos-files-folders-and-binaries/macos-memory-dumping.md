# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Geheue-artefakte

### Swap-lêers

Swap files, such as `/private/var/vm/swapfile0`, dien as **buffervoorrade wanneer die fisiese geheue vol is**. Wanneer daar nie meer plek in die fisiese geheue is nie, word die data na ’n swap-lêer geskuif en weer teruggesit in die fisiese geheue soos benodig. Meerdere swap-lêers kan voorkom, met name soos swapfile0, swapfile1, ensovoorts.

### Hibernate Image

Die lêer by `/private/var/vm/sleepimage` is noodsaaklik tydens **hibernation mode**. **Data uit die geheue word in hierdie lêer gestoor wanneer OS X in hibernasie gaan**. Wanneer die rekenaar wakker word, haal die stelsel geheuedata uit hierdie lêer terug sodat die gebruiker kan voortgaan waar hy opgehou het.

Dit is die moeite werd om te noem dat op moderne macOS-stelsels hierdie lêer tipies versleuteld is om veiligheidsredes, wat herstel bemoeilik.

- Om te kontroleer of enkripsie vir die sleepimage geaktiveer is, kan die opdrag `sysctl vm.swapusage` uitgevoer word. Dit sal wys of die lêer versleuteld is.

### Geheue-drukloglêers

Nog ’n belangrike geheueverwante lêer op macOS-stelsels is die **memory pressure log**. Hierdie logs is geleë in `/var/log` en bevat gedetaileerde inligting oor die stelsel se geheuegebruik en drukgebeurtenisse. Hulle kan besonder nuttig wees vir die diagnose van geheueverwante probleme of om te verstaan hoe die stelsel oor tyd geheue bestuur.

## Geheue uittreksel met osxpmem

Om die geheue op ’n MacOS-masjien uit te trek, kan jy [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) gebruik.

**Note**: Dit is deesdae hoofsaaklik ’n **legacy workflow**. `osxpmem` is afhanklik van die laai van ’n kernel extension, die [Rekall](https://github.com/google/rekall) projek is gearchiveer, die jongste vrystelling is van **2017**, en die gepubliseerde binêre rig op **Intel Macs**. Op huidige macOS-vrystellings, veral op **Apple Silicon**, word kext-based full-RAM acquisition gewoonlik geblokkeer deur moderne kernel-extension beperkings, SIP, en platform-signing requirements. In die praktyk sal jy op moderne stelsels meer gereeld ’n **process-scoped dump** doen in plaas van ’n hele-RAM beeld.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
As jy hierdie fout kry: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` kan jy dit regmaak deur:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Ander foute** kan dalk reggemaak word deur **toestemming te gee vir die laai van die kext** in "Security & Privacy --> General", gee dit net **toestemming**.

Jy kan ook hierdie **oneliner** gebruik om die toepassing af te laai, die kext te laai en die geheue te dump:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live process dumping with LLDB

Vir **recent macOS versions** is die mees praktiese benadering gewoonlik om die memory van 'n **specific process** te dump, eerder as om te probeer om alle physical memory te image.

LLDB kan 'n Mach-O core file vanaf 'n live target stoor:
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
Dit is gewoonlik genoeg wanneer die doel is om te herwin:

- Ontsleutelde konfigurasie blobs
- In-geheue tokens, cookies, of credentials
- Onversleutelde geheime wat slegs by rus beskerm word
- Ontsleutelde Mach-O bladsye na unpacking / JIT / runtime patching

As die teiken beskerm word deur die **hardened runtime**, of as `taskgated` die attach weier, benodig jy gewoonlik een van die volgende toestande:

- Die teiken dra **`get-task-allow`**
- Jou debugger is onderteken met die toepaslike **debugger entitlement**
- Jy is **root** en die teiken is 'n nie-hardened derdeparty-proses

Vir meer agtergrond oor hoe om 'n task port te bekom en wat daarmee gedoen kan word:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Selective dumps with Frida or userland readers

Wanneer 'n volledige core te raserig is, is dit dikwels vinniger om slegs **interessante leesbare reekse** te dump. Frida is veral nuttig omdat dit goed werk vir **targeted extraction** sodra jy by die proses kan aanheg.

Voorbeeldaanpak:

1. Enumereer leesbare/skryfbare reekse
2. Filter volgens module, heap, stack, of anonieme geheue
3. Dump slegs die streke wat kandidaatstrings, sleutels, protobufs, plist/XML blobs, of ontsleutelde kode/data bevat

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
Dit is nuttig as jy reusagtige core-lêers wil vermy en slegs wil versamel:

- App heap chunks containing secrets
- Anonymous regions created by custom packers or loaders
- JIT / unpacked code pages after changing protections

Ouer userland-instrumente soos [`readmem`](https://github.com/gdbinit/readmem) bestaan ook, maar hulle is hoofsaaklik nuttig as **bronverwysings** vir direkte `task_for_pid`/`vm_read`-styl dumping en word nie goed onderhou vir moderne Apple Silicon-werkvloeie nie.

## Vinnige triage-notas

- `sysctl vm.swapusage` bly nog 'n vinnige manier om **swapgebruik** en of swap **geënkripteer** is, te kontroleer.
- `sleepimage` bly hoofsaaklik relevant vir **hibernasie/veilige slaap**-scenario's, maar moderne stelsels beskerm dit gewoonlik, so dit moet as 'n **artefakbron om te kontroleer** beskou word, nie as 'n betroubare verkrygingspad nie.
- Op onlangse macOS-uitgawes is **process-level dumping** gewoonlik meer realisties as **full physical memory imaging**, tensy jy die bootbeleid, SIP-toestand en kext-lading beheer.

## Verwysings

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
