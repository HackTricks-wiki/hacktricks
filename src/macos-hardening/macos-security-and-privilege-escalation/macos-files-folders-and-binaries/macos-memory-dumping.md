# Kuondoa kumbukumbu za macOS

{{#include ../../../banners/hacktricks-training.md}}

## Mabaki ya Kumbukumbu

### Faili za Swap

Faili za swap, kama `/private/var/vm/swapfile0`, hutoa **cache wakati kumbukumbu ya kimwili imejaa**. Wakati hakuna nafasi tena katika kumbukumbu ya kimwili, data yake imesogezwa kwenda kwenye faili ya swap na kisha kurudishwa kwenye kumbukumbu ya kimwili inapohitajika. Faili nyingi za swap zinaweza kuwepo, zikiwa na majina kama swapfile0, swapfile1, n.k.

### Hibernate Image

Faili iliyopo `/private/var/vm/sleepimage` ni muhimu wakati wa **hibernation mode**. **Data kutoka kumbukumbu huhifadhiwa kwenye faili hii wakati OS X inapohibernate**. Wakati kompyuta inapoamka, mfumo hurudisha data ya kumbukumbu kutoka kwenye faili hii, ikiruhusu mtumiaji kuendelea mahali alipoacha.

Inafaa kutambua kwamba kwenye mifumo ya kisasa ya MacOS, faili hii kawaida hupigwa encryption kwa sababu za usalama, na kufanya urejeshaji kuwa mgumu.

- Ili kukagua ikiwa encryption imewezeshwa kwa sleepimage, amri `sysctl vm.swapusage` inaweza kutumika. Hii itaonyesha kama faili imewekwa kwa encryption.

### Logs za shinikizo la kumbukumbu

Faida nyingine muhimu inayohusiana na kumbukumbu kwenye mifumo ya MacOS ni **log ya shinikizo la kumbukumbu**. Logs hizi zipo katika `/var/log` na zina taarifa za kina kuhusu matumizi ya kumbukumbu ya mfumo na matukio ya shinikizo. Zinaweza kuwa muhimu hasa kwa kutathmini matatizo yanayohusiana na kumbukumbu au kuelewa jinsi mfumo unavyosimamia kumbukumbu kwa muda.

## Dumping memory with osxpmem

Ili kutoa kumbukumbu kwenye mashine ya MacOS unaweza kutumia [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Kumbuka**: Hii sasa kwa kawaida ni **legacy workflow**. `osxpmem` inategemea kuingiza kernel extension, mradi wa [Rekall](https://github.com/google/rekall) umearchivishwa, toleo la mwisho ni kutoka **2017**, na binary iliyochapishwa inalenga **Intel Macs**. Katika toleo za sasa za macOS, hasa kwenye **Apple Silicon**, kunasa RAM nzima kwa kutumia kext kawaida hubanwa na vizuizi vya kisasa vya kernel-extension, SIP, na mahitaji ya kusaini platform. Kivitendo, kwenye mifumo ya kisasa mara nyingi utamaliza kwa kufanya **process-scoped dump** badala ya picha ya RAM yote.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Kama unapata hitilafu hii: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Unaweza kuitatua kwa kufanya:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Hitilafu nyingine** zinaweza kurekebishwa kwa **kuruhusu upakiaji wa kext** katika "Security & Privacy --> General", **iruhusu** tu.

Unaweza pia kutumia hii **oneliner** kupakua programu, kupakia kext na dump memory:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live process dumping with LLDB

Kwa matoleo **mapya ya macOS**, njia inayofaa zaidi kawaida ni ku-dump memory ya **mchakato maalum** badala ya kujaribu ku-image memory fiziki yote.

LLDB inaweza kuhifadhi Mach-O core file kutoka kwa target hai:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Kwa chaguo-msingi hii kawaida huunda **skinny core**. Ili kulazimisha LLDB kujumuisha kumbukumbu zote za mchakato zilizopangwa:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Amri za ziada muhimu kabla ya dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Hii kwa kawaida inatosha wakati lengo ni kurejesha:

- Vifurushi vya usanidi vilivyofichuliwa
- Token, cookies, au credentials zilizopo katika kumbukumbu
- Siri zilizo wazi (plaintext) ambazo zinalindwa tu wakati ziko hifadhi (at rest)
- Ukurasa za Mach-O zilizofichuliwa baada ya unpacking / JIT / runtime patching

Ikiwa lengo limewalindwa na the **hardened runtime**, au `taskgated` inakataza ku-attach, mara nyingi unahitaji mojawapo ya vigezo vifuatavyo:

- Lengo lina **`get-task-allow`**
- Debugger yako imesainiwa na entitlements sahihi za **debugger entitlement**
- Wewe ni **root** na lengo ni mchakato wa upande wa tatu usio-hardened

For more background on obtaining a task port and what can be done with it:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Dump za kuchagua kwa Frida au userland readers

Wakati core kamili inakuwa noisy, ku-dump maeneo tu ya **interesting readable ranges** mara nyingi huwa haraka zaidi. Frida ni hasa muhimu kwa sababu inafanya kazi vizuri kwa ajili ya **targeted extraction** mara tu unapoweza ku-attach kwenye mchakato.

Mfano wa mbinu:

1. Orodhesha maeneo yanayosomwa/yanayoandikwa
2. Chuja kwa module, heap, stack, au anonymous memory
3. Dump tu maeneo yanayojumuisha candidate strings, keys, protobufs, plist/XML blobs, au decrypted code/data

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
Hili ni muhimu unapotaka kuepuka faili kubwa za core na kukusanya tu:

- App heap chunks containing secrets
- Anonymous regions created by custom packers or loaders
- JIT / unpacked code pages after changing protections

Zana za zamani za userland kama [`readmem`](https://github.com/gdbinit/readmem) pia zipo, lakini kwa kiasi kikubwa zimetumika zaidi kama **marejeo ya chanzo** kwa ajili ya dump za mtindo wa moja kwa moja `task_for_pid`/`vm_read` na hazidumishiwi vizuri kwa workflows za kisasa za Apple Silicon.

## Vidokezo vya triage ya haraka

- `sysctl vm.swapusage` bado ni njia ya haraka ya kuangalia **matumizi ya swap** na kama swap ni **imesimbwa**.
- `sleepimage` bado ina umuhimu hasa kwa matukio ya **hibernate/safe sleep**, lakini mifumo ya kisasa kwa kawaida hukilinda, hivyo inapaswa kutazamwa kama **chanzo cha artifact cha kukagua**, sio kama njia ya kupata data inayotegemewa.
- Katika toleo za hivi karibuni za macOS, **process-level dumping** kwa ujumla ni ya kweli zaidi kuliko **full physical memory imaging** isipokuwa ukidhibiti boot policy, SIP state, na kext loading.

## Marejeo

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
