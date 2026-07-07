# macOS मेमोरी डंपिंग

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap files, जैसे `/private/var/vm/swapfile0`, **जब physical memory भर जाती है तब caches** के रूप में काम करते हैं। जब physical memory में और जगह नहीं होती, तो उसका data एक swap file में transfer किया जाता है और फिर जरूरत के अनुसार वापस physical memory में लाया जाता है। Multiple swap files मौजूद हो सकते हैं, जिनके नाम swapfile0, swapfile1, और इसी तरह हो सकते हैं।

### Hibernate Image

`/private/var/vm/sleepimage` पर स्थित file **hibernation mode** के दौरान महत्वपूर्ण होती है। **जब OS X hibernates करता है, memory का data इस file में store होता है**। Computer के wake होने पर, system इस file से memory data retrieve करता है, जिससे user वहीं से जारी रख सकता है जहां उसने छोड़ा था।

ध्यान देने योग्य बात यह है कि modern MacOS systems पर, security reasons के कारण यह file आमतौर पर encrypted होती है, जिससे recovery कठिन हो जाती है।

- यह check करने के लिए कि sleepimage के लिए encryption enabled है या नहीं, `sysctl vm.swapusage` command run की जा सकती है। यह दिखाएगा कि file encrypted है या नहीं।

### Memory Pressure Logs

MacOS systems में memory से संबंधित एक और important file **memory pressure log** है। ये logs `/var/log` में स्थित होते हैं और system के memory usage तथा pressure events के बारे में detailed information रखते हैं। ये memory-related issues diagnose करने या समय के साथ system memory को कैसे manage करता है, इसे समझने में विशेष रूप से useful हो सकते हैं।

## osxpmem के साथ memory dumping

MacOS machine में memory dump करने के लिए आप [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) का उपयोग कर सकते हैं।

**Note**: यह आजकल मुख्यतः एक **legacy workflow** है। `osxpmem` एक kernel extension load करने पर निर्भर करता है, [Rekall](https://github.com/google/rekall) project archived है, latest release **2017** की है, और published binary **Intel Macs** को target करता है। Current macOS releases पर, खासकर **Apple Silicon** पर, kext-based full-RAM acquisition आमतौर पर modern kernel-extension restrictions, SIP, और platform-signing requirements के कारण blocked होती है। Practical रूप से, modern systems पर आप अक्सर पूरे-RAM image के बजाय **process-scoped dump** करेंगे।
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
यदि आपको यह error मिलता है: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` तो आप इसे इस तरह ठीक कर सकते हैं:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**अन्य त्रुटियाँ** को **kext को लोड करने की अनुमति** देकर "Security & Privacy --> General" में ठीक किया जा सकता है, बस इसे **allow** करें।

आप इस **oneliner** का भी उपयोग करके application डाउनलोड कर सकते हैं, kext लोड कर सकते हैं और memory dump कर सकते हैं:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB के साथ Live process dumping

**recent macOS versions** के लिए, सबसे practical approach आमतौर पर **specific process** की memory dump करना होता है, बजाय सभी physical memory को image करने की कोशिश के।

LLDB live target से Mach-O core file save कर सकता है:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
डिफ़ॉल्ट रूप से यह आमतौर पर एक **skinny core** बनाता है। LLDB को सभी mapped process memory शामिल करने के लिए मजबूर करने हेतु:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
डंपिंग से पहले उपयोगी follow-up commands:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
यह आमतौर पर पर्याप्त होता है जब लक्ष्य यह recover करना हो:

- Decrypted configuration blobs
- In-memory tokens, cookies, or credentials
- Plaintext secrets that are only protected at rest
- Decrypted Mach-O pages after unpacking / JIT / runtime patching

यदि target **hardened runtime** द्वारा protected है, या `taskgated` attach को deny करता है, तो आमतौर पर आपको इनमें से किसी एक condition की आवश्यकता होगी:

- Target में **`get-task-allow`** मौजूद हो
- आपका debugger सही **debugger entitlement** के साथ signed हो
- आप **root** हों और target एक non-hardened third-party process हो

Task port प्राप्त करने और उसके साथ क्या किया जा सकता है, इस पर अधिक background के लिए:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

LLDB/Frida पर समय खर्च करने से पहले, जल्दी से verify करें कि target वास्तव में **dumpable** है या नहीं:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
व्यावहारिक रूप से, इसका आम तौर पर मतलब है:

- **`get-task-allow`** के साथ shipped किसी third-party app को अक्सर LLDB से सीधे dump किया जा सकता है, और resulting dump में वह TCC-protected data उजागर हो सकती है जिसे app पहले ही access कर चुकी है।
- **hardened** target जिसमें `get-task-allow` नहीं है, वह आम तौर पर attaches reject करेगा, root होने पर भी, जब तक कि आपके पास relevant debugger entitlements / policy path का control न हो।
- Unhardened third-party processes अभी भी `lldb`, `vmmap`, Frida, या custom `task_for_pid`/`vm_read` readers इस्तेमाल करने की सबसे आसान जगह हैं।

## Frida या userland readers के साथ selective dumps

जब full core बहुत noisy हो, तो सिर्फ **interesting readable ranges** को dump करना अक्सर तेज़ होता है। Frida खास तौर पर उपयोगी है क्योंकि once you can attach to the process, यह **targeted extraction** के लिए अच्छी तरह काम करता है।

Example approach:

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
यह तब उपयोगी है जब आप बड़े core files से बचना चाहते हैं और केवल यह collect करना चाहते हैं:

- App heap chunks जिनमें secrets हों
- Custom packers या loaders द्वारा बनाए गए anonymous regions
- Protections बदलने के बाद JIT / unpacked code pages

`readmem` जैसे पुराने userland tools भी मौजूद हैं, लेकिन वे मुख्यतः direct `task_for_pid`/`vm_read` style dumping के लिए **source references** के रूप में उपयोगी हैं और modern Apple Silicon workflows के लिए अच्छी तरह maintained नहीं हैं।

## Heap / VM snapshots with `.memgraph`

यदि आपको मुख्य रूप से **heap objects**, **allocation provenance**, या ऐसा snapshot चाहिए जिसे किसी दूसरे machine पर ले जाया जा सके, तो `.memgraph` अक्सर एक बड़े Mach-O core से अधिक practical होता है। `leaks` tooling live process से एक बना सकता है:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
फिर standard Apple tooling के साथ इसे offline triage करें:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` `-fullContent` capture को संभालकर रखने का मुख्य कारण है, क्योंकि memory contents का वर्णन करने वाले labels एक minimal `.memgraph` से omit हो जाते हैं।

यह खास तौर पर उपयोगी है जब:

- आप full core के बजाय एक **छोटा, shareable snapshot** चाहते हैं
- `MallocStackLogging` enabled था और आप **allocation backtraces** चाहते हैं
- आपको पहले से कोई **interesting heap address** पता है और आप `malloc_history` के साथ pivot करना चाहते हैं
- full dump के noise के लायक है या नहीं, यह तय करने से पहले आपको quick **VM/heap breakdown** चाहिए

## Swift-heavy targets: `swift-inspect`

उन applications के लिए जो high-value data को **Swift runtime objects** के अंदर रखते हैं, `swift-inspect` LLDB या Frida का एक अच्छा complement हो सकता है। सब कुछ पहले dump करने के बजाय, आप live process से specific Swift runtime structures query कर सकते हैं:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
यह पहचानने में मददगार है:

- रोचक डेटा को बफ़र करने वाले बड़े Swift arrays
- Metadata allocations जो runtime पर लोड हुए types को प्रकट करते हैं
- Swift concurrency state (`Task`, actor, thread relationships) ताकि अधिक targeted dump करने से पहले समझा जा सके

जब आप पहले से process inspect कर सकते हों, तब object-level runtime triage के लिए [memory में objects पर dedicated page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) देखें।

## Quick triage notes

- `sysctl vm.swapusage` अभी भी **swap usage** और swap के **encrypted** होने की जांच का एक तेज़ तरीका है।
- `sleepimage` मुख्यतः **hibernate/safe sleep** scenarios के लिए relevant रहता है, लेकिन modern systems इसे आमतौर पर protect करते हैं, इसलिए इसे **artifact source to check** के रूप में देखना चाहिए, न कि reliable acquisition path के रूप में।
- Recent macOS releases पर, **process-level dumping** आम तौर पर **full physical memory imaging** से अधिक realistic है, जब तक कि आपके पास boot policy, SIP state, और kext loading पर control न हो।

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
