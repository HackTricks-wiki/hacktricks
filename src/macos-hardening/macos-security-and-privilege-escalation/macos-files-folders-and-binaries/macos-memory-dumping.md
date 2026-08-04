# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

`/private/var/vm/swapfile0` जैसी Swap files **physical memory के भर जाने पर caches के रूप में काम करती हैं**। जब physical memory में और जगह नहीं बचती, तो इसका data swap file में transfer कर दिया जाता है और आवश्यकता पड़ने पर वापस physical memory में लाया जाता है। कई swap files मौजूद हो सकती हैं, जिनके नाम swapfile0, swapfile1 आदि हो सकते हैं।

### Hibernate Image

`/private/var/vm/sleepimage` पर स्थित file **hibernation mode** के दौरान महत्वपूर्ण होती है। **जब OS X hibernate होता है, तो memory का data इस file में store किया जाता है**। Computer के जागने पर system इस file से memory data retrieve करता है, जिससे user वहीं से काम जारी रख सकता है जहाँ उसने छोड़ा था।

यह ध्यान देने योग्य है कि modern MacOS systems पर security reasons से यह file आमतौर पर encrypted होती है, जिससे recovery कठिन हो जाती है।

- यह जांचने के लिए कि sleepimage के लिए encryption enabled है या नहीं, `sysctl vm.swapusage` command चलाई जा सकती है। यह दिखाएगा कि file encrypted है या नहीं।

### Memory Pressure Logs

MacOS systems में memory से संबंधित एक अन्य महत्वपूर्ण file **memory pressure log** है। ये logs `/var/log` में स्थित होते हैं और system के memory usage तथा pressure events के बारे में detailed information रखते हैं। ये memory-related issues का diagnosis करने या यह समझने में विशेष रूप से उपयोगी हो सकते हैं कि system समय के साथ memory को कैसे manage करता है।

## osxpmem के साथ memory dump करना

MacOS machine में memory dump करने के लिए आप [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) का उपयोग कर सकते हैं।

**Note**: अब यह मुख्यतः एक **legacy workflow** है। `osxpmem` kernel extension लोड करने पर निर्भर करता है, [Rekall](https://github.com/google/rekall) project archived है, latest release **2017** की है, और published binary **Intel Macs** को target करती है। Current macOS releases पर, विशेष रूप से **Apple Silicon** पर, kext-based full-RAM acquisition आमतौर पर modern kernel-extension restrictions, SIP और platform-signing requirements के कारण blocked होती है। व्यवहार में, modern systems पर अक्सर whole-RAM image के बजाय **process-scoped dump** करना पड़ता है।
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
**अन्य errors** को "Security & Privacy --> General" में **kext को load करने की अनुमति देकर** ठीक किया जा सकता है, बस **allow** करें।

आप application को download करने, kext को load करने और memory dump करने के लिए इस **oneliner** का भी उपयोग कर सकते हैं:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB के साथ live process dumping

**हाल के macOS versions** के लिए, आमतौर पर सबसे व्यावहारिक तरीका पूरी physical memory की image बनाने की कोशिश करने के बजाय किसी **विशिष्ट process** की memory dump करना होता है।

LLDB किसी live target से Mach-O core file save कर सकता है:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
डिफ़ॉल्ट रूप से, यह आमतौर पर एक **skinny core** बनाता है। LLDB को सभी mapped process memory शामिल करने के लिए बाध्य करने हेतु:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Dumping से पहले उपयोगी follow-up commands:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
यह आमतौर पर तब पर्याप्त होता है जब लक्ष्य हो:

- Decrypted configuration blobs
- In-memory tokens, cookies, या credentials
- Plaintext secrets जो केवल at rest protected हों
- Unpacking / JIT / runtime patching के बाद Decrypted Mach-O pages

यदि target **hardened runtime** से protected है, या `taskgated` attach को deny करता है, तो आमतौर पर आपको इनमें से किसी एक condition की आवश्यकता होती है:

- Target में **`get-task-allow`** मौजूद हो
- आपका debugger उचित **debugger entitlement** के साथ signed हो
- आप **root** हों और target एक non-hardened third-party process हो

Task port प्राप्त करने और उससे किए जा सकने वाले कार्यों की अधिक background जानकारी के लिए:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

LLDB/Frida पर समय बिताने से पहले, तुरंत verify करें कि target वास्तव में **dumpable** है या नहीं:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
व्यावहारिक रूप से, इसका आमतौर पर अर्थ है:

- **`get-task-allow`** के साथ shipped third-party app को अक्सर LLDB से सीधे dump किया जा सकता है, और resulting dump में वह TCC-protected data उजागर हो सकता है जिसे app पहले ही access कर चुका है।
- **hardened** target, जिसमें `get-task-allow` नहीं है, आमतौर पर attaches को reject करेगा, यहाँ तक कि `root` के रूप में भी, जब तक कि आपके नियंत्रण में relevant debugger entitlements / policy path न हो।
- Unhardened third-party processes अभी भी `lldb`, `vmmap`, Frida, या custom `task_for_pid`/`vm_read` readers का उपयोग करने के लिए सबसे आसान स्थान हैं।

### Dumpable nested helpers खोजें

Notarized macOS apps पर हालिया research में main GUI binary के बजाय nested helpers में **`get-task-allow`** मिलता रहा है। जब कोई top-level app hardened दिखे, तो हार मानने से पहले उसके **XPC services**, **login items**, **helper tools**, और bundled CLIs को enumerate करें:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
`get-task-allow` वाला nested executable अक्सर `lldb` से attach करने, core dump करने या custom `task_for_pid` client से memory प्राप्त करने के लिए सबसे आसान स्थान होता है, भले ही main app बेहतर तरीके से hardened हो।

## Frida या userland readers के साथ selective dumps

जब full core बहुत noisy हो, तब केवल **interesting readable ranges** को dump करना अक्सर अधिक तेज़ होता है। Frida विशेष रूप से उपयोगी है, क्योंकि process से attach करने के बाद यह **targeted extraction** के लिए अच्छी तरह काम करता है।

उदाहरण का तरीका:

1. readable/writable ranges को enumerate करें
2. module, heap, stack या anonymous memory के आधार पर filter करें
3. केवल उन regions को dump करें जिनमें candidate strings, keys, protobufs, plist/XML blobs या decrypted code/data मौजूद हों

सभी readable anonymous ranges को dump करने का Minimal Frida example:
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
यह तब उपयोगी होता है जब आप बड़ी core files से बचना चाहते हैं और केवल ये collect करना चाहते हैं:

- secrets वाले App heap chunks
- custom packers या loaders द्वारा बनाए गए Anonymous regions
- protections बदलने के बाद के JIT / unpacked code pages

जब आप dump कर रहे हों और target लगातार **allocating / freeing** कर रहा हो, तो unstable ranges के लिए `readByteArray()` के बजाय Frida के **`readVolatile()`** primitive को प्राथमिकता दें। यह धीमा है, लेकिन यदि read के बीच में कोई page unreadable हो जाए, तो यह target को crash होने से बचाता है। बड़े acquisitions के लिए, target के अंदर हजारों छोटी files बनाने के बजाय `send(..., data)` के साथ chunks को stream करके controller side पर compress करना भी अधिक साफ-सुथरा हो सकता है।

[`readmem`](https://github.com/gdbinit/readmem) जैसे पुराने userland tools भी मौजूद हैं, लेकिन वे मुख्यतः direct `task_for_pid`/`vm_read` style dumping के लिए **source references** के रूप में उपयोगी हैं और modern Apple Silicon workflows के लिए अच्छी तरह maintain नहीं किए जाते।

## Heap / VM snapshots with `.memgraph`

यदि आपकी मुख्य रुचि **heap objects**, **allocation provenance**, या ऐसे snapshot में है जिसे किसी अन्य machine पर ले जाया जा सके, तो एक `.memgraph` अक्सर giant Mach-O core की तुलना में अधिक practical होता है। `leaks` tooling live process से ऐसा snapshot generate कर सकती है:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
फिर standard Apple tooling का उपयोग करके इसे offline triage करें:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` `-fullContent` capture को संभालकर रखने का मुख्य कारण है, क्योंकि memory contents का वर्णन करने वाले labels minimal `.memgraph` से हटा दिए जाते हैं।

यह विशेष रूप से उपयोगी है जब:

- आपको full core के बजाय **छोटा, shareable snapshot** चाहिए
- `MallocStackLogging` enabled था और आपको **allocation backtraces** चाहिए
- आपको पहले से कोई **interesting heap address** पता है और `malloc_history` के साथ pivot करना चाहते हैं
- full dump का noise उचित है या नहीं, यह तय करने से पहले आपको एक त्वरित **VM/heap breakdown** चाहिए

### Differential memgraph triage

यदि आप target के start होने के तरीके को नियंत्रित करते हैं, तो launch से पहले **historical allocation logging** enabled करें, ताकि बाद के snapshots उपयोगी alloc/free backtraces को preserve कर सकें:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
फिर interesting action के आसपास snapshots capture करें और उन्हें offline diff करें:
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
यह **post-authentication objects**, बड़े `CFData` buffers, या **anonymous VM regions** को अलग करने का एक व्यावहारिक तरीका है, जो केवल decryption, unpacking या secret-retrieval stage के बाद दिखाई देते हैं।

## Swift-heavy targets: `swift-inspect`

ऐसे applications के लिए, जो high-value data को **Swift runtime objects** के अंदर रखते हैं, `swift-inspect`, LLDB या Frida का अच्छा complement हो सकता है। सब कुछ पहले dump करने के बजाय, आप live process से specific Swift runtime structures को query कर सकते हैं:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
यह पहचानने के लिए उपयोगी है:

- Interesting data को buffer करने वाले बड़े Swift arrays
- Runtime पर लोड किए गए types को प्रकट करने वाले Metadata allocations
- अधिक targeted dump करने से पहले Swift concurrency state (`Task`, actor, thread relationships)

Process का पहले से निरीक्षण कर पाने के बाद object-level runtime triage के लिए, [memory में objects पर dedicated page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) देखें।

## Quick triage notes

- `sysctl vm.swapusage` अभी भी **swap usage** और swap **encrypted** है या नहीं, यह जांचने का quick तरीका है।
- `sleepimage` मुख्य रूप से **hibernate/safe sleep** scenarios में relevant रहता है, लेकिन modern systems आमतौर पर इसे protect करते हैं; इसलिए इसे reliable acquisition path के बजाय **check करने योग्य artifact source** माना जाना चाहिए।
- Recent macOS releases पर **process-level dumping**, आमतौर पर **full physical memory imaging** की तुलना में अधिक realistic है, जब तक कि आपका boot policy, SIP state और kext loading पर control न हो।

## References

- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [https://keith.github.io/xcode-man-pages/leaks.1.html](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
