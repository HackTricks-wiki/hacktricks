# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## मेमोरी आर्टिफैक्ट्स

### स्वैप फ़ाइलें

Swap files, such as `/private/var/vm/swapfile0`, serve as **caches when the physical memory is full**. जब फिज़िकल मेमोरी भर जाती है, तो उसका डेटा एक swap file में ट्रांसफर कर दिया जाता है और आवश्यकता पड़ने पर फिर से फिज़िकल मेमोरी में लाया जाता है। कई swap फाइलें मौजूद हो सकती हैं, जिनके नाम swapfile0, swapfile1, आदि हो सकते हैं।

### हाइबरनेशन इमेज

The file located at `/private/var/vm/sleepimage` is crucial during **hibernation mode**. **Data from memory is stored in this file when OS X hibernates**. कंप्यूटर को वाक अप करने पर, सिस्टम इस फाइल से मेमोरी डेटा पुनः प्राप्त करता है, जिससे उपयोगकर्ता वही काम जारी रख सकता है जहाँ से वह रुका था।

ध्यान देने योग्य बात ये है कि आधुनिक MacOS सिस्टम्स पर यह फ़ाइल आमतौर पर सुरक्षा कारणों से एन्क्रिप्टेड होती है, जिससे रिकवरी कठिन हो जाती है।

- To check if encryption is enabled for the sleepimage, the command `sysctl vm.swapusage` can be run. यह दिखाएगा कि फाइल एन्क्रिप्टेड है या नहीं।

### मेमोरी प्रेशर लॉग्स

Another important memory-related file in MacOS systems is the **memory pressure log**. ये लॉग्स `/var/log` में स्थित होते हैं और सिस्टम के मेमोरी उपयोग और pressure इवेंट्स के बारे में विस्तृत जानकारी रखते हैं। ये मेमोरी-संबंधी समस्याओं का निदान करने या यह समझने में विशेष रूप से उपयोगी हो सकते हैं कि सिस्टम समय के साथ मेमोरी कैसे मैनेज करता है।

## osxpmem के साथ मेमोरी डंप करना

In order to dump the memory in a MacOS machine you can use [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**नोट**: यह अब ज्यादातर एक **legacy workflow** है। `osxpmem` का निर्भरता एक kernel extension को लोड करने पर है, the [Rekall](https://github.com/google/rekall) project archived है, इसकी latest release **2017** की है, और प्रकाशित बाइनरी Intel Macs को लक्षित करती है। वर्तमान macOS रिलीज़ पर, विशेषकर **Apple Silicon** पर, kext-based full-RAM acquisition सामान्यतः आधुनिक kernel-extension restrictions, SIP, और platform-signing requirements के कारण रोकी जाती है। व्यवहार में, आधुनिक सिस्टम्स पर आप अक्सर एक whole-RAM image के बजाय एक **process-scoped dump** करने का विकल्प चुनते हैं।
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
यदि आप यह त्रुटि पाते हैं: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` तो आप इसे ठीक कर सकते हैं:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**अन्य त्रुटियाँ** संभवतः "Security & Privacy --> General" में **kext को लोड करने की अनुमति देने** से ठीक हो सकती हैं, बस इसे **अनुमति दें**।

आप इस **oneliner** का उपयोग करके एप्लिकेशन डाउनलोड कर सकते हैं, kext को लोड कर सकते हैं और मेमोरी को dump कर सकते हैं:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB के साथ लाइव प्रोसेस डंपिंग

**recent macOS versions** के लिए, सामान्यतः सबसे व्यावहारिक तरीका यह होता है कि सभी physical memory की image बनाने की कोशिश करने के बजाय किसी एक **specific process** की memory डम्प की जाए।

LLDB एक Mach-O core file को live target से सेव कर सकता है:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
डिफ़ॉल्ट रूप से यह आम तौर पर एक **skinny core** बनाता है। LLDB को सभी मैप्ड प्रोसेस मेमोरी शामिल करने के लिए मजबूर करने के लिए:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
dumping से पहले उपयोगी अनुवर्ती कमांड:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
यह आमतौर पर पर्याप्त होता है जब लक्ष्य निम्नलिखित चीज़ों को recover करना हो:

- Decrypted configuration blobs
- In-memory tokens, cookies, or credentials
- Plaintext secrets that are only protected at rest
- Decrypted Mach-O pages after unpacking / JIT / runtime patching

यदि लक्ष्य **hardened runtime** द्वारा सुरक्षित है, या `taskgated` attach को deny करता है, तो आम तौर पर आपको इनमें से किसी एक शर्त की आवश्यकता होती है:

- The target carries **`get-task-allow`**
- Your debugger is signed with the proper **debugger entitlement**
- You are **root** and the target is a non-hardened third-party process

task port प्राप्त करने और इसके साथ क्या किया जा सकता है इस पर अधिक पृष्ठभूमि के लिए:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Frida या userland readers के साथ चयनित डंप्स

जब एक full core बहुत noisy हो, तो केवल वह भाग dump करना जो वास्तव में "interesting readable ranges" हैं अक्सर तेज़ होता है। Frida विशेष रूप से उपयोगी है क्योंकि एक बार आप process में attach कर सकें तो यह **targeted extraction** के लिए बेहतर काम करता है।

उदाहरणात्मक दृष्टिकोण:

1. readable/writable ranges को enumerate करें
2. module, heap, stack, या anonymous memory के आधार पर filter करें
3. केवल उन regions को dump करें जिनमें candidate strings, keys, protobufs, plist/XML blobs, या decrypted code/data मौजूद हैं

सभी readable anonymous ranges को dump करने के लिए न्यूनतम Frida उदाहरण:
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
यह उपयोगी है जब आप विशाल core files से बचना चाहते हैं और केवल एकत्र करना चाहते हैं:

- App heap chunks जो secrets रखते हैं
- कस्टम packers या loaders द्वारा बनाए गए anonymous regions
- protections बदलने के बाद के JIT / unpacked code pages

पुराने userland tools जैसे [`readmem`](https://github.com/gdbinit/readmem) भी मौजूद हैं, लेकिन वे मुख्य रूप से सीधे `task_for_pid`/`vm_read` शैली के dumping के लिए **स्रोत संदर्भ** के रूप में उपयोगी हैं और आधुनिक Apple Silicon वर्कफ़्लोज़ के लिए अच्छी तरह से मेंटेन नहीं किए जाते हैं।

## त्वरित प्राथमिक जाँच नोट्स

- `sysctl vm.swapusage` अभी भी **swap उपयोग** और यह कि swap **एन्क्रिप्टेड** है या नहीं जांचने का तेज़ तरीका है।
- `sleepimage` मुख्य रूप से **hibernate/safe sleep** परिदृश्यों के लिए प्रासंगिक है, लेकिन आधुनिक सिस्टम आम तौर पर इसे संरक्षित करते हैं, इसलिए इसे विश्वसनीय acquisition path के बजाय **जाँच करने के लिए एक artifact source** के रूप में माना जाना चाहिए।
- हाल के macOS रिलीज़ पर, **process-level dumping** आमतौर पर **full physical memory imaging** की तुलना में अधिक वास्तविकवादी है जब तक कि आप boot policy, SIP state, और kext loading नियंत्रित न करें।

## संदर्भ

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
