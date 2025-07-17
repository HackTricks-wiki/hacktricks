# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**इस रिपोर्ट में**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) कई कमजोरियों को समझाया गया है जिन्होंने सॉफ़्टवेयर अपडेटर को समझौता करते हुए कर्नेल को प्रभावित किया।\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild Kernel 0-days (CVE-2024-23225 & CVE-2024-23296)

Apple ने मार्च 2024 में iOS और macOS के खिलाफ सक्रिय रूप से शोषित दो मेमोरी-क्षति बग को पैच किया (macOS 14.4/13.6.5/12.7.4 में ठीक किया गया)।

* **CVE-2024-23225 – Kernel**
• XNU वर्चुअल-मेमोरी सबसिस्टम में आउट-ऑफ-बाउंड्स लिखने से एक अप्रिविलेज्ड प्रक्रिया को कर्नेल एड्रेस स्पेस में मनमाना पढ़ने/लिखने की अनुमति मिलती है, PAC/KTRR को बायपास करते हुए।
• एक तैयार XPC संदेश के माध्यम से उपयोगकर्ता स्थान से ट्रिगर किया गया जो `libxpc` में एक बफर को ओवरफ्लो करता है, फिर संदेश को पार्स करते समय कर्नेल में पिवट करता है।
* **CVE-2024-23296 – RTKit**
• Apple Silicon RTKit (रीयल-टाइम सह-प्रोसेसर) में मेमोरी क्षति।
• शोषण श्रृंखलाएँ देखी गईं जिन्होंने कर्नेल R/W के लिए CVE-2024-23225 और सुरक्षित सह-प्रोसेसर सैंडबॉक्स से बाहर निकलने और PAC को निष्क्रिय करने के लिए CVE-2024-23296 का उपयोग किया।

Patch level detection:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
यदि अपग्रेड करना संभव नहीं है, तो कमजोर सेवाओं को बंद करके जोखिम को कम करें:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIG प्रकार-भ्रम – CVE-2023-41075

`mach_msg()` अनुरोध जो एक अप्रिविलेज्ड IOKit उपयोगकर्ता क्लाइंट को भेजे जाते हैं, MIG द्वारा उत्पन्न गोंद-कोड में एक **प्रकार भ्रम** का कारण बनते हैं। जब उत्तर संदेश को एक बड़े आउट-ऑफ-लाइन वर्णनकर्ता के साथ फिर से व्याख्यायित किया जाता है जो मूल रूप से आवंटित किया गया था, तो एक हमलावर नियंत्रित **OOB लिखने** में सक्षम हो सकता है और अंततः `root` तक बढ़ सकता है।

Primitive outline (Sonoma 14.0-14.1, Ventura 13.5-13.6):
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
Public exploits बग को इस प्रकार हथियार बनाते हैं:
1. सक्रिय पोर्ट पॉइंटर्स के साथ `ipc_kmsg` बफर्स को स्प्रे करना।
2. एक लटकते पोर्ट के `ip_kobject` को ओवरराइट करना।
3. `mprotect()` का उपयोग करके PAC-फर्ज़ किए गए पते पर मैप किए गए शेलकोड पर कूदना।

---

## 2024-2025: तीसरे पक्ष के Kexts के माध्यम से SIP बायपास – CVE-2024-44243 (जिसे “Sigma” कहा जाता है)

Microsoft के सुरक्षा शोधकर्ताओं ने दिखाया कि उच्च-विशिष्टता डेमन `storagekitd` को **असाइन किए गए कर्नेल एक्सटेंशन** को लोड करने के लिए मजबूर किया जा सकता है और इस प्रकार पूरी तरह से पैच किए गए macOS (15.2 से पहले) पर **सिस्टम इंटीग्रिटी प्रोटेक्शन (SIP)** को पूरी तरह से निष्क्रिय कर दिया जा सकता है। हमले का प्रवाह इस प्रकार है:

1. हमलावर के नियंत्रण में एक सहायक उत्पन्न करने के लिए निजी अधिकार `com.apple.storagekitd.kernel-management` का दुरुपयोग करना।
2. सहायक एक तैयार की गई सूचना-शब्दकोश के साथ `IOService::AddPersonalitiesFromKernelModule` को कॉल करता है जो एक दुर्भावनापूर्ण kext बंडल की ओर इशारा करता है।
3. चूंकि SIP ट्रस्ट जांचें `storagekitd` द्वारा kext के स्टेज होने के *बाद* की जाती हैं, कोड रिंग-0 में मान्यता से पहले निष्पादित होता है और SIP को `csr_set_allow_all(1)` के साथ बंद किया जा सकता है।

Detection tips:
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
तत्काल सुधार के लिए macOS Sequoia 15.2 या इसके बाद के संस्करण में अपडेट करें।

---

### त्वरित गणना चीटशीट
```bash
uname -a                          # Kernel build
kmutil showloaded                 # List loaded kernel extensions
kextstat | grep -v com.apple      # Legacy (pre-Catalina) kext list
sysctl kern.kaslr_enable          # Verify KASLR is ON (should be 1)
csrutil status                    # Check SIP from RecoveryOS
spctl --status                    # Confirms Gatekeeper state
```
---

## Fuzzing & Research Tools

* **Luftrauser** – Mach संदेश फज़्ज़र जो MIG उपप्रणालियों को लक्षित करता है (`github.com/preshing/luftrauser`).
* **oob-executor** – IPC आउट-ऑफ-बाउंड प्राइमिटिव जनरेटर जो CVE-2024-23225 अनुसंधान में उपयोग किया गया.
* **kmutil inspect** – अंतर्निहित Apple उपयोगिता (macOS 11+) जो लोड करने से पहले kexts का स्थैतिक विश्लेषण करती है: `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “macOS Sonoma 14.4 की सुरक्षा सामग्री के बारे में।” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “CVE-2024-44243 का विश्लेषण, एक macOS सिस्टम इंटीग्रिटी प्रोटेक्शन बायपास जो कर्नेल एक्सटेंशनों के माध्यम से है।” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
