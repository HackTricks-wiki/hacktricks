# मास्क किए गए पथ

{{#include ../../../../banners/hacktricks-training.md}}

मास्क किए गए पथ runtime protections हैं जो container से kernel-facing फ़ाइल सिस्टम की खास तौर पर संवेदनशील लोकेशनों को bind-mounting करके या अन्यथा अप्राप्य बनाकर छुपाते हैं। उद्देश्य यह है कि workload सीधे उन इंटरफेस के साथ इंटरैक्ट न करें जिनकी सामान्य applications को ज़रूरत नहीं होती, खासकर procfs के भीतर।

यह महत्वपूर्ण है क्योंकि कई container escapes और host-impacting tricks अक्सर `/proc` या `/sys` के अंतर्गत विशेष फाइलें पढ़ने/लिखने से शुरू होते हैं। यदि उन लोकेशनों को masked कर दिया गया है तो आक्रमणकर्ता को container के अंदर कोड निष्पादन मिलने के बाद भी kernel control surface के एक उपयोगी हिस्से तक सीधा पहुंच नहीं रहती।

## ऑपरेशन

Runtimes आमतौर पर निम्नलिखित जैसे चुने हुए पथ mask करते हैं:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

सटीक सूची runtime और host configuration पर निर्भर करती है। महत्वपूर्ण बात यह है कि container के दृष्टिकोण से वह पथ अनुपलब्ध या प्रतिस्थापित हो जाता है, जबकि वह host पर अभी भी मौजूद रहता है।

## लैब

Docker द्वारा प्रदर्शित masked-path कॉन्फ़िगरेशन का निरीक्षण करें:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
वर्कलोड के अंदर वास्तविक mount व्यवहार की जाँच करें:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## सुरक्षा प्रभाव

Masking मुख्य isolation boundary नहीं बनाती, लेकिन यह कई उच्च-मूल्य वाले post-exploitation लक्ष्यों को हटा देती है। Masking न होने पर, एक compromised container kernel state की जांच कर सकता है, sensitive प्रक्रिया या keying जानकारी पढ़ सकता है, या उन procfs/sysfs objects के साथ इंटरैक्ट कर सकता है जो application के लिए कभी दिखाई नहीं देने चाहिए थे।

## गलत कॉन्फ़िगरेशन

मुख्य गलती सुविधा या debugging के लिए व्यापक path classes को unmask करने की होती है। Podman में यह `--security-opt unmask=ALL` या लक्षित unmasking के रूप में दिखाई दे सकता है। Kubernetes में, अत्यधिक व्यापक proc exposure `procMount: Unmasked` के माध्यम से दिखाई दे सकती है। एक और गंभीर समस्या होस्ट `/proc` या `/sys` को bind mount के जरिए expose करना है, जो reduced container view के सिद्धांत को पूरी तरह bypass कर देता है।

## दुरुपयोग

यदि masking कमजोर है या अनुपस्थित है, तो पहले यह पहचानें कि कौन से sensitive procfs/sysfs paths सीधे पहुँचने योग्य हैं:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
यदि कोई कथित masked path सुलभ है, तो उसे सावधानीपूर्वक जाँचें:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` can expose host timer and scheduler data. This is mostly a reconnaissance primitive, but it confirms that the container can read kernel-facing information that is normally hidden.
- `/proc/keys` is much more sensitive. Depending on the host configuration, it may reveal keyring entries, key descriptions, and relationships between host services using the kernel keyring subsystem.
- `/sys/firmware` helps identify boot mode, firmware interfaces, and platform details that are useful for host fingerprinting and for understanding whether the workload is seeing host-level state.
- `/proc/config.gz` may reveal the running kernel configuration, which is valuable for matching public kernel exploit prerequisites or understanding why a specific feature is reachable.
- `/proc/sched_debug` exposes scheduler state and often bypasses the intuitive expectation that the PID namespace should hide unrelated process information completely.

Interesting results include direct reads from those files, evidence that the data belongs to the host rather than to a constrained container view, or access to other procfs/sysfs locations that are commonly masked by default.

## जांच

इन checks का उद्देश्य यह निर्धारित करना है कि runtime ने किन paths को जानबूझकर छिपाया है और क्या वर्तमान workload अभी भी एक सीमित kernel-facing filesystem देख रहा है।
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
What is interesting here:
- कठिन runtimes में लंबी masked-path सूची सामान्य है।
- संवेदनशील procfs एंट्रियों पर masking का अभाव गहन जांच का विषय है।
- यदि कोई संवेदनशील path सुलभ है और container के पास मजबूत capabilities या व्यापक mounts भी हैं, तो यह exposure अधिक महत्वपूर्ण है।

## रनटाइम डिफ़ॉल्ट

| Runtime / platform | डिफ़ॉल्ट स्थिति | डिफ़ॉल्ट व्यवहार | सामान्य मैनुअल कमजोर करने के तरीके |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से सक्षम | Docker एक डिफ़ॉल्ट masked path सूची परिभाषित करता है | होस्ट proc/sys mounts को एक्सपोज़ करना, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से सक्षम | Podman डिफ़ॉल्ट masked paths लागू करता है जब तक कि उन्हें मैन्युअल रूप से unmask न किया जाए | `--security-opt unmask=ALL`, targeted unmasking, `--privileged` |
| Kubernetes | रनटाइम डिफ़ॉल्ट्स को विरासत में लेता है | Pod सेटिंग्स proc exposure को कमजोर न करें तो यह underlying runtime के masking व्यवहार का उपयोग करता है | `procMount: Unmasked`, privileged वर्कलोड पैटर्न, व्यापक host mounts |
| containerd / CRI-O under Kubernetes | रनटाइम डिफ़ॉल्ट | आम तौर पर OCI/runtime masked paths लागू करता है जब तक कि ओवरराइड न किया जाए | डायरेक्ट runtime config परिवर्तन, वही Kubernetes कमजोर करने वाले paths |

Masked paths आम तौर पर डिफ़ॉल्ट रूप से मौजूद होते हैं। मुख्य संचालन समस्या runtime से उनकी अनुपस्थिति नहीं है, बल्कि जानबूझकर unmasking या host bind mounts हैं जो सुरक्षा को निरस्त कर देते हैं।
{{#include ../../../../banners/hacktricks-training.md}}
