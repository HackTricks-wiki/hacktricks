# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths रनटाइम सुरक्षा उपाय हैं, जो container के लिए विशेष रूप से संवेदनशील kernel-facing filesystem locations को उनके ऊपर bind-mount करके या अन्यथा उन्हें inaccessible बनाकर छिपाते हैं। इसका उद्देश्य workload को उन interfaces के साथ सीधे interact करने से रोकना है जिनकी सामान्य applications को आवश्यकता नहीं होती, खासकर procfs के अंदर।

यह महत्वपूर्ण है क्योंकि कई container escapes और host-impacting tricks `/proc` या `/sys` के अंतर्गत मौजूद विशेष files को पढ़ने या लिखने से शुरू होती हैं। यदि वे locations masked हों, तो container के अंदर code execution प्राप्त करने के बाद भी attacker kernel control surface के एक उपयोगी हिस्से तक सीधी पहुंच खो देता है।

## Operation

Runtimes आमतौर पर चुनिंदा paths को mask करते हैं, जैसे:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

सटीक सूची runtime और host configuration पर निर्भर करती है। महत्वपूर्ण बात यह है कि container के दृष्टिकोण से path inaccessible या replaced हो जाता है, भले ही वह host पर अभी भी मौजूद हो।

## Lab

Docker द्वारा exposed masked-path configuration का निरीक्षण करें:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
workload के अंदर वास्तविक mount behavior का निरीक्षण करें:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Security Impact

Masking मुख्य isolation boundary नहीं बनाता, लेकिन यह कई high-value post-exploitation targets को हटा देता है। Masking के बिना, compromised container kernel state का निरीक्षण करने, sensitive process या keying information पढ़ने, या procfs/sysfs objects के साथ interact करने में सक्षम हो सकता है, जो application के लिए कभी visible नहीं होने चाहिए।

## Misconfigurations

मुख्य गलती convenience या debugging के लिए paths की broad classes को unmask करना है। Podman में यह `--security-opt unmask=ALL` या targeted unmasking के रूप में दिखाई दे सकता है। Kubernetes में, अत्यधिक broad proc exposure `procMount: Unmasked` के माध्यम से दिखाई दे सकता है। एक अन्य गंभीर समस्या bind mount के माध्यम से host `/proc` या `/sys` को expose करना है, जो reduced container view के विचार को पूरी तरह bypass करता है।

## Abuse

यदि Masking कमजोर या अनुपस्थित है, तो पहले यह पहचानना शुरू करें कि कौन से sensitive procfs/sysfs paths सीधे reachable हैं:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
यदि कथित रूप से masked path accessible है, तो उसका सावधानीपूर्वक निरीक्षण करें:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
ये commands क्या प्रकट कर सकती हैं:

- `/proc/timer_list` host के timer और scheduler data को expose कर सकता है। यह मुख्यतः reconnaissance primitive है, लेकिन यह पुष्टि करता है कि container kernel-facing information को read कर सकता है, जो सामान्यतः hidden होती है।
- `/proc/keys` कहीं अधिक sensitive है। host configuration के आधार पर, यह keyring entries, key descriptions और kernel keyring subsystem का उपयोग करने वाली host services के बीच relationships को reveal कर सकता है।
- `/sys/firmware` boot mode, firmware interfaces और platform details की पहचान करने में मदद करता है, जो host fingerprinting और यह समझने के लिए उपयोगी हैं कि workload को host-level state दिखाई दे रही है या नहीं।
- `/proc/config.gz` running kernel configuration को reveal कर सकता है, जो public kernel exploit prerequisites से matching करने या यह समझने के लिए valuable है कि कोई specific feature reachable क्यों है।
- `/proc/sched_debug` scheduler state को expose करता है और अक्सर इस intuitive expectation को bypass करता है कि PID namespace को unrelated process information को पूरी तरह hide करना चाहिए।

Interesting results में उन files से direct reads, यह evidence कि data constrained container view के बजाय host से संबंधित है, या अन्य procfs/sysfs locations तक access शामिल हैं, जिन्हें default रूप से सामान्यतः masked किया जाता है।

## Checks

इन checks का उद्देश्य यह निर्धारित करना है कि runtime ने किन paths को intentionally hidden किया है और क्या current workload को अभी भी reduced kernel-facing filesystem दिखाई देता है।
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
यहाँ क्या interesting है:

- Hardened runtimes में एक लंबी masked-path list सामान्य है।
- Sensitive procfs entries पर masking का न होना अधिक गहन inspection का कारण है।
- यदि कोई sensitive path accessible है और container में strong capabilities या broad mounts भी हैं, तो exposure अधिक महत्वपूर्ण हो जाता है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से Enabled | Docker एक default masked path list define करता है | host proc/sys mounts को expose करना, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से Enabled | Podman default masked paths लागू करता है, जब तक उन्हें manually unmask न किया जाए | `--security-opt unmask=ALL`, targeted unmasking, `--privileged` |
| Kubernetes | Runtime defaults inherit करता है | Pod settings proc exposure को कमजोर न करें, तब तक underlying runtime के masking behavior का उपयोग करता है | `procMount: Unmasked`, privileged workload patterns, broad host mounts |
| containerd / CRI-O under Kubernetes | Runtime default | आमतौर पर OCI/runtime masked paths लागू करता है, जब तक override न किया जाए | direct runtime config changes, वही Kubernetes weakening paths |

Masked paths आमतौर पर डिफ़ॉल्ट रूप से मौजूद होते हैं। मुख्य operational problem runtime में उनकी अनुपस्थिति नहीं, बल्कि deliberate unmasking या host bind mounts हैं, जो इस protection को निष्प्रभावी कर देते हैं।

{{#include ../../../../banners/hacktricks-training.md}}
