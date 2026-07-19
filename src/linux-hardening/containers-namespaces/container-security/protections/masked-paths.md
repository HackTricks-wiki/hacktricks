# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths ऐसी runtime protections हैं जो उन विशेष रूप से संवेदनशील kernel-facing filesystem locations को container से छिपाती हैं, जिन्हें इनके ऊपर bind-mount करके या अन्यथा inaccessible बनाकर सुरक्षित किया जाता है। इसका उद्देश्य workload को उन interfaces के साथ सीधे interact करने से रोकना है जिनकी ordinary applications को आवश्यकता नहीं होती, विशेष रूप से procfs के अंदर।

यह महत्वपूर्ण है क्योंकि कई container escapes और host-impacting tricks `/proc` या `/sys` के अंतर्गत मौजूद special files को पढ़ने या लिखने से शुरू होती हैं। यदि वे locations masked हों, तो container के अंदर code execution प्राप्त करने के बाद भी attacker kernel control surface के एक उपयोगी हिस्से तक direct access खो देता है।

## Operation

Runtimes आमतौर पर निम्न जैसे selected paths को mask करते हैं:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

सटीक list runtime और host configuration पर निर्भर करती है। महत्वपूर्ण property यह है कि container के दृष्टिकोण से path inaccessible या replaced हो जाता है, भले ही वह host पर अभी भी मौजूद हो।

## Lab

Docker द्वारा exposed masked-path configuration को inspect करें:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
वर्कलोड के अंदर वास्तविक mount behavior का निरीक्षण करें:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Security Impact

Masking मुख्य isolation boundary नहीं बनाता, लेकिन यह कई high-value post-exploitation targets को हटा देता है। Masking के बिना, compromised container kernel state का निरीक्षण कर सकता है, sensitive process या keying information पढ़ सकता है, या ऐसे procfs/sysfs objects के साथ interact कर सकता है जो application को कभी दिखाई नहीं देने चाहिए।

## Misconfigurations

मुख्य गलती सुविधा या debugging के लिए paths की broad classes को unmask करना है। Podman में यह `--security-opt unmask=ALL` या targeted unmasking के रूप में दिखाई दे सकता है। Kubernetes में, अत्यधिक broad proc exposure `procMount: Unmasked` के माध्यम से दिखाई दे सकता है। एक अन्य गंभीर समस्या bind mount के माध्यम से host `/proc` या `/sys` को expose करना है, जो reduced container view की पूरी अवधारणा को bypass करता है।

## Abuse

यदि masking कमजोर या अनुपस्थित है, तो पहले यह पहचानना शुरू करें कि कौन-से sensitive procfs/sysfs paths सीधे reachable हैं:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
यदि supposedly masked path accessible है, तो उसका सावधानीपूर्वक निरीक्षण करें:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
ये commands क्या reveal कर सकते हैं:

- `/proc/timer_list` host के timer और scheduler data को expose कर सकता है। यह मुख्यतः एक reconnaissance primitive है, लेकिन इससे पुष्टि होती है कि container ऐसी kernel-facing information पढ़ सकता है जो सामान्यतः hidden रहती है।
- `/proc/keys` कहीं अधिक sensitive है। Host configuration के आधार पर, यह keyring entries, key descriptions और kernel keyring subsystem का उपयोग करने वाली host services के बीच relationships reveal कर सकता है।
- `/sys/firmware` boot mode, firmware interfaces और platform details की पहचान करने में मदद करता है, जो host fingerprinting और यह समझने के लिए उपयोगी हैं कि workload को host-level state दिखाई दे रही है या नहीं।
- `/proc/config.gz` running kernel configuration reveal कर सकता है, जो public kernel exploit prerequisites से matching करने या यह समझने के लिए valuable है कि कोई specific feature क्यों reachable है।
- `/proc/sched_debug` scheduler state expose करता है और अक्सर इस intuitive expectation को bypass करता है कि PID namespace unrelated process information को पूरी तरह hide कर देगा।

Interesting results में उन files से direct reads, इस बात के evidence कि data constrained container view के बजाय host से संबंधित है, या अन्य procfs/sysfs locations तक access शामिल हैं, जिन्हें सामान्यतः default रूप से masked किया जाता है।

## Checks

इन checks का उद्देश्य यह निर्धारित करना है कि runtime ने किन paths को जानबूझकर hide किया है और क्या current workload को अभी भी एक reduced kernel-facing filesystem दिखाई दे रहा है।
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
यहाँ क्या महत्वपूर्ण है:

- Hardened runtimes में लंबी masked-path list सामान्य होती है।
- संवेदनशील procfs entries पर masking का न होना अधिक गहन निरीक्षण योग्य है।
- यदि कोई संवेदनशील path accessible है और container में strong capabilities या broad mounts भी हैं, तो exposure अधिक महत्वपूर्ण हो जाता है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से Enabled | Docker एक default masked path list निर्धारित करता है | host proc/sys mounts को expose करना, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से Enabled | Podman default masked paths लागू करता है, जब तक उन्हें manually unmask न किया जाए | `--security-opt unmask=ALL`, targeted unmasking, `--privileged` |
| Kubernetes | Runtime defaults से inherit करता है | proc exposure को कमजोर करने वाली Pod settings न होने पर underlying runtime के masking behavior का उपयोग करता है | `procMount: Unmasked`, privileged workload patterns, broad host mounts |
| containerd / CRI-O under Kubernetes | Runtime default | override न किए जाने पर आमतौर पर OCI/runtime masked paths लागू करता है | direct runtime config changes, वही Kubernetes weakening paths |

Masked paths आमतौर पर डिफ़ॉल्ट रूप से मौजूद होते हैं। मुख्य operational समस्या runtime से उनका absent होना नहीं, बल्कि deliberate unmasking या ऐसे host bind mounts हैं जो इस protection को निष्प्रभावी कर देते हैं।
{{#include ../../../../banners/hacktricks-training.md}}
