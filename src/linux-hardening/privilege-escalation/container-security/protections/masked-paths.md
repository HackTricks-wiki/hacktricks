# मास्क किए गए पथ

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths वे runtime protections हैं जो container से विशेष रूप से संवेदनशील kernel-facing फ़ाइलसिस्टम स्थानों को छिपाते हैं — उदाहरण के लिए उन पर bind-mounting करके या अन्य तरीकों से उन्हें असुलभ बना कर। उद्देश्य यह है कि एक workload सीधे उन इंटरफेसों के साथ इंटरैक्ट न कर सके जिनकी ordinary applications को ज़रूरत नहीं होती, विशेष रूप से procfs के अंदर।

यह इसलिए महत्वपूर्ण है क्योंकि कई container escapes और host-impacting ट्रिक्स `/proc` या `/sys` के अंतर्गत विशेष फ़ाइलों को पढ़ने या लिखने से शुरू होते हैं। यदि उन स्थानों को masked किया गया है, तो attacker container के अंदर code execution प्राप्त करने के बाद भी kernel control surface के उपयोगी हिस्से तक सीधी पहुँच खो देता है।

## संचालन

Runtimes आमतौर पर निम्नलिखित जैसे चयनित पथों को mask करते हैं:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

सटीक सूची runtime और host configuration पर निर्भर करती है। महत्वपूर्ण गुण यह है कि path container के दृष्टिकोण से असुलभ या प्रतिस्थापित दिखता है, भले ही वह host पर अभी भी मौजूद हो।

## प्रयोगशाला

Docker द्वारा प्रदर्शित masked-path configuration की जांच करें:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
वर्कलोड के अंदर वास्तविक mount व्यवहार का निरीक्षण करें:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## सुरक्षा प्रभाव

Masking मुख्य isolation boundary नहीं बनाता, लेकिन यह कई उच्च-मूल्य वाले post-exploitation targets को हटा देता है। Masking के बिना, एक compromised container kernel state का निरीक्षण कर सकता है, sensitive process या keying information पढ़ सकता है, या उन procfs/sysfs objects के साथ interact कर सकता है जो कभी भी application के लिए दिखाई नहीं होने चाहिए थे।

## Misconfigurations

मुख्य गलती सुविधाजनक या debugging के लिए व्यापक वर्गों के पाथ्स को unmasking करना है। Podman में यह `--security-opt unmask=ALL` या लक्षित unmasking के रूप में दिख सकता है। Kubernetes में, बहुत व्यापक proc exposure `procMount: Unmasked` के माध्यम से नजर आ सकती है। एक और गंभीर समस्या host `/proc` या `/sys` को bind mount के माध्यम से एक्सपोज़ करना है, जो पूरी तरह से reduced container view के विचार को बाईपास कर देता है।

## Abuse

यदि masking कमजोर है या अनुपस्थित है, तो यह पहचानने से शुरू करें कि कौन से संवेदनशील procfs/sysfs paths सीधे पहुँच योग्य हैं:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
यदि कोई कथित रूप से masked path सुलभ है, तो इसे सावधानी से निरीक्षण करें:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` होस्ट timer और scheduler डेटा उजागर कर सकता है। यह अधिकांशतः reconnaissance primitive है, लेकिन यह पुष्टि करता है कि container सामान्यतः छिपी हुई kernel-facing जानकारी पढ़ सकता है।
- `/proc/keys` बहुत अधिक संवेदनशील है। होस्ट कॉन्फ़िगरेशन के अनुसार, यह keyring entries, key descriptions, और उन होस्ट सेवाओं के बीच संबंध प्रकट कर सकता है जो kernel keyring subsystem का उपयोग कर रही हैं।
- `/sys/firmware` बूट मोड, firmware interfaces, और platform विवरण पहचानने में मदद करता है जो host fingerprinting के लिए उपयोगी होते हैं और यह समझने के लिए कि workload host-level state देख रहा है या नहीं।
- `/proc/config.gz` चलती हुई kernel configuration प्रकट कर सकता है, जो public kernel exploit prerequisites से मेल खाने या यह समझने के लिए मूल्यवान है कि कोई विशिष्ट feature क्यों पहुंच योग्य है।
- `/proc/sched_debug` scheduler state उजागर करता है और अक्सर उस स्वाभाविक उम्मीद को बायपास कर देता है कि PID namespace अप्रासंगिक process जानकारी को पूरी तरह छिपा देगा।

दिलचस्प परिणामों में उन फाइलों से सीधे पढ़ना, इस बात के प्रमाण कि डेटा constrained container view के बजाय host का है, या अन्य procfs/sysfs स्थानों तक पहुँच शामिल हैं जो सामान्यतः डिफ़ॉल्ट रूप से masked होते हैं।

## Checks

इन checks का उद्देश्य यह निर्धारित करना है कि runtime ने किन paths को जानबूझकर छिपाया था और क्या वर्तमान workload अब भी एक reduced kernel-facing filesystem देखता है।
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
क्या यहाँ रोचक है:

- एक लंबी masked-path सूची hardened runtimes में सामान्य है।
- संवेदनशील procfs प्रविष्टियों पर masking का अभाव गहन जांच के योग्य है।
- यदि कोई संवेदनशील path सुलभ है और container के पास मजबूत capabilities या व्यापक mounts भी हैं, तो यह exposure अधिक महत्वपूर्ण हो जाता है।

## रनटाइम डिफ़ॉल्ट्स

| Runtime / platform | डिफ़ॉल्ट स्थिति | डिफ़ॉल्ट व्यवहार | आम मैन्युअल कमजोर करने के तरीके |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से सक्षम | Docker एक डिफ़ॉल्ट masked path सूची परिभाषित करता है | होस्ट proc/sys mounts को एक्सपोज़ करना, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से सक्षम | Podman डिफ़ॉल्ट masked paths लागू करता है जब तक कि मैन्युअल रूप से unmask न किया गया हो | `--security-opt unmask=ALL`, लक्षित unmasking, `--privileged` |
| Kubernetes | रनटाइम डिफ़ॉल्ट्स को विरासत में लेता है | Pod सेटिंग्स proc एक्सपोज़र को कमजोर न करें तो यह अंतर्निहित runtime के masking व्यवहार का उपयोग करता है | `procMount: Unmasked`, privileged workload patterns, व्यापक host mounts |
| containerd / CRI-O under Kubernetes | रनटाइम डिफ़ॉल्ट | आम तौर पर OCI/runtime masked paths लागू करता है जब तक ओवरराइड न किया गया हो | डायरेक्ट runtime config बदलाव, वही Kubernetes कमजोर करने वाले तरीके |

Masked paths आम तौर पर डिफ़ॉल्ट रूप से मौजूद रहते हैं। मुख्य संचालन संबंधी समस्या runtime में उनकी अनुपस्थिति नहीं है, बल्कि जानबूझकर unmasking या host bind mounts हैं जो सुरक्षा को निष्प्रभावी कर देते हैं।
