# मास्क किए गए पथ

{{#include ../../../../banners/hacktricks-training.md}}

मास्क किए गए पथ runtime protections हैं, जो विशेष रूप से संवेदनशील kernel-facing filesystem locations को bind-mount करके या उन्हें किसी अन्य तरीके से पहुंच से बाहर करके container से छिपाते हैं। OCI runtime specification `maskedPaths` को ऐसे absolute paths के रूप में परिभाषित करती है जिन्हें container के अंदर पढ़ा नहीं जा सकता। <sup>[[1]](#references)</sup>

यह इसलिए महत्वपूर्ण है क्योंकि कई container escapes और host को प्रभावित करने वाली तरकीबें `/proc` या `/sys` के अंतर्गत मौजूद special files को पढ़ने या लिखने से शुरू होती हैं। यदि ये locations masked हों, तो container के अंदर code execution हासिल करने के बाद भी हमलावर kernel control surface के एक उपयोगी हिस्से तक सीधे नहीं पहुंच सकता।

## काम करने का तरीका

Runtimes आमतौर पर चुने हुए paths को mask करते हैं, जैसे:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

सटीक सूची runtime और host configuration पर निर्भर करती है। महत्वपूर्ण बात यह है कि host पर path मौजूद रहने के बावजूद, container के नज़रिए से वह पहुंच से बाहर हो जाता है या उसकी जगह कुछ और आ जाता है।

## लैब

Docker द्वारा उपलब्ध कराई गई masked-path configuration देखें:

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

workload के अंदर वास्तविक mount behavior का निरीक्षण करें:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

सूचीबद्ध path का पढ़ने योग्य होना तय नहीं है: runc किसी file को `/dev/null` bind mount से और किसी directory को read-only खाली tmpfs से mask कर सकता है। सिर्फ यह न देखें कि `ls` सफल होता है या नहीं; exact mountpoint जांचें। <sup>[[4]](#references)</sup>

## सुरक्षा प्रभाव

Masking मुख्य isolation boundary नहीं बनाता, लेकिन post-exploitation के कई high-value targets हटा देता है। Masking के बिना, compromised container kernel state inspect कर सकता है, संवेदनशील process या keying जानकारी पढ़ सकता है, या procfs/sysfs objects के साथ interact कर सकता है, जिन्हें application को कभी दिखाई नहीं देना चाहिए।

## गलत कॉन्फ़िगरेशन

मुख्य गलती सुविधा या debugging के लिए paths की व्यापक श्रेणियों को unmask करना है। Podman में यह `--security-opt unmask=ALL` या targeted unmasking के रूप में दिख सकता है। <sup>[[2]](#references)</sup> Kubernetes में, बहुत व्यापक proc exposure `procMount: Unmasked` के ज़रिए हो सकता है; मौजूदा Kubernetes में इस setting के लिए `spec.hostUsers: false` (एक user namespace) ज़रूरी है, जबकि versions 1.12–1.29 में यह आवश्यकता लागू नहीं थी। <sup>[[3]](#references)</sup> एक और गंभीर समस्या bind mount के ज़रिए host `/proc` या `/sys` को expose करना है, जो reduced container view के विचार को पूरी तरह दरकिनार कर देता है।

## दुरुपयोग

अगर masking कमज़ोर है या मौजूद नहीं है, तो पहले पहचानें कि procfs/sysfs के कौन-से संवेदनशील paths सीधे पहुंच योग्य हैं:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

यदि कोई supposedly masked path पहुँच योग्य हो, तो उसकी सावधानीपूर्वक जाँच करें:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

ये commands क्या उजागर कर सकते हैं:

- `/proc/timer_list` host के timer और scheduler data को उजागर कर सकता है। यह मुख्यतः reconnaissance primitive है, लेकिन इससे पुष्टि होती है कि container ऐसी kernel-facing जानकारी पढ़ सकता है जो आम तौर पर छिपी रहती है।
- `/proc/keys` केवल उन keys का metadata सूचीबद्ध करता है जिनके लिए reader के पास **view** permission है और जो LSM checks के अधीन हैं। इससे key types और descriptions का पता चल सकता है, लेकिन key payloads dump नहीं होते। <sup>[[6]](#references)</sup>
- `/sys/firmware` boot mode, firmware interfaces और platform details पहचानने में मदद करता है, जो host fingerprinting और यह समझने के लिए उपयोगी हैं कि workload को host-level state दिख रही है या नहीं।
- `/proc/config.gz` चल रहे kernel configuration को उजागर कर सकता है, जो public kernel exploit prerequisites से मिलान करने या यह समझने के लिए उपयोगी है कि कोई खास feature क्यों accessible है।
- `/proc/sched_debug` scheduler state उजागर करता है और अक्सर इस सहज अपेक्षा को दरकिनार करता है कि PID namespace को असंबंधित process की जानकारी पूरी तरह छिपानी चाहिए।

दिलचस्प नतीजों में इन files से सीधे पढ़ पाना, इस बात के सबूत कि data किसी सीमित container view के बजाय host का है, या अन्य ऐसे procfs/sysfs locations तक पहुंच शामिल हैं जिन्हें आम तौर पर default रूप से mask किया जाता है।

### Container startup के दौरान mask-source race

कमज़ोर runc implementations में file masks, container के `/dev/null` inode पर निर्भर करते हैं। कोई attacker shared mounts वाले concurrent containers, जिनमें parallel BuildKit steps भी शामिल हैं, की व्यवस्था करके startup के दौरान race कर सकता है और runc द्वारा masked procfs files पर `/dev/null` bind करने से पहले उसे हटा सकता है। इसके बाद runtime, missing **source** को ऐसे मानता है जैसे mask destination मौजूद न हो, और चुपचाप उन file masks को छोड़ देता है। यह विफलता runtime setup के दौरान race पर निर्भर करती है; startup के बाद `/dev/null` हटाने से पहले से लगा mask नहीं हटता। <sup>[[4]](#references)</sup>

नियंत्रित test के बाद, अनुरोधित mask list की तुलना नए container के भीतर exact mountpoints से करें। <sup>[[4]](#references)</sup> `findmnt -M` किसी parent mount पर fallback करने के बजाय नामित mountpoint को जांचता है; अगर `findmnt` मौजूद न हो, तो `/proc/self/mountinfo` देखें। <sup>[[5]](#references)</sup> `ls` का सफल होना या `cat` का खाली होना यह साबित नहीं कर सकता कि mask मौजूद नहीं है। <sup>[[4]](#references)</sup>

नए container में अनुरोधित masks की exact mounts से तुलना करने के लिए [नीचे दिए गए checks](#checks) का उपयोग करें।

छूटा हुआ file mask, सामान्य permissions और LSM policy अनुमति दें तो procfs data उजागर कर सकता है। इससे अपने-आप `/proc/sys` writable **नहीं** होता: यह एक अलग [read-only-path](read-only-paths.md) control है। `/dev/null` symlink substitution का अलग मामला, जो bind mount को writable procfs target की ओर redirect कर सकता है, [PID-namespace runtime race](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs) के अंतर्गत कवर किया गया है। <sup>[[4]](#references)</sup>

## Checks

इन checks का उद्देश्य यह पता लगाना है कि runtime ने जानबूझकर कौन-से paths छिपाए और क्या मौजूदा workload को अब भी सीमित kernel-facing filesystem दिख रहा है।

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Exact-mount जाँच का उपयोग करें, क्योंकि masked file अब भी मौजूद हो सकती है और `/dev/null` से पढ़ने पर खाली परिणाम मिल सकता है। Mountpoint का अनुपस्थित होना जाँचने योग्य निष्कर्ष है, अपने-आप में इस बात का प्रमाण नहीं कि host data पढ़ा जा सकता है। <sup>[[4]](#references)[[5]](#references)</sup>

यहाँ क्या दिलचस्प है:

- Hardened runtimes में masked paths की लंबी सूची सामान्य है।
- संवेदनशील procfs entries पर masking न होना अधिक बारीकी से जाँचने योग्य है।
- यदि कोई संवेदनशील path accessible है और container के पास strong capabilities या व्यापक mounts भी हैं, तो यह exposure अधिक मायने रखता है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से Enabled | Docker एक default masked path list तय करता है | host proc/sys mounts को expose करना, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से Enabled | Podman, जब तक manually unmask न किया जाए, default masked paths लागू करता है | `--security-opt unmask=ALL`, targeted unmasking, `--privileged` |
| Kubernetes | Runtime defaults से inherit करता है | जब तक Pod settings proc exposure को कमज़ोर न करें, underlying runtime का masking behavior उपयोग करता है | `procMount: Unmasked` (वर्तमान releases में `hostUsers: false` आवश्यक है), privileged workload patterns, व्यापक host mounts |
| containerd / CRI-O under Kubernetes | Runtime default | आमतौर पर OCI/runtime masked paths लागू करता है, जब तक override न किया जाए | सीधे runtime config में बदलाव, Kubernetes में वही weakening paths |

Masked paths आमतौर पर डिफ़ॉल्ट रूप से मौजूद होते हैं। मुख्य operational समस्या runtime में इनका न होना नहीं, बल्कि जानबूझकर इन्हें unmask करना या ऐसे host bind mounts का उपयोग करना है जो सुरक्षा को निष्प्रभावी कर दें।

## References

- [1] [Open Container Initiative - Linux container configuration: Masked Paths](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Podman documentation - `podman run` security options](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Kubernetes Documentation - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [runc advisory: masked-path mount source race](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [findmnt(8) manual](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [keyrings(7) manual](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
