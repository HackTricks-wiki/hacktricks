# उपयोगकर्ता नेमस्पेस

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

उपयोगकर्ता नेमस्पेस user और group IDs के अर्थ को बदल देता है क्योंकि यह kernel को नेमस्पेस के अंदर देखे गए IDs को बाहर के अलग IDs से map करने देता है। यह आधुनिक container सुरक्षा के सबसे महत्वपूर्ण उपायों में से एक है क्योंकि यह क्लासिक containers की सबसे बड़ी ऐतिहासिक समस्या को सीधे संबोधित करता है: **container के अंदर का root host पर root के बहुत करीब हुआ करता था**।

उपयोगकर्ता नेमस्पेस के साथ, कोई process container के अंदर UID 0 के रूप में चल सकती है और फिर भी host पर एक unprivileged UID रेंज से संबंधित हो सकती है। इसका मतलब है कि process बहुत से in-container कार्यों के लिए root की तरह व्यवहार कर सकती है जबकि host की नज़र में इसका प्रभाव बहुत कम होता है। यह हर container सुरक्षा समस्या का समाधान नहीं है, लेकिन यह container compromise के परिणामों को काफी बदल देता है।

## संचालन

एक उपयोगकर्ता नेमस्पेस में `/proc/self/uid_map` और `/proc/self/gid_map` जैसे mapping फाइलें होती हैं जो बताती हैं कि नेमस्पेस IDs parent IDs में कैसे translate होते हैं। अगर नेमस्पेस के अंदर का root किसी unprivileged host UID से map होता है, तो वे ऑपरेशंस जिन्हें असली host root चाहिए होता, उनका प्रभाव वही नहीं रहता। यही वजह है कि user namespaces **rootless containers** के लिए केंद्रीय हैं और यही पुरानी rootful container defaults और आधुनिक least-privilege डिज़ाइनों के बीच सबसे बड़े अंतर में से एक हैं।

बात सूक्ष्म पर महत्वपूर्ण है: container के अंदर का root हटाया नहीं गया है, बल्कि उसे **translated** किया गया है। प्रोसेस अभी भी स्थानीय रूप से एक root-सा परिवेश अनुभव करता है, लेकिन host को इसे पूरा root मानकर नहीं चलना चाहिए।

## लैब

एक मैनुअल परीक्षण है:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
यह वर्तमान उपयोगकर्ता को namespace के अंदर root के रूप में दिखाता है, जबकि बाहर host पर वह root नहीं होता। यह user namespaces इतने मूल्यवान क्यों हैं समझने के लिए सबसे सरल और बेहतरीन डेमो में से एक है।

कंटेनरों में, आप दिखाई देने वाले mapping की तुलना कर सकते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
सटीक आउटपुट इस बात पर निर्भर करता है कि engine user namespace remapping का उपयोग कर रहा है या अधिक पारंपरिक rootful configuration।

आप host साइड से mapping भी पढ़ सकते हैं:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## रनटाइम उपयोग

Rootless Podman उन सबसे स्पष्ट उदाहरणों में से एक है जहाँ उपयोगकर्ता नामस्थान (user namespaces) को एक प्रथम-श्रेणी सुरक्षा तंत्र के रूप में माना जाता है। Rootless Docker भी उन पर निर्भर करता है। Docker का userns-remap समर्थन rootful daemon deployments में सुरक्षा सुधारता है, हालांकि ऐतिहासिक रूप से कई deployments को अनुकूलता कारणों से निष्क्रिय रखा गया था। Kubernetes में user namespaces का समर्थन बेहतर हुआ है, लेकिन अपनाने की दर और डिफ़ॉल्ट विकल्प रनटाइम, डिस्ट्रो, और क्लस्टर पॉलिसी के अनुसार भिन्न होते हैं। Incus/LXC सिस्टम भी UID/GID शिफ्टिंग और idmapping विचारों पर काफी निर्भर करते हैं।

## उन्नत मैपिंग विवरण

जब एक अनाधिकारिक (unprivileged) प्रक्रिया `uid_map` या `gid_map` में लिखती है, तो kernel उन नियमों को लागू करता है जो privileged parent namespace writer के लिए लागू नियमों की तुलना में कड़े होते हैं। केवल सीमित मैपिंग की अनुमति होती है, और `gid_map` के लिए writer को आम तौर पर पहले `setgroups(2)` को निष्क्रिय करने की आवश्यकता होती है:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
यह विवरण महत्वपूर्ण है क्योंकि यह समझाता है कि user-namespace सेटअप rootless प्रयोगों में कभी-कभी क्यों असफल होता है और क्यों runtimes को UID/GID delegation के आसपास सावधान सहायक लॉजिक की आवश्यकता होती है।

एक और उन्नत फीचर है **ID-mapped mount**। डिस्क पर मौजूद ownership बदलने के बजाय, एक ID-mapped mount user-namespace mapping को एक mount पर लागू करता है ताकि ownership उस mount के दृश्य से अनुवादित दिखाई दे। यह rootless और आधुनिक runtime सेटअप्स में विशेष रूप से प्रासंगिक है क्योंकि यह shared host paths को recursive `chown` ऑपरेशन्स के बिना उपयोग करने की अनुमति देता है। सुरक्षा के दृष्टि से, यह फीचर यह बदल देता है कि namespace के अंदर से एक bind mount writable कैसे दिखाई देता है, भले ही यह underlying filesystem metadata को री-राइट न करे।

अंत में, ध्यान रखें कि जब कोई process नया user namespace बनाता है या उसमें प्रवेश करता है, तो उसे उस namespace के अंदर एक पूर्ण capability सेट मिल जाता है (**inside that namespace**)। इसका मतलब यह नहीं कि उसने अचानक host-global शक्ति पा ली है। इसका मतलब यह है कि वे capabilities केवल उन जगहों पर उपयोग किए जा सकते हैं जहाँ namespace मॉडल और अन्य सुरक्षा उपाय उन्हें अनुमति देते हैं। इसी कारण `unshare -U` अचानक mounting या namespace-स्थानीय privileged ऑपरेशन्स को संभव बना सकता है बिना सीधे host root सीमा को गायब किए।

## गलत कॉन्फ़िगरेशन

मुख्य कमजोरी सरलतः उन वातावरणों में user namespaces का उपयोग न करना है जहाँ यह संभव होता। अगर container root बहुत सीधे host root से map होता है, तो writable host mounts और privileged kernel operations कहीं अधिक ख़तरनाक हो जाते हैं। एक और समस्या यह है कि compatibility के लिए host user namespace sharing को मजबूर करना या remapping को अक्षम करना बिना यह समझे कि इससे trust boundary कितना बदलता है।

User namespaces को मॉडल के बाकी हिस्सों के साथ मिलकर भी माना जाना चाहिए। भले ही वे सक्रिय हों, एक व्यापक runtime API exposure या बहुत कमजोर runtime configuration फिर भी अन्य रास्तों से privilege escalation की अनुमति दे सकता है। लेकिन उनके बिना, कई पुराने breakout classes का exploit करना काफी आसान हो जाता है।

## दुरुपयोग

यदि container user namespace separation के बिना rootful है, तो एक writable host bind mount काफी अधिक ख़तरनाक हो जाता है क्योंकि process वास्तव में host root के रूप में लिख रहा हो सकता है। Dangerous capabilities भी अधिक मायने रखती हैं। attacker को translation boundary के खिलाफ उतना संघर्ष करने की जरूरत नहीं रहती क्योंकि translation boundary लगभग मौजूद ही नहीं होता।

User namespace की उपस्थिति या अनुपस्थिति को container breakout path का आकलन करते समय जल्दी जाँचना चाहिए। यह हर प्रश्न का उत्तर नहीं देता, लेकिन यह तुरंत दिखा देता है कि क्या "root in container" का सीधे host के साथ संबंध है।

सबसे व्यावहारिक दुरुपयोग पैटर्न यह है कि mapping की पुष्टि करें और फिर तुरंत यह परीक्षण करें कि host-mounted कंटेंट host-relevant privileges के साथ writable है या नहीं:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
यदि फ़ाइल वास्तविक host root के रूप में बनाई गई है, तो उस पथ के लिए user namespace isolation प्रभावी रूप से अनुपस्थित हो जाती है। उस बिंदु पर पारंपरिक host-file दुर्व्यवहार वास्तविक हो जाते हैं:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
लाइव असेसमेंट पर सुरक्षित पुष्टि के लिए महत्वपूर्ण फ़ाइलों में संशोधन करने के बजाय एक हानिरहित चिन्ह लिखें:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
ये जाँचें इसलिए मायने रखती हैं क्योंकि ये असली सवाल का तेज़ जवाब देती हैं: क्या इस container में root host root के साथ इतना नज़दीक से map होता है कि एक writable host mount तुरंत host compromise का मार्ग बन जाता है?

### पूर्ण उदाहरण: Namespace-Local Capabilities की पुनःप्राप्ति

यदि seccomp `unshare` की अनुमति देता है और environment एक नया user namespace बनाने की अनुमति देता है, तो प्रक्रिया उस नए namespace के अंदर एक पूरा capability सेट पुनः प्राप्त कर सकती है:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
यह अपने आप में किसी host escape के बराबर नहीं है। इसका महत्व इसलिए है कि user namespaces privileged namespace-local actions को फिर से सक्षम कर सकते हैं, जो बाद में weak mounts, vulnerable kernels, या badly exposed runtime surfaces के साथ मिलकर समस्या पैदा कर सकते हैं।

## Checks

ये commands इस पेज के सबसे महत्वपूर्ण सवाल का जवाब देने के लिए हैं: इस container के अंदर का root host पर किससे map होता है?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- यदि प्रक्रिया UID 0 है और maps सीधे या बहुत निकट host-root mapping दिखाती हैं, तो container कहीं अधिक खतरनाक होता है।
- यदि root किसी unprivileged host range में map होता है, तो यह एक बहुत सुरक्षित baseline है और आमतौर पर वास्तविक user namespace isolation को दर्शाता है।
- Mapping files, अकेले `id` की तुलना में, अधिक मूल्यवान हैं, क्योंकि `id` केवल namespace-local identity दिखाता है।

यदि workload UID 0 के रूप में चलती है और mapping यह दिखाती है कि यह host root के बहुत निकट अनुरूप है, तो आपको container के शेष privileges की व्याख्या अधिक कड़ाई से करनी चाहिए।
