# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## अवलोकन

user namespace user और group IDs के अर्थ को बदल देता है, क्योंकि kernel namespace के अंदर दिखाई देने वाले IDs को बाहर के अलग IDs से map करने देता है। यह modern container सुरक्षा उपायों में से एक सबसे महत्वपूर्ण है क्योंकि यह classic containers की सबसे बड़ी ऐतिहासिक समस्या को सीधे संबोधित करता है: **container के अंदर root host पर root के बहुत करीब माना जाता था**।

user namespaces के साथ, एक process container के अंदर UID 0 के रूप में चल सकता है और फिर भी host पर एक unprivileged UID range से मेल खा सकता है। इसका मतलब है कि process कई in-container tasks के लिए root जैसा व्यवहार कर सकता है जबकि host के नजरिए से इसकी शक्तियाँ काफी कम होंगी। यह हर container security समस्या का समाधान नहीं करता, लेकिन यह container compromise के परिणामों को काफी हद तक बदल देता है।

## संचालन

एक user namespace में mapping फ़ाइलें होती हैं जैसे `/proc/self/uid_map` और `/proc/self/gid_map` जो बताती हैं कि namespace IDs parent IDs में कैसे translate होते हैं। यदि namespace के अंदर का root किसी unprivileged host UID से map होता है, तो वे operations जो असल host root की आवश्यकता रखते थे, उनका असर अब वैसा नहीं रहेगा। यही कारण है कि user namespaces **rootless containers** के लिए केंद्रीय हैं और यही पुराने rootful container defaults और आधुनिक least-privilege designs के बीच एक बड़ा अंतर है।

बात सूक्ष्म लेकिन महत्वपूर्ण है: container के अंदर का root हटाया नहीं गया है, उसे **अनुवादित** किया गया है। process अभी भी स्थानीय स्तर पर root-जैसा वातावरण अनुभव करता है, लेकिन host को इसे पूर्ण root के रूप में नहीं मानना चाहिए।

## Lab

एक मैनुअल परीक्षण है:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
यह वर्तमान उपयोगकर्ता को namespace के अंदर root के रूप में दिखाता है जबकि इसके बाहर host पर वह root नहीं होता। यह समझने के लिए सबसे अच्छे सरल डेमो में से एक है कि user namespaces इतने मूल्यवान क्यों हैं।

Containers में, आप दिखाई देने वाले mapping की तुलना निम्न के साथ कर सकते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
सटीक आउटपुट इस बात पर निर्भर करेगा कि क्या engine user namespace remapping का उपयोग कर रहा है या एक अधिक पारंपरिक rootful configuration।

आप host साइड से mapping भी पढ़ सकते हैं:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtime Usage

Rootless Podman user namespaces को एक प्रथम-श्रेणी सुरक्षा तंत्र के रूप में माना जाने के सबसे स्पष्ट उदाहरणों में से एक है। Rootless Docker भी इन पर निर्भर करता है। Docker का userns-remap सपोर्ट rootful daemon deployments में भी सुरक्षा बढ़ाता है, हालांकि ऐतिहासिक रूप से कई deployments ने compatibility कारणों से इसे disabled रखा हुआ था। Kubernetes का user namespaces के लिए समर्थन सुधरा है, लेकिन adoption और defaults runtime, distro, और cluster policy के अनुसार बदलते हैं। Incus/LXC सिस्टम भी UID/GID shifting और idmapping विचारों पर काफी हद तक निर्भर करते हैं।

## Advanced Mapping Details

जब कोई बिना-प्रिविलेज वाली प्रक्रिया `uid_map` या `gid_map` में लिखती है, kernel उन नियमों को लागू करता है जो privileged parent namespace writer के लिए लागू होने वाले नियमों से कड़े होते हैं। केवल सीमित mappings की अनुमति होती है, और `gid_map` के लिए writer को आमतौर पर पहले `setgroups(2)` को disable करना पड़ता है:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
यह विवरण इसलिए महत्वपूर्ण है क्योंकि यह समझाता है कि user-namespace सेटअप rootless प्रयोगों में कभी-कभी क्यों विफल होता है और क्यों runtimes को UID/GID delegation के आसपास सावधानीपूर्वक helper logic की आवश्यकता होती है।

एक और उन्नत फीचर **ID-mapped mount** है। डिस्क पर ownership बदलने के बजाय, एक ID-mapped mount उस mount पर user-namespace mapping लागू करता है ताकि ownership उस mount view के माध्यम से अनुवादित दिखाई दे। यह खासकर rootless और आधुनिक runtime सेटअप्स में प्रासंगिक है क्योंकि यह साझा host paths को recursive `chown` ऑपरेशनों के बिना उपयोग करने की अनुमति देता है। सुरक्षा की दृष्टि से, यह फीचर यह बदल देता है कि namespace के अंदर एक bind mount कितनी writable दिखाई देती है, भले ही यह underlying filesystem metadata को फिर से नहीं लिखता।

अंत में, याद रखें कि जब कोई process नया user namespace बनाता है या उसमें प्रवेश करता है, तो उसे उस namespace के अंदर पूरी capability सेट मिलती है (**inside that namespace**). इसका मतलब यह नहीं कि उसने अचानक host-global शक्ति प्राप्त कर ली है। इसका मतलब यह है कि उन capabilities का उपयोग केवल उन्हीं क्षेत्रों में किया जा सकता है जहाँ namespace मॉडल और अन्य सुरक्षा उपाय उन्हें अनुमति देते हैं। यही कारण है कि `unshare -U` अचानक mounting या namespace-लोकल privileged ऑपरेशनों को संभव बना सकता है, बिना सीधे host root boundary को गायब किए।

## Misconfigurations

मुख्य कमजोरी बस यह है कि उन environments में user namespaces का उपयोग नहीं किया जाता जहाँ वे संभव होते। अगर container root बहुत सीधे host root के साथ map होता है, तो writable host mounts और privileged kernel ऑपरेशन्स बहुत अधिक खतरनाक हो जाते हैं। एक और समस्या यह है कि compatibility के लिए host user namespace sharing को मजबूर करना या remapping को disable करना, इस बात को पहचानने के बिना कि यह trust boundary को कितना बदल देता है।

user namespaces को मॉडल के बाकी हिस्सों के साथ मिलाकर भी विचार करना चाहिए। सक्रिय होने पर भी, एक व्यापक runtime API exposure या बहुत कमजोर runtime configuration अन्य रास्तों से privilege escalation की अनुमति दे सकता है। लेकिन उनके बिना, कई पुराने breakout वर्गों का exploit करना बहुत आसान हो जाता है।

## Abuse

यदि container user namespace separation के बिना rootful है, तो एक writable host bind mount बहुत अधिक खतरनाक हो जाता है क्योंकि process वास्तव में host root के रूप में लिख रहा हो सकता है। खतरनाक capabilities भी उसी तरह अधिक मायने रखने लगती हैं। attacker को translation boundary के खिलाफ उतनी मेहनत करने की आवश्यकता नहीं रहती क्योंकि translation boundary लगभग मौजूद ही नहीं रहती।

container breakout path का मूल्यांकन करते समय user namespace की उपस्थिति या अनुपस्थिति को जल्दी जांचना चाहिए। यह हर सवाल का जवाब नहीं देता, लेकिन यह तुरंत दिखाता है कि "root in container" का host पर सीधा प्रभाव है या नहीं।

सबसे व्यावहारिक abuse पैटर्न है mapping की पुष्टि करना और फिर तुरंत यह परीक्षण करना कि host-mounted content host-relevant privileges के साथ writable है या नहीं:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
यदि फ़ाइल असली host root के रूप में बनाई जाती है, तो उस path के लिए user namespace isolation प्रभावी रूप से अनुपस्थित होता है। उस समय, classic host-file abuses वास्तविक हो जाते हैं:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Live assessment पर एक अधिक सुरक्षित पुष्टि यह है कि महत्वपूर्ण फ़ाइलों को संशोधित करने के बजाय एक हानिरहित मार्कर लिखें:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
ये चेक इसलिए मायने रखते हैं क्योंकि वे असली सवाल का तेज़ी से जवाब देते हैं: क्या इस container में root host के root के साथ इतना नज़दीकी से map होता है कि एक writable host mount तुरंत host compromise path बन जाता है?

### पूर्ण उदाहरण: Namespace-Local Capabilities पुनः प्राप्त करना

यदि seccomp `unshare` की अनुमति देता है और environment एक नया user namespace बनाने की अनुमति देता है, तो process उस नए namespace के अंदर पूरा capability set पुनः प्राप्त कर सकता है:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
यह अपने आप में host escape नहीं है। इसका महत्व इसलिए है कि user namespaces privileged namespace-local actions को फिर से सक्षम कर सकते हैं, जो बाद में weak mounts, vulnerable kernels, या badly exposed runtime surfaces के साथ मिलकर समस्याएँ पैदा कर सकती हैं।

## जांच

ये commands इस पृष्ठ का सबसे महत्वपूर्ण प्रश्न का उत्तर देने के लिए हैं: इस container के अंदर root होस्ट पर किसके रूप में map होता है?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- यदि प्रक्रिया UID 0 है और maps दर्शाते हैं कि host-root का mapping सीधा या बहुत निकट है, तो container बहुत अधिक खतरनाक होता है।
- यदि root किसी unprivileged host range से map होता है, तो वह एक बहुत सुरक्षित baseline है और आमतौर पर वास्तविक user namespace isolation को इंगित करता है।
- mapping files `id` अकेले से अधिक मूल्यवान हैं, क्योंकि `id` केवल namespace-local identity दिखाता है।

यदि workload UID 0 के रूप में चलता है और mapping दिखाती है कि यह host root के काफी निकट है, तो आपको container के बाकी privileges को कहीं अधिक सख्ती से व्याख्या करना चाहिए।
{{#include ../../../../../banners/hacktricks-training.md}}
