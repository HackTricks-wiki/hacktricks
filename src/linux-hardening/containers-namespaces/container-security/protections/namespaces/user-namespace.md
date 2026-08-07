# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The user namespace kernel को user और group IDs का अर्थ बदलने की अनुमति देता है, क्योंकि यह namespace के अंदर दिखाई देने वाले IDs को उसके बाहर के अलग-अलग IDs से map करता है। यह आधुनिक container protections में सबसे महत्वपूर्ण protections में से एक है, क्योंकि यह classic containers की सबसे बड़ी ऐतिहासिक समस्या को सीधे संबोधित करता है: **container के अंदर का root, host के root के असहज रूप से बहुत करीब हुआ करता था**।

User namespaces के साथ, कोई process container के अंदर UID 0 के रूप में चल सकता है और फिर भी host पर किसी unprivileged UID range से संबंधित हो सकता है। इसका अर्थ है कि process कई in-container tasks के लिए root की तरह व्यवहार कर सकता है, जबकि host के दृष्टिकोण से वह बहुत कम शक्तिशाली होता है। इससे container security की हर समस्या हल नहीं होती, लेकिन container compromise के परिणामों में महत्वपूर्ण बदलाव आता है।

## Operation

एक user namespace में `/proc/self/uid_map` और `/proc/self/gid_map` जैसी mapping files होती हैं, जो बताती हैं कि namespace IDs parent IDs में कैसे translate होते हैं। यदि namespace के अंदर का root किसी unprivileged host UID से map होता है, तो जिन operations के लिए वास्तविक host root की आवश्यकता होती, उनका प्रभाव समान नहीं रहता। यही कारण है कि user namespaces **rootless containers** के लिए केंद्रीय हैं और पुराने rootful container defaults तथा अधिक आधुनिक least-privilege designs के बीच सबसे बड़े अंतरों में से एक हैं।

बात सूक्ष्म लेकिन अत्यंत महत्वपूर्ण है: container के अंदर का root समाप्त नहीं होता, बल्कि **translate** होता है। Process स्थानीय रूप से root-जैसे environment का अनुभव करता रहता है, लेकिन host को इसे full root की तरह नहीं मानना चाहिए।

## Lab

एक manual test है:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
यह current user को namespace के अंदर root के रूप में दिखाई देता है, जबकि उसके बाहर वह अभी भी host root नहीं होता। यह समझने के लिए सबसे अच्छे सरल demos में से एक है कि user namespaces इतने valuable क्यों हैं।

containers में, आप visible mapping की तुलना इस प्रकार कर सकते हैं:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
सटीक output इस बात पर निर्भर करता है कि engine user namespace remapping का उपयोग कर रहा है या अधिक पारंपरिक rootful configuration का।

आप host side से mapping को इस प्रकार भी पढ़ सकते हैं:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtime का उपयोग

Rootless Podman user namespaces को first-class security mechanism के रूप में उपयोग किए जाने का सबसे स्पष्ट उदाहरण है। Rootless Docker भी इन पर निर्भर करता है। Docker का userns-remap support rootful daemon deployments में भी safety को बेहतर बनाता है, हालांकि ऐतिहासिक रूप से कई deployments ने compatibility कारणों से इसे disabled रखा। Kubernetes में user namespaces के लिए support बेहतर हुआ है, लेकिन adoption और defaults runtime, distro और cluster policy के अनुसार अलग-अलग होते हैं। Incus/LXC systems भी UID/GID shifting और idmapping ideas पर काफी निर्भर करते हैं।

सामान्य trend स्पष्ट है: जो environments user namespaces का गंभीरता से उपयोग करते हैं, वे आमतौर पर इस प्रश्न का बेहतर उत्तर देते हैं कि "container root का वास्तव में क्या अर्थ है?" उन environments की तुलना में जो इनका उपयोग नहीं करते।

## Advanced Mapping का विवरण

जब कोई unprivileged process `uid_map` या `gid_map` में write करता है, तो kernel privileged parent namespace writer की तुलना में अधिक strict rules लागू करता है। केवल limited mappings की अनुमति होती है, और `gid_map` के लिए writer को आमतौर पर पहले `setgroups(2)` को disable करना पड़ता है:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
यह विवरण महत्वपूर्ण है क्योंकि यह समझाता है कि rootless experiments में user-namespace setup कभी-कभी क्यों विफल होता है और UID/GID delegation के आसपास runtimes को सावधानीपूर्वक helper logic की आवश्यकता क्यों होती है।

एक अन्य advanced feature **ID-mapped mount** है। On-disk ownership बदलने के बजाय, ID-mapped mount किसी mount पर user-namespace mapping लागू करता है, ताकि उस mount view के माध्यम से ownership translated दिखाई दे। यह rootless और modern runtime setups में विशेष रूप से प्रासंगिक है क्योंकि इससे recursive `chown` operations के बिना shared host paths का उपयोग किया जा सकता है। Security के दृष्टिकोण से, यह feature बदलता है कि namespace के अंदर से कोई bind mount कितना writable दिखाई देता है, हालांकि यह underlying filesystem metadata को rewrite नहीं करता।

अंत में, याद रखें कि जब कोई process नया user namespace बनाता है या उसमें प्रवेश करता है, तो उसे **उस namespace के अंदर** capabilities का पूरा set मिलता है। इसका अर्थ यह नहीं है कि उसे अचानक host-global power मिल गई। इसका अर्थ है कि इन capabilities का उपयोग केवल वहीं किया जा सकता है जहां namespace model और अन्य protections इसकी अनुमति देते हैं। यही कारण है कि `unshare -U` सीधे host root boundary को समाप्त किए बिना mounting या namespace-local privileged operations को संभव बना सकता है।

## Misconfigurations

मुख्य weakness केवल इतनी है कि उन environments में user namespaces का उपयोग न किया जाए जहां वे feasible हों। यदि container root को host root से बहुत सीधे map किया जाता है, तो writable host mounts और privileged kernel operations कहीं अधिक खतरनाक हो जाते हैं। एक अन्य समस्या compatibility के लिए host user namespace sharing को force करना या remapping को disable करना है, बिना यह समझे कि इससे trust boundary कितना बदल जाता है।

User namespaces को model के बाकी हिस्सों के साथ मिलाकर भी consider करना आवश्यक है। इनके active होने पर भी, broad runtime API exposure या बहुत weak runtime configuration अन्य paths के माध्यम से privilege escalation की अनुमति दे सकती है। लेकिन इनके बिना, कई पुराने breakout classes को exploit करना काफी आसान हो जाता है।

## Abuse

यदि user namespace separation के बिना container rootful है, तो writable host bind mount कहीं अधिक खतरनाक हो जाता है क्योंकि process वास्तव में host root के रूप में write कर सकता है। इसी तरह, dangerous capabilities भी अधिक meaningful हो जाती हैं। Attacker को translation boundary के विरुद्ध उतना संघर्ष नहीं करना पड़ता क्योंकि translation boundary लगभग मौजूद ही नहीं होती।

Container breakout path का evaluation करते समय user namespace की presence या absence को शुरुआती चरण में check किया जाना चाहिए। यह हर प्रश्न का उत्तर नहीं देता, लेकिन तुरंत दिखा देता है कि "root in container" का host पर direct relevance है या नहीं।

सबसे practical abuse pattern है mapping की पुष्टि करना और फिर तुरंत यह test करना कि host-mounted content को host-relevant privileges के साथ writable बनाया जा सकता है या नहीं:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
यदि फ़ाइल वास्तविक host root के रूप में बनाई जाती है, तो उस path के लिए user namespace isolation प्रभावी रूप से अनुपस्थित हो जाता है। उस बिंदु पर classic host-file abuses वास्तविक संभावना बन जाते हैं:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
live assessment पर अधिक सुरक्षित पुष्टि के लिए critical files को modify करने के बजाय एक benign marker लिखें:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
ये checks महत्वपूर्ण हैं क्योंकि ये वास्तविक प्रश्न का तुरंत उत्तर देते हैं: क्या इस container में root, host के root से इतना closely map होता है कि writable host mount तुरंत host compromise का रास्ता बन जाए?

### Full Example: Regaining Namespace-Local Capabilities

यदि seccomp `unshare` की अनुमति देता है और environment एक fresh user namespace की अनुमति देता है, तो process उस नए namespace के अंदर full capability set फिर से प्राप्त कर सकता है:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
यह अपने आप में host escape नहीं है। इसका महत्व इसलिए है क्योंकि user namespaces privileged namespace-local actions को फिर से सक्षम कर सकते हैं, जो बाद में weak mounts, vulnerable kernels या ठीक से exposed न किए गए runtime surfaces के साथ मिल जाते हैं।

## Checks

इन commands का उद्देश्य इस page के सबसे महत्वपूर्ण प्रश्न का उत्तर देना है: इस container के अंदर का root host पर किससे map होता है?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
यहाँ क्या महत्वपूर्ण है:

- यदि process का UID 0 है और maps में host-root का direct या बहुत निकट mapping दिखाई देता है, तो container कहीं अधिक खतरनाक है।
- यदि root किसी unprivileged host range पर map होता है, तो यह अधिक सुरक्षित baseline है और आमतौर पर वास्तविक user namespace isolation को दर्शाता है।
- Mapping files, केवल `id` से अधिक महत्वपूर्ण हैं, क्योंकि `id` केवल namespace-local identity दिखाता है।

यदि workload UID 0 के रूप में चलता है और mapping दिखाती है कि यह host root के निकट correspond करता है, तो आपको container के बाकी privileges की व्याख्या कहीं अधिक सख्ती से करनी चाहिए।

{{#include ../../../../../banners/hacktricks-training.md}}
