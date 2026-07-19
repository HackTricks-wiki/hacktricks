# Değerlendirme ve Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

İyi bir container assessment iki paralel soruyu yanıtlamalıdır. İlk olarak, bir attacker mevcut workload üzerinden ne yapabilir? İkinci olarak, bunu mümkün kılan operator tercihleri hangileridir? Enumeration tools ilk soruya, hardening guidance ise ikinci soruya yardımcı olur. Her ikisini aynı sayfada tutmak, bu bölümü yalnızca escape tekniklerinden oluşan bir katalog yerine sahada kullanılabilecek bir referans hâline getirir.

Modern ortamlar için pratik bir güncelleme, birçok eski container writeup'ının sessizce **rootful runtime**, **user namespace isolation olmaması** ve çoğu zaman **cgroup v1** varsaymasıdır. Bu varsayımlar artık güvenli değildir. Eski escape primitive'lerine zaman ayırmadan önce workload'un rootless veya userns-remapped olup olmadığını, host'un cgroup v2 kullanıp kullanmadığını ve Kubernetes veya runtime'ın varsayılan seccomp ve AppArmor profillerini uygulayıp uygulamadığını doğrulayın. Bu ayrıntılar çoğu zaman ünlü bir breakout tekniğinin hâlâ geçerli olup olmadığını belirler.

## Enumeration Tools

Bir dizi tool, bir container ortamının özelliklerini hızlıca belirlemek için hâlâ kullanışlıdır:

- `linpeas` birçok container göstergesini, mounted socket'leri, capability set'lerini, tehlikeli filesystem'leri ve breakout ipuçlarını tespit edebilir.
- `CDK` özellikle container ortamlarına odaklanır ve enumeration ile bazı otomatik escape kontrollerini içerir.
- `amicontained` hafiftir; container kısıtlamalarını, capability'leri, namespace exposure'ını ve olası breakout sınıflarını belirlemek için kullanışlıdır.
- `deepce`, breakout odaklı kontroller içeren başka bir container-focused enumerator'dır.
- `grype`, assessment yalnızca runtime escape analysis yerine image-package vulnerability review içerdiğinde kullanışlıdır.
- `Tracee`, özellikle şüpheli process execution, file access ve container-aware event collection için, yalnızca statik posture yerine **runtime evidence** gerektiğinde kullanışlıdır.
- `Inspektor Gadget`, pod'lara, container'lara, namespace'lere ve diğer üst düzey kavramlara bağlanan eBPF destekli visibility gerektiğinde Kubernetes ve Linux-host investigations için kullanışlıdır.

Bu tool'ların değeri kesinlikten çok hız ve kapsamdır. Genel posture'u hızlıca ortaya çıkarmaya yardımcı olurlar; ancak ilgi çekici bulguların gerçek runtime, namespace, capability ve mount modeliyle karşılaştırılarak manuel şekilde yorumlanması gerekir.

## Hardening Öncelikleri

En önemli hardening ilkeleri, uygulamaları platforma göre değişse de kavramsal olarak basittir. Privileged container'lardan kaçının. Mounted runtime socket'lerinden kaçının. Çok özel bir neden olmadıkça container'lara writable host path'leri vermeyin. Uygun olduğu durumlarda user namespace'leri veya rootless execution kullanın. Tüm capability'leri drop edin ve yalnızca workload'un gerçekten ihtiyaç duyduğu capability'leri geri ekleyin. Application compatibility sorunlarını çözmek için seccomp, AppArmor ve SELinux'u devre dışı bırakmak yerine etkin tutun. Compromised bir container'ın host üzerinde kolayca denial of service oluşturamaması için resource'ları sınırlandırın.

Image ve build hygiene, runtime posture kadar önemlidir. Minimal image'lar kullanın, sık sık rebuild edin, image'ları scan edin, uygulanabilir olduğunda provenance zorunlu tutun ve secret'ları layer'ların dışında tutun. Non-root olarak çalışan, küçük bir image kullanan ve dar bir syscall ve capability surface'e sahip bir container'ı savunmak; host-equivalent root olarak çalışan ve debugging tool'ları önceden kurulmuş büyük bir convenience image'ı savunmaktan çok daha kolaydır.

Kubernetes için mevcut hardening baseline'ları, birçok operator'ün hâlâ varsaydığından daha opinionated'dır. Yerleşik **Pod Security Standards**, `restricted` profilini "güncel en iyi uygulama" profili olarak ele alır: `allowPrivilegeEscalation` değeri `false` olmalı, workload'lar non-root olarak çalışmalı, seccomp açıkça `RuntimeDefault` veya `Localhost` olarak ayarlanmalı ve capability set'leri agresif biçimde drop edilmelidir. Assessment sırasında bu önemlidir; çünkü yalnızca `warn` veya `audit` label'larını kullanan bir cluster, pratikte riskli pod'ları kabul etmeye devam ederken kâğıt üzerinde hardened görünebilir.

## Modern Triage Soruları

Escape odaklı sayfalara geçmeden önce şu hızlı soruları yanıtlayın:

1. Workload **rootful**, **rootless** veya **userns-remapped** mi?
2. Node **cgroup v1** mi yoksa **cgroup v2** mi kullanıyor?
3. **seccomp** ve **AppArmor/SELinux** açıkça yapılandırılmış mı, yoksa yalnızca mevcut olduğunda mı inherit ediliyor?
4. Kubernetes'te namespace gerçekten `baseline` veya `restricted` uyguluyor mu, yoksa yalnızca warning/audit mi yapıyor?

Yararlı kontroller:
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
Burada ilginç olan nedir:

- `/proc/self/uid_map`, container root'un **yüksek bir host UID aralığına** eşlendiğini gösteriyorsa, eski host-root writeup'larının çoğu artık daha az ilgili olabilir; çünkü container içindeki root artık host-root eşdeğeri değildir.
- `/sys/fs/cgroup` `cgroup2fs` ise, `release_agent` abuse gibi eski **cgroup v1**-özel writeup'lar artık ilk tahmininiz olmamalıdır.
- seccomp ve AppArmor yalnızca örtük olarak devralınıyorsa, portability defender'ların beklediğinden daha zayıf olabilir. Kubernetes'te açıkça `RuntimeDefault` ayarlamak, node varsayılanlarına sessizce güvenmekten genellikle daha güçlüdür.
- `supplementalGroupsPolicy` `Strict` olarak ayarlanmışsa pod, image içindeki `/etc/group` dosyasından ek group üyeliklerini sessizce devralmamalıdır. Bu, group tabanlı volume ve file erişimi davranışını daha öngörülebilir hâle getirir.
- `pod-security.kubernetes.io/enforce=restricted` gibi namespace label'larını doğrudan kontrol etmek faydalıdır. `warn` ve `audit` kullanışlıdır; ancak riskli bir pod'un oluşturulmasını engellemezler.

## Runtime Baseline Triage

Bir runtime baseline, bir container'ın sıradan ve izole bir workload'a mı, yoksa host'u etkileyebilecek bir control plane foothold'una mı benzediğini hızlıca gösteren kontroldür. Bir sonraki okunacak sayfaya öncelik vermek için yeterli gerçekleri toplamalıdır: runtime socket abuse, host mount'ları, namespace'ler, cgroup'lar, capability'ler veya image-secret incelemesi.

Bir workload içinden yapılabilecek useful kontroller:
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Yorum:

- `memory.max` / `pids.max` değerlerinin eksik veya sınırsız olması, başarılı bir escape olmasa bile blast radius kontrollerinin zayıf olduğunu gösterir.
- `NoNewPrivs: 0`, geniş capabilities ve permissive seccomp ile çalışan bir root shell, dar kapsamlı bir non-root workload'dan çok daha ilgi çekicidir.
- Runtime sockets ve writable host mounts, zaten bir management veya filesystem control path açığa çıkardıkları için genellikle kernel exploits'lerden daha önceliklidir.
- Paylaşılan PID, network, IPC veya cgroup namespaces her zaman tek başlarına full escape sağlamaz; ancak sonraki adımı bulmayı kolaylaştırırlar.

## Resource-Exhaustion Examples

Resource kontrolleri gösterişli değildir; ancak compromise'ın blast radius'unu sınırladıkları için container security'nin bir parçasıdır. Memory, CPU veya PID limitleri olmadan basit bir shell bile host'u ya da komşu workload'ları olumsuz etkileyebilir.

Host'u etkileyen test örnekleri:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Bu örnekler, her tehlikeli container sonucunun temiz bir "escape" olmadığını göstermeleri açısından faydalıdır. Zayıf cgroup limitleri, code execution'ı yine de gerçek bir operasyonel etkiye dönüştürebilir.

Kubernetes destekli ortamlarda, DoS'u teorik olarak değerlendirmeden önce resource kontrollerinin gerçekten mevcut olup olmadığını da kontrol edin:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Araçları

Docker merkezli ortamlar için `docker-bench-security`, yaygın olarak kabul gören benchmark yönergelerine göre yaygın yapılandırma sorunlarını kontrol ettiğinden, host tarafında denetim için hâlâ yararlı bir temel niteliğindedir:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Bu araç threat modeling'in yerini tutmaz; ancak zaman içinde biriken dikkatsiz daemon, mount, network ve runtime varsayılanlarını bulmak için yine de değerlidir.

Kubernetes ve runtime ağırlıklı ortamlarda statik kontrolleri runtime görünürlüğüyle birlikte kullanın:

- `Tracee`, container-aware runtime detection ve güvenliği ihlal edilmiş bir workload'un gerçekte nelerle etkileşime girdiğini doğrulamanız gerektiğinde hızlı forensics için kullanışlıdır.
- `Inspektor Gadget`, assessment kapsamında kernel-level telemetry'nin pod'lara, container'lara, DNS etkinliğine, file execution'a veya network davranışına eşlenmesi gerektiğinde kullanışlıdır.

## Kontroller

Assessment sırasında bunları hızlı ilk geçiş komutları olarak kullanın:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Burada ilgi çekici olanlar:

- Geniş yetkilere sahip bir root process ve `Seccomp: 0` hemen incelenmelidir.
- Ayrıca **1:1 UID map** kullanan bir root process, uygun şekilde izole edilmiş bir user namespace içindeki "root" process'ten çok daha ilgi çekicidir.
- `cgroup2fs` genellikle eski **cgroup v1** escape chain'lerinin başlangıç noktası olarak en iyi seçenek olmadığı anlamına gelir; ancak `memory.max` veya `pids.max` değerlerinin eksik olması, zayıf blast-radius kontrollerine işaret eder.
- Şüpheli mount'lar ve runtime socket'leri, herhangi bir kernel exploit'inden genellikle daha hızlı bir impact yolu sağlar.
- Zayıf runtime posture ile zayıf resource limit'lerinin birleşimi, genellikle tek bir izole hatadan ziyade genel olarak permissive bir container environment olduğunu gösterir.

## Referanslar

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: runc, BuildKit ve Moby'de Birden Fazla Vulnerability](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
