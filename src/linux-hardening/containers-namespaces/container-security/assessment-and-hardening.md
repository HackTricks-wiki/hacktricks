# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

İyi bir container assessment iki paralel soruyu yanıtlamalıdır. İlk olarak, bir attacker mevcut workload üzerinden ne yapabilir? İkinci olarak, bunu mümkün kılan operator seçimleri hangileridir? Enumeration araçları ilk soruya, hardening guidance ise ikinci soruya yardımcı olur. İkisini aynı sayfada tutmak, bu bölümü yalnızca escape teknikleri kataloğu olmaktan çıkarıp sahada kullanılabilecek bir referans hâline getirir.

Modern ortamlar için pratik bir güncelleme şudur: Eski container writeup'larının çoğu sessizce **rootful runtime**, **user namespace isolation olmaması** ve genellikle **cgroup v1** varsayımına dayanır. Bu varsayımlar artık güvenli değildir. Eski escape primitive'lerine zaman ayırmadan önce workload'un rootless veya userns-remapped olup olmadığını, host'un cgroup v2 kullanıp kullanmadığını ve Kubernetes ya da runtime'ın varsayılan seccomp ve AppArmor profillerini uygulayıp uygulamadığını doğrulayın. Bu ayrıntılar, ünlü bir breakout yönteminin hâlâ geçerli olup olmadığını çoğu zaman belirler.

## Enumeration Tools

Birçok tool, container ortamını hızlıca karakterize etmek için hâlâ kullanışlıdır:

- `linpeas`, birçok container göstergesini, mount edilmiş socket'leri, capability set'lerini, tehlikeli filesystem'leri ve breakout ipuçlarını tespit edebilir.
- `CDK`, özellikle container ortamlarına odaklanır ve enumeration ile bazı otomatik escape kontrollerini içerir.
- `amicontained`, container kısıtlamalarını, capability'leri, namespace exposure'ını ve olası breakout sınıflarını belirlemek için hafif ve kullanışlıdır.
- `deepce`, breakout odaklı kontroller içeren başka bir container odaklı enumerator'dır.
- `grype`, assessment yalnızca runtime escape analysis yerine image-package vulnerability review'ı da içerdiğinde kullanışlıdır.
- `Tracee`, özellikle şüpheli process execution, file access ve container-aware event collection için yalnızca static posture yerine **runtime evidence** gerektiğinde kullanışlıdır.
- `Inspektor Gadget`, pod'lara, container'lara, namespace'lere ve diğer üst düzey kavramlara bağlanan eBPF destekli görünürlüğe ihtiyaç duyduğunuz Kubernetes ve Linux-host investigations sırasında kullanışlıdır.

Bu tool'ların değeri kesinlikten ziyade hız ve kapsamdır. Genel posture'u hızlıca ortaya çıkarmaya yardımcı olurlar; ancak ilgi çekici bulguların gerçek runtime, namespace, capability ve mount modeli doğrultusunda manuel olarak yorumlanması gerekir.

## Hardening Priorities

En önemli hardening ilkeleri, platforma göre uygulama şekilleri değişse de kavramsal olarak basittir. Privileged container'lar kullanmaktan kaçının. Mount edilmiş runtime socket'lerinden kaçının. Çok özel bir neden olmadıkça container'lara writable host path'leri vermeyin. Mümkün olduğunda user namespace'leri veya rootless execution kullanın. Tüm capability'leri drop edin ve yalnızca workload'un gerçekten ihtiyaç duyduğu capability'leri geri ekleyin. Application compatibility sorunlarını çözmek için seccomp, AppArmor ve SELinux'u devre dışı bırakmak yerine etkin tutun. Compromised bir container'ın host üzerinde kolayca denial of service gerçekleştirememesi için kaynakları sınırlayın.

Image ve build hygiene, runtime posture kadar önemlidir. Minimal image'lar kullanın, bunları sık sık yeniden build edin, scan edin, pratik olduğu durumlarda provenance gerektirin ve secret'ları layer'ların dışında tutun. Non-root olarak çalışan, küçük bir image'a ve dar bir syscall ile capability surface'ına sahip bir container'ı savunmak; debugging tool'ları önceden yüklenmiş, host-equivalent root olarak çalışan büyük bir convenience image'ı savunmaktan çok daha kolaydır.

Kubernetes için mevcut hardening baseline'ları, birçok operator'ün hâlâ varsaydığından daha belirgin kurallara sahiptir. Yerleşik **Pod Security Standards**, `restricted` profilini "current best practice" profili olarak kabul eder: `allowPrivilegeEscalation` değeri `false` olmalıdır, workload'lar non-root olarak çalışmalıdır, seccomp açıkça `RuntimeDefault` veya `Localhost` olarak ayarlanmalıdır ve capability set'leri agresif biçimde drop edilmelidir. Assessment sırasında bu önemlidir; çünkü yalnızca `warn` veya `audit` label'larını kullanan bir cluster, pratikte riskli pod'ları kabul etmeye devam ederken kâğıt üzerinde hardened görünebilir.<sup>[[1]](#references)</sup>

## Modern Triage Questions

Escape-specific sayfalara geçmeden önce şu hızlı soruları yanıtlayın:

1. Workload **rootful**, **rootless** veya **userns-remapped** mi?
2. Node **cgroup v1** mi yoksa **cgroup v2** mi kullanıyor?
3. **seccomp** ve **AppArmor/SELinux** açıkça yapılandırılmış mı, yoksa yalnızca mevcut olduğunda mı inherit ediliyor?
4. Kubernetes'te namespace gerçekten `baseline` veya `restricted` uyguluyor mu, yoksa yalnızca warning/auditing mi yapıyor?

Useful checks:
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
Burada ilginç olanlar:

- `/proc/self/uid_map`, container root'un **yüksek bir host UID aralığına** eşlendiğini gösteriyorsa, daha eski host-root writeup'larının çoğu daha az ilgili hâle gelir; çünkü container içindeki root artık host-root eşdeğeri değildir.
- `/sys/fs/cgroup` değeri `cgroup2fs` ise, `release_agent` abuse gibi eski **cgroup v1** odaklı writeup'lar artık ilk tahmininiz olmamalıdır.
- seccomp ve AppArmor yalnızca örtük olarak miras alınıyorsa taşınabilirlik, defender'ların beklediğinden daha zayıf olabilir. Kubernetes'te açıkça `RuntimeDefault` ayarlamak, node varsayımlarına sessizce güvenmekten genellikle daha güçlüdür.
- `supplementalGroupsPolicy` `Strict` olarak ayarlanmışsa pod, image içindeki `/etc/group` dosyasından ek grup üyeliklerini sessizce miras almamalıdır. Bu, grup tabanlı volume ve dosya erişimi davranışını daha öngörülebilir hâle getirir.
- `pod-security.kubernetes.io/enforce=restricted` gibi namespace label'larını doğrudan kontrol etmeye değer. `warn` ve `audit` kullanışlıdır, ancak riskli bir pod'un oluşturulmasını engellemez.

## Runtime Baseline Triage

Runtime baseline, bir container'ın sıradan ve izole bir workload gibi mi, yoksa host'u etkileyebilecek bir control plane foothold'u gibi mi göründüğünü hızlıca belirleyen kontroldür. Bir sonraki okunacak sayfaya öncelik verebilmek için yeterli bilgiyi toplamalıdır: runtime socket abuse, host mount'ları, namespace'ler, cgroup'lar, capabilities veya image-secret incelemesi.

Bir workload içinden yapılabilecek kullanışlı kontroller:
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

- Eksik veya sınırsız `memory.max` / `pids.max`, temiz bir escape olmasa bile zayıf blast-radius kontrollerine işaret eder.
- `NoNewPrivs: 0` değerine sahip, geniş yetenekli ve izin verici seccomp kullanan bir root shell, dar kapsamlı bir non-root workload'dan çok daha ilgi çekicidir.
- Runtime socket'leri ve yazılabilir host mount'ları, zaten bir yönetim veya dosya sistemi kontrol yolu açığa çıkardıkları için genellikle kernel exploit'lerinden daha önceliklidir.
- Paylaşılan PID, network, IPC veya cgroup namespace'leri tek başlarına her zaman tam escape sağlamaz; ancak sonraki adımı bulmayı kolaylaştırırlar.

## Kaynak Tüketimi Örnekleri

Kaynak kontrolleri gösterişli değildir; ancak compromise'ın blast radius'unu sınırladıkları için container security'nin bir parçasıdır. Memory, CPU veya PID limitleri olmadığında basit bir shell, host'u veya komşu workload'ları degrade etmek için yeterli olabilir.

Host'u etkileyen test örnekleri:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Bu örnekler kullanışlıdır; çünkü her tehlikeli container sonucunun temiz bir "escape" olmadığını gösterir. Zayıf cgroup limitleri, code execution'ı yine de gerçek bir operasyonel etkiye dönüştürebilir.

Kubernetes-backed ortamlarda, DoS'u teorik olarak değerlendirmeden önce resource controls'ün mevcut olup olmadığını da kontrol edin:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Araçları

Docker odaklı ortamlar için `docker-bench-security`, yaygın olarak kabul gören benchmark yönergelerine göre genel yapılandırma sorunlarını denetlediği için host tarafında kullanışlı bir audit temel ölçütü olmaya devam eder:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Araç, threat modeling'in yerini tutmaz; ancak zaman içinde biriken dikkatsiz daemon, mount, network ve runtime varsayılanlarını bulmak için yine de değerlidir.

Kubernetes ve runtime ağırlıklı ortamlarda statik kontrolleri runtime görünürlüğüyle birlikte kullanın:

- `Tracee`, container-aware runtime detection ve ele geçirilmiş bir workload'un gerçekte neleri etkilediğini doğrulamanız gerektiğinde hızlı forensics için kullanışlıdır.
- `Inspektor Gadget`, assessment sırasında kernel-level telemetry'nin pod'lara, container'lara, DNS activity'ye, file execution'a veya network behavior'a eşlenmesi gerektiğinde kullanışlıdır.

## Kontroller

Assessment sırasında hızlı bir ilk geçiş için bunları kullanın:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Burada ilginç olanlar:

- Geniş yetkilere sahip ve `Seccomp: 0` değerini taşıyan bir root process'i derhâl incelenmelidir.
- Aynı zamanda **1:1 UID map** kullanan bir root process'i, düzgün şekilde izole edilmiş bir user namespace içindeki "root" process'inden çok daha ilgi çekicidir.
- `cgroup2fs` genellikle eski **cgroup v1** escape chain'lerinin en iyi başlangıç noktası olmadığı anlamına gelir; ancak `memory.max` veya `pids.max` değerlerinin eksik olması, blast radius kontrollerinin hâlâ zayıf olduğuna işaret eder.
- Şüpheli mount'lar ve runtime socket'leri, herhangi bir kernel exploit'inden daha hızlı bir impact yolu sağlayabilir.
- Zayıf runtime posture ile zayıf resource limit'lerinin birleşimi, genellikle tekil ve izole bir hatadan ziyade genel olarak permissive bir container environment bulunduğunu gösterir.

## References

- [1] [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)

{{#include ../../../banners/hacktricks-training.md}}
