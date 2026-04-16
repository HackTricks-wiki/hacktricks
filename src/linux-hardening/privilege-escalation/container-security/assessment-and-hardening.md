# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

İyi bir container assessment, iki paralel soruya cevap vermelidir. Birincisi, mevcut workload'dan bir attacker ne yapabilir? İkincisi, bunu mümkün kılan hangi operator seçimleri yapıldı? Enumeration araçları ilk soruya, hardening guidance ise ikinci soruya yardımcı olur. İkisini aynı sayfada tutmak, bölümü sadece escape trick'lerin bir kataloğu olmaktan çıkarıp daha kullanışlı bir saha referansı haline getirir.

Modern ortamlar için pratik bir güncelleme, birçok eski container writeup'ın sessizce **rootful runtime**, **no user namespace isolation** ve çoğu zaman **cgroup v1** varsaymasıdır. Bu varsayımlar artık güvenli değil. Eski escape primitive'lerine zaman harcamadan önce, workload'un rootless mı yoksa userns-remapped mi olduğunu, host'un cgroup v2 kullanıp kullanmadığını ve Kubernetes ya da runtime'ın artık default seccomp ve AppArmor profilleri uygulayıp uygulamadığını doğrulayın. Bu ayrıntılar çoğu zaman ünlü bir breakout'un hâlâ geçerli olup olmadığını belirler.

## Enumeration Tools

Aşağıdaki araçlar, bir container environment'ını hızlıca karakterize etmek için hâlâ kullanışlıdır:

- `linpeas` birçok container göstergesini, mount edilmiş socket'leri, capability set'lerini, tehlikeli filesystem'leri ve breakout ipuçlarını tespit edebilir.
- `CDK` özellikle container environment'larına odaklanır ve enumeration ile birlikte bazı otomatik escape kontrolleri içerir.
- `amicontained` hafiftir ve container kısıtlamalarını, capability'leri, namespace exposure'ını ve olası breakout class'larını belirlemek için kullanışlıdır.
- `deepce` breakout odaklı kontroller içeren başka bir container merkezli enumerator'dür.
- `grype`, assessment image-package vulnerability review içeriyorsa, yalnızca runtime escape analysis yerine kullanışlıdır.
- `Tracee`, özellikle şüpheli process execution, file access ve container-aware event collection için yalnızca statik duruş yerine **runtime evidence** gerektiğinde kullanışlıdır.
- `Inspektor Gadget`, bulguları pod'lara, container'lara, namespace'lere ve diğer daha üst seviye kavramlara bağlamanız gereken Kubernetes ve Linux-host incelemelerinde eBPF destekli görünürlük sağlamak için kullanışlıdır.

Bu araçların değeri hız ve kapsama alanıdır, kesinlik değil. Rough posture'ı hızlıca ortaya çıkarmaya yardımcı olurlar, ancak ilginç bulguların yine de gerçek runtime, namespace, capability ve mount modeline karşı manuel olarak yorumlanması gerekir.

## Hardening Priorities

En önemli hardening prensipleri, uygulamaları platforma göre değişse de kavramsal olarak basittir. Privileged container'lardan kaçının. Mounted runtime socket'lerinden kaçının. Çok özel bir gerekçe yoksa container'lara yazılabilir host path'leri vermeyin. Mümkün olduğunda user namespace veya rootless execution kullanın. Tüm capability'leri düşürün ve yalnızca workload'un gerçekten ihtiyaç duyduklarını geri ekleyin. Uygulama uyumluluk sorunlarını çözmek için seccomp, AppArmor ve SELinux'u devre dışı bırakmak yerine etkin tutun. Ele geçirilmiş bir container'ın host'a kolayca denial of service uygulayamaması için kaynakları sınırlayın.

Image ve build hygiene, runtime posture kadar önemlidir. Minimal image'lar kullanın, sık rebuild edin, scan edin, mümkün olduğunda provenance zorunlu kılın ve secrets'ı layer'ların dışında tutun. Non-root olarak çalışan, küçük image'a ve dar bir syscall ile capability yüzeyine sahip bir container'ı savunmak, debugging araçları önceden kurulu, host'a eşdeğer root ile çalışan büyük bir convenience image'dan çok daha kolaydır.

Kubernetes için güncel hardening baseline'ları, birçok operator'ün hâlâ varsaydığından daha opinionated'dir. Yerleşik **Pod Security Standards**, `restricted` profilini "current best practice" olarak ele alır: `allowPrivilegeEscalation` `false` olmalıdır, workload'lar non-root olarak çalışmalıdır, seccomp açıkça `RuntimeDefault` veya `Localhost` olarak ayarlanmalıdır ve capability set'leri agresif biçimde düşürülmelidir. Assessment sırasında bunun önemi şudur: yalnızca `warn` veya `audit` etiketleri kullanan bir cluster kağıt üzerinde hardened görünebilir, ancak pratikte yine de riskli pod'ları kabul ediyor olabilir.

## Modern Triage Questions

Escape-spesifik sayfalara dalmadan önce şu hızlı soruları yanıtlayın:

1. Workload **rootful**, **rootless** veya **userns-remapped** mi?
2. Node **cgroup v1** mi yoksa **cgroup v2** mi kullanıyor?
3. **seccomp** ve **AppArmor/SELinux** açıkça yapılandırılmış mı, yoksa yalnızca mevcut olduklarında devralınıyor mu?
4. Kubernetes'te namespace gerçekten `baseline` veya `restricted` uyguluyor mu, yoksa sadece warning/auditing mi yapıyor?

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

- Eğer `/proc/self/uid_map` container root’u yüksek bir host UID aralığına map ediyorsa, eski host-root writeup’larının çoğu artık daha az relevant olur; çünkü container içindeki root artık host-root eşdeğeri değildir.
- Eğer `/sys/fs/cgroup` `cgroup2fs` ise, `release_agent` abuse gibi eski **cgroup v1**-özel writeup’ları artık ilk tahmininiz olmamalıdır.
- Eğer seccomp ve AppArmor yalnızca dolaylı olarak inherit ediliyorsa, portability defender’ların beklediğinden daha zayıf olabilir. Kubernetes’te `RuntimeDefault`’u açıkça set etmek, node defaults’a sessizce güvenmekten çoğu zaman daha güçlüdür.
- Eğer `supplementalGroupsPolicy` `Strict` olarak ayarlanmışsa, pod image içindeki `/etc/group` üzerinden ekstra group membership’leri sessizce inherit etmekten kaçınmalıdır; bu da group-based volume ve file access davranışını daha predictable hale getirir.
- `pod-security.kubernetes.io/enforce=restricted` gibi namespace labels doğrudan kontrol edilmeye değerdir. `warn` ve `audit` faydalıdır, ancak risky bir pod’un oluşturulmasını engellemezler.

## Resource-Exhaustion Examples

Resource controls gösterişli değildir, ama container security’nin bir parçasıdır; çünkü compromise’ın blast radius’unu sınırlarlar. Memory, CPU veya PID limits olmadan, basit bir shell bile host’u veya komşu workloads’u degrade etmek için yeterli olabilir.

Host’u etkileyen örnek tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Bu örnekler faydalıdır çünkü her tehlikeli container sonucunun temiz bir "escape" olmadığını gösterir. Zayıf cgroup limitleri, code execution’ı gerçek operasyonel etkiye yine de dönüştürebilir.

Kubernetes-backed ortamlarda, DoS’ı teorik olarak değerlendirmeden önce resource control’lerin gerçekten mevcut olup olmadığını da kontrol edin:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Docker merkezli ortamlar için, `docker-bench-security` yaygın yapılandırma sorunlarını geniş çapta kabul gören benchmark rehberliğiyle karşılaştırarak kontrol ettiği için host tarafı bir audit baseline olarak kullanışlı olmaya devam eder:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Araç, threat modeling için bir alternatif değildir, ancak zaman içinde biriken dikkatsiz daemon, mount, network ve runtime varsayılanlarını bulmak için yine de değerlidir.

Kubernetes ve runtime-ağır ortamlarda, static checks ile runtime görünürlüğünü birlikte kullanın:

- `Tracee`, container-aware runtime detection ve ele geçirilmiş bir workload’un gerçekte neye dokunduğunu doğrulamanız gerektiğinde hızlı forensics için kullanışlıdır.
- `Inspektor Gadget`, assessment’ın kernel-level telemetry’nin pod’lara, container’lara, DNS activity’ye, file execution’a veya network davranışına eşlenmesini gerektirdiği durumlarda kullanışlıdır.

## Checks

Bunları assessment sırasında hızlı ilk geçiş komutları olarak kullanın:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Burada ilginç olan:

- Geniş yeteneklere sahip ve `Seccomp: 0` olan bir root process, hemen dikkat edilmesi gereken bir durumdur.
- Ayrıca **1:1 UID map**’e sahip bir root process, düzgün şekilde izole edilmiş bir user namespace içindeki "root"tan çok daha ilginçtir.
- `cgroup2fs` genellikle daha eski **cgroup v1** escape zincirlerinin en iyi başlangıç noktası olmadığı anlamına gelir; buna karşın `memory.max` veya `pids.max` eksikliği hâlâ zayıf blast-radius kontrollerine işaret eder.
- Şüpheli mounts ve runtime sockets çoğu zaman herhangi bir kernel exploit’ten daha hızlı bir etki yolu sağlar.
- Zayıf runtime posture ile zayıf resource limits kombinasyonu genellikle tek bir izole hatadan ziyade, genel olarak permissive bir container environment olduğunu gösterir.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
