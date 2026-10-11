# Değerlendirme Ve Güçlendirme

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

İyi bir container değerlendirmesi iki paralel soruyu yanıtlamalıdır. İlk olarak, bir saldırgan mevcut workload üzerinden ne yapabilir? İkinci olarak, bunu mümkün kılan operatör tercihleri nelerdir? Enumeration araçları ilk soruya, güçlendirme kılavuzları ise ikinci soruya yardımcı olur. Her ikisini aynı sayfada tutmak, bu bölümü yalnızca escape yöntemleri kataloğu olmaktan çıkarıp sahada başvurulabilecek daha kullanışlı bir kaynağa dönüştürür.

Modern ortamlara yönelik pratik bir güncelleme olarak, eski container yazılarının çoğunun fark ettirmeden **rootful runtime**, **user namespace izolasyonu olmaması** ve çoğu zaman **cgroup v1** varsaydığını belirtmek gerekir. Bu varsayımlar artık güvenli değil. Eski escape yöntemlerini incelemeye zaman ayırmadan önce workload'un rootless veya userns-remapped olup olmadığını, host'un cgroup v2 kullanıp kullanmadığını ve Kubernetes'in ya da runtime'ın artık varsayılan seccomp ve AppArmor profillerini uygulayıp uygulamadığını doğrulayın. Bu ayrıntılar, çok bilinen bir breakout yönteminin hâlâ işe yarayıp yaramayacağını çoğu zaman belirler.

## Enumeration Araçları

Container ortamını hızlıca tanımlamak için çeşitli araçlar hâlâ kullanışlıdır:

- `linpeas` birçok container göstergesini, mount edilmiş socket'leri, capability kümelerini, tehlikeli dosya sistemlerini ve breakout ipuçlarını tespit edebilir.
- `CDK` özellikle container ortamlarına odaklanır; enumeration ve bazı otomatik escape kontrollerini içerir.
- `amicontained` hafiftir; container kısıtlamalarını, capability'leri, namespace görünürlüğünü ve olası breakout sınıflarını belirlemek için kullanışlıdır.
- `deepce`, breakout odaklı kontroller içeren, container'lara yönelik başka bir enumeration aracıdır.
- `grype`, değerlendirme yalnızca runtime escape analizini değil, image paketlerindeki zafiyetlerin incelenmesini de kapsıyorsa kullanışlıdır.
- `Tracee`, yalnızca statik duruş yerine **runtime kanıtı** gerektiğinde; özellikle şüpheli process çalıştırma, dosya erişimi ve container farkındalığıyla olay toplama için kullanışlıdır.
- `Inspektor Gadget`, eBPF destekli görünürlüğü pod, container, namespace ve diğer üst düzey kavramlarla ilişkilendirmeniz gereken Kubernetes ve Linux host incelemelerinde kullanışlıdır.

Bu araçların değeri kesinlik değil, hız ve kapsamdır. Genel güvenlik duruşunu hızla ortaya çıkarmaya yardımcı olurlar; ancak önemli bulguların gerçek runtime, namespace, capability ve mount modeli bağlamında elle yorumlanması gerekir.

## Güçlendirme Öncelikleri

Uygulamaları platforma göre değişse de en önemli güçlendirme ilkeleri kavramsal olarak basittir. Privileged container'lardan kaçının. Runtime socket'lerini mount etmekten kaçının. Çok özel bir neden olmadıkça container'lara yazılabilir host path'leri vermeyin. Mümkünse user namespace'leri veya rootless çalıştırmayı kullanın. Tüm capability'leri kaldırın ve yalnızca workload'un gerçekten ihtiyaç duyduklarını geri ekleyin. Uygulama uyumluluğu sorunlarını çözmek için seccomp, AppArmor ve SELinux'u devre dışı bırakmak yerine etkin tutun. Ele geçirilmiş bir container'ın host'ta kolayca hizmet reddine yol açamaması için kaynakları sınırlayın.

Image ve build hijyeni, runtime duruşu kadar önemlidir. Minimal image'ler kullanın, bunları sık sık yeniden oluşturup tarayın, mümkün olduğunda provenance şartı koyun ve secret'ları katmanlara eklemeyin. Non-root olarak çalışan, küçük bir image kullanan ve dar bir syscall ve capability yüzeyine sahip container'ı savunmak; host ile eşdeğer yetkilere sahip root olarak çalışan, debug araçları önceden yüklenmiş büyük bir kolaylık image'ını savunmaktan çok daha kolaydır.

Kubernetes için güncel güçlendirme temel ölçütleri, birçok operatörün hâlâ varsaydığından daha katıdır. Yerleşik **Pod Security Standards**, `restricted` profilini "güncel en iyi uygulama" olarak ele alır: `allowPrivilegeEscalation` değeri `false` olmalı, workload'lar non-root olarak çalışmalı, seccomp açıkça `RuntimeDefault` veya `Localhost` olarak ayarlanmalı ve capability kümeleri olabildiğince kapsamlı biçimde kaldırılmalıdır. Değerlendirme sırasında bu önemlidir; çünkü yalnızca `warn` veya `audit` etiketlerini kullanan bir cluster, kâğıt üzerinde güçlendirilmiş görünürken gerçekte riskli pod'ları kabul ediyor olabilir.<sup>[[1]](#references)</sup>

Bir Pod'da mount edilmiş bir service-account token varsa, izinlerini **her hedef namespace için ayrı ayrı** değerlendirin. Bir namespace'teki Pod'ları listeleyen bir kural, başka bir namespace için izin olduğunu göstermez; farklı bir Pod'a mount edilmiş token'ın yetkileri farklı olabilir. İncelenen kimlikle `kubectl auth can-i list pods -n <target-namespace>` ve `kubectl auth can-i list secrets -n <target-namespace>` komutlarını kullanın. Secret listeleme kontrolünün izinli olması ciddi bir bulgudur; çünkü liste yanıtında Secret içerikleri yer alabilir, ancak bu tek başına ayrıcalıklı bir token bulunduğunu kanıtlamaz. Host erişimi için ayrıca kullanılabilir bir workload oluşturma yetkisi, önerilen `hostPath` mount'unun kabul edilmesi ve hedeflenen dosya işlemini yapmaya izin veren bir node/pod güvenlik bağlamı gerekir. Kubernetes'in [authorization kontrollerine](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) ve [RBAC ayrıcalık yükseltme kılavuzuna](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) bakın.

## Modern Triage Soruları

Escape'e özel sayfalara geçmeden önce şu kısa soruları yanıtlayın:

1. Workload **rootful**, **rootless** veya **userns-remapped** mı?
2. Node **cgroup v1** mi yoksa **cgroup v2** mi kullanıyor?
3. **seccomp** ve **AppArmor/SELinux** açıkça yapılandırılmış mı, yoksa yalnızca mevcut olduklarında devralınıyorlar mı?
4. Kubernetes'te namespace gerçekten `baseline` veya `restricted` ilkesini **uyguluyor** mu, yoksa yalnızca uyarı mı veriyor ya da denetim mi yapıyor?

Kullanışlı kontroller:

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

Burada dikkat çekenler:

- `/proc/self/uid_map`, container root kullanıcısının **yüksek bir host UID aralığına** eşlendiğini gösteriyorsa, eski host-root yazıları daha az ilgili hâle gelir; çünkü container içindeki root artık host-root ile eşdeğer değildir.
- `/sys/fs/cgroup` `cgroup2fs` ise, `release_agent` kötüye kullanımı gibi eski **cgroup v1** odaklı yazılar artık ilk akla gelen seçenek olmamalıdır.
- seccomp ve AppArmor yalnızca örtük olarak devralınıyorsa, taşınabilirlik savunucuların beklediğinden daha düşük olabilir. Kubernetes'te `RuntimeDefault` değerini açıkça ayarlamak, çoğu zaman sessizce node varsayılanlarına güvenmekten daha güçlüdür.
- `supplementalGroupsPolicy` `Strict` olarak ayarlanmışsa pod, image içindeki `/etc/group` dosyasından fazladan grup üyeliklerini sessizce devralmamalıdır; bu da grup tabanlı volume ve dosya erişimi davranışını daha öngörülebilir kılar.
- `pod-security.kubernetes.io/enforce=restricted` gibi namespace etiketlerini doğrudan kontrol etmek faydalıdır. `warn` ve `audit` işlevseldir, ancak riskli bir pod'un oluşturulmasını engellemezler.

## Runtime Baseline Triage

Runtime baseline, bir container'ın sıradan, yalıtılmış bir workload'a mı yoksa host'u etkileyebilecek bir control plane foothold'una mı benzediğini anlamanızı sağlayan hızlı kontroldür. Sonraki adımda hangi konuyu inceleyeceğinize (runtime socket kötüye kullanımı, host mount'ları, namespace'ler, cgroup'lar, capabilities veya image secret incelemesi) öncelik vermek için yeterli bilgi toplamalıdır.

Bir workload içinden yapılabilecek faydalı kontroller:

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

Yorumlama:

- `memory.max` / `pids.max` değerlerinin eksik veya sınırsız olması, temiz bir escape olmasa bile etki alanını sınırlayan kontrollerin zayıf olduğuna işaret eder.
- `NoNewPrivs: 0`, geniş yetenekler ve izin verici seccomp ile çalışan bir root shell, kısıtlı bir non-root workload'dan çok daha dikkat çekicidir.
- Runtime socket'leri ve yazılabilir host mount'ları genellikle kernel exploit'lerinden önce gelir; çünkü bunlar zaten bir yönetim veya dosya sistemi kontrol yolu sunar.
- Paylaşılan PID, network, IPC veya cgroup namespace'leri tek başlarına her zaman tam bir escape sağlamaz, ancak bir sonraki adımı bulmayı kolaylaştırır.

## Kaynak Tüketimi Örnekleri

Kaynak kontrolleri gösterişli değildir, ancak bir ihlalin etki alanını sınırladıkları için container security'nin bir parçasıdır. Bellek, CPU veya PID limitleri olmadığında, basit bir shell bile host'un veya komşu workload'ların performansını düşürmeye yetebilir.

Host'u etkileyen test örnekleri:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

Bu örnekler, container’larda ortaya çıkabilecek her tehlikeli sonucun sorunsuz bir “escape” olmadığını gösterdiği için yararlıdır. Zayıf cgroup limitleri, code execution’ı gerçek operasyonel etkiye dönüştürebilir.

Kubernetes destekli ortamlarda, DoS’u teorik bir ihtimal olarak değerlendirmeden önce kaynak denetimlerinin mevcut olup olmadığını da kontrol edin:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Güvenlik Sıkılaştırma Araçları

Docker odaklı ortamlarda `docker-bench-security`, yaygın yapılandırma sorunlarını geniş çapta kabul gören benchmark yönergelerine göre denetlediği için ana makine tarafında yararlı bir denetim başlangıç noktası olmaya devam ediyor. Yapılandırma benchmark'ı, kurulu runtime'ın yeni açıklanmış bir güvenlik açığından etkilenip etkilenmediğini tespit edemeyeceğinden, runtime güvenlik duyuruları ayrıca incelenmelidir. <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

Araç, tehdit modellemesinin yerini tutmaz; ancak zaman içinde biriken özensiz daemon, mount, network ve runtime varsayılanlarını bulmak için yine de değerlidir.

Kubernetes ve runtime ağırlıklı ortamlarda statik kontrolleri runtime görünürlüğüyle birlikte kullanın:

- `Tracee`, container farkındalığına sahip runtime tespiti ve ele geçirilmiş bir workload'un gerçekte nelere eriştiğini doğrulamanız gerektiğinde hızlı adli inceleme için kullanışlıdır.
- `Inspektor Gadget`, değerlendirmede kernel düzeyinde telemetrinin pod'larla, container'larla, DNS etkinliğiyle, dosya yürütmeyle veya network davranışıyla eşleştirilmesi gerektiğinde kullanışlıdır.

## Kontroller

Değerlendirme sırasında hızlı bir ilk kontrol için şu komutları kullanın:

```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

Burada dikkat çekenler:

- Geniş capabilities değerlerine sahip ve `Seccomp: 0` olan bir root process hemen incelenmelidir.
- **1:1 UID map** kullanan bir root process, uygun şekilde yalıtılmış bir user namespace içindeki "root"tan çok daha dikkat çekicidir.
- `cgroup2fs` genellikle eski **cgroup v1** escape zincirlerinin en iyi başlangıç noktası olmadığı anlamına gelir; ancak `memory.max` veya `pids.max` değerlerinin olmaması, blast radius kontrollerinin zayıf olduğuna işaret eder.
- Şüpheli mount'lar ve runtime socket'leri, çoğu zaman herhangi bir kernel exploit'ten daha hızlı etki yaratma yolu sunar.
- Zayıf runtime duruşu ile zayıf kaynak limitlerinin bir arada bulunması, genellikle tekil bir hatadan ziyade genel olarak izinleri geniş bir container ortamına işaret eder.

## References

- [1] [Kubernetes Pod Güvenlik Standartları](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker Güvenlik Uyarısı: runc, BuildKit ve Moby'de Birden Fazla Güvenlik Açığı](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
