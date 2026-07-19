# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## Bir Container Gerçekte Nedir

Bir container'ı tanımlamanın pratik bir yolu şudur: Bir container, kontrollü bir dosya sistemi, kontrollü bir kernel kaynak kümesi ve kısıtlı bir ayrıcalık modeli görecek şekilde belirli bir OCI tarzı yapılandırmayla başlatılmış **normal bir Linux process tree**'dir. Process kendisinin PID 1 olduğuna, kendi network stack'ine sahip olduğuna, kendi hostname ve IPC kaynaklarının sahibi olduğuna inanabilir ve hatta kendi user namespace'i içinde root olarak çalışabilir. Ancak temelinde hâlâ kernel'in diğer tüm process'ler gibi zamanladığı bir host process'idir.

Container security konusunun aslında bu yanılsamanın nasıl oluşturulduğunu ve nasıl başarısız olduğunu incelemesinin nedeni budur. Mount namespace zayıfsa process host filesystem'ını görebilir. User namespace yoksa veya devre dışı bırakılmışsa container içindeki root, host üzerindeki root'a fazla yakın şekilde eşlenebilir. seccomp unconfined durumdaysa ve capability set çok genişse process, erişilememesi gereken syscall'lara ve ayrıcalıklı kernel özelliklerine ulaşabilir. Runtime socket container içine mount edilmişse container'ın bir kernel breakout gerçekleştirmesi bile gerekmeyebilir; çünkü runtime'dan daha güçlü bir sibling container başlatmasını veya host root filesystem'ını doğrudan mount etmesini isteyebilir.

## Container'lar Virtual Machine'lerden Nasıl Farklıdır

Bir VM normalde kendi kernel'ini ve donanım abstraction boundary'sini taşır. Bu, guest kernel'in çökmesi, panic yaşaması veya exploit edilmesinin otomatik olarak host kernel'inin doğrudan kontrol edildiği anlamına gelmemesini sağlar. Container'larda workload ayrı bir kernel almaz. Bunun yerine host'un kullandığı aynı kernel'in dikkatle filtrelenmiş ve namespace'lere ayrılmış bir görünümünü alır. Sonuç olarak container'lar genellikle daha hafiftir, daha hızlı başlar, bir makine üzerinde daha yoğun şekilde çalıştırılabilir ve kısa ömürlü application deployment için daha uygundur. Bunun karşılığında isolation boundary, doğru host ve runtime yapılandırmasına çok daha doğrudan bağlıdır.

Bu, container'ların "insecure", VM'lerin ise "secure" olduğu anlamına gelmez. Security model'in farklı olduğu anlamına gelir. Rootless execution, user namespaces, varsayılan seccomp, strict capability set, host namespace paylaşımının olmaması ve güçlü SELinux veya AppArmor enforcement kullanan iyi yapılandırılmış bir container stack oldukça sağlam olabilir. Buna karşılık `--privileged`, host PID/network paylaşımı, içine Docker socket mount edilmiş olması ve `/` için writable bind mount ile başlatılmış bir container, güvenli şekilde izole edilmiş bir application sandbox'dan ziyade işlevsel olarak host root erişimine çok daha yakındır. Farkı oluşturan, etkinleştirilen veya devre dışı bırakılan katmanlardır.

Okuyucuların anlaması gereken bir orta nokta da vardır; çünkü gerçek ortamlarda bu model giderek daha sık görülmektedir. **Sandboxed container runtimes** olan **gVisor** ve **Kata Containers**, boundary'yi klasik bir `runc` container'ından daha fazla harden edecek şekilde tasarlanmıştır. gVisor, workload ile birçok host kernel interface'i arasına bir userspace kernel katmanı yerleştirirken Kata, workload'u lightweight bir virtual machine içinde başlatır. Bunlar hâlâ container ecosystem'leri ve orchestration workflow'ları üzerinden kullanılır; ancak security özellikleri plain OCI runtime'larından farklıdır ve her şey aynı şekilde çalışıyormuş gibi "normal Docker containers" grubuna zihinsel olarak dahil edilmemelidir.

## Container Stack: Tek Bir Katman Değil, Birden Fazla Katman

Birisi "bu container insecure" dediğinde sorulması gereken yararlı devam sorusu şudur: **Onu insecure yapan hangi katmandı?** Containerized bir workload genellikle birlikte çalışan birkaç component'in sonucudur.

En üstte genellikle OCI image'ını ve metadata'yı oluşturan BuildKit, Buildah veya Kaniko gibi bir **image build layer** bulunur. Low-level runtime'ın üzerinde Docker Engine, Podman, containerd, CRI-O, Incus veya systemd-nspawn gibi bir **engine veya manager** olabilir. Cluster ortamlarında, istenen security posture'ı workload configuration üzerinden belirleyen Kubernetes gibi bir **orchestrator** da bulunabilir. Son olarak, namespaces, cgroups, seccomp ve MAC policy'yi gerçekten enforce eden **kernel**'dir.

Bu layered model, default'ları anlamak için önemlidir. Bir restriction Kubernetes tarafından istenebilir, CRI aracılığıyla containerd veya CRI-O üzerinden çevrilebilir, runtime wrapper tarafından bir OCI spec'e dönüştürülebilir ve ancak bundan sonra `runc`, `crun`, `runsc` veya başka bir runtime tarafından workload'a karşı kernel üzerinde enforce edilebilir. Ortamlar arasındaki default'lar farklı olduğunda bunun nedeni genellikle bu katmanlardan birinin final configuration'ı değiştirmesidir. Bu nedenle aynı mekanizma Docker veya Podman'da bir CLI flag'i, Kubernetes'te bir Pod veya `securityContext` field'ı ve lower-level runtime stack'lerinde workload için oluşturulan OCI configuration olarak görülebilir. Bu nedenle bu bölümdeki CLI örnekleri, her tool tarafından desteklenen universal flag'ler olarak değil, **genel bir container konsepti için runtime-specific syntax** olarak okunmalıdır.

## Gerçek Container Security Boundary

Pratikte container security, tek bir kusursuz control'den değil, **birbiriyle örtüşen control'lerden** gelir. Namespaces görünürlüğü izole eder. cgroups kaynak kullanımını yönetir ve sınırlar. Capabilities, ayrıcalıklı görünen bir process'in gerçekte neler yapabileceğini azaltır. seccomp, dangerous syscall'ları kernel'e ulaşmadan önce engeller. AppArmor ve SELinux, normal DAC check'lerinin üzerine Mandatory Access Control ekler. `no_new_privs`, masked procfs path'leri ve read-only system path'leri yaygın privilege ve proc/sys abuse chain'lerini zorlaştırır. Runtime'ın kendisi de önemlidir; çünkü mount'ların, socket'lerin, label'ların ve namespace join'lerinin nasıl oluşturulacağına o karar verir.

Bu nedenle container security documentation'ının büyük bir kısmı tekrarlı görünür. Aynı escape chain çoğu zaman birden fazla mekanizmaya aynı anda bağlıdır. Örneğin writable bir host bind mount kötüdür; ancak container gerçek root olarak çalışıyorsa, `CAP_SYS_ADMIN` sahibiyse, seccomp tarafından unconfined durumdaysa ve SELinux veya AppArmor tarafından kısıtlanmıyorsa çok daha tehlikeli hâle gelir. Benzer şekilde host PID paylaşımı ciddi bir exposure'dır; ancak `CAP_SYS_PTRACE`, zayıf procfs protection'ları veya `nsenter` gibi namespace-entry tool'larıyla birleştirildiğinde attacker için çok daha kullanışlı olur. Bu nedenle konuyu document etmenin doğru yolu, her sayfada aynı attack'ı tekrarlamak değil, her katmanın final boundary'ye ne kattığını açıklamaktır.

## Bu Bölüm Nasıl Okunmalı

Bölüm, en genel konseptlerden en spesifik olanlara doğru düzenlenmiştir.

Runtime ve ecosystem overview ile başlayın:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Ardından, bir attacker'ın kernel escape'e ihtiyaç duyup duymayacağını sıklıkla belirleyen control plane'leri ve supply-chain surface'lerini inceleyin:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Ardından protection model'e geçin:

{{#ref}}
protections/
{{#endref}}

Namespace sayfaları, kernel isolation primitive'lerini ayrı ayrı açıklar:

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths ve read-only system paths sayfaları, genellikle namespaces üzerine layered olarak eklenen mekanizmaları açıklar:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## İyi Bir İlk Enumeration Yaklaşımı

Containerized bir target'ı değerlendirirken, ünlü escape PoC'lerine hemen geçmektense küçük bir dizi kesin teknik soru sormak çok daha yararlıdır. Öncelikle **stack**'i belirleyin: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer veya daha specialized bir şey. Ardından **runtime**'ı belirleyin: `runc`, `crun`, `runsc`, `kata-runtime` veya başka bir OCI-compatible implementation. Bundan sonra ortamın **rootful veya rootless** olup olmadığını, **user namespaces**'in aktif olup olmadığını, herhangi bir **host namespace**'in paylaşılıp paylaşılmadığını, hangi **capabilities**'in kaldığını, **seccomp**'un etkin olup olmadığını, bir **MAC policy**'nin gerçekten enforce edilip edilmediğini, **dangerous mount veya socket** bulunup bulunmadığını ve process'in container runtime API ile etkileşime girip giremediğini kontrol edin.

Bu yanıtlar, gerçek security posture hakkında base image name'in verebileceğinden çok daha fazla bilgi sağlar. Birçok assessment'ta, yalnızca final container configuration'ı anlayarak tek bir application file okumadan önce olası breakout ailesini tahmin edebilirsiniz.

## Kapsam

Bu bölüm, eski Docker odaklı materyali container merkezli bir organizasyon altında kapsar: runtime ve daemon exposure, authorization plugins, image trust ve build secrets, sensitive host mounts, distroless workloads, privileged containers ve container execution çevresinde normalde layered olarak kullanılan kernel protections.
{{#include ../../../banners/hacktricks-training.md}}
