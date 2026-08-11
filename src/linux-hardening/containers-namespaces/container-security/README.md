# Container Güvenliği

## Bir Container Aslında Nedir

Bir container'ı tanımlamanın pratik bir yolu şudur: container, kontrollü bir dosya sistemini, kontrollü bir kernel kaynakları kümesini ve kısıtlanmış bir yetki modelini görecek şekilde belirli bir OCI tarzı yapılandırmayla başlatılmış **normal bir Linux process tree**'sidir. Process kendisinin PID 1 olduğuna inanabilir, kendi network stack'ine sahip olduğunu düşünebilir, kendi hostname'ine ve IPC kaynaklarına sahip olduğuna inanabilir ve hatta kendi user namespace'i içinde root olarak çalışabilir. Ancak perde arkasında hâlâ kernel'ın diğer tüm process'ler gibi schedule ettiği bir host process'idir.

Container security çalışmasının temelinde, bu yanılsamanın nasıl oluşturulduğunu ve nasıl başarısız olduğunu anlamak vardır. Mount namespace zayıfsa process host filesystem'ini görebilir. User namespace yoksa veya devre dışı bırakılmışsa container içindeki root, host üzerindeki root'a fazla doğrudan eşlenebilir. seccomp unconfined durumdaysa ve capability set fazla genişse process, erişilememesi gereken syscall'lara ve ayrıcalıklı kernel özelliklerine ulaşabilir. Runtime socket container içine mount edilmişse container'ın kernel breakout gerçekleştirmesine bile gerek kalmayabilir; çünkü runtime'dan daha güçlü bir sibling container başlatmasını veya host root filesystem'ini doğrudan mount etmesini isteyebilir.

## Container'lar Virtual Machine'lerden Nasıl Farklıdır

Bir VM normalde kendi kernel'ini ve hardware abstraction boundary'sini barındırır. Bu, guest kernel'ın çökmesi, panic vermesi veya exploit edilmesinin otomatik olarak host kernel'ı üzerinde doğrudan kontrol anlamına gelmemesini sağlar. Container'larda workload ayrı bir kernel almaz. Bunun yerine host'un kullandığı kernel'ın dikkatle filtrelenmiş ve namespace'lere ayrılmış bir görünümünü kullanır. Sonuç olarak container'lar genellikle daha hafiftir, daha hızlı başlar, bir makine üzerinde daha yoğun şekilde çalıştırılabilir ve kısa ömürlü application deployment için daha uygundur. Bunun bedeli, isolation boundary'nin doğru host ve runtime yapılandırmasına çok daha doğrudan bağlı olmasıdır.

Bu, container'ların "insecure", VM'lerin ise "secure" olduğu anlamına gelmez. Security model'in farklı olduğu anlamına gelir. Rootless execution, user namespaces, default seccomp, strict capability set, host namespace paylaşımının olmaması ve güçlü SELinux veya AppArmor enforcement içeren iyi yapılandırılmış bir container stack oldukça sağlam olabilir. Buna karşılık `--privileged`, host PID/network paylaşımı, container içine mount edilmiş Docker socket'i ve `/` için writable bind mount ile başlatılan bir container, güvenli şekilde izole edilmiş bir application sandbox'tan çok host root erişimine yakındır. Fark, etkinleştirilen veya devre dışı bırakılan katmanlardan kaynaklanır.

Ayrıca okuyucuların anlaması gereken bir middle ground da vardır; çünkü bu yaklaşım gerçek ortamlarda giderek daha sık görülmektedir. **Sandboxed container runtimes** olan **gVisor** ve **Kata Containers**, boundary'yi klasik bir `runc` container'ına kıyasla kasıtlı olarak güçlendirir. gVisor, workload ile birçok host kernel interface'i arasına bir userspace kernel katmanı yerleştirirken Kata, workload'u lightweight bir virtual machine içinde başlatır. Bunlar hâlâ container ecosystem'leri ve orchestration workflow'ları üzerinden kullanılır, ancak security özellikleri plain OCI runtime'larından farklıdır ve her şey aynı şekilde davranıyormuş gibi zihinsel olarak "normal Docker container'ları" ile aynı gruba konulmamalıdır.

## Container Stack'i: Tek Bir Katman Değil, Birden Fazlası

Birisi "bu container insecure" dediğinde sorulması gereken yararlı devam sorusu şudur: **onu insecure yapan hangi katmandı?** Containerized bir workload genellikle birlikte çalışan birkaç component'in sonucudur.

En üstte, OCI image'ını ve metadata'sını oluşturan BuildKit, Buildah veya Kaniko gibi bir **image build layer** bulunur. Low-level runtime'ın üzerinde Docker Engine, Podman, containerd, CRI-O, Incus veya systemd-nspawn gibi bir **engine veya manager** olabilir. Cluster ortamlarında Kubernetes gibi bir **orchestrator** da workload configuration üzerinden istenen security posture'ı belirliyor olabilir. Son olarak **kernel**, namespaces, cgroups, seccomp ve MAC policy'yi gerçekten enforce eden bileşendir.

Bu layered model, default'ları anlamak açısından önemlidir. Bir restriction Kubernetes tarafından istenebilir, CRI üzerinden containerd veya CRI-O tarafından çevrilebilir, runtime wrapper tarafından bir OCI spec'e dönüştürülebilir ve ancak bundan sonra `runc`, `crun`, `runsc` veya başka bir runtime tarafından kernel'a karşı enforce edilebilir. Ortamlar arasındaki default'lar farklı olduğunda bunun nedeni çoğu zaman bu katmanlardan birinin final configuration'ı değiştirmesidir. Bu nedenle aynı mekanizma Docker veya Podman'da bir CLI flag'i, Kubernetes'te bir Pod veya `securityContext` alanı ve lower-level runtime stack'lerinde workload için oluşturulan OCI configuration olarak görünebilir. Bu yüzden bu bölümdeki CLI örnekleri, her tool tarafından desteklenen universal flag'ler olarak değil, **genel bir container konsepti için runtime-specific syntax** olarak okunmalıdır.

## Gerçek Container Security Boundary'si

Pratikte container security, tek bir kusursuz kontrolden değil, **birbirini tamamlayan kontrollerden** oluşur. Namespaces görünürlüğü izole eder. cgroups kaynak kullanımını yönetir ve sınırlar. Capabilities, privileged görünen bir process'in gerçekte neler yapabileceğini azaltır. seccomp, tehlikeli syscall'ları kernel'a ulaşmadan önce engeller. AppArmor ve SELinux, normal DAC kontrollerinin üzerine Mandatory Access Control ekler. `no_new_privs`, masked procfs path'leri ve read-only system path'leri, yaygın privilege ve proc/sys abuse chain'lerini zorlaştırır. Runtime da önemlidir; çünkü mount'ların, socket'lerin, label'ların ve namespace join işlemlerinin nasıl oluşturulacağına o karar verir.

Bu nedenle container security dokümantasyonunun büyük bölümü tekrarlı görünebilir. Aynı escape chain çoğu zaman birden fazla mekanizmaya aynı anda bağlıdır. Örneğin writable bir host bind mount kötüdür; ancak container aynı zamanda host üzerinde gerçek root olarak çalışıyorsa, `CAP_SYS_ADMIN` yetkisine sahipse, seccomp tarafından unconfined durumdaysa ve SELinux veya AppArmor tarafından kısıtlanmıyorsa durum çok daha tehlikeli hâle gelir. Benzer şekilde host PID sharing ciddi bir exposure'dır; ancak `CAP_SYS_PTRACE`, zayıf procfs protections veya `nsenter` gibi namespace-entry tool'larıyla birleştiğinde attacker için çok daha kullanışlı olur. Bu nedenle konuyu belgelemenin doğru yolu, her sayfada aynı attack'i tekrarlamak değil, her katmanın final boundary'ye ne kattığını açıklamaktır.

## Bu Bölüm Nasıl Okunmalı

Bölüm, en genel konseptlerden en spesifik olanlara doğru düzenlenmiştir.

Runtime ve ecosystem overview ile başlayın:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Ardından, bir attacker'sın kernel escape'e ihtiyaç duyup duymayacağını sıklıkla belirleyen control plane'leri ve supply-chain surface'lerini inceleyin:

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

Namespace sayfaları kernel isolation primitive'lerini tek tek açıklar:

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths ve read-only system paths sayfaları, genellikle namespaces üzerine eklenen mekanizmaları açıklar:

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

Containerized bir target'ı değerlendirirken, ünlü escape PoC'lerine hemen geçmektense küçük ve kesin bir dizi teknik soru sormak çok daha faydalıdır. Öncelikle **stack**'i belirleyin: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer veya daha specialized bir yapı. Ardından **runtime**'ı belirleyin: `runc`, `crun`, `runsc`, `kata-runtime` veya başka bir OCI-compatible implementation. Bundan sonra ortamın **rootful veya rootless** olup olmadığını, **user namespaces**'in etkin olup olmadığını, herhangi bir **host namespace**'in paylaşılıp paylaşılmadığını, hangi **capabilities**'in kaldığını, **seccomp**'un etkin olup olmadığını, bir **MAC policy**'nin gerçekten enforcement yapıp yapmadığını, **dangerous mount veya socket** bulunup bulunmadığını ve process'in container runtime API'siyle etkileşime girip giremediğini kontrol edin.

Bu yanıtlar size gerçek security posture hakkında base image adından çok daha fazla bilgi verir. Birçok assessment'ta, tek bir application file okumadan önce yalnızca final container configuration'ı anlayarak olası breakout family'sini tahmin edebilirsiniz.

## Kapsam

Bu bölüm, eski Docker-focused içeriği container-oriented bir organizasyon altında ele alır: runtime ve daemon exposure, authorization plugins, image trust ve build secrets, sensitive host mounts, distroless workloads, privileged containers ve container execution çevresinde normalde katmanlanan kernel protections.

{{#include ../../../banners/hacktricks-training.md}}
