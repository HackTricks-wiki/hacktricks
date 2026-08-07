# Container Güvenliği

{{#include ../../../banners/hacktricks-training.md}}

## Bir Container Aslında Nedir

Bir container'ı tanımlamanın pratik bir yolu şudur: container, kontrollü bir dosya sistemi, kontrollü bir kernel kaynak kümesi ve kısıtlanmış bir yetki modeli görecek şekilde belirli bir OCI tarzı yapılandırma altında başlatılmış **normal bir Linux process tree**'dir. Process kendisinin PID 1 olduğuna, kendi network stack'ine sahip olduğuna, kendi hostname'inin ve IPC kaynaklarının sahibi olduğuna inanabilir ve hatta kendi user namespace'i içinde root olarak çalışabilir. Ancak temelde hâlâ kernel'in diğer tüm process'ler gibi schedule ettiği bir host process'idir.

Container security'nin aslında bu illüzyonun nasıl oluşturulduğunu ve nasıl başarısız olduğunu incelemesinin nedeni budur. Mount namespace zayıfsa process host dosya sistemini görebilir. User namespace yoksa veya devre dışı bırakılmışsa container içindeki root, host üzerindeki root'a fazla yakın şekilde map edilebilir. seccomp unconfined durumdaysa ve capability set çok genişse process, erişilemez olması gereken syscall'lara ve ayrıcalıklı kernel özelliklerine ulaşabilir. Runtime socket container içine mount edilmişse container'ın bir kernel breakout gerçekleştirmesi bile gerekmeyebilir; çünkü runtime'dan daha güçlü bir sibling container başlatmasını veya host root filesystem'ini doğrudan mount etmesini isteyebilir.

## Container'lar Virtual Machine'lerden Nasıl Farklıdır

Bir VM normalde kendi kernel'ini ve hardware abstraction boundary'sini taşır. Bu, guest kernel'in crash olmasının, panic yaşamasının veya exploit edilmesinin otomatik olarak host kernel'i üzerinde doğrudan kontrol anlamına gelmediği anlamına gelir. Container'larda workload ayrı bir kernel almaz. Bunun yerine host'un kullandığı kernel'in dikkatle filtrelenmiş ve namespace'lere ayrılmış bir görünümünü alır. Sonuç olarak container'lar genellikle daha hafiftir, daha hızlı başlar, bir makine üzerinde daha yoğun şekilde çalıştırılabilir ve kısa ömürlü application deployment'ları için daha uygundur. Bunun karşılığında isolation boundary, doğru host ve runtime yapılandırmasına çok daha doğrudan bağlıdır.

Bu, container'ların "insecure", VM'lerin ise "secure" olduğu anlamına gelmez. Security model'in farklı olduğu anlamına gelir. Rootless execution, user namespace'ler, varsayılan seccomp, strict bir capability set, host namespace paylaşımının olmaması ve güçlü SELinux veya AppArmor enforcement kullanan iyi yapılandırılmış bir container stack oldukça dayanıklı olabilir. Buna karşılık `--privileged`, host PID/network sharing, içine Docker socket mount edilmiş ve `/` için writable bind mount kullanan bir container, güvenli şekilde izole edilmiş bir application sandbox'tan ziyade işlevsel olarak host root erişimine çok daha yakındır. Fark, etkinleştirilen veya devre dışı bırakılan katmanlardan kaynaklanır.

Okuyucuların anlaması gereken bir orta nokta da vardır; çünkü bu yaklaşım gerçek ortamlarda giderek daha sık görülmektedir. **Sandboxed container runtime'ları** olan **gVisor** ve **Kata Containers**, klasik bir `runc` container'ının ötesinde boundary'yi kasıtlı olarak güçlendirir. gVisor, workload ile birçok host kernel interface'i arasına bir userspace kernel katmanı yerleştirirken Kata, workload'u lightweight bir virtual machine içinde başlatır. Bunlar hâlâ container ecosystem'leri ve orchestration workflow'ları üzerinden kullanılır; ancak security özellikleri plain OCI runtime'larından farklıdır ve her şey aynı şekilde çalışıyormuş gibi "normal Docker container'ları" ile zihinsel olarak aynı grupta değerlendirilmemelidir.

## Container Stack: Tek Bir Katman Değil, Birden Fazla Katman

Birisi "bu container insecure" dediğinde sorulması gereken faydalı devam sorusu şudur: **hangi katman onu insecure hâle getirdi?** Containerized bir workload genellikle birlikte çalışan birkaç component'in sonucudur.

En üstte çoğu zaman OCI image'ını ve metadata'sını oluşturan BuildKit, Buildah veya Kaniko gibi bir **image build layer** bulunur. Low-level runtime'ın üzerinde Docker Engine, Podman, containerd, CRI-O, Incus veya systemd-nspawn gibi bir **engine veya manager** olabilir. Cluster ortamlarında, workload configuration aracılığıyla istenen security posture'a karar veren Kubernetes gibi bir **orchestrator** da bulunabilir. Son olarak **kernel**, namespaces, cgroups, seccomp ve MAC policy'yi gerçekten uygulayan bileşendir.

Bu layered model, default'ları anlamak için önemlidir. Bir restriction Kubernetes tarafından talep edilebilir, CRI üzerinden containerd veya CRI-O tarafından çevrilebilir, runtime wrapper tarafından bir OCI spec'e dönüştürülebilir ve ancak bundan sonra `runc`, `crun`, `runsc` veya başka bir runtime tarafından kernel'e karşı enforce edilebilir. Ortamlar arasındaki default'lar farklı olduğunda bunun nedeni çoğu zaman bu katmanlardan birinin final configuration'ı değiştirmiş olmasıdır. Bu nedenle aynı mekanizma Docker veya Podman'da bir CLI flag'i, Kubernetes'te bir Pod veya `securityContext` field'ı ve low-level runtime stack'lerinde workload için oluşturulan OCI configuration olarak görülebilir. Bu sebeple bu bölümdeki CLI örnekleri, her tool tarafından desteklenen universal flag'ler olarak değil, **genel bir container kavramı için runtime-specific syntax** olarak okunmalıdır.

## Gerçek Container Security Boundary

Pratikte container security, tek bir kusursuz kontrolden değil, **birbirini tamamlayan kontrollerden** gelir. Namespaces görünürlüğü izole eder. cgroups kaynak kullanımını yönetir ve sınırlar. Capabilities, privileged görünen bir process'in gerçekte neler yapabileceğini azaltır. seccomp, dangerous syscall'ları kernel'e ulaşmadan önce engeller. AppArmor ve SELinux, normal DAC kontrollerinin üzerine Mandatory Access Control ekler. `no_new_privs`, masked procfs path'leri ve read-only system path'leri yaygın privilege ve proc/sys abuse chain'lerini zorlaştırır. Runtime'ın kendisi de önemlidir; çünkü mount'ların, socket'lerin, label'ların ve namespace join'lerinin nasıl oluşturulacağına karar verir.

Bu nedenle birçok container security dokümanı tekrarlı görünür. Aynı escape chain çoğu zaman aynı anda birden fazla mekanizmaya bağlıdır. Örneğin writable bir host bind mount kötüdür; ancak container aynı zamanda host üzerinde gerçek root olarak çalışıyorsa, `CAP_SYS_ADMIN`'e sahipse, seccomp tarafından unconfined durumdaysa ve SELinux veya AppArmor tarafından kısıtlanmıyorsa çok daha kötü hâle gelir. Benzer şekilde host PID sharing ciddi bir exposure'dır; ancak `CAP_SYS_PTRACE`, zayıf procfs korumaları veya `nsenter` gibi namespace-entry tool'larıyla birleştirildiğinde attacker için çok daha kullanışlı olur. Bu nedenle konuyu dokümante etmenin doğru yolu, aynı attack'i her sayfada tekrarlamak değil, her katmanın final boundary'ye ne kattığını açıklamaktır.

## Bu Bölüm Nasıl Okunmalı

Bölüm, en genel kavramlardan en spesifik kavramlara doğru düzenlenmiştir.

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

Sonra protection model'e geçin:

{{#ref}}
protections/
{{#endref}}

Namespace sayfaları kernel isolation primitive'lerini tek tek açıklar:

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths ve read-only system paths hakkındaki sayfalar, genellikle namespaces üzerine layered olarak eklenen mekanizmaları açıklar:

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

Containerized bir target'ı değerlendirirken, ünlü escape PoC'lerine hemen geçmektense küçük bir dizi kesin technical question sormak çok daha faydalıdır. Öncelikle **stack**'i belirleyin: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer veya daha specialized bir yapı. Ardından **runtime**'ı belirleyin: `runc`, `crun`, `runsc`, `kata-runtime` veya başka bir OCI-compatible implementation. Bundan sonra ortamın **rootful veya rootless** olup olmadığını, **user namespaces**'in active olup olmadığını, herhangi bir **host namespace**'in paylaşılıp paylaşılmadığını, hangi **capabilities**'in kaldığını, **seccomp**'un enabled olup olmadığını, bir **MAC policy**'nin gerçekten enforcing durumda olup olmadığını, **dangerous mounts veya socket**'lerin mevcut olup olmadığını ve process'in container runtime API ile etkileşime girip giremediğini kontrol edin.

Bu cevaplar, gerçek security posture hakkında base image name'in verebileceğinden çok daha fazla bilgi sağlar. Birçok assessment'ta, final container configuration'ı anlayarak tek bir application file okumadan önce olası breakout family'sini tahmin edebilirsiniz.

## Kapsam

Bu bölüm, container-oriented organization altında eski Docker-focused materyali kapsar: runtime ve daemon exposure, authorization plugins, image trust ve build secrets, sensitive host mounts, distroless workload'lar, privileged container'lar ve container execution etrafında normalde layered olarak kullanılan kernel protections.

{{#include ../../../banners/hacktricks-training.md}}
