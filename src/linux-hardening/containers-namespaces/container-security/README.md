# Container Güvenliği

{{#include ../../../banners/hacktricks-training.md}}

## Bir Container Gerçekte Nedir?

Bir container'ı tanımlamanın pratik bir yolu şudur: container, belirli bir OCI tarzı yapılandırmayla başlatılmış **normal bir Linux process tree**'dir; bu sayede kontrollü bir filesystem, kontrollü bir kernel resource kümesi ve kısıtlanmış bir privilege model görür. Process kendisinin PID 1 olduğuna inanabilir, kendi network stack'ine sahip olduğuna inanabilir, kendi hostname'ine ve IPC resource'larına sahip olduğunu düşünebilir ve hatta kendi user namespace'i içinde root olarak çalışabilir. Ancak perde arkasında hâlâ kernel tarafından diğer process'ler gibi schedule edilen bir host process'idir.

Container security konusunun aslında bu illüzyonun nasıl oluşturulduğunu ve nasıl bozulduğunu incelemesi bu yüzdendir. Mount namespace zayıfsa process host filesystem'ini görebilir. User namespace yoksa veya devre dışı bırakılmışsa, container içindeki root host üzerindeki root'a fazlasıyla yakın bir eşlemeye sahip olabilir. seccomp unconfined durumdaysa ve capability set çok genişse process, erişim dışında kalması gereken syscall'lara ve privileged kernel özelliklerine ulaşabilir. Runtime socket container içine mount edilmişse container'ın bir kernel breakout gerçekleştirmesine bile gerek kalmayabilir; çünkü runtime'dan daha güçlü bir sibling container başlatmasını veya host root filesystem'ini doğrudan mount etmesini isteyebilir.

## Container'lar Virtual Machine'lerden Nasıl Farklıdır?

Bir VM normalde kendi kernel'ini ve hardware abstraction boundary'sini barındırır. Bu, guest kernel'in çökmesinin, panic yaşamasının veya exploit edilmesinin otomatik olarak host kernel'inin doğrudan kontrol edildiği anlamına gelmemesini sağlar. Container'larda workload ayrı bir kernel almaz. Bunun yerine host'un kullandığı aynı kernel'in dikkatle filtrelenmiş ve namespace'lerle ayrılmış bir görünümünü alır. Sonuç olarak container'lar genellikle daha hafiftir, daha hızlı başlar, bir makine üzerinde daha yüksek yoğunlukta çalıştırılabilir ve kısa ömürlü application deployment için daha uygundur. Bunun bedeli, isolation boundary'nin doğru host ve runtime yapılandırmasına çok daha doğrudan bağlı olmasıdır.

Bu, container'ların "insecure", VM'lerin ise "secure" olduğu anlamına gelmez. Security model'in farklı olduğu anlamına gelir. Rootless execution, user namespace'ler, varsayılan seccomp, strict bir capability set, host namespace paylaşımı olmaması ve güçlü SELinux veya AppArmor enforcement içeren, iyi yapılandırılmış bir container stack'i oldukça sağlam olabilir. Buna karşılık `--privileged`, host PID/network sharing, içine Docker socket mount edilmiş ve `/` için writable bind mount kullanılmış bir container, güvenli şekilde izole edilmiş bir application sandbox'ından çok host root access'e yakındır. Fark, etkinleştirilen veya devre dışı bırakılan layer'larda ortaya çıkar.

Okuyucuların anlaması gereken bir orta nokta da vardır; çünkü bu yaklaşım gerçek ortamlarda giderek daha sık görülmektedir. **Sandboxed container runtime'ları** olan **gVisor** ve **Kata Containers**, classic `runc` container'ının ötesinde boundary'yi bilinçli olarak güçlendirir. gVisor, workload ile birçok host kernel interface'i arasına bir userspace kernel layer yerleştirirken Kata, workload'u lightweight bir virtual machine içinde başlatır. Bunlar hâlâ container ecosystem'leri ve orchestration workflow'ları üzerinden kullanılır; ancak security özellikleri plain OCI runtime'larından farklıdır ve her şey aynı şekilde davranıyormuş gibi zihinsel olarak "normal Docker container'ları" grubuna dahil edilmemelidir.

## Container Stack'i: Tek Bir Layer Değil, Birkaç Layer

Birisi "bu container insecure" dediğinde sorulması gereken yararlı devam sorusu şudur: **onu hangi layer insecure hâle getirdi?** Containerized bir workload genellikle birlikte çalışan birkaç component'in sonucudur.

En üstte çoğu zaman OCI image'ını ve metadata'yı oluşturan BuildKit, Buildah veya Kaniko gibi bir **image build layer** bulunur. Low-level runtime'ın üzerinde Docker Engine, Podman, containerd, CRI-O, Incus veya systemd-nspawn gibi bir **engine veya manager** olabilir. Cluster ortamlarında Kubernetes gibi bir **orchestrator** da workload configuration üzerinden talep edilen security posture'u belirleyebilir. Son olarak, namespace'leri, cgroup'ları, seccomp'u ve MAC policy'yi gerçekten enforce eden **kernel**'dir.

Bu layered model, default'ları anlamak açısından önemlidir. Bir restriction Kubernetes tarafından talep edilebilir, CRI üzerinden containerd veya CRI-O tarafından çevrilebilir, runtime wrapper tarafından bir OCI spec'e dönüştürülebilir ve ancak bundan sonra `runc`, `crun`, `runsc` veya başka bir runtime tarafından kernel'e karşı enforce edilebilir. Ortamlar arasındaki default'lar farklı olduğunda bunun nedeni çoğunlukla bu layer'lardan birinin final configuration'ı değiştirmiş olmasıdır. Bu nedenle aynı mekanizma Docker veya Podman'da bir CLI flag'i, Kubernetes'te bir Pod veya `securityContext` field'ı ve lower-level runtime stack'lerinde workload için oluşturulan OCI configuration olarak görünebilir. Bu yüzden bu section'daki CLI örnekleri, her tool tarafından desteklenen universal flag'ler olarak değil, **genel bir container konsepti için runtime-specific syntax** olarak okunmalıdır.

## Gerçek Container Security Boundary'si

Pratikte container security, tek bir kusursuz control'den değil, **overlapping control'lerden** oluşur. Namespace'ler görünürlüğü izole eder. cgroup'lar resource kullanımını yönetir ve sınırlar. Capabilities, privileged görünen bir process'in gerçekte neler yapabileceğini azaltır. seccomp, tehlikeli syscall'ları kernel'e ulaşmadan önce engeller. AppArmor ve SELinux, normal DAC check'lerinin üzerine Mandatory Access Control ekler. `no_new_privs`, masked procfs path'leri ve read-only system path'leri yaygın privilege ve proc/sys abuse chain'lerini zorlaştırır. Runtime'ın kendisi de önemlidir; çünkü mount'ların, socket'lerin, label'ların ve namespace join'lerinin nasıl oluşturulacağına o karar verir.

Bu nedenle container security documentation'ının büyük bir bölümü tekrarlı gibi görünür. Aynı escape chain çoğu zaman aynı anda birden fazla mekanizmaya bağlıdır. Örneğin writable bir host bind mount kötüdür; ancak container aynı zamanda host üzerinde gerçek root olarak çalışıyorsa, `CAP_SYS_ADMIN` içeriyorsa, seccomp tarafından unconfined durumdaysa ve SELinux veya AppArmor tarafından kısıtlanmıyorsa bu durum çok daha tehlikeli hâle gelir. Benzer şekilde host PID sharing ciddi bir exposure'dır; ancak `CAP_SYS_PTRACE`, zayıf procfs protections veya `nsenter` gibi namespace-entry tool'larıyla birleştirildiğinde attacker için çok daha yararlı hâle gelir. Bu nedenle konuyu document etmenin doğru yolu, aynı attack'ı her page'de tekrarlamak değil, her layer'ın final boundary'ye ne kattığını açıklamaktır.

## Bu Section Nasıl Okunmalı?

Section, en genel konseptlerden en spesifik olanlara doğru düzenlenmiştir.

Runtime ve ecosystem overview ile başlayın:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Ardından, bir attacker'ın kernel escape'e ihtiyaç duyup duymayacağını sıkça belirleyen control plane'leri ve supply-chain surface'lerini inceleyin:

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

Namespace page'leri kernel isolation primitive'lerini ayrı ayrı açıklar:

{{#ref}}
protections/namespaces/
{{#endref}}

cgroup'lar, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked path'ler ve read-only system path'leri hakkındaki page'ler, genellikle namespace'lerin üzerine layered edilen mekanizmaları açıklar:

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

Containerized bir target'ı değerlendirirken, doğrudan ünlü escape PoC'lerine atlamak yerine küçük bir dizi kesin teknik soru sormak çok daha yararlıdır. Önce **stack**'i belirleyin: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer veya daha specialized bir şey. Ardından **runtime**'ı belirleyin: `runc`, `crun`, `runsc`, `kata-runtime` veya başka bir OCI-compatible implementation. Bundan sonra ortamın **rootful veya rootless** olup olmadığını, **user namespace**'lerin etkin olup olmadığını, herhangi bir **host namespace**'in paylaşılıp paylaşılmadığını, hangi **capability**'lerin kaldığını, **seccomp**'un etkin olup olmadığını, bir **MAC policy**'nin gerçekten enforcement yapıp yapmadığını, **dangerous mount veya socket** bulunup bulunmadığını ve process'in container runtime API ile etkileşime girip giremediğini kontrol edin.

Bu cevaplar, gerçek security posture hakkında base image adının verebileceğinden çok daha fazla bilgi sağlar. Birçok assessment'ta, tek bir application file okumadan önce bile final container configuration'ı anlayarak olası breakout family'sini tahmin edebilirsiniz.

## Kapsam

Bu section, eski Docker-focused materyali container-oriented bir organization altında kapsar: runtime ve daemon exposure, authorization plugins, image trust ve build secrets, sensitive host mounts, distroless workload'lar, privileged container'lar ve container execution çevresinde normalde layered edilen kernel protections.

{{#include ../../../banners/hacktricks-training.md}}
