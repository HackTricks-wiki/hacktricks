# Konteyner Güvenliği

{{#include ../../../banners/hacktricks-training.md}}

## Bir Konteyner Aslında Nedir

Pratik bir tanım şu: bir konteyner, belirli bir OCI tarzı konfigürasyon altında başlatılmış ve kontrollü bir dosya sistemi, kontrollü bir çekirdek kaynak kümesi ve kısıtlı bir ayrıcalık modeli gören **normal bir Linux süreç ağacı**dır. Süreç kendisinin PID 1 olduğuna inanabilir, kendi ağ yığınına sahip olduğunu düşünebilir, kendi hostname ve IPC kaynaklarının sahibi olduğunu sanabilir ve hatta kendi user namespace'i içinde root olarak çalışıyor olabilir. Ama perde arkasında hâlâ çekirdeğin diğer süreçler gibi zamanladığı bir host sürecidir.

Bu yüzden konteyner güvenliği aslında o illüzyonun nasıl inşa edildiğinin ve nasıl başarısız olduğunun incelenmesidir. Eğer mount namespace zayıfsa, süreç host dosya sistemini görebilir. Eğer user namespace yoksa veya devre dışıysa, konteyner içindeki root hosttaki root ile çok yakın şekilde eşleşebilir. Eğer seccomp kısıtlanmamışsa ve capability set çok genişse, süreç çekirdeğe ulaşmaması gereken syscal lara ve ayrıcalıklı kernel özelliklerine erişebilir. Eğer runtime socket konteyner içine mount edildiyse, konteynerin kernel breakout'una bile ihtiyacı olmayabilir çünkü runtime'dan daha güçlü bir kardeş konteyner başlatmasını ya da doğrudan host root filesystem'ini mount etmesini isteyebilir.

## Konteynerler Sanal Makinelerden Nasıl Farklıdır

Bir VM normalde kendi kernel'ini ve donanım soyutlama sınırını taşır. Bu, guest kernel'in çökebileceği, panic yapabileceği veya exploitlenebileceği anlamına gelir; bu durum otomatik olarak host kernel üzerinde doğrudan kontrol elde edildiği anlamına gelmez. Konteynerlerde ise iş yükü ayrı bir kernel almaz. Bunun yerine, hostun kullandığı aynı kernel'in dikkatle filtrelenmiş ve namespaced bir görünümünü elde eder. Sonuç olarak, konteynerler genellikle daha hafif, daha hızlı başlar, bir makinede daha yoğun paketlenmesi kolaydır ve kısa ömürlü uygulama dağıtımı için daha uygundur. Bedeli ise izolasyon sınırının doğru host ve runtime konfigürasyonuna çok daha doğrudan bağlı olmasıdır.

Bu, konteynerlerin "güvenli olmadığı" ve VM'lerin "güvenli olduğu" anlamına gelmez. Anlamı güvenlik modelinin farklı olduğudur. Rootless yürütme, user namespaces, varsayılan seccomp, sıkı bir capability seti, host namespace paylaşımının olmaması ve güçlü SELinux veya AppArmor uygulaması olan iyi yapılandırılmış bir konteyner yığını çok sağlam olabilir. Tersine, `--privileged` ile başlatılmış, host PID/ağ paylaşımı olan, Docker socket'in içinde mount edildiği ve `/` için yazılabilir bind mount bulunan bir konteyner işlevsel olarak güvenli izole bir uygulama sandbox'ından ziyade host root erişimine çok daha yakın olur. Fark, hangi katmanların etkinleştirildiği veya devre dışı bırakıldığı ile ilgilidir.

Okuyucuların anlaması gereken bir orta yol da vardır çünkü gerçek ortamlarda giderek daha sık görülür. **Sandboxed container runtimes** gibi **gVisor** ve **Kata Containers** kasıtlı olarak klasik bir `runc` konteynerinin ötesinde sınırı sertleştirir. gVisor, iş yükü ile birçok host kernel arayüzü arasında bir userspace kernel katmanı koyarken, Kata iş yükünü hafif bir sanal makine içinde başlatır. Bunlar hala konteyner ekosistemleri ve orkestrasyon iş akışları aracılığıyla kullanılır, ancak güvenlik özellikleri sade OCI runtime'lardan farklıdır ve "normal Docker konteynerleri" ile zihnen aynı gruba konmamalıdır.

## Konteyner Yığını: Birkaç Katman, Tek Katman Değil

Birisi "bu konteyner güvensiz" dediğinde, faydalı takip sorusu şudur: **hangi katman onu güvensiz yaptı?** Konteynerize iş yükü genellikle bir arada çalışan birkaç bileşenin sonucudur.

En üstte sıklıkla BuildKit, Buildah veya Kaniko gibi bir **image build layer** bulunur; bunlar OCI imajını ve metadata'yı oluşturur. Düşük seviyeli runtime'ın üzerinde Docker Engine, Podman, containerd, CRI-O, Incus veya systemd-nspawn gibi bir **engine veya manager** olabilir. Küme ortamlarında, istenen güvenlik duruşunu workload konfigürasyonu aracılığıyla belirleyen Kubernetes gibi bir **orchestrator** da olabilir. Son olarak, gerçek anlamda namespaces, cgroups, seccomp ve MAC politikasını uygulayan çekirdektir.

Bu katmanlı model, varsayılanları anlamak için önemlidir. Bir kısıtlama Kubernetes tarafından istenebilir, CRI aracılığıyla containerd veya CRI-O tarafından çevrilebilir, runtime wrapper tarafından bir OCI spesifikasyonuna dönüştürülebilir ve ancak daha sonra `runc`, `crun`, `runsc` veya başka bir runtime tarafından çekirdeğe karşı uygulanır. Ortamlar arasındaki varsayılanlar farklıysa, genellikle bu katmanlardan birinin nihai konfigürasyonu değiştirmesindendir. Aynı mekanizma bu nedenle Docker veya Podman'da bir CLI bayrağı, Kubernetes'te bir Pod veya `securityContext` alanı ve daha düşük seviyeli runtime yığınlarında iş yükü için oluşturulmuş OCI konfigürasyonu olarak görünebilir. Bu nedenle, bu bölümdeki CLI örnekleri genel bir konteyner kavramı için runtime-spesifik sözdizimi olarak okunmalıdır, her aracın desteklediği evrensel bayraklar olarak değil.

## Gerçek Konteyner Güvenlik Sınırı

Pratikte, konteyner güvenliği tek bir mükemmel kontrolden değil, **örtüşen kontrollerden** gelir. Namespaces görünürlüğü izole eder. cgroups kaynak kullanımını yönetir ve sınırlar. Capabilities, ayrıcalıklı görünen bir sürecin gerçekte neler yapabileceğini azaltır. seccomp tehlikeli syscal ları çekirdeğe ulaşmadan engeller. AppArmor ve SELinux normal DAC kontrollerinin üzerine Mandatory Access Control ekler. `no_new_privs`, masked procfs yolları ve salt okunur sistem yolları, yaygın ayrıcalık yükseltme ve proc/sys kötüye kullanım zincirlerini zorlaştırır. Runtime kendisi de önemlidir çünkü mount'ların, socket'lerin, etiketlerin ve namespace join'lerin nasıl oluşturulacağına karar verir.

Bu yüzden birçok konteyner güvenliği dokümantasyonu tekrar ediyormuş gibi görünür. Aynı escape zinciri genellikle birden fazla mekanizmaya aynı anda bağlıdır. Örneğin, yazılabilir bir host bind mount kötüdür, ancak konteyner aynı zamanda host üzerinde gerçek root olarak çalışıyorsa, `CAP_SYS_ADMIN`'e sahipse, seccomp tarafından kısıtlanmamışsa ve SELinux veya AppArmor tarafından sınırlandırılmamışsa çok daha kötü hale gelir. Benzer şekilde, host PID paylaşımı ciddi bir açıklıktır, fakat bu, `CAP_SYS_PTRACE`, zayıf procfs korumaları veya `nsenter` gibi namespace-giriş araçları ile birleştirildiğinde saldırgan için dramatik şekilde daha faydalı olur. Konuyu belgelemenin doğru yolu bu yüzden aynı saldırıyı her sayfada tekrarlamak değil, her katmanın nihai sınıra ne katkıda bulunduğunu açıklamaktır.

## Bu Bölüm Nasıl Okunur

Bölüm en genel kavramlardan en spesifik olanlara doğru düzenlenmiştir.

Başlangıç olarak runtime ve ekosistem genel bakışı ile başlayın:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Sonra bir saldırganın gerçekten bir kernel escape ihtiyacı olup olmadığını sıkça belirleyen kontrol düzlemlerini ve tedarik zinciri yüzeylerini gözden geçirin:

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

Ardından koruma modeline geçin:

{{#ref}}
protections/
{{#endref}}

Namespace sayfaları kernel izolasyon ilkelini tek tek açıklar:

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths ve salt okunur sistem yolları üzerine olan sayfalar, genellikle namespaces üzerine katmanlanan mekanizmaları açıklar:

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

## İyi Bir İlk Enumeration Zihniyeti

Bir konteyner hedefini değerlendirirken, ünlü escape PoC'larına hemen atlamak yerine küçük ve kesin teknik sorular sormak çok daha faydalıdır. Önce **stack**'i belirleyin: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer veya daha özelleşmiş bir şey mi? Sonra **runtime**'ı belirleyin: `runc`, `crun`, `runsc`, `kata-runtime` veya başka bir OCI-uyumlu uygulama mı? Bundan sonra ortamın **rootful** veya **rootless** olup olmadığına, **user namespaces**'in aktif olup olmadığına, herhangi bir **host namespace** paylaşımının olup olmadığına, hangi **capabilities**'lerin kaldığına, **seccomp**'un etkin olup olmadığına, bir **MAC policy**'nin gerçekten uygulayıp uygulamadığına, hangi **tehlikeli mountlar veya socketler**in mevcut olduğuna ve sürecin container runtime API ile etkileşime girip giremeyeceğine bakın.

Bu cevaplar gerçek güvenlik duruşu hakkında base image adının asla söylemeyeceğinden çok daha fazlasını söyler. Birçok değerlendirmede, tek bir uygulama dosyasını okumadan önce yalnızca nihai konteyner konfigürasyonunu anlayarak olası breakout ailesini tahmin edebilirsiniz.

## Kapsam

Bu bölüm, konteyner odaklı organizasyon altında eski Docker merkezli materyali kapsar: runtime ve daemon exposure, authorization plugins, image trust ve build secrets, sensitive host mounts, distroless iş yükleri, privileged containers ve genellikle konteyner yürütmesi etrafına katmanlanan kernel korumaları.
{{#include ../../../banners/hacktricks-training.md}}
