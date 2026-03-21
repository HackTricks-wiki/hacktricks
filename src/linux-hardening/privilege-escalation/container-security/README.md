# Konteyner Güvenliği

{{#include ../../../banners/hacktricks-training.md}}

## Bir Konteyner Aslında Nedir

Pratik bir tanım: bir konteyner, kontrollü bir dosya sistemi, kontrollü bir kernel kaynağı seti ve kısıtlı bir ayrıcalık modeli görecek şekilde belirli bir OCI tarzı konfigürasyon altında başlatılmış **normal bir Linux süreç ağacı**dır. Süreç kendisinin PID 1 olduğunu, kendi network yığınına sahip olduğunu, kendi hostname ve IPC kaynaklarının sahibi olduğunu ve hatta kendi user namespace içinde root olarak çalıştığını düşünebilir. Ancak perde arkasında hala kernel'in diğer süreçleri gibi zamanladığı bir host sürecidir.

Bu yüzden konteyner güvenliği aslında o illüzyonun nasıl inşa edildiğini ve nasıl hata verdiğini incelemektir. Eğer mount namespace zayıfsa süreç host dosya sistemini görebilir. Eğer user namespace yoksa veya devre dışıysa konteyner içindeki root, host üzerindeki root ile çok yakın eşleşebilir. Eğer seccomp sınırlı değilse ve capability seti çok genişse süreç ulaşmaması gereken syscalls ve ayrıcalıklı kernel özelliklerine erişebilir. Eğer runtime socket konteyner içine mount edildiyse konteynerin kernel breakout'u bile gerekmeyebilir çünkü runtime'dan daha güçlü bir kardeş konteyner başlatmasını veya doğrudan host root filesystem'ini mount etmesini isteyebilir.

## Konteynerler ile Sanal Makineler Arasındaki Fark

Bir VM normalde kendi kernel'ini ve donanım soyutlama sınırını taşır. Bu, guest kernel'in çökmesi, panic olması veya exploit edilmesinin otomatik olarak host kernel üzerinde doğrudan kontrol anlamına gelmeyeceği demektir. Konteynerlerde iş yükü ayrı bir kernel sahibi olmaz. Bunun yerine host'un kullandığı aynı kernel'e filtrelenmiş ve namespaced bir görünüm elde eder. Sonuç olarak, konteynerler genellikle daha hafif, başlatmaları daha hızlı, bir makinede yoğun şekilde paketlenmeleri daha kolay ve kısa ömürlü uygulama dağıtımına daha uygun olur. Bedel, izolasyon sınırının doğru host ve runtime konfigürasyonuna çok daha doğrudan bağlı olmasıdır.

Bu, konteynerlerin "güvensiz" ve VM'lerin "güvenli" olduğu anlamına gelmez. Anlamı, güvenlik modelinin farklı olduğudur. rootless execution, user namespaces, varsayılan seccomp, katı capability seti, host namespace paylaşımının olmaması ve güçlü SELinux veya AppArmor uygulaması ile iyi yapılandırılmış bir konteyner yığını çok sağlam olabilir. Tersine, `--privileged` ile başlatılmış, host PID/network paylaşımı olan, Docker socket'i içinde mount edilmiş ve `/`'in yazılabilir bind mount'u olduğu bir konteyner işlevsel olarak güvenli izolasyondan ziyade host root erişimine çok daha yakın olur. Fark, etkinleştirilen veya devre dışı bırakılan katmanlardan kaynaklanır.

Ayrıca gerçek ortamda giderek daha sık görülen bir orta yol vardır. gVisor ve Kata Containers gibi sandboxed container runtimes kasıtlı olarak sınırı klasik bir `runc` konteynerinin ötesinde sertleştirir. gVisor, iş yükü ile birçok host kernel arayüzü arasında bir userspace kernel katmanı yerleştirirken, Kata işi hafif bir VM içinde başlatır. Bunlar hâlâ container ekosistemleri ve orkestrasyon iş akışları üzerinden kullanılır, fakat güvenlik özellikleri düz OCI runtime'lardan farklıdır ve "normal Docker konteynerleri" ile aynı şekilde davranıyormuş gibi zihinsel olarak gruplanmamalıdır.

## Konteyner Yığını: Tek Katman Değil, Birkaç Katman

Birisi "bu konteyner güvensiz" dediğinde faydalı takip sorusu şudur: **hangi katman onu güvensiz yaptı?** Bir konteynerleştirilmiş işyükü genellikle birlikte çalışan birkaç bileşenin sonucudur.

Üstte genellikle BuildKit, Buildah veya Kaniko gibi bir **image build layer** vardır; bu katman OCI image ve metadata'yı oluşturur. Düşük seviyeli runtime'ın üzerinde Docker Engine, Podman, containerd, CRI-O, Incus veya systemd-nspawn gibi bir **engine veya manager** olabilir. Küme ortamlarında, Kubernetes gibi bir **orchestrator** da işyükü konfigürasyonu yoluyla istenen güvenlik duruşunu kararlaştırıyor olabilir. Son olarak, **kernel** namespaces, cgroups, seccomp ve MAC politikasını fiilen uygulayan noktadır.

Bu katmanlı model varsayılanları anlamak için önemlidir. Bir kısıtlama Kubernetes tarafından istenebilir, CRI aracılığıyla containerd veya CRI-O tarafından çevrilebilir, runtime wrapper tarafından bir OCI spec'e dönüştürülebilir ve ancak o zaman `runc`, `crun`, `runsc` veya başka bir runtime tarafından kernel'e karşı uygulanır. Varsayılanlar ortamlar arasında farklılık gösterdiğinde, sıklıkla bu katmanlardan birinin son konfigürasyonu değiştirmiş olması nedenidir. Aynı mekanizma bu yüzden Docker veya Podman'da bir CLI flag'i, Kubernetes'te bir Pod veya `securityContext` alanı ve daha düşük seviyeli runtime yığınlarında işyükü için oluşturulmuş OCI konfigürasyonu olarak görünebilir. Bu nedenle bu bölümdeki CLI örnekleri genel bir konteyner kavramı için **runtime-spesifik sözdizimi** olarak okunmalıdır, her aracın desteklediği evrensel flag'ler olarak değil.

## Gerçek Konteyner Güvenlik Sınırı

Pratikte, konteyner güvenliği tek bir mükemmel kontrolden değil, **örtüşen kontrollerden** gelir. Namespaces görünürlüğü izole eder. cgroups kaynak kullanımını yönetir ve sınırlar. Capabilities ayrıcalıklı görünen bir sürecin gerçekten neler yapabileceğini azaltır. seccomp tehlikeli syscalls'un kernel'e ulaşmadan önce engeller. AppArmor ve SELinux normal DAC kontrollerinin üzerine Mandatory Access Control ekler. `no_new_privs`, masked procfs paths ve read-only system paths ortak ayrıcalık ve proc/sys kötüye kullanım zincirlerini zorlaştırır. Runtime'ın kendisi de önemlidir çünkü mount'ların, socket'lerin, label'ların ve namespace join'lerin nasıl oluşturulacağını belirler.

Bu yüzden birçok konteyner güvenliği dokümanı tekrara kaçıyor gibi görünür. Aynı escape zinciri genellikle birden fazla mekanizmaya aynı anda dayanır. Örneğin, yazılabilir bir host bind mount kötüdür, ama konteyner aynı zamanda host üzerinde gerçek root olarak çalışıyorsa, `CAP_SYS_ADMIN`'a sahipse, seccomp ile sınırlanmamışsa ve SELinux veya AppArmor tarafından kısıtlanmamışsa çok daha kötü hale gelir. Benzer şekilde, host PID paylaşımı ciddi bir açığa neden olur, ancak bu `CAP_SYS_PTRACE`, zayıf procfs korumaları veya `nsenter` gibi namespace-entry araçlarıyla birleştiğinde bir saldırgan için dramatik şekilde daha kullanışlı olur. Konuyu belgelemek için doğru yol bu yüzden aynı saldırıyı her sayfada tekrarlamak değil, her katmanın nihai sınır üzerindeki katkısını açıklamaktır.

## Bu Bölüm Nasıl Okunmalı

Bölüm en genel kavramlardan en spesifik olanlara doğru organize edilmiştir.

Önce runtime ve ekosistem genel bakışı ile başlayın:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Sonra bir saldırganın gerçekten bir kernel escape'a ihtiyaç duyup duymayacağını sıkça belirleyen kontrol düzlemlerini ve supply-chain yüzeylerini gözden geçirin:

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

Namespace sayfaları kernel izolasyon ilkellerini bireysel olarak açıklar:

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths ve read-only system paths hakkındaki sayfalar genellikle namespaces'in üzerine katmanlanan mekanizmaları açıklar:

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

Konteynerleştirilmiş bir hedefi değerlendirirken, meşhur escape PoC'lerine hemen atlamak yerine küçük bir dizi kesin teknik soru sormak çok daha faydalıdır. Önce **stack**'i belirleyin: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer veya daha özelleşmiş bir şey mi? Sonra **runtime**'ı belirleyin: `runc`, `crun`, `runsc`, `kata-runtime` veya başka bir OCI-uyumlu implementasyon mu? Bundan sonra ortamın **rootful veya rootless** olup olmadığını, **user namespaces** aktif mi, herhangi bir **host namespace** paylaşılıyor mu, hangi **capabilities** kalmış, **seccomp** etkin mi, bir **MAC policy** gerçekten enforcement yapıyor mu, herhangi bir **tehlikeli mount veya socket** var mı ve süreç container runtime API ile etkileşim kurabiliyor mu diye kontrol edin.

Bu cevaplar gerçek güvenlik duruşu hakkında base image isminden çok daha fazlasını söyler. Birçok değerlendirmede, tek bir uygulama dosyası okumadan önce son konteyner konfigürasyonunu anlayarak muhtemel breakout ailesini tahmin edebilirsiniz.

## Kapsam

Bu bölüm, container-odaklı organizasyon altında eski Docker-odaklı materyali kapsar: runtime ve daemon exposure, authorization plugins, image trust ve build secrets, sensitive host mounts, distroless workloads, privileged containers ve normalde konteyner yürütmenin etrafına katmanlanan kernel korumaları.
