# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Container güvenliğindeki en büyük kafa karışıklığı kaynaklarından biri, birbirinden tamamen farklı birkaç bileşenin sıklıkla aynı kelimeyle anılmasıdır. “Docker” bir image formatını, CLI’ı, daemon’ı, build sistemini, runtime stack’ini ya da genel olarak container kavramını ifade edebilir. Güvenlik çalışmaları açısından bu belirsizlik bir sorundur; çünkü farklı katmanlar farklı korumalardan sorumludur. Hatalı bir bind mount nedeniyle gerçekleşen breakout, düşük seviyeli bir runtime bug’ının neden olduğu breakout ile aynı şey değildir; ikisi de Kubernetes’teki bir cluster policy hatasıyla aynı değildir.

Bu sayfada ekosistem, bileşenlerin rollerine göre ayrılıyor. Böylece bölümün geri kalanında bir korumanın ya da zayıflığın gerçekte hangi katmanda bulunduğundan kesin olarak söz edilebilir.

## OCI As The Common Language

Modern Linux container stack’leri genellikle bir dizi OCI spesifikasyonunu kullandıkları için birlikte çalışabilir. **OCI Image Specification**, image’ların ve katmanların nasıl temsil edildiğini tanımlar. **OCI Runtime Specification**, namespace’ler, mount’lar, cgroup’lar ve güvenlik ayarları da dahil olmak üzere runtime’ın süreci nasıl başlatması gerektiğini tanımlar. **OCI Distribution Specification** ise registry’lerin içeriği nasıl sunacağını standartlaştırır.

Bu, bir araçla oluşturulan container image’ının neden sıklıkla başka bir araçla çalıştırılabildiğini ve birkaç engine’in neden aynı düşük seviyeli runtime’ı paylaşabildiğini açıklar. Ayrıca güvenlik davranışının farklı ürünlerde neden benzer görünebildiğini de açıklar: Bunların çoğu aynı OCI runtime yapılandırmasını oluşturup aynı küçük runtime kümesine iletiyor.

## Low-Level OCI Runtimes

Düşük seviyeli runtime, kernel sınırına en yakın bileşendir. Namespace’leri gerçekten oluşturan, cgroup ayarlarını yazan, capabilities ve seccomp filtrelerini uygulayan ve son olarak container sürecinde `execve()` çağıran bileşen budur. İnsanlar “container isolation” konusunu mekanik açıdan tartışırken, açıkça söylemeseler bile genellikle bu katmandan bahsederler.

### `runc`

`runc`, referans OCI runtime’ıdır ve en iyi bilinen uygulama olmaya devam etmektedir. Docker, containerd ve birçok Kubernetes dağıtımında yoğun şekilde kullanılır. Yaygın olduğu ve Linux container denince birçok kişinin aklına gelen temel modeli belirlediği için, kamuya açık araştırmaların ve exploit materyallerinin önemli bir kısmı `runc` tarzı ortamları hedefler. Bu nedenle `runc`’ı anlamak, klasik container isolation için güçlü bir zihinsel model sağlar.

### `crun`

`crun`, C ile yazılmış ve modern Podman ortamlarında yaygın olarak kullanılan başka bir OCI runtime’ıdır. İyi cgroup v2 desteği, güçlü rootless kullanım kolaylığı ve daha düşük ek yükü nedeniyle sıkça övülür. Güvenlik açısından önemli olan, farklı bir dilde yazılmış olması değil, aynı rolü üstlenmesidir: OCI yapılandırmasını alıp kernel altında çalışan bir süreç ağacına dönüştüren bileşendir. Rootless Podman iş akışının daha güvenli hissettirmesi çoğu zaman `crun`’ın her şeyi sihirli bir şekilde düzeltmesinden değil, etrafındaki genel stack’in user namespace’lere ve least privilege’a daha fazla dayanmasından kaynaklanır.

### `runsc` From gVisor

`runsc`, gVisor tarafından kullanılan runtime’dır. Burada sınırın anlamı önemli ölçüde değişir. gVisor, çoğu syscall’ı alışılmış şekilde doğrudan host kernel’e iletmek yerine, Linux arayüzünün büyük bir kısmını emüle eden veya denetleyen bir userspace kernel katmanı ekler. Sonuç, birkaç ek flag içeren sıradan bir `runc` container’ı değildir; host kernel’in saldırı yüzeyini azaltmayı amaçlayan farklı bir sandbox tasarımıdır. Uyumluluk ve performans ödünleşimleri bu tasarımın bir parçasıdır. Bu nedenle `runsc` kullanan ortamlar, normal OCI runtime ortamlarından farklı şekilde belgelenmelidir.

### `kata-runtime`

Kata Containers, workload’u hafif bir virtual machine içinde başlatarak sınırı daha da ileri taşır. Yönetim açısından bu hâlâ bir container dağıtımı gibi görünebilir ve orchestration katmanları da bunu bu şekilde ele alabilir; ancak temeldeki isolation sınırı, klasik host kernel’ini paylaşan bir container’dan çok virtualization’a yakındır. Bu da Kata’yı, container odaklı iş akışlarından vazgeçmeden daha güçlü tenant isolation isteyenler için kullanışlı kılar.

## Engines And Container Managers

Düşük seviyeli runtime kernel ile doğrudan konuşan bileşense, engine veya manager genellikle kullanıcıların ve operatörlerin etkileşim kurduğu bileşendir. Image indirmelerini, metadata’yı, log’ları, network’leri, volume’leri, lifecycle işlemlerini ve API erişimini yönetir. Bu katman son derece önemlidir; çünkü gerçek dünyadaki birçok ihlal burada gerçekleşir: Runtime socket’ine veya daemon API’sine erişim, düşük seviyeli runtime tamamen sağlıklı olsa bile host’un ele geçirilmesine eşdeğer olabilir.

### Docker Engine

Docker Engine, geliştiricilerin en iyi tanıdığı container platformudur ve container terminolojisinin Docker biçiminde şekillenmesinin nedenlerinden biridir. Yaygın iş akışı `docker` CLI’dan `dockerd`’a, oradan da `containerd` ve bir OCI runtime gibi daha düşük seviyeli bileşenlerin yönetimine uzanır. Docker dağıtımları tarihsel olarak çoğunlukla **rootful** olmuştur; bu nedenle Docker socket’ine erişim çok güçlü bir yetkidir. Pratik privilege-escalation materyallerinin büyük kısmının `docker.sock`’a odaklanmasının nedeni budur: Bir süreç `dockerd`’dan privileged bir container oluşturmasını, host path’lerini mount etmesini veya host namespace’lerine katılmasını isteyebiliyorsa kernel exploit’ine hiç ihtiyaç duymayabilir.

Release numaralarını noktaları kaldırarak değil, major, minor ve patch bileşenlerine göre karşılaştırın: `18.09.1`, sıfırla doldurulmuş minor bileşenine rağmen hem `18.09.2` hem de `18.09.4` sürümünden eskidir. Docker’ın [18.09 release notes](https://docs.docker.com/engine/release-notes/18.09/) sayfasında CVE-2019-5736 için `runc` düzeltmesinin 18.09.2’de, CVE-2019-13139 için build-reference düzeltmesinin ise 18.09.4’te dahil edildiği belirtilir. Bunlar, erişilebilir bir exploit’in kanıtı değil, sürüme dayalı ipuçlarıdır. Aynı release notes, daemon, client ve runtime’ın ayrı paketlendiği konusunda uyarır. Bu nedenle daemon sürümünün yanı sıra kurulu runtime’ı ve vendor backport’larını da kontrol edin; build-reference sorunundan etkilenmek için ayrıca etkilenen build workflow’una erişim ve saldırgan kontrollü girdi gerekir.

### Podman

Podman, daemon’sız bir model temel alınarak tasarlanmıştır. Operasyonel açıdan bu, container’ların uzun süre çalışan tek bir privileged daemon yerine standart Linux mekanizmalarıyla yönetilen süreçler olduğu fikrini pekiştirmeye yardımcı olur. Podman ayrıca birçok kişinin ilk öğrendiği klasik Docker dağıtımlarına kıyasla çok daha güçlü bir **rootless** yaklaşım sunar. Bu, Podman’ı otomatik olarak güvenli yapmaz; ancak özellikle user namespace’ler, SELinux ve `crun` ile birlikte kullanıldığında varsayılan risk profilini önemli ölçüde değiştirir.

### containerd

containerd, birçok modern stack’te kullanılan temel bir runtime yönetimi bileşenidir. Docker’ın altında kullanılır ve Kubernetes’in baskın runtime backend’lerinden biridir. Güçlü API’ler sunar, image’ları ve snapshot’ları yönetir, son süreç oluşturma işini ise düşük seviyeli bir runtime’a devreder. containerd hakkındaki güvenlik tartışmalarında, arayüz ve iş akışı daha az “geliştirici dostu” görünse bile containerd socket’ine veya `ctr`/`nerdctl` işlevlerine erişimin Docker API’sine erişmek kadar tehlikeli olabileceği vurgulanmalıdır.

### CRI-O

CRI-O, Docker Engine’den daha dar kapsamlıdır. Genel amaçlı bir geliştirici platformu olmak yerine, Kubernetes Container Runtime Interface’ini doğru şekilde uygulamak üzere tasarlanmıştır. Bu nedenle Kubernetes dağıtımlarında ve OpenShift gibi SELinux’un yoğun kullanıldığı ekosistemlerde özellikle yaygındır. Güvenlik açısından bu dar kapsam yararlıdır; çünkü kavramsal karmaşayı azaltır: CRI-O, her şeyi kapsayan bir platformdan çok “Kubernetes için container çalıştırma” katmanının bir parçasıdır.

Bir Kubernetes node’u CRI-O kullanıyorsa, **node’un etkin CRI-O release’ini** ve mevcut kimliğin bu node’a schedule edilen bir namespace’te Pod oluşturup oluşturamadığını kontrol edin. [CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7), etkilenen sürümlerde işlenmiş Pod sysctl değerlerinin host kernel parametresini değiştirmesine ve host-root yetkisine ulaşmasına olanak tanıyordu. Upstream advisory, yamalı sürümleri ve geçici çözümleri listeler. Yerel `crio --version` çıktısı, Minikube veya başka bir node container’ının içindeki runtime’ı göstermeyebilir. Minikube’un okunabilir başlangıç log’u sürüm için ipucu sağlayabilir, ancak bu geçmişe ait kanıttır; çalışan runtime’ın veya yama durumunun kanıtı değildir. Bu durumu erişilebilir bir yetki yükseltme yolu olarak değerlendirmeden önce gerçek node runtime’ını, Pod oluşturma yetkisini, admission kurallarını ve ilgili seccomp ile user namespace sınırlarını doğrulayın.

Ayrıca doğrudan yerel bir `pinns` inceleme yolu da vardır: [araştırmacılar, hatalı helper’ı çalıştırmak için Kubernetes gerekmediğini belirtiyor](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). Mevcut hesabın root’a ait setuid `pinns` dosyasını çalıştırıp çalıştıramadığını, NoNewPrivs veya `nosuid` mount’un bu geçişi engelleyip engellemediğini ve kurulu **helper build’ında** düzeltmenin bulunup bulunmadığını kontrol edin. [Upstream advisory](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7), yamalı release sürümlerini listeler; ancak daemon’ın gösterdiği sürüm tek başına hangi helper binary’sinin kurulu olduğunu kanıtlamaz ve distributor backport’ları etkilenme durumunu değiştirebilir. Setuid dosyası yalnızca incelenmeye değer bir adaydır; rutin enumeration sırasında çalıştırmadan helper’ın kaynağını, yapılandırmasını ve host sysctl davranışını doğrulayın.

### Incus, LXD, And LXC

Incus/LXD/LXC sistemlerini Docker tarzı application container’larından ayrı değerlendirmek gerekir; çünkü bunlar sıklıkla **system container** olarak kullanılır. Bir system container’dan genellikle daha kapsamlı bir userspace’e, uzun süre çalışan servislere, daha geniş cihaz erişimine ve host ile daha kapsamlı entegrasyona sahip hafif bir makine gibi davranması beklenir. Isolation mekanizmaları yine kernel primitive’leridir, ancak operasyonel beklentiler farklıdır. Bu nedenle buradaki yanlış yapılandırmalar çoğu zaman “hatalı app-container varsayılanları”ndan çok hafif virtualization veya host yetki devrindeki hatalara benzer.

### systemd-nspawn

systemd-nspawn, systemd’ye özgü olması ve test, debugging ve işletim sistemi benzeri ortamları çalıştırmak için oldukça kullanışlı olması nedeniyle ilginç bir yere sahiptir. Cloud-native üretim ortamlarında baskın runtime değildir, ancak lab’lerde ve dağıtım odaklı ortamlarda yeterince sık görülür; bu nedenle anılmayı hak eder. Güvenlik analizi açısından, “container” kavramının birden fazla ekosistemi ve operasyonel tarzı kapsadığını bir kez daha hatırlatır.

### Apptainer / Singularity

Apptainer (eski adıyla Singularity), araştırma ve HPC ortamlarında yaygındır. Güven varsayımları, kullanıcı iş akışı ve yürütme modeli, Docker/Kubernetes odaklı stack’lerden önemli ölçüde farklıdır. Özellikle bu ortamlarda, kullanıcılara geniş privileged container yönetimi yetkileri vermeden paketlenmiş workload’ları çalıştırma olanağı sunmak büyük önem taşır. Bir incelemeci her container ortamının temelde “bir sunucuda Docker” olduğunu varsayarsa, bu dağıtımları yanlış anlayacaktır.

## Build-Time Tooling

Güvenlik tartışmalarının çoğu yalnızca run time’ı ele alır; ancak build-time araçları da önemlidir, çünkü image içeriğini, build secret’larının açığa çıkma riskini ve son artifact’a ne kadar güvenilir bağlamın eklendiğini belirler.

**BuildKit** ve `docker buildx`, caching, secret mount’ları, SSH forwarding ve multi-platform build’ler gibi özellikleri destekleyen modern build backend’leridir. Bunlar kullanışlı özelliklerdir; ancak güvenlik açısından secret’ların image katmanlarına leak edebileceği veya gereğinden geniş bir build context’inin hiçbir zaman dahil edilmemesi gereken dosyaları açığa çıkarabileceği noktalar da oluştururlar. **Buildah**, OCI tabanlı ekosistemlerde, özellikle Podman etrafında benzer bir rol oynarken **Kaniko** genellikle build pipeline’ına privileged Docker daemon yetkisi vermek istemeyen CI ortamlarında kullanılır.

Temel ders, image oluşturma ve image çalıştırmanın farklı aşamalar olduğudur; ancak zayıf bir build pipeline’ı, container başlatılmadan çok önce zayıf bir runtime güvenlik duruşu yaratabilir.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes zihinsel olarak runtime’ın kendisiyle eşitlenmemelidir. Kubernetes orchestrator’dır. Pod’ları schedule eder, istenen durumu saklar ve workload yapılandırması aracılığıyla güvenlik policy’sini ifade eder. Ardından kubelet, containerd veya CRI-O gibi bir CRI uygulamasıyla konuşur; bu uygulama da `runc`, `crun`, `runsc` veya `kata-runtime` gibi düşük seviyeli bir runtime’ı çağırır.

Bu ayrım önemlidir; çünkü birçok kişi gerçekte node runtime’ı tarafından uygulanan bir korumayı yanlışlıkla “Kubernetes”e atfeder ya da Pod spec’inden kaynaklanan bir davranıştan “containerd varsayılanları”nı sorumlu tutar. Pratikte nihai güvenlik duruşu bir bileşimdir: Orchestrator bir şey ister, runtime stack’i bunu dönüştürür ve sonunda kernel uygular.

## Why Runtime Identification Matters During Assessment

Engine’i ve runtime’ı erkenden tespit ederseniz, sonraki gözlemlerin çoğunu yorumlamak kolaylaşır. Rootless Podman container’ı, user namespace’lerin muhtemelen önemli bir rolü olduğunu düşündürür. Bir workload’a mount edilmiş Docker socket’i, API üzerinden privilege escalation’ın gerçekçi bir yol olduğunu gösterir. CRI-O/OpenShift node’u, hemen SELinux label’larını ve restricted workload policy’sini akla getirmelidir. gVisor veya Kata ortamında ise klasik bir `runc` breakout PoC’sinin aynı şekilde çalışacağını varsayma konusunda daha temkinli olunmalıdır.

Container assessment’ın ilk adımlarından biri daima şu iki basit soruyu yanıtlamak olmalıdır: **Container’ı hangi bileşen yönetiyor** ve **süreci gerçekte hangi runtime başlattı**? Bu yanıtlar netleştiğinde ortamın geri kalanını anlamak genellikle çok daha kolaylaşır.

## Runtime Vulnerabilities

Her container escape, operatörün yanlış yapılandırmasından kaynaklanmaz. Bazen zayıf olan bileşen runtime’ın kendisidir. Bu önemlidir; çünkü dikkatli yapılandırılmış gibi görünen bir workload bile düşük seviyeli bir runtime açığı nedeniyle risk altında olabilir.

Klasik örnek, `runc` içindeki **CVE-2019-5736**’dır. Bu açıkta kötü amaçlı bir container, host’taki `runc` binary’sinin üzerine yazabilir ve ardından daha sonraki bir `docker exec` veya benzer runtime çağrısının saldırgan kontrollü kodu çalıştırmasını bekleyebilirdi. Bu exploit yolu, basit bir bind mount veya capability hatasından çok farklıdır; çünkü exec işlemi sırasında runtime’ın container süreç alanına yeniden girmesini nasıl kullandığını istismar eder.<sup>[[1]](#references)</sup>

Red-team açısından minimal bir reproduction iş akışı şöyledir:

```bash
go build main.go
./main
```

Ardından, host üzerinden:

```bash
docker exec -it <container-name> /bin/sh
```

Temel çıkarım, geçmişteki exploit’in tam olarak nasıl uygulandığı değil, güvenlik değerlendirmesine etkisidir: runtime sürümü savunmasızsa, görünür container yapılandırması bariz biçimde zayıf görünmese bile container içindeki sıradan kod yürütme host’u ele geçirmek için yeterli olabilir.

`runc` içindeki `CVE-2024-21626`, BuildKit mount yarış koşulları ve containerd ayrıştırma hataları gibi güncel runtime CVE’leri aynı noktayı pekiştiriyor. Runtime sürümü ve yama seviyesi, yalnızca bakım ayrıntıları değil, güvenlik sınırının bir parçasıdır.

## References

- [1] [runC aracılığıyla Docker’dan kaçış – CVE-2019-5736 açıklaması](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
