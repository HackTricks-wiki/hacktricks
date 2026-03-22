# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Konteyner güvenliğinde en büyük kafa karışıklığı kaynaklarından biri, tamamen farklı birkaç bileşenin aynı kelime altında toplanmasıdır. "Docker" bir image formatına, bir CLI'ya, bir daemon'a, bir build sistemine, bir runtime yığınına veya basitçe konteyner kavramına atıfta bulunabilir. Güvenlik çalışmaları için bu belirsizlik sorun yaratır, çünkü farklı katmanlar farklı korumalardan sorumludur. Kötü bir bind mount yüzünden oluşan bir kaçış, düşük seviye bir runtime hatasından kaynaklanan bir kaçışla aynı şey değildir ve hiçbiri Kubernetes'teki bir cluster politika hatasıyla aynı değildir.

Bu sayfa ekosistemi rolüne göre ayırır, böylece bölümün geri kalanı bir korumanın veya zayıflığın gerçekten nerede olduğunu hassas şekilde ele alabilir.

## OCI As The Common Language

Modern Linux konteyner yığınları genellikle bir dizi OCI spesifikasyonunu konuştuğu için birlikte çalışabilir. **OCI Image Specification** image'ların ve layer'ların nasıl temsil edildiğini açıklar. **OCI Runtime Specification** runtime'ın süreci nasıl başlatması gerektiğini, namespace'ler, mount'lar, cgroup'lar ve güvenlik ayarları dahil olmak üzere tarif eder. **OCI Distribution Specification** ise registry'lerin içeriği nasıl sunduğunu standartlaştırır.

Bu, bir araçla oluşturulan bir container image'ının genellikle başka bir araçla çalıştırılabilmesinin ve birkaç engine'in aynı düşük seviyeli runtime'ı paylaşabilmesinin nedenini açıklar. Ayrıca birçok ürünün güvenlik davranışının neden benzer görünebileceğini açıklar: birçoğu aynı OCI runtime yapılandırmasını oluşturup aynı küçük runtime setine veriyor.

## Low-Level OCI Runtimes

Düşük seviye runtime, kernel sınırına en yakın olan bileşendir. Namespace'leri gerçekten yaratıp cgroup ayarlarını yazan, capability'leri ve seccomp filtrelerini uygulayan ve nihayetinde container sürecini `execve()` ile çalıştıran kısımdır. İnsanlar mekanik seviyede "container izolasyonu"ndan bahsettiğinde genellikle açıkça söylemeseler bile bu katmandan bahsediyorlardır.

### `runc`

`runc` referans OCI runtime'dır ve en bilinen uygulama olmaya devam eder. Docker, containerd ve birçok Kubernetes dağıtımında yoğun şekilde kullanılır. Birçok kamu araştırması ve exploit materyali `runc`-stil ortamlara yöneliktir çünkü bunlar yaygındır ve `runc` birçok kişinin bir Linux konteynerini hayal ederken aklına gelen temel tanımı belirler. `runc`'u anlamak, klasik konteyner izolasyonu için okuyucuya güçlü bir zihinsel model sağlar.

### `crun`

`crun`, C ile yazılmış başka bir OCI runtime'dır ve modern Podman ortamlarında yaygın olarak kullanılır. Genellikle iyi cgroup v2 desteği, güçlü root'suz ergonomi ve daha düşük yük nedeniyle övülür. Güvenlik açısından önemli olan farklı bir dilde yazılmış olması değil, aynı rolü oynamasıdır: OCI yapılandırmasını kernel altında çalışan bir process ağacına dönüştüren bileşendir. Root'suz bir Podman iş akışı sıkça daha güvenli hissettirir; bunun nedeni `crun`'un sihirle her şeyi düzeltmesi değil, çevresindeki yığının kullanıcı namespace'lerine ve en az ayrıcalık ilkesine daha fazla eğilim göstermesidir.

### `runsc` From gVisor

`runsc` gVisor tarafından kullanılan runtime'dır. Burada sınır anlamlı şekilde değişir. Çoğu syscall'ü normal yolla host kernel'e yönlendirmek yerine, gVisor kullanıcı alanı bir kernel katmanı ekler ve Linux arayüzünün büyük bölümlerini emüle eder veya aracılık eder. Sonuç, birkaç ekstra flag'e sahip normal bir `runc` konteyneri değildir; host-kernel saldırı yüzeyini azaltmayı amaçlayan farklı bir sandbox tasarımıdır. Uyumluluk ve performans ödünleri bu tasarımın parçasıdır, bu yüzden `runsc` kullanan ortamlar normal OCI runtime ortamlarından farklı şekilde belgelenmelidir.

### `kata-runtime`

Kata Containers sınırı daha da ileri taşır ve workload'u hafif bir sanal makine içinde başlatır. Yönetimsel olarak bu hâlâ bir konteyner dağıtımı gibi görünebilir ve orkestrasyon katmanları onu öyle davranış olarak ele alabilir, ancak alttaki izolasyon sınırı klasik host-kernel paylaşımlı konteynerden ziyade sanallaştırmaya daha yakındır. Bu, daha güçlü tenant izolasyonu istendiğinde container-merkezli iş akışlarından vazgeçmeden Kata'yı faydalı kılar.

## Engines And Container Managers

Düşük seviye runtime kernel ile doğrudan konuşan bileşense, engine veya manager kullanıcıların ve operatörlerin genellikle etkileştiği bileşendir. Image pull'larını, metadata'yı, log'ları, ağları, volume'leri, lifecycle operasyonlarını ve API sunumunu yönetir. Bu katman çok önemlidir çünkü gerçek dünya kompromolarının birçoğu burada gerçekleşir: bir runtime soketine veya daemon API'sine erişmek düşük seviye runtime kendisi mükemmel olsa bile host ele geçirilmesi ile eşdeğer olabilir.

### Docker Engine

Docker Engine geliştiriciler için en tanınmış konteyner platformudur ve konteyner vokabülerinin bu kadar Docker-şekilli olmasının sebeplerinden biridir. Tipik yol `docker` CLI'dan `dockerd`'e, oradan da `containerd` ve bir OCI runtime gibi daha düşük seviye bileşenlere koordinasyondur. Tarihsel olarak Docker dağıtımları sıklıkla **rootful** olmuştur ve bu yüzden Docker socket'e erişim çok güçlü bir primitif olmuştur. Bu yüzden pratik privilege-escalation materyallerinin çoğu `docker.sock` üzerine yoğunlaşır: eğer bir süreç `dockerd`'en ayrıcalıklı bir container oluşturmasını, host yollarını mount etmesini veya host namespace'lerine katılmasını isteyebiliyorsa, kernel exploit'ine bile ihtiyaç duymayabilir.

### Podman

Podman daha daemon'sız bir model etrafında tasarlandı. Operasyonel olarak bu, konteynerlerin tek uzun ömürlü ayrıcalıklı bir daemon yerine standart Linux mekanizmalarıyla yönetilen süreçler olduğu fikrini pekiştirmeye yardımcı olur. Podman ayrıca birçok kişinin ilk öğrendiği klasik Docker dağıtımlarına kıyasla çok daha güçlü bir **rootless** hikayesine sahiptir. Bu Podman'ı otomatik olarak güvenli yapmaz, ancak özellikle kullanıcı namespace'leri, SELinux ve `crun` ile birleştirildiğinde varsayılan risk profilini önemli ölçüde değiştirir.

### containerd

containerd birçok modern yığında temel bir runtime yönetim bileşenidir. Docker altında kullanılır ve aynı zamanda dominant Kubernetes runtime backend'lerinden biridir. Güçlü API'ler sunar, image ve snapshot'ları yönetir ve nihai süreç oluşturmayı düşük seviye bir runtime'a devreder. containerd etrafındaki güvenlik tartışmaları, containerd soketine veya `ctr`/`nerdctl` fonksiyonelliğine erişimin Docker'ın API'sine erişim kadar tehlikeli olabileceğini vurgulamalıdır; arayüz ve iş akışı "geliştirici dostu" hissetmese bile.

### CRI-O

CRI-O Docker Engine'den daha odaklıdır. Genel amaçlı bir geliştirici platformu olmak yerine Kubernetes Container Runtime Interface'i temiz bir şekilde uygulamak etrafında inşa edilmiştir. Bu, onu Kubernetes dağıtımlarında ve OpenShift gibi SELinux-ağır ekosistemlerde özellikle yaygın kılar. Güvenlik açısından bu daha dar kapsam kavramsal karmaşayı azaltır: CRI-O esasen "Kubernetes için konteyner çalıştır" katmanının bir parçasıdır, her şeye hizmet eden bir platform değildir.

### Incus, LXD, And LXC

Incus/LXD/LXC sistemleri Docker-tarzı uygulama konteynerlerinden ayrı tutulmaya değerdir çünkü genellikle **system containers** olarak kullanılırlar. Bir system container genellikle daha dolu bir userspace, uzun süre çalışan servisler, daha zengin device maruziyeti ve daha kapsamlı host entegrasyonu ile hafif bir makine gibi görülmesi beklenir. İzolasyon mekanizmaları hâlâ kernel primitifleridir, ama operasyonel beklentiler farklıdır. Sonuç olarak, burada yapılan yanlış yapılandırmalar genellikle "kötü uygulama-konteyner varsayımları"ndan ziyade hafif sanallaştırma veya host devri hataları gibi görünür.

### systemd-nspawn

systemd-nspawn ilginç bir konum işgal eder çünkü systemd-yerelidir ve test, debugging ve OS-benzeri ortamları çalıştırmak için çok kullanışlıdır. Bulut-native üretim runtime'ı olarak baskın olmasa da lab'larda ve dağıtım odaklı ortamlarda sıkça göründüğü için bahsi geçmeye değerdir. Güvenlik analizinde bu, "konteyner" kavramının birden fazla ekosistem ve operasyonel stile yayıldığının bir hatırlatıcısıdır.

### Apptainer / Singularity

Apptainer (eski adıyla Singularity) araştırma ve HPC ortamlarında yaygındır. Güven varsayımları, kullanıcı iş akışı ve çalışma modeli Docker/Kubernetes-merkezli yığınlardan önemli derecede farklıdır. Özellikle bu ortamlar genellikle kullanıcıların paketlenmiş workload'ları geniş ayrıcalıklı container-yönetim yetkileri vermeden çalıştırmasına çok önem verir. Eğer bir değerlendirme yapan kişi her konteyner ortamının temel olarak "bir sunucuda Docker" olduğunu varsayarsa, bu dağıtımları ciddi şekilde yanlış anlayacaktır.

## Build-Time Tooling

Birçok güvenlik tartışması sadece çalışma zamanından bahseder, ama build-time tooling de önemlidir çünkü image içeriklerini, build sırasındaki secret'ların exposure'unu ve ne kadar güvenilen bağlamın son artefakta gömüldüğünü belirler.

**BuildKit** ve `docker buildx` cache, secret mount etme, SSH yönlendirme ve multi-platform build'ler gibi özellikleri destekleyen modern build backend'leridir. Bunlar faydalı özelliklerdir, ama güvenlik açısından aynı zamanda secrets'in image layer'larına leak olabileceği veya aşırı geniş bir build context'in dahil edilmemesi gereken dosyaları açığa çıkarabileceği yerler yaratır. **Buildah** özellikle Podman etrafındaki OCI-native ekosistemlerde benzer bir rol oynar, mentre **Kaniko** genellikle build pipeline'ına ayrıcalıklı bir Docker daemon vermek istemeyen CI ortamlarında kullanılır.

Önemli ders şudur: image oluşturma ve image çalıştırma farklı aşamalardır, ama zayıf bir build pipeline'ı konteyner başlatılmadan çok önce zayıf bir runtime duruşu yaratabilir.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes, zihnen runtime ile eşitlenmemelidir. Kubernetes orkestratördür. Pod'ları planlar, istenen durumu depolar ve workload konfigürasyonu aracılığıyla güvenlik politikasını ifade eder. kubelet sonra containerd veya CRI-O gibi bir CRI uygulamasıyla konuşur; bu da sırasıyla `runc`, `crun`, `runsc` veya `kata-runtime` gibi düşük seviye bir runtime'ı çağırır.

Bu ayrım önemlidir çünkü birçok kişi bir korumayı "Kubernetes"e atfederken aslında nodeların runtime'ı tarafından uygulandığını veya davranış için "containerd varsayımları"nı suçlarken gerçek kaynağın bir Pod spec olduğunu yanlışlıkla düşünür. Pratikte nihai güvenlik duruşu bir bileşimdir: orkestratör bir şey ister, runtime yığını bunu çevirir ve kernel nihayetinde uygular.

## Why Runtime Identification Matters During Assessment

Engine ve runtime'ı erken tanımlarsanız, sonraki birçok gözlem yorumlamayı kolaylaştırır. Root'suz bir Podman container kullanıcı namespace'lerinin hikayenin bir parçası olma olasılığını işaret eder. Bir workload'a monte edilmiş bir Docker socket API kaynaklı privilege escalation'ın gerçekçi bir yol olduğunu gösterir. CRI-O/OpenShift node'u SELinux etiketleri ve kısıtlı workload politikası hakkında hemen düşündürmelidir. gVisor veya Kata ortamı klasik bir `runc` breakout PoC'sunun aynı şekilde davranacağını varsaymamanız gerektiğini aklınıza getirir.

Bu yüzden container değerlendirmesinde ilk adımlardan biri her zaman iki basit soruyu cevaplamak olmalıdır: **hangi bileşen container'ı yönetiyor** ve **hangisi aslında süreci başlattı**. Bu cevaplar netleştiğinde, ortamın geri kalanı genellikle akıl yürütmeyi çok daha kolaylaştırır.

## Runtime Vulnerabilities

Her konteyner kaçışı operator yanlış yapılandırmasından kaynaklanmaz. Bazen runtime'ın kendisi savunmasız bileşendir. Bu önemlidir çünkü bir workload dikkatli bir konfigürasyonla çalışıyor gibi görünse bile düşük seviyeli bir runtime açığıyla hâlâ açığa çıkabilir.

Klasik örnek `runc`'daki **CVE-2019-5736**'dır; kötü niyetli bir container host `runc` binary'sini üzerine yazabilir ve sonra daha sonraki bir `docker exec` veya benzeri runtime çağrısının tetiklediği saldırgan kontrollü kodu çalıştırmayı bekleyebilirdi. Exploit yolu basit bir bind-mount veya capability hatasından çok farklıdır çünkü exec işleme sırasında runtime'ın container süreç alanına nasıl yeniden girdiğini suistimal eder.

Kırmızı takım perspektifinden minimal bir yeniden üretim iş akışı şudur:
```bash
go build main.go
./main
```
Daha sonra, host'tan:
```bash
docker exec -it <container-name> /bin/sh
```
Temel ders tam olarak geçmiş exploit uygulaması değil, değerlendirme açısından taşıdığı sonuçtur: eğer runtime sürümü zafiyete sahipse, sıradan in-container code execution, görünür container yapılandırması bariz zayıf görünmese bile host'u ele geçirmek için yeterli olabilir.

runc içindeki `CVE-2024-21626`, BuildKit mount races ve containerd parsing bugs aynı noktayı pekiştiriyor. Runtime sürümü ve yama seviyesi güvenlik sınırının parçasıdır; sadece bakımsel bir ayrıntı değildir.
{{#include ../../../banners/hacktricks-training.md}}
