# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Konteyner güvenliğinde en büyük kafa karışıklık kaynaklarından biri, tamamen farklı birkaç bileşenin sıklıkla aynı kelime altında toplanmasıdır. "Docker" bir image formatını, bir CLI'yi, bir daemon'ı, bir build sistemini, bir runtime yığını veya basitçe konteyner fikrini ifade edebilir. Güvenlik çalışmaları için bu belirsizlik bir sorundur, çünkü farklı katmanlar farklı korumaların sorumluluğunu taşır. Kötü bir bind mount nedeniyle oluşan bir breakout, düşük seviye bir runtime hatasından kaynaklanan bir breakout ile aynı şey değildir ve hiçbiri Kubernetes'teki bir cluster politika hatasıyla aynı değildir.

Bu sayfa ekosistemi rolüne göre ayırır, böylece bölümün geri kalanı bir koruma veya zayıflığın aslında nerede olduğunu kesin olarak konuşabilir.

## OCI As The Common Language

Modern Linux konteyner yığınları genellikle bir dizi OCI spesifikasyonunu konuştukları için birlikte çalışabilir. **OCI Image Specification**, image'ların ve katmanların nasıl temsil edildiğini açıklar. **OCI Runtime Specification**, runtime'ın süreci nasıl başlatması gerektiğini, namespace'ler, mount'lar, cgroup'lar ve güvenlik ayarları dahil olmak üzere tanımlar. **OCI Distribution Specification** ise registry'lerin içeriği nasıl sunduğunu standardize eder.

Bu önemlidir çünkü bir araçla oluşturulan bir container image'ın genellikle başka bir araçla çalıştırılabilmesinin ve birkaç engine'in aynı düşük seviyeli runtime'ı paylaşabilmesinin nedenini açıklar. Ayrıca birçok ürünün benzer güvenlik davranışları göstermesinin nedenini açıklar: birçokları aynı OCI runtime konfigürasyonunu oluşturup aynı küçük runtime kümesine veriyor.

## Low-Level OCI Runtimes

Low-level runtime, kernel sınırına en yakın olan bileşendir. Namespace'leri gerçekten oluşturan, cgroup ayarlarını yazan, capability ve seccomp filtrelerini uygulayan ve sonunda container sürecini `execve()` eden kısımdır. İnsanlar mekanik düzeyde "container izolasyonunu" tartıştıklarında, genellikle açıkça belirtmeseler bile bu katmandan bahsediyorlardır.

### `runc`

`runc` referans OCI runtime'dır ve en iyi bilinen uygulama olmaya devam eder. Docker, containerd ve birçok Kubernetes dağıtımında yoğun şekilde kullanılır. Birçok kamuya açık araştırma ve istismar materyali `runc`-stil ortamları hedef alır; çünkü bunlar yaygındır ve `runc` birçok kişinin Linux konteynerini hayal ederken düşündüğü temel noktasını tanımlar. Bu yüzden `runc`'ı anlamak, klasik konteyner izolasyonu için güçlü bir zihinsel model sağlar.

### `crun`

`crun`, C ile yazılmış başka bir OCI runtime'dır ve modern Podman ortamlarında yaygın olarak kullanılır. Genellikle iyi cgroup v2 desteği, güçlü rootless ergonomisi ve daha düşük overhead için övülür. Güvenlik açısından önemli olan, farklı bir dilde yazılmış olması değil, aynı rolü oynamasıdır: OCI konfigürasyonunu kernel altında çalışan bir işlem ağacına dönüştüren bileşendir. Rootless bir Podman iş akışı sıklıkla her şeyi sihirli bir şekilde düzeltmesinden değil, çevresindeki yığının user namespace'lere ve en az ayrıcalığa daha fazla eğilim göstermesinden dolayı daha güvenli hissettirir.

### `runsc` From gVisor

`runsc`, gVisor tarafından kullanılan runtime'dır. Burada sınır anlamlı şekilde değişir. Çoğu syscall'ü normal şekilde doğrudan host kernel'e geçirmek yerine, gVisor büyük bölümlerini emüle eden veya arabuluculuk yapan bir userspace kernel katmanı ekler. Sonuç, birkaç ekstra bayraklı normal bir `runc` container'ı değildir; host-kernel saldırı yüzeyini azaltmayı amaçlayan farklı bir sandbox tasarımıdır. Uyumluluk ve performans takasları bu tasarımın parçasıdır, bu yüzden `runsc` kullanan ortamlar normal OCI runtime ortamlarından farklı şekilde belgelenmelidir.

### `kata-runtime`

Kata Containers, iş yükünü hafif bir sanal makine içinde başlatarak sınırı daha da ileri götürür. Yönetimsel olarak bu hâlâ bir konteyner dağıtımı gibi görünebilir ve orkestrasyon katmanları bunu hâlâ öyle ele alabilir, ancak altında yatan izolasyon sınırı klasik host-kernel paylaşımlı bir konteynere göre sanallaştırmaya daha yakındır. Bu, konteyner merkezli iş akışlarından vazgeçmeden daha güçlü tenant izolasyonu istendiğinde Kata'yı faydalı kılar.

## Engines And Container Managers

Low-level runtime kernel ile doğrudan konuşan bileşen ise, engine veya manager kullanıcıların ve operatörlerin genellikle etkileşime geçtiği bileşendir. Image pull'ları, metadata, log'lar, network'ler, volume'ler, yaşam döngüsü işlemleri ve API sunumu ile ilgilenir. Bu katman son derece önemlidir çünkü birçok gerçek dünya ihlali burada olur: bir runtime socket veya daemon API'sine erişim, low-level runtime kendisi mükemmel durumda olsa bile host ele geçirilmesine eşdeğer olabilir.

### Docker Engine

Docker Engine, geliştiriciler için en tanınmış konteyner platformudur ve konteyner sözlüğünün bu kadar Docker-odaklı hale gelmesinin nedenlerinden biridir. Tipik yol `docker` CLI'den `dockerd`'e, oradan da `containerd` ve bir OCI runtime gibi daha düşük seviyeli bileşenleri koordine etmektir. Tarihsel olarak, Docker dağıtımları sıklıkla **rootful** oldu ve bu yüzden Docker socket'e erişim çok güçlü bir ilkel olmuştur. Bu yüzden pratik privilege-escalation materyalinin büyük kısmı `docker.sock` üzerine odaklanır: eğer bir süreç `dockerd`'en privileged bir container oluşturmasını, host yollarını mount etmesini veya host namespace'lerine katılmasını isteyebiliyorsa, kernel exploit'e hiç gerek olmayabilir.

### Podman

Podman daha daemonless bir model etrafında tasarlandı. Operasyonel olarak bu, konteynerlerin uzun süre çalışan ayrıcalıklı bir daemon yerine standart Linux mekanizmalarıyla yönetilen süreçler olduğu fikrini güçlendirir. Podman ayrıca birçok kişinin ilk öğrendiği klasik Docker dağıtımlarına göre çok daha güçlü bir **rootless** hikâyesine sahiptir. Bu Podman'ı otomatik olarak güvenli yapmaz, ama özellikle user namespace'ler, SELinux ve `crun` ile birleştirildiğinde varsayılan risk profilini önemli ölçüde değiştirir.

### containerd

containerd birçok modern yığının temel runtime yönetim bileşenidir. Docker altında kullanılır ve aynı zamanda dominant Kubernetes runtime backend'lerinden biridir. Güçlü API'ler sunar, image'ları ve snapshot'ları yönetir ve nihai süreç oluşturmayı low-level bir runtime'a devreder. containerd etrafındaki güvenlik tartışmaları, containerd socket'ine veya `ctr`/`nerdctl` fonksiyonelliğine erişimin Docker'ın API'sine erişim kadar tehlikeli olabileceğini vurgulamalıdır; arayüz ve iş akışı "geliştirici dostu" hissetmese bile.

### CRI-O

CRI-O, Docker Engine'den daha odaklıdır. Genel amaçlı bir geliştirici platformu olmak yerine, Kubernetes Container Runtime Interface'i temiz bir şekilde uygulamak etrafında inşa edilmiştir. Bu, özellikle Kubernetes dağıtımlarında ve OpenShift gibi SELinux-ağırlıklı ekosistemlerde onu yaygın kılar. Güvenlik açısından bu daha dar kapsam kavramsal karışıklığı azaltır: CRI-O büyük ölçüde "Kubernetes için konteyner çalıştır" katmanının bir parçasıdır, her şeye yönelik bir platform değildir.

### Incus, LXD, And LXC

Incus/LXD/LXC sistemleri Docker tarzı uygulama konteynerlerinden ayrı tutulmaya değerdir çünkü genellikle **system container** olarak kullanılırlar. Bir system container genellikle daha dolu bir userspace, uzun süre çalışan servisler, daha zengin cihaz maruziyeti ve daha kapsamlı host entegrasyonu ile hafif bir makine gibi görünmesi beklenir. İzolasyon mekanizmaları hâlâ kernel primitifleridir, ancak operasyonel beklentiler farklıdır. Sonuç olarak, buradaki yanlış yapılandırmalar genellikle "kötü uygulama-container varsayımları" gibi değil, hafif sanallaştırma veya host devri hataları gibi görünür.

### systemd-nspawn

systemd-nspawn ilginç bir yere sahiptir çünkü systemd-yerli olup test, hata ayıklama ve OS-benzeri ortamları çalıştırmak için çok yararlıdır. Bulut-native üretim runtime'ı olarak baskın olmasa da, laboratuvarlarda ve dağıtım odaklı ortamlarda yeterince sık görülür ve bu yüzden anılmaya değerdir. Güvenlik analizinde, "konteyner" kavramının birden çok ekosistemi ve operasyonel stili kapsadığını hatırlatan bir başka örnektir.

### Apptainer / Singularity

Apptainer (önceden Singularity) araştırma ve HPC ortamlarında yaygındır. Güven ilişkileri, kullanıcı iş akışı ve yürütme modeli Docker/Kubernetes-merkezli yığınlardan önemli şekilde farklıdır. Özellikle bu ortamlar genellikle kullanıcılara paketlenmiş iş yüklerini çalıştırma imkânı tanımayı önemser; onlara geniş yetkili container-yönetim güçleri vermemek isterler. Bir inceleyen her konteyner ortamının temelde "bir sunucuda Docker" olduğunu varsayarsa, bu dağıtımları ciddi şekilde yanlış anlar.

## Build-Time Tooling

Birçok güvenlik tartışması sadece runtime'dan bahseder, ama build-time tooling de önemlidir çünkü image içeriğini, build secret'larının maruziyetini ve ne kadar güvenilir bağlamın nihai artifakt içine gömüldüğünü belirler.

**BuildKit** ve `docker buildx` önbellekleme, secret mounting, SSH forwarding ve multi-platform build'leri destekleyen modern build backend'leridir. Bunlar faydalı özelliklerdir, ama güvenlik açısından aynı zamanda secret'ların image katmanlarına leak olabileceği veya aşırı geniş bir build context'in asla dahil edilmemesi gereken dosyaları açığa çıkarabileceği yerler yaratırlar. **Buildah** özellikle Podman etrafındaki OCI-native ekosistemlerinde benzer bir rol oynarken, **Kaniko** genellikle build hattına ayrıcalıklı bir Docker daemon vermek istemeyen CI ortamlarında kullanılır.

Ana ders şudur: image oluşturma ve image çalıştırma farklı aşamalardır, ama zayıf bir build pipeline'ı konteyner başlatılmadan çok önce zayıf bir runtime duruşu yaratabilir.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes zihinsel olarak runtime ile eşit tutulmamalıdır. Kubernetes orkestratördür. Pod'ları planlar, istenen durumu saklar ve workload konfigürasyonu yoluyla güvenlik politikasını ifade eder. kubelet sonra containerd veya CRI-O gibi bir CRI uygulamasıyla konuşur; bu da `runc`, `crun`, `runsc` veya `kata-runtime` gibi düşük seviyeli bir runtime'ı çağırır.

Bu ayrım önemlidir çünkü birçok kişi yanlışlıkla bir korumayı "Kubernetes"e atfederken aslında node runtime tarafından uygulandığını veya bir davranış için "containerd varsayımları"nı suçlarken gerçekte bir Pod spesifikasyonundan kaynaklandığını düşünür. Pratikte nihai güvenlik duruşu bir bileşimdir: orkestratör bir şey talep eder, runtime yığını bunu çevirir ve kernel son olarak bunu uygular.

## Why Runtime Identification Matters During Assessment

Eğer engine ve runtime'ı erken tespit ederseniz, birçok sonraki gözlem yorumlamayı kolaylaştırır. Rootless bir Podman container user namespace'lerin muhtemelen hikâyenin bir parçası olduğunu düşündürür. Bir workload içine monte edilmiş bir Docker socket API kaynaklı privilege escalation'ın gerçekçi bir yol olduğunu düşündürür. Bir CRI-O/OpenShift node SELinux label'ları ve kısıtlı workload politikasını hemen akla getirmelidir. gVisor veya Kata ortamı klasik bir `runc` breakout PoC'sunun aynı şekilde davranacağını varsaymamanız gerektiğini düşündürmelidir.

Bu yüzden konteyner değerlendirmesinde ilk adımlardan biri her zaman iki basit soruyu cevaplamak olmalıdır: **hangi bileşen konteyneri yönetiyor** ve **hangi runtime gerçekte süreci başlattı**. Bu cevaplar net olduğunda, ortamın geri kalanı genellikle akıl yürütmeyi çok daha kolay hale getirir.

## Runtime Vulnerabilities

Her konteyner kaçışı operatör yanlış yapılandırmasından kaynaklanmaz. Bazen runtime'ın kendisi zayıf bileşendir. Bu önemlidir çünkü bir workload dikkatli bir konfigürasyonla çalışıyor gibi görünse bile düşük seviyeli bir runtime hatası aracılığıyla açığa çıkabilir.

Klasik örnek `runc`'ta bulunan **CVE-2019-5736**'dır; burada kötü niyetli bir container host `runc` ikilisini üzerine yazabilir ve sonra ileride yapılacak bir `docker exec` veya benzeri runtime çağrısının saldırgan kontrollü kodu tetiklemesini bekleyebilirdi. İstismar yolu basit bir bind-mount veya capability hatasından çok farklıdır çünkü exec işlemi sırasında runtime'ın container süreç alanına yeniden giriş şeklini kötüye kullanır.

Kırmızı takım perspektifinden minimal bir yeniden üretim iş akışı şudur:
```bash
go build main.go
./main
```
Sonra, host'tan:
```bash
docker exec -it <container-name> /bin/sh
```
Temel ders, tam olarak geçmişteki exploit uygulaması değil, değerlendirme sonucu/çıkarımıdır: eğer runtime sürümü savunmasızsa, sıradan in-container kod yürütmesi, görünür container yapılandırması bariz şekilde zayıf görünmese bile host'u ele geçirmek için yeterli olabilir.

Son runtime CVE'leri — `CVE-2024-21626` in `runc`, BuildKit mount races ve containerd parsing bugs — aynı noktayı vurguluyor. Runtime version and patch level güvenlik sınırının bir parçasıdır, yalnızca bakımla ilgili bir ayrıntı değildir.
