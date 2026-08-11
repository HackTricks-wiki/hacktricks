# Container Runtime'ları, Engine'ler, Builder'lar ve Sandbox'lar

Container security alanındaki en büyük kafa karışıklığı kaynaklarından biri, birbirinden tamamen farklı birkaç bileşenin çoğu zaman aynı kelime altında toplanmasıdır. "Docker"; bir image formatını, CLI'ı, daemon'ı, build sistemini, runtime stack'ini veya genel olarak container kavramını ifade edebilir. Security çalışmaları açısından bu belirsizlik bir sorundur; çünkü farklı katmanlar farklı korumalardan sorumludur. Hatalı bir bind mount nedeniyle oluşan breakout, low-level runtime bug nedeniyle oluşan breakout ile aynı şey değildir; ikisi de Kubernetes'teki bir cluster policy hatasıyla aynı değildir.

Bu sayfa ecosystem'i rollerine göre ayırır. Böylece bölümün geri kalanında bir korumanın veya zayıflığın gerçekte nerede bulunduğu kesin biçimde ele alınabilir.

## OCI Ortak Dil Olarak

Modern Linux container stack'leri, bir dizi OCI specification'ı konuştukları için çoğu zaman birlikte çalışabilir. **OCI Image Specification**, image'ların ve layer'ların nasıl temsil edildiğini tanımlar. **OCI Runtime Specification**, namespace'ler, mount'lar, cgroup'lar ve security ayarları dahil olmak üzere runtime'ın process'i nasıl başlatması gerektiğini tanımlar. **OCI Distribution Specification** ise registry'lerin içeriği nasıl sunduğunu standardize eder.

Bu önemlidir; çünkü bir tool ile oluşturulan bir container image'ının neden çoğu zaman başka bir tool ile çalıştırılabildiğini ve birkaç engine'in neden aynı low-level runtime'ı paylaşabildiğini açıklar. Ayrıca security davranışının farklı product'lar arasında neden benzer görünebildiğini de açıklar: Bunların çoğu aynı OCI runtime configuration'ını oluşturup aynı küçük runtime kümesine iletir.

## Low-Level OCI Runtime'ları

Low-level runtime, kernel sınırına en yakın bileşendir. Namespace'leri gerçekten oluşturan, cgroup ayarlarını yazan, capability'leri ve seccomp filter'larını uygulayan ve son olarak container process'ine `execve()` yapan kısım budur. İnsanlar mekanik düzeyde "container isolation" hakkında konuştuğunda, açıkça söylemeseler bile genellikle bu katmanı kastederler.

### `runc`

`runc`, referans OCI runtime'ıdır ve en bilinen implementation olmaya devam eder. Docker, containerd ve birçok Kubernetes deployment'ında yoğun biçimde kullanılır. Public research ve exploitation materyallerinin büyük bölümü `runc` tarzı environment'ları hedefler; bunun nedeni bunların yaygın olması ve `runc`'ın birçok kişinin Linux container düşündüğünde zihninde canlandırdığı temel modeli tanımlamasıdır. Bu nedenle `runc`'ı anlamak, okuyucuya klasik container isolation için güçlü bir zihinsel model sağlar.

### `crun`

`crun`, C ile yazılmış ve modern Podman environment'larında yaygın olarak kullanılan başka bir OCI runtime'dır. İyi cgroup v2 desteği, güçlü rootless ergonomisi ve daha düşük overhead nedeniyle çoğu zaman övgü alır. Security açısından önemli olan, farklı bir dilde yazılmış olması değil, aynı rolü oynamaya devam etmesidir: OCI configuration'ını kernel altında çalışan bir process tree'ye dönüştüren bileşen odur. Rootless Podman workflow'u çoğu zaman daha güvenli hissettirir; bunun nedeni `crun`'ın her şeyi sihirli biçimde düzeltmesi değil, etrafındaki genel stack'in user namespace'lerine ve least privilege yaklaşımına daha fazla önem verme eğiliminde olmasıdır.

### gVisor'dan `runsc`

`runsc`, gVisor tarafından kullanılan runtime'dır. Burada sınır anlamlı biçimde değişir. gVisor, syscall'ların çoğunu olağan şekilde doğrudan host kernel'ına iletmek yerine, Linux interface'inin büyük bölümünü emüle eden veya araya girerek yöneten bir userspace kernel katmanı ekler. Sonuç, birkaç ekstra flag'e sahip normal bir `runc` container değildir; host-kernel attack surface'ini azaltmayı amaçlayan farklı bir sandbox tasarımıdır. Compatibility ve performance trade-off'ları bu tasarımın parçasıdır. Bu nedenle `runsc` kullanan environment'lar, normal OCI runtime environment'larından farklı biçimde dokümante edilmelidir.

### `kata-runtime`

Kata Containers, workload'u lightweight bir virtual machine içinde başlatarak sınırı daha da ileri taşır. Yönetim açısından bu hâlâ bir container deployment'ı gibi görünebilir ve orchestration layer'ları da bunu bu şekilde ele alabilir; ancak temel isolation sınırı, klasik host-kernel-shared container'dan çok virtualization'a yakındır. Bu durum, container merkezli workflow'lardan vazgeçmeden daha güçlü tenant isolation istendiğinde Kata'yı kullanışlı hâle getirir.

## Engine'ler ve Container Manager'ları

Low-level runtime doğrudan kernel ile konuşan bileşense, engine veya manager genellikle kullanıcıların ve operator'ların etkileşim kurduğu bileşendir. Image pull'larını, metadata'yı, log'ları, network'leri, volume'leri, lifecycle operasyonlarını ve API exposure'ını yönetir. Bu katman son derece önemlidir; çünkü gerçek dünyadaki birçok compromise burada gerçekleşir: Runtime socket'ine veya daemon API'sine erişim, low-level runtime tamamen sağlıklı olsa bile host compromise ile eşdeğer olabilir.

### Docker Engine

Docker Engine, developer'lar için en tanınabilir container platformudur ve container terminolojisinin Docker merkezli hâle gelmesinin nedenlerinden biridir. Tipik yol `docker` CLI'dan `dockerd`'e, oradan da `containerd` ve bir OCI runtime gibi low-level bileşenleri koordine etmeye uzanır. Tarihsel olarak Docker deployment'ları çoğu zaman **rootful** olmuştur; bu nedenle Docker socket'ine erişim son derece güçlü bir primitive hâline gelmiştir. Pratik privilege-escalation materyallerinin büyük bölümünün `docker.sock` üzerine odaklanmasının nedeni budur: Bir process, `dockerd`'den privileged bir container oluşturmasını, host path'lerini mount etmesini veya host namespace'lerine katılmasını isteyebiliyorsa kernel exploit'ine hiç ihtiyaç duymayabilir.

### Podman

Podman daha çok daemonless bir model etrafında tasarlanmıştır. Operasyonel olarak bu, container'ların uzun süre çalışan tek bir privileged daemon yerine standart Linux mekanizmalarıyla yönetilen process'ler olduğu fikrini güçlendirir. Podman ayrıca birçok kişinin ilk öğrendiği klasik Docker deployment'larına kıyasla çok daha güçlü bir **rootless** yaklaşımına sahiptir. Bu durum Podman'ı otomatik olarak güvenli yapmaz; ancak özellikle user namespace'leri, SELinux ve `crun` ile birlikte kullanıldığında varsayılan risk profilini önemli ölçüde değiştirir.

### containerd

containerd, birçok modern stack'te temel bir runtime management bileşenidir. Docker'ın altında kullanılır ve aynı zamanda baskın Kubernetes runtime backend'lerinden biridir. Güçlü API'ler sunar, image'ları ve snapshot'ları yönetir ve son process oluşturma işlemini low-level runtime'a devreder. containerd hakkındaki security tartışmaları, containerd socket'ine veya `ctr`/`nerdctl` işlevlerine erişimin Docker API'sine erişim kadar tehlikeli olabileceğini vurgulamalıdır; interface ve workflow daha az "developer friendly" görünse bile.

### CRI-O

CRI-O, Docker Engine'e kıyasla daha odaklıdır. Genel amaçlı bir developer platformu olmak yerine, Kubernetes Container Runtime Interface'ını temiz biçimde uygulamak üzere tasarlanmıştır. Bu nedenle Kubernetes distribution'larında ve OpenShift gibi SELinux ağırlıklı ecosystem'lerde özellikle yaygındır. Security açısından bu daha dar kapsam kullanışlıdır; çünkü kavramsal karmaşayı azaltır: CRI-O, her şeyi kapsayan bir platformdan ziyade kesinlikle "Kubernetes için container çalıştırma" katmanının parçasıdır.

### Incus, LXD ve LXC

Incus/LXD/LXC sistemlerini Docker tarzı application container'larından ayrı değerlendirmek gerekir; çünkü bunlar çoğu zaman **system container** olarak kullanılır. Bir system container'ın genellikle daha kapsamlı bir userspace'e, uzun süre çalışan service'lere, daha zengin device exposure'a ve host ile daha geniş integration'a sahip lightweight bir machine gibi görünmesi beklenir. Isolation mekanizmaları hâlâ kernel primitive'leridir; ancak operasyonel beklentiler farklıdır. Sonuç olarak buradaki misconfiguration'lar çoğu zaman "hatalı app-container default'ları"ndan çok lightweight virtualization veya host delegation hatalarına benzer.

### systemd-nspawn

systemd-nspawn, systemd-native olması ve testing, debugging ve OS benzeri environment'ları çalıştırmak için oldukça kullanışlı olması nedeniyle ilginç bir konuma sahiptir. Cloud-native production runtime'ı olarak baskın değildir; ancak lab'lerde ve distro odaklı environment'larda yeterince sık görülür ve anılmayı hak eder. Security analysis açısından bu, "container" kavramının birden fazla ecosystem'i ve operasyonel tarzı kapsadığını bir kez daha hatırlatır.

### Apptainer / Singularity

Apptainer (eski adıyla Singularity), research ve HPC environment'larında yaygındır. Trust assumption'ları, user workflow'u ve execution model'i Docker/Kubernetes merkezli stack'lerden önemli ölçüde farklıdır. Özellikle bu environment'lar, kullanıcılara geniş privileged container-management yetkileri vermeden packaged workload'ları çalıştırmalarına izin vermeye büyük önem verir. Bir reviewer her container environment'ının temelde "bir server üzerinde Docker" olduğunu varsayarsa bu deployment'ları ciddi biçimde yanlış anlayacaktır.

## Build-Time Tooling

Birçok security tartışması yalnızca runtime'dan bahseder; ancak build-time tooling de önemlidir. Çünkü image içeriğini, build secret'larının exposure'ını ve final artifact içine ne kadar trusted context gömüldüğünü belirler.

**BuildKit** ve `docker buildx`, caching, secret mounting, SSH forwarding ve multi-platform build'ler gibi özellikleri destekleyen modern build backend'leridir. Bunlar kullanışlı özelliklerdir; ancak security açısından secret'ların image layer'larına leak edebileceği veya aşırı geniş bir build context'in dahil edilmemesi gereken dosyaları açığa çıkarabileceği noktalar da oluştururlar. **Buildah**, özellikle Podman çevresinde OCI-native ecosystem'lerde benzer bir rol oynarken, **Kaniko** çoğu zaman build pipeline'ına privileged bir Docker daemon vermek istemeyen CI environment'larında kullanılır.

Temel ders şudur: Image oluşturma ve image çalıştırma farklı aşamalardır; ancak zayıf bir build pipeline, container başlatılmadan çok önce zayıf bir runtime posture oluşturabilir.

## Orchestration Başka Bir Katmandır, Runtime Değildir

Kubernetes zihinsel olarak runtime'ın kendisiyle eşitlenmemelidir. Kubernetes orchestrator'dır. Pod'ları schedule eder, desired state'i saklar ve workload configuration aracılığıyla security policy ifade eder. Kubelet daha sonra containerd veya CRI-O gibi bir CRI implementation'ı ile konuşur; bu implementation da `runc`, `crun`, `runsc` veya `kata-runtime` gibi bir low-level runtime'ı çağırır.

Bu ayrım önemlidir; çünkü birçok kişi gerçekte node runtime tarafından uygulanan bir korumayı yanlışlıkla "Kubernetes"e atfeder veya bir Pod spec'inden kaynaklanan davranış için "containerd default'ları"nı suçlar. Uygulamada final security posture bir bileşimdir: Orchestrator bir şey talep eder, runtime stack bunu dönüştürür ve sonunda kernel bunu uygular.

## Assessment Sırasında Runtime Identification Neden Önemlidir?

Engine ve runtime'ı erken tespit ederseniz sonraki birçok gözlemi yorumlamak kolaylaşır. Rootless bir Podman container'ı, user namespace'lerinin muhtemelen sürecin bir parçası olduğunu gösterir. Bir workload içine mount edilmiş Docker socket'i, API-driven privilege escalation'ın gerçekçi bir yol olduğunu gösterir. Bir CRI-O/OpenShift node'u, SELinux label'larını ve restricted workload policy'yi hemen düşünmenizi sağlamalıdır. Bir gVisor veya Kata environment'ı ise klasik bir `runc` breakout PoC'sinin aynı şekilde çalışacağını varsayma konusunda daha temkinli olmanızı gerektirir.

Bu nedenle container assessment'ın ilk adımlarından biri her zaman şu iki basit soruyu yanıtlamak olmalıdır: **container'ı hangi component yönetiyor** ve **process'i gerçekte hangi runtime başlattı**? Bu yanıtlar netleştiğinde environment'ın geri kalanını anlamlandırmak genellikle çok daha kolay olur.

## Runtime Vulnerabilities

Her container escape operator misconfiguration'ından kaynaklanmaz. Bazen vulnerable component doğrudan runtime'ın kendisidir. Bu önemlidir; çünkü bir workload dikkatli göründüğü bir configuration ile çalışıyor olsa bile low-level runtime flaw üzerinden exposed olabilir.

Klasik örnek, `runc` içindeki **CVE-2019-5736**'dır. Bu vulnerability'de malicious bir container, host üzerindeki `runc` binary'sinin üzerine yazabilir ve daha sonra gerçekleştirilecek bir `docker exec` veya benzer runtime invocation'ının attacker-controlled code'u tetiklemesini bekleyebilir. Exploit path, basit bir bind-mount veya capability hatasından oldukça farklıdır; çünkü exec handling sırasında runtime'ın container process space'e nasıl yeniden girdiğini abuse eder.<sup>[[1]](#references)</sup>

Red-team perspective'inden minimal reproduction workflow'u şöyledir:
```bash
go build main.go
./main
```
Ardından, host üzerinden:
```bash
docker exec -it <container-name> /bin/sh
```
Temel çıkarım, exploit'in tam tarihsel uygulaması değil, değerlendirme açısından ortaya çıkan sonuçtur: runtime sürümü güvenlik açığı içeriyorsa, görünür container yapılandırması bariz şekilde zayıf görünmese bile sıradan bir container içi code execution host'u compromise etmek için yeterli olabilir.

`runc` içindeki `CVE-2024-21626`, BuildKit mount race'leri ve containerd parsing bug'ları gibi güncel runtime CVE'leri aynı noktayı pekiştiriyor. Runtime sürümü ve patch seviyesi yalnızca bakım ayrıntıları değil, security boundary'nin bir parçasıdır.

## References

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
