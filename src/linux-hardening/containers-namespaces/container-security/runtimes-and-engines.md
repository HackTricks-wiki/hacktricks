# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Container security alanındaki en büyük kafa karışıklığı kaynaklarından biri, tamamen farklı birkaç bileşenin sıklıkla aynı kelime altında toplanmasıdır. "Docker"; bir image formatını, bir CLI'ı, bir daemon'ı, bir build sistemini, bir runtime stack'ini veya genel olarak container kavramını ifade edebilir. Security çalışmaları açısından bu belirsizlik bir sorundur; çünkü farklı katmanlar farklı protection'lardan sorumludur. Hatalı bir bind mount kaynaklı breakout, low-level runtime bug kaynaklı breakout ile aynı şey değildir; ikisi de Kubernetes'teki bir cluster policy hatasıyla aynı değildir.

Bu sayfa ecosystem'i rollerine göre ayırır. Böylece section'ın geri kalanı bir protection'ın veya weakness'ın gerçekte nerede bulunduğundan kesin olarak bahsedebilir.

## OCI As The Common Language

Modern Linux container stack'leri, bir dizi OCI specification'ını konuştukları için sıklıkla birlikte çalışabilir. **OCI Image Specification**, image'ların ve layer'ların nasıl temsil edildiğini açıklar. **OCI Runtime Specification**, runtime'ın namespace'ler, mount'lar, cgroup'lar ve security setting'leri dahil olmak üzere process'i nasıl başlatması gerektiğini açıklar. **OCI Distribution Specification** ise registry'lerin içeriği nasıl sunacağını standardize eder.

Bu önemlidir; çünkü bir tool ile build edilmiş bir container image'ının neden çoğu zaman başka bir tool ile çalıştırılabildiğini ve birçok engine'in neden aynı low-level runtime'ı paylaşabildiğini açıklar. Ayrıca security davranışının farklı product'lar arasında neden benzer görünebildiğini de açıklar: bunların çoğu aynı OCI runtime configuration'ını oluşturur ve bunu aynı küçük runtime grubuna iletir.

## Low-Level OCI Runtimes

Low-level runtime, kernel sınırına en yakın bileşendir. Namespace'leri gerçekten oluşturan, cgroup ayarlarını yazan, capability'leri ve seccomp filter'larını uygulayan ve son olarak container process'ini `execve()` eden kısım budur. İnsanlar "container isolation" konusunu mekanik düzeyde tartışırken, açıkça söylemeseler bile genellikle bu katmandan bahsederler.

### `runc`

`runc`, reference OCI runtime'dır ve en bilinen implementation olmaya devam eder. Docker, containerd ve birçok Kubernetes deployment'ında yoğun olarak kullanılır. Çok sayıda public research ve exploitation material'ı, yalnızca yaygın oldukları ve `runc` birçok kişinin Linux container tasavvurundaki baseline'ı tanımladığı için `runc` tarzı environment'ları hedefler. Bu nedenle `runc`'ı anlamak, okuyucuya klasik container isolation için güçlü bir mental model sağlar.

### `crun`

`crun`, C ile yazılmış ve modern Podman environment'larında yaygın olarak kullanılan başka bir OCI runtime'dır. İyi cgroup v2 desteği, güçlü rootless ergonomics ve daha düşük overhead özellikleri nedeniyle sıklıkla övülür. Security açısından önemli olan, farklı bir language ile yazılmış olması değil, aynı rolü üstlenmeye devam etmesidir: OCI configuration'ını kernel altında çalışan bir process tree'ye dönüştüren bileşendir. Rootless bir Podman workflow'u çoğu zaman daha güvenli hissettirir; bunun nedeni `crun`'ın her şeyi sihirli biçimde düzeltmesi değil, çevresindeki stack'in user namespace'lerine ve least privilege'a daha fazla yönelme eğiliminde olmasıdır.

### `runsc` From gVisor

`runsc`, gVisor tarafından kullanılan runtime'dır. Burada boundary'nin anlamı önemli ölçüde değişir. gVisor, çoğu syscall'ı normal şekilde doğrudan host kernel'ine iletmek yerine, Linux interface'inin büyük bölümünü emüle eden veya aracılık eden bir userspace kernel layer ekler. Sonuç, birkaç ek flag'e sahip normal bir `runc` container değil; host-kernel attack surface'ini azaltmayı amaçlayan farklı bir sandbox tasarımıdır. Compatibility ve performance trade-off'ları bu tasarımın parçasıdır. Bu nedenle `runsc` kullanan environment'lar, normal OCI runtime environment'larından farklı şekilde dokümante edilmelidir.

### `kata-runtime`

Kata Containers, workload'u lightweight bir virtual machine içinde başlatarak boundary'yi daha da ileri taşır. Yönetimsel açıdan bu hâlâ bir container deployment'ı gibi görünebilir ve orchestration layer'ları da bunu böyle ele alabilir; ancak temel isolation boundary, klasik host-kernel-shared container'dan çok virtualization'a yakındır. Bu durum, container merkezli workflow'lardan vazgeçmeden daha güçlü tenant isolation istendiğinde Kata'yı kullanışlı kılar.

## Engines And Container Managers

Low-level runtime doğrudan kernel ile iletişim kuran bileşense, engine veya manager kullanıcıların ve operator'ların genellikle etkileşim kurduğu bileşendir. Image pull'larını, metadata'yı, log'ları, network'leri, volume'ları, lifecycle operation'larını ve API exposure'ı yönetir. Bu katman son derece önemlidir; çünkü gerçek dünyadaki birçok compromise burada gerçekleşir: Low-level runtime tamamen sağlıklı olsa bile bir runtime socket'ine veya daemon API'sine erişim host compromise ile eşdeğer olabilir.

### Docker Engine

Docker Engine, developer'lar için en tanınabilir container platform'udur ve container vocabulary'sinin Docker merkezli hâle gelmesinin nedenlerinden biridir. Tipik yol `docker` CLI'dan `dockerd`'a, oradan da `containerd` ve bir OCI runtime gibi lower-level component'leri koordine etmeye uzanır. Tarihsel olarak Docker deployment'ları çoğunlukla **rootful** olmuştur ve bu nedenle Docker socket'ine erişim çok güçlü bir primitive hâline gelmiştir. Bu yüzden pratik privilege-escalation material'ının büyük bölümü `docker.sock` üzerine odaklanır: Bir process, `dockerd`'dan privileged bir container oluşturmasını, host path'lerini mount etmesini veya host namespace'lerine katılmasını isteyebiliyorsa kernel exploit'ine hiç ihtiyaç duymayabilir.

### Podman

Podman, daha daemonless bir model etrafında tasarlanmıştır. Operasyonel olarak bu, container'ların uzun süre çalışan tek bir privileged daemon yerine standard Linux mechanism'leriyle yönetilen process'ler olduğu fikrini güçlendirir. Podman ayrıca, birçok kişinin ilk öğrendiği klasik Docker deployment'larından çok daha güçlü bir **rootless** yaklaşımına sahiptir. Bu, Podman'ı otomatik olarak güvenli yapmaz; ancak özellikle user namespace'leri, SELinux ve `crun` ile birlikte kullanıldığında varsayılan risk profilini önemli ölçüde değiştirir.

### containerd

containerd, birçok modern stack'te temel bir runtime management component'idir. Docker'ın altında kullanılır ve aynı zamanda baskın Kubernetes runtime backend'lerinden biridir. Güçlü API'ler sunar, image'ları ve snapshot'ları yönetir ve son process oluşturma işlemini low-level runtime'a devreder. containerd hakkındaki security tartışmaları, containerd socket'ine veya `ctr`/`nerdctl` functionality'sine erişimin, interface ve workflow daha az "developer friendly" görünse bile Docker API'sine erişim kadar tehlikeli olabileceğini vurgulamalıdır.

### CRI-O

CRI-O, Docker Engine'den daha odaklıdır. General-purpose developer platform'u olmak yerine, Kubernetes Container Runtime Interface'ını düzgün şekilde uygulamak amacıyla geliştirilmiştir. Bu nedenle Kubernetes distribution'larında ve OpenShift gibi SELinux ağırlıklı ecosystem'lerde özellikle yaygındır. Security açısından bu daha dar kapsam kullanışlıdır; çünkü kavramsal karmaşayı azaltır: CRI-O, "Kubernetes için container çalıştırma" katmanının bir parçasıdır; her şeyi kapsayan bir platform değildir.

### Incus, LXD, And LXC

Incus/LXD/LXC sistemlerini Docker tarzı application container'larından ayrı değerlendirmek gerekir; çünkü bunlar sıklıkla **system container** olarak kullanılır. Bir system container'dan genellikle daha dolu bir userspace'e, uzun süre çalışan service'lere, daha zengin device exposure'a ve host ile daha kapsamlı integration'a sahip lightweight bir machine gibi davranması beklenir. Isolation mechanism'leri hâlâ kernel primitive'leridir; ancak operasyonel beklentiler farklıdır. Bu nedenle buradaki misconfiguration'lar genellikle "bad app-container defaults"tan çok lightweight virtualization veya host delegation hataları gibi görünür.

### systemd-nspawn

systemd-nspawn, systemd-native olması ve testing, debugging ile OS benzeri environment'ları çalıştırmak için kullanışlı olması nedeniyle ilginç bir konuma sahiptir. Cloud-native production runtime'ı olarak baskın değildir; ancak lab'lerde ve distro odaklı environment'larda yeterince sık görülür ve anılmayı hak eder. Security analysis açısından bu, "container" kavramının birden fazla ecosystem'i ve operasyonel yaklaşımı kapsadığını hatırlatan başka bir örnektir.

### Apptainer / Singularity

Apptainer (eski adıyla Singularity), research ve HPC environment'larında yaygındır. Trust assumption'ları, user workflow'u ve execution model'i Docker/Kubernetes merkezli stack'lerden önemli ölçüde farklıdır. Özellikle bu environment'lar, kullanıcılara geniş privileged container-management yetkileri vermeden packaged workload'ları çalıştırabilmeye büyük önem verir. Bir reviewer her container environment'ının temelde "bir server üzerinde Docker" olduğunu varsayarsa bu deployment'ları ciddi şekilde yanlış anlayacaktır.

## Build-Time Tooling

Birçok security tartışması yalnızca runtime'dan bahseder; ancak build-time tooling de önemlidir, çünkü image içeriğini, build secret exposure'ını ve final artifact içine ne kadar trusted context gömüldüğünü belirler.

**BuildKit** ve `docker buildx`, caching, secret mounting, SSH forwarding ve multi-platform build'ler gibi feature'ları destekleyen modern build backend'leridir. Bunlar kullanışlı feature'lardır; ancak security açısından secret'ların image layer'larına leak edebileceği veya gereğinden geniş bir build context'in asla dahil edilmemesi gereken dosyaları açığa çıkarabileceği alanlar da oluştururlar. **Buildah**, özellikle Podman çevresindeki OCI-native ecosystem'lerde benzer bir rol üstlenir. **Kaniko** ise privileged bir Docker daemon'ını build pipeline'a vermek istemeyen CI environment'larında sıklıkla kullanılır.

Temel ders şudur: Image creation ve image execution farklı phase'lerdir; ancak zayıf bir build pipeline, container başlatılmadan çok önce zayıf bir runtime posture oluşturabilir.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes zihinsel olarak runtime'ın kendisiyle eşleştirilmemelidir. Kubernetes orchestrator'dır. Pod'ları schedule eder, desired state'i saklar ve workload configuration üzerinden security policy ifade eder. Daha sonra kubelet, containerd veya CRI-O gibi bir CRI implementation ile iletişim kurar; bu implementation da `runc`, `crun`, `runsc` veya `kata-runtime` gibi bir low-level runtime'ı çağırır.

Bu ayrım önemlidir; çünkü birçok kişi bir protection'ı gerçekte node runtime tarafından uygulanırken yanlışlıkla "Kubernetes"e atfeder veya bir davranış Pod spec'ten kaynaklandığı hâlde "containerd defaults"ı suçlar. Pratikte final security posture bir bileşimdir: Orchestrator bir şey ister, runtime stack bunu dönüştürür ve sonunda kernel bunu enforce eder.

## Why Runtime Identification Matters During Assessment

Engine ve runtime'ı erken tespit ederseniz, sonraki birçok gözlemi yorumlamak kolaylaşır. Rootless bir Podman container'ı, user namespace'lerinin muhtemelen sürecin parçası olduğunu gösterir. Bir workload içine mount edilmiş Docker socket'i, API-driven privilege escalation'ın gerçekçi bir yol olduğunu gösterir. Bir CRI-O/OpenShift node'u, sizi hemen SELinux label'larını ve restricted workload policy'yi düşünmeye yönlendirmelidir. Bir gVisor veya Kata environment'ı ise klasik bir `runc` breakout PoC'sinin aynı şekilde çalışacağını varsayma konusunda daha temkinli olmanızı gerektirir.

Bu nedenle container assessment'ın ilk adımlarından biri her zaman şu iki basit soruyu yanıtlamak olmalıdır: **container'ı hangi component yönetiyor** ve **process'i gerçekte hangi runtime başlattı**. Bu yanıtlar netleştiğinde environment'ın geri kalanını anlamlandırmak genellikle çok daha kolay olur.

## Runtime Vulnerabilities

Her container escape, operator misconfiguration'ından kaynaklanmaz. Bazen vulnerable component doğrudan runtime'ın kendisidir. Bu önemlidir; çünkü workload dikkatli görünen bir configuration ile çalışıyor olsa bile low-level runtime flaw üzerinden hâlâ exposed olabilir.

Klasik örnek, `runc` içindeki **CVE-2019-5736**'dır. Bu açığı kullanarak malicious bir container host'taki `runc` binary'sinin üzerine yazabilir ve daha sonra `docker exec` veya benzer bir runtime invocation'ının attacker-controlled code'u tetiklemesini bekleyebilirdi. Exploit path, basit bir bind-mount veya capability hatasından çok farklıdır; çünkü exec handling sırasında runtime'ın container process space'e nasıl yeniden girdiğini abuse eder.

Bir red-team perspektifinden minimal reproduction workflow'u şöyledir:
```bash
go build main.go
./main
```
Ardından, host üzerinden:
```bash
docker exec -it <container-name> /bin/sh
```
Temel çıkarım, geçmişteki exploit uygulamasının tam olarak nasıl gerçekleştirildiği değil, değerlendirme açısından taşıdığı sonuçtur: runtime sürümü savunmasızsa, görünür container yapılandırması bariz şekilde zayıf görünmese bile container içindeki sıradan code execution host'u ele geçirmek için yeterli olabilir.

`runc` içindeki `CVE-2024-21626`, BuildKit mount race'leri ve containerd parsing bug'ları gibi güncel runtime CVE'leri de aynı noktayı pekiştirir. Runtime sürümü ve patch seviyesi yalnızca bakım ayrıntıları değil, security boundary'nin bir parçasıdır.
{{#include ../../../banners/hacktricks-training.md}}
