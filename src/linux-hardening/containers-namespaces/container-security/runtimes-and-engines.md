# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Container security alanındaki en büyük kafa karışıklığı kaynaklarından biri, birbirinden tamamen farklı birkaç bileşenin çoğu zaman aynı kelimeyle ifade edilmesidir. "Docker"; bir image formatını, CLI'yi, daemon'ı, build sistemini, runtime stack'ini veya genel olarak container kavramını ifade edebilir. Security çalışmaları açısından bu belirsizlik bir sorundur; çünkü farklı katmanlar farklı korumalardan sorumludur. Hatalı bir bind mount nedeniyle gerçekleşen bir breakout, low-level runtime bug nedeniyle gerçekleşen bir breakout ile aynı şey değildir; ikisi de Kubernetes'teki bir cluster policy hatasıyla aynı değildir.

Bu sayfa, ekosistemi rollerine göre ayırır. Böylece bölümün geri kalanında bir korumanın veya weakness'ın gerçekte nerede bulunduğu kesin biçimde ele alınabilir.

## OCI As The Common Language

Modern Linux container stack'leri, bir dizi OCI specification kullandıkları için genellikle birlikte çalışabilir. **OCI Image Specification**, image'ların ve layer'ların nasıl temsil edildiğini açıklar. **OCI Runtime Specification**, runtime'ın namespaces, mounts, cgroups ve security settings dahil olmak üzere process'i nasıl başlatması gerektiğini açıklar. **OCI Distribution Specification** ise registry'lerin içeriği nasıl sunduğunu standardize eder.

Bu önemlidir; çünkü bir tool ile build edilen container image'ın neden çoğu zaman başka bir tool ile çalıştırılabildiğini ve birkaç engine'in neden aynı low-level runtime'ı paylaşabildiğini açıklar. Ayrıca farklı ürünlerde security davranışının neden benzer görünebildiğini de açıklar: Bunların çoğu aynı OCI runtime configuration'ını oluşturup aynı küçük runtime grubuna iletir.

## Low-Level OCI Runtimes

Low-level runtime, kernel sınırına en yakın bileşendir. Namespaces oluşturur, cgroup ayarlarını yazar, capabilities ve seccomp filters uygular ve son olarak container process'i için `execve()` çağrısı yapar. İnsanlar "container isolation" kavramını mekanik düzeyde tartıştıklarında, açıkça belirtmeseler bile genellikle bu katmandan bahsederler.

### `runc`

`runc`, referans OCI runtime'dır ve en iyi bilinen implementation olmaya devam eder. Docker, containerd ve birçok Kubernetes deployment'ı altında yoğun biçimde kullanılır. Birçok public research ve exploitation materyali `runc` tarzı ortamları hedefler; bunun nedeni bu ortamların yaygın olması ve `runc`'un birçok kişinin Linux container'ı düşündüğünde aklına gelen temel modeli tanımlamasıdır. Bu nedenle `runc`'u anlamak, okuyucuya klasik container isolation için güçlü bir zihinsel model sağlar.

### `crun`

`crun`, C ile yazılmış ve modern Podman ortamlarında yaygın olarak kullanılan başka bir OCI runtime'dır. İyi cgroup v2 desteği, güçlü rootless ergonomisi ve daha düşük overhead özellikleriyle sıkça övülür. Security açısından önemli olan, farklı bir dilde yazılmış olması değil, aynı rolü üstlenmesidir: OCI configuration'ını kernel altında çalışan bir process tree'ye dönüştüren bileşendir. Rootless Podman workflow'u genellikle `crun` her şeyi sihirli biçimde düzelttiği için değil, etrafındaki genel stack user namespaces ve least privilege yaklaşımını daha güçlü biçimde benimsediği için daha güvenli hissettirir.

### `runsc` From gVisor

`runsc`, gVisor tarafından kullanılan runtime'dır. Burada sınır anlamlı biçimde değişir. Çoğu syscall'ı normal şekilde doğrudan host kernel'e iletmek yerine gVisor, Linux interface'inin büyük bölümlerini emüle eden veya aracılık eden bir userspace kernel layer ekler. Sonuç, birkaç ekstra flag'e sahip normal bir `runc` container değildir; host-kernel attack surface'ini azaltmak amacıyla tasarlanmış farklı bir sandbox modelidir. Compatibility ve performance trade-off'ları bu tasarımın bir parçasıdır. Bu nedenle `runsc` kullanan ortamlar, normal OCI runtime ortamlarından farklı şekilde dokümante edilmelidir.

### `kata-runtime`

Kata Containers, workload'u lightweight virtual machine içinde başlatarak sınırı daha da ileri taşır. Yönetim açısından bu hâlâ bir container deployment'ı gibi görünebilir ve orchestration layer'ları da bunu bu şekilde ele alabilir; ancak temel isolation boundary, klasik host-kernel-shared container'dan ziyade virtualization'a daha yakındır. Bu durum, container merkezli workflow'lardan vazgeçmeden daha güçlü tenant isolation istendiğinde Kata'yı kullanışlı kılar.

## Engines And Container Managers

Low-level runtime doğrudan kernel ile konuşan bileşense, engine veya manager genellikle kullanıcıların ve operatörlerin etkileşim kurduğu bileşendir. Image pull işlemlerini, metadata'yı, log'ları, network'leri, volume'ları, lifecycle operasyonlarını ve API exposure'ı yönetir. Bu katman son derece önemlidir; çünkü gerçek dünyadaki birçok compromise burada gerçekleşir: Runtime socket'ine veya daemon API'ye erişim, low-level runtime tamamen sağlıklı olsa bile host compromise ile eşdeğer olabilir.

### Docker Engine

Docker Engine, developer'lar için en tanınabilir container platformudur ve container terminolojisinin Docker merkezli hâle gelmesinin nedenlerinden biridir. Tipik yol `docker` CLI'den `dockerd`'a, oradan da `containerd` ve bir OCI runtime gibi low-level bileşenleri koordine etmeye uzanır. Tarihsel olarak Docker deployment'ları çoğunlukla **rootful** olmuştur; bu nedenle Docker socket'ine erişim çok güçlü bir primitive hâline gelmiştir. Pratik privilege-escalation materyalinin büyük bölümünün `docker.sock` üzerine odaklanmasının nedeni budur: Bir process, `dockerd`'dan privileged container oluşturmasını, host path'lerini mount etmesini veya host namespaces'e katılmasını isteyebiliyorsa kernel exploit'ine hiç ihtiyaç duymayabilir.

### Podman

Podman, daha daemonless bir model temelinde tasarlanmıştır. Operasyonel olarak bu yaklaşım, container'ların uzun süre çalışan privileged bir daemon yerine standart Linux mekanizmalarıyla yönetilen process'lerden ibaret olduğu fikrini güçlendirir. Podman ayrıca birçok kişinin ilk öğrendiği klasik Docker deployment'larına kıyasla çok daha güçlü bir **rootless** yaklaşımına sahiptir. Bu, Podman'ı otomatik olarak güvenli hâle getirmez; ancak özellikle user namespaces, SELinux ve `crun` ile birlikte kullanıldığında varsayılan risk profilini önemli ölçüde değiştirir.

### containerd

containerd, birçok modern stack'te temel bir runtime management bileşenidir. Docker altında kullanılır ve aynı zamanda baskın Kubernetes runtime backend'lerinden biridir. Güçlü API'ler sunar, image'ları ve snapshot'ları yönetir ve nihai process oluşturma işlemini low-level runtime'a devreder. containerd ile ilgili security tartışmalarında, containerd socket'ine veya `ctr`/`nerdctl` işlevlerine erişimin, interface ve workflow daha az "developer friendly" hissettirse bile Docker API'sine erişim kadar tehlikeli olabileceği vurgulanmalıdır.

### CRI-O

CRI-O, Docker Engine'e kıyasla daha odaklıdır. Genel amaçlı bir developer platformu olmak yerine Kubernetes Container Runtime Interface'ını temiz biçimde uygulamak üzere tasarlanmıştır. Bu nedenle Kubernetes distribution'larında ve OpenShift gibi SELinux ağırlıklı ecosystem'lerde özellikle yaygındır. Security açısından bu daha dar kapsam kullanışlıdır; çünkü kavramsal karmaşayı azaltır: CRI-O, her şeyi kapsayan bir platformdan ziyade açıkça "Kubernetes için container çalıştırma" katmanının parçasıdır.

### Incus, LXD, And LXC

Incus/LXD/LXC sistemlerini Docker tarzı application container'larından ayrı değerlendirmek gerekir; çünkü bunlar çoğu zaman **system container** olarak kullanılır. Bir system container'ın daha full bir userspace'e, uzun süre çalışan service'lere, daha zengin device exposure'a ve host ile daha kapsamlı integration'a sahip lightweight machine gibi davranması beklenir. Isolation mechanisms hâlâ kernel primitives'tir; ancak operasyonel beklentiler farklıdır. Bu nedenle buradaki misconfiguration'lar genellikle "bad app-container defaults" gibi değil, lightweight virtualization veya host delegation hataları gibi görünür.

### systemd-nspawn

systemd-nspawn, systemd-native olması ve testing, debugging ile OS-like environment'lar çalıştırmak için kullanışlı olması nedeniyle ilginç bir konuma sahiptir. Cloud-native production runtime'ı olarak baskın değildir; ancak lab'larda ve distro odaklı ortamlarda yeterince sık görülür. Bu nedenle anılmayı hak eder. Security analysis açısından, "container" kavramının birçok ecosystem'i ve operasyonel yaklaşımı kapsadığını hatırlatan başka bir örnektir.

### Apptainer / Singularity

Apptainer (eski adıyla Singularity), research ve HPC ortamlarında yaygındır. Trust assumptions, user workflow ve execution model bakımından Docker/Kubernetes merkezli stack'lerden önemli ölçüde farklıdır. Özellikle bu ortamlar, kullanıcılara geniş kapsamlı privileged container-management yetkileri vermeden packaged workload'ları çalıştırabilmeye büyük önem verir. Bir reviewer her container ortamının temelde "bir server üzerinde Docker" olduğunu varsayarsa bu deployment'ları ciddi biçimde yanlış anlayacaktır.

## Build-Time Tooling

Birçok security tartışması yalnızca runtime'ı ele alır; ancak build-time tooling de önemlidir. Çünkü image içeriğini, build secrets exposure'ını ve final artifact içine ne kadar trusted context gömüldüğünü belirler.

**BuildKit** ve `docker buildx`, caching, secret mounting, SSH forwarding ve multi-platform build gibi özellikleri destekleyen modern build backend'leridir. Bunlar kullanışlı özelliklerdir; ancak security açısından secret'ların image layer'larına leak edebileceği veya gereğinden geniş bir build context'in hiçbir zaman dahil edilmemesi gereken dosyaları açığa çıkarabileceği noktalar da oluştururlar. **Buildah**, özellikle Podman etrafındaki OCI-native ecosystem'lerde benzer bir rol üstlenirken, **Kaniko** genellikle build pipeline'a privileged Docker daemon yetkisi vermek istemeyen CI ortamlarında kullanılır.

Temel ders şudur: Image oluşturma ve image çalıştırma farklı aşamalardır; ancak zayıf bir build pipeline, container başlatılmadan çok önce zayıf bir runtime posture oluşturabilir.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes zihinsel olarak runtime'ın kendisiyle eşitlenmemelidir. Kubernetes orchestrator'dır. Pod'ları schedule eder, desired state'i saklar ve workload configuration aracılığıyla security policy'yi ifade eder. Daha sonra kubelet, containerd veya CRI-O gibi bir CRI implementation ile konuşur; bu implementation da `runc`, `crun`, `runsc` veya `kata-runtime` gibi bir low-level runtime'ı çağırır.

Bu ayrım önemlidir; çünkü birçok kişi bir protection'ı yanlış biçimde "Kubernetes"e atfeder; oysa protection gerçekte node runtime tarafından enforce ediliyor olabilir. Ya da Pod spec'ten kaynaklanan bir davranış için "containerd defaults" suçlanabilir. Pratikte final security posture bir bileşimdir: Orchestrator bir şey talep eder, runtime stack bunu dönüştürür ve kernel son olarak enforce eder.

## Why Runtime Identification Matters During Assessment

Engine ve runtime'ı erken tespit ederseniz, sonraki birçok gözlemi yorumlamak kolaylaşır. Rootless Podman container, user namespaces'in muhtemelen sürecin bir parçası olduğunu gösterir. Bir workload içine mount edilmiş Docker socket'i, API-driven privilege escalation'ın gerçekçi bir yol olduğunu gösterir. CRI-O/OpenShift node'u, hemen SELinux labels ve restricted workload policy'yi düşünmenizi sağlamalıdır. gVisor veya Kata ortamı ise klasik bir `runc` breakout PoC'sinin aynı şekilde çalışacağını varsayma konusunda daha temkinli olmanızı gerektirir.

Bu nedenle container assessment sırasında ilk adımlardan biri her zaman şu iki basit soruyu yanıtlamak olmalıdır: **container'ı hangi component yönetiyor** ve **process'i gerçekte hangi runtime başlattı**. Bu yanıtlar netleştiğinde, ortamın geri kalanını anlamlandırmak genellikle çok daha kolay hâle gelir.

## Runtime Vulnerabilities

Her container escape, operator misconfiguration nedeniyle gerçekleşmez. Bazen runtime'ın kendisi vulnerable component'tir. Bu önemlidir; çünkü workload dikkatli göründüğü bir configuration ile çalışıyor olsa bile low-level runtime flaw üzerinden exposed olabilir.

Klasik örnek, `runc` içindeki **CVE-2019-5736**'dır. Bu vulnerability'de malicious container, host üzerindeki `runc` binary'sini overwrite edebilir ve daha sonra gerçekleşecek bir `docker exec` veya benzer runtime invocation işleminin attacker-controlled code'u tetiklemesini bekleyebilirdi. Exploit path'i, basit bir bind-mount veya capability hatasından oldukça farklıdır; çünkü exec handling sırasında runtime'ın container process space'e yeniden girmesinden yararlanır.<sup>[[1]](#references)</sup>

Red-team perspective açısından minimal reproduction workflow şu şekildedir:
```bash
go build main.go
./main
```
Ardından, host üzerinden:
```bash
docker exec -it <container-name> /bin/sh
```
Temel çıkarım, geçmişteki exploit uygulamasının tam olarak nasıl gerçekleştirildiği değil, değerlendirme açısından taşıdığı anlamdır: runtime sürümü vulnerable ise, görünür container yapılandırması bariz şekilde zayıf görünmese bile normal container içi code execution host'u compromise etmek için yeterli olabilir.

`runc` içindeki `CVE-2024-21626`, BuildKit mount race'leri ve containerd parsing bug'ları gibi güncel runtime CVE'leri de aynı noktayı pekiştiriyor. Runtime sürümü ve patch seviyesi yalnızca bakım ayrıntıları değil, security boundary'nin bir parçasıdır.

## Referanslar

- [1] [Docker'dan runC üzerinden çıkış – CVE-2019-5736 açıklaması](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
