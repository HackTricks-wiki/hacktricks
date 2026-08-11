# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Container security alanındaki en büyük karmaşa kaynaklarından biri, tamamen farklı birkaç bileşenin çoğu zaman aynı kelimeyle ifade edilmesidir. "Docker"; bir image formatını, bir CLI'yi, bir daemon'u, bir build sistemini, bir runtime stack'ini veya genel olarak container kavramını ifade ediyor olabilir. Security çalışmaları açısından bu belirsizlik bir sorundur; çünkü farklı katmanlar farklı korumalardan sorumludur. Hatalı bir bind mount nedeniyle gerçekleşen bir breakout, low-level runtime bug nedeniyle gerçekleşen bir breakout ile aynı şey değildir; ikisi de Kubernetes'teki bir cluster policy hatasıyla aynı değildir.

Bu sayfa, ecosystem'i rollerine göre ayırır. Böylece bölümün geri kalanında bir protection veya weakness'ın gerçekte nerede bulunduğundan kesin şekilde bahsedilebilir.

## OCI As The Common Language

Modern Linux container stack'leri, bir dizi OCI specification'ı konuştukları için çoğu zaman birlikte çalışabilir. **OCI Image Specification**, image'ların ve layer'ların nasıl temsil edildiğini açıklar. **OCI Runtime Specification**, runtime'ın namespace'ler, mount'lar, cgroup'lar ve security ayarları da dahil olmak üzere process'i nasıl başlatması gerektiğini açıklar. **OCI Distribution Specification** ise registry'lerin content'i nasıl sunduğunu standardize eder.

Bu önemlidir; çünkü bir tool ile build edilen bir container image'ın neden çoğu zaman başka bir tool ile çalıştırılabildiğini ve birkaç engine'in neden aynı low-level runtime'ı paylaşabildiğini açıklar. Ayrıca security davranışının farklı product'lar arasında neden benzer görünebildiğini de açıklar: Bunların çoğu aynı OCI runtime configuration'ını oluşturur ve bunu aynı küçük runtime grubuna iletir.

## Low-Level OCI Runtimes

Low-level runtime, kernel sınırına en yakın bileşendir. Namespace'leri gerçekten oluşturan, cgroup ayarlarını yazan, capability'leri ve seccomp filter'larını uygulayan ve son olarak container process'ini `execve()` eden kısım budur. İnsanlar mekanik düzeyde "container isolation" hakkında konuştuğunda, açıkça belirtmeseler bile genellikle bu katmandan bahsederler.

### `runc`

`runc`, reference OCI runtime'dır ve en bilinen implementation olmaya devam eder. Docker, containerd ve birçok Kubernetes deployment'ında yoğun şekilde kullanılır. Birçok public research ve exploitation materyali, yaygın olmaları ve `runc`'ın birçok kişinin Linux container düşündüğünde aklına gelen baseline'ı tanımlaması nedeniyle `runc` tarzı environment'ları hedefler. Bu nedenle `runc`'ı anlamak, okuyucuya klasik container isolation için güçlü bir zihinsel model sağlar.

### `crun`

`crun`, C ile yazılmış ve modern Podman environment'larında yaygın olarak kullanılan başka bir OCI runtime'dır. İyi cgroup v2 desteği, güçlü rootless ergonomisi ve daha düşük overhead nedeniyle sıkça övülür. Security açısından önemli olan, farklı bir dilde yazılmış olması değil, aynı rolü oynamaya devam etmesidir: OCI configuration'ını kernel altında çalışan bir process tree'ye dönüştüren bileşendir. Rootless Podman workflow'u genellikle `crun` her şeyi sihirli şekilde düzelttiği için değil, etrafındaki genel stack user namespace'lere ve least privilege'a daha fazla yöneldiği için daha güvenli hissettirir.

### `runsc` From gVisor

`runsc`, gVisor tarafından kullanılan runtime'dır. Burada sınır anlamlı şekilde değişir. gVisor, çoğu syscall'ı olağan şekilde doğrudan host kernel'ine iletmek yerine, Linux interface'inin büyük bölümlerini taklit eden veya yöneten bir userspace kernel layer ekler. Sonuç, birkaç ek flag'e sahip normal bir `runc` container değildir; host-kernel attack surface'ini azaltmayı amaçlayan farklı bir sandbox tasarımıdır. Compatibility ve performance tradeoff'ları bu tasarımın parçasıdır. Bu nedenle `runsc` kullanan environment'lar, normal OCI runtime environment'larından farklı şekilde dokümante edilmelidir.

### `kata-runtime`

Kata Containers, workload'u lightweight bir virtual machine içinde başlatarak sınırı daha ileri taşır. Yönetim açısından bu hâlâ bir container deployment'ı gibi görünebilir ve orchestration layer'ları bunu hâlâ bu şekilde ele alabilir; ancak temel isolation boundary, klasik host-kernel-shared container'dan çok virtualization'a yakındır. Bu, container merkezli workflow'lardan vazgeçmeden daha güçlü tenant isolation istendiğinde Kata'yı kullanışlı kılar.

## Engines And Container Managers

Low-level runtime doğrudan kernel ile konuşan bileşense, engine veya manager kullanıcıların ve operator'ların genellikle etkileşim kurduğu bileşendir. Image pull'larını, metadata'yı, log'ları, network'leri, volume'ları, lifecycle operation'larını ve API exposure'ı yönetir. Bu katman son derece önemlidir; çünkü gerçek dünyadaki birçok compromise burada gerçekleşir: Runtime socket'ine veya daemon API'sine erişim, low-level runtime tamamen sağlıklı olsa bile host compromise'a eşdeğer olabilir.

### Docker Engine

Docker Engine, developer'lar için en tanınabilir container platformudur ve container vocabulary'sinin Docker şeklinde oluşmasının nedenlerinden biridir. Tipik yol `docker` CLI'den `dockerd`'a, oradan da `containerd` ve bir OCI runtime gibi lower-level component'leri koordine etmeye uzanır. Docker deployment'ları tarihsel olarak çoğunlukla **rootful** olmuştur ve Docker socket'ine erişim bu nedenle çok güçlü bir primitive hâline gelmiştir. Bu yüzden pratik privilege-escalation materyallerinin büyük bölümü `docker.sock` üzerine odaklanır: Bir process, `dockerd`'dan privileged bir container oluşturmasını, host path'lerini mount etmesini veya host namespace'lerine katılmasını isteyebiliyorsa kernel exploit'ine hiç ihtiyaç duymayabilir.

### Podman

Podman, daha daemonless bir model etrafında tasarlanmıştır. Operasyonel açıdan bu, container'ların uzun süre çalışan privileged bir daemon yerine standart Linux mekanizmalarıyla yönetilen process'ler olduğu fikrini güçlendirir. Podman ayrıca birçok kişinin ilk öğrendiği klasik Docker deployment'larından çok daha güçlü bir **rootless** yaklaşımına sahiptir. Bu, Podman'ı otomatik olarak güvenli yapmaz; ancak özellikle user namespace'ler, SELinux ve `crun` ile birleştirildiğinde varsayılan risk profilini önemli ölçüde değiştirir.

### containerd

containerd, birçok modern stack'te temel bir runtime management component'tir. Docker altında kullanılır ve aynı zamanda baskın Kubernetes runtime backend'lerinden biridir. Güçlü API'ler sunar, image'ları ve snapshot'ları yönetir ve son process creation işlemini bir low-level runtime'a devreder. containerd hakkındaki security tartışmaları, containerd socket'ine veya `ctr`/`nerdctl` işlevlerine erişimin, interface ve workflow daha az "developer friendly" görünse bile Docker API'sine erişim kadar tehlikeli olabileceğini vurgulamalıdır.

### CRI-O

CRI-O, Docker Engine'den daha odaklıdır. Genel amaçlı bir developer platformu olmak yerine, Kubernetes Container Runtime Interface'i temiz şekilde uygulamak üzere oluşturulmuştur. Bu nedenle Kubernetes distribution'larında ve OpenShift gibi SELinux ağırlıklı ecosystem'lerde özellikle yaygındır. Security açısından bu daha dar kapsam faydalıdır; çünkü kavramsal karmaşayı azaltır: CRI-O, tamamen bir "Kubernetes için container çalıştırma" katmanının parçasıdır; her şeyi kapsayan bir platform değildir.

### Incus, LXD, And LXC

Incus/LXD/LXC sistemlerini Docker tarzı application container'larından ayrı değerlendirmek gerekir; çünkü bunlar çoğu zaman **system container** olarak kullanılır. Bir system container'ın daha full bir userspace'e, uzun süre çalışan service'lere, daha zengin device exposure'a ve host ile daha kapsamlı integration'a sahip lightweight bir machine gibi görünmesi beklenir. Isolation mechanism'ları hâlâ kernel primitive'leridir; ancak operasyonel beklentiler farklıdır. Bunun sonucunda buradaki misconfiguration'lar çoğu zaman "kötü app-container default'ları"ndan çok lightweight virtualization veya host delegation hataları şeklinde görünür.

### systemd-nspawn

systemd-nspawn, systemd-native olması ve testing, debugging ile OS benzeri environment'ları çalıştırmak için oldukça kullanışlı olması nedeniyle ilginç bir konuma sahiptir. Dominant cloud-native production runtime değildir; ancak lab'lerde ve distro odaklı environment'larda yeterince sık görüldüğü için anılmayı hak eder. Security analysis açısından bu, "container" kavramının birden fazla ecosystem'i ve operasyonel tarzı kapsadığını hatırlatan başka bir örnektir.

### Apptainer / Singularity

Apptainer (eski adıyla Singularity), research ve HPC environment'larında yaygındır. Trust assumption'ları, user workflow'u ve execution model'i Docker/Kubernetes merkezli stack'lerden önemli şekillerde farklıdır. Özellikle bu environment'lar, kullanıcılara geniş privileged container-management yetkileri vermeden packaged workload'ları çalıştırmalarına izin vermeye büyük önem verir. Bir reviewer her container environment'ının temelde "bir server üzerinde Docker" olduğunu varsayarsa bu deployment'ları ciddi şekilde yanlış anlayacaktır.

## Build-Time Tooling

Birçok security tartışması yalnızca runtime'dan bahseder; ancak build-time tooling de önemlidir, çünkü image içeriğini, build secret'larının exposure'ını ve ne kadar trusted context'in final artifact içine gömüldüğünü belirler.

**BuildKit** ve `docker buildx`, caching, secret mounting, SSH forwarding ve multi-platform build'ler gibi özellikleri destekleyen modern build backend'leridir. Bunlar kullanışlı özelliklerdir; ancak security açısından secret'ların image layer'larına leak edebileceği veya gereğinden geniş bir build context'in hiçbir zaman dahil edilmemesi gereken file'ları açığa çıkarabileceği alanlar da oluştururlar. **Buildah**, özellikle Podman çevresindeki OCI-native ecosystem'lerde benzer bir rol oynar. **Kaniko** ise çoğu zaman build pipeline'a privileged bir Docker daemon vermek istemeyen CI environment'larında kullanılır.

Temel ders şudur: Image creation ve image execution farklı aşamalardır; ancak zayıf bir build pipeline, container başlatılmadan çok önce zayıf bir runtime security posture oluşturabilir.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes, zihinsel olarak runtime'ın kendisiyle eşitlenmemelidir. Kubernetes orchestrator'dır. Pod'ları schedule eder, desired state'i saklar ve workload configuration aracılığıyla security policy'yi ifade eder. Ardından kubelet, containerd veya CRI-O gibi bir CRI implementation ile konuşur; bu implementation da `runc`, `crun`, `runsc` veya `kata-runtime` gibi bir low-level runtime'ı çağırır.

Bu ayrım önemlidir; çünkü birçok kişi bir protection'ı gerçekten node runtime tarafından uygulanıyorken yanlışlıkla "Kubernetes"e atfeder veya bir davranış Pod spec'ten kaynaklanırken "containerd default'larını" suçlar. Uygulamada final security posture bir bileşimdir: Orchestrator bir şey ister, runtime stack bunu çevirir ve kernel son olarak bunu uygular.

## Why Runtime Identification Matters During Assessment

Engine ve runtime'ı erkenden tespit ederseniz, sonraki birçok gözlemi yorumlamak kolaylaşır. Rootless Podman container, user namespace'lerin muhtemelen sürecin bir parçası olduğunu gösterir. Bir workload içine mount edilmiş Docker socket'i, API-driven privilege escalation'ın gerçekçi bir yol olduğunu gösterir. CRI-O/OpenShift node'u, hemen SELinux label'larını ve restricted workload policy'yi düşünmenizi sağlamalıdır. gVisor veya Kata environment'ı, klasik bir `runc` breakout PoC'sinin aynı şekilde çalışacağını varsayma konusunda daha temkinli olmanızı gerektirir.

Bu nedenle container assessment'ın ilk adımlarından biri her zaman şu iki basit soruyu yanıtlamak olmalıdır: **container'ı hangi component yönetiyor** ve **process'i gerçekte hangi runtime başlattı**. Bu yanıtlar netleştiğinde environment'ın geri kalanını anlamlandırmak genellikle çok daha kolaylaşır.

## Runtime Vulnerabilities

Her container escape, operator misconfiguration'ından kaynaklanmaz. Bazen vulnerable component doğrudan runtime'ın kendisidir. Bu önemlidir; çünkü workload dikkatli görünen bir configuration ile çalışıyor olsa bile low-level runtime flaw üzerinden hâlâ exposed olabilir.

Klasik örnek, `runc` içindeki **CVE-2019-5736**'dır. Bu vulnerability'de malicious bir container host üzerindeki `runc` binary'sini overwrite edebilir ve ardından attacker-controlled code'u tetikleyecek daha sonraki bir `docker exec` veya benzer runtime invocation'ını bekleyebilir. Exploit path'i basit bir bind-mount veya capability hatasından oldukça farklıdır; çünkü exec handling sırasında runtime'ın container process space'e nasıl yeniden girdiğini abuse eder.<sup>[[1]](#references)</sup>

Red-team perspective'inden minimal bir reproduction workflow'u şu şekildedir:
```bash
go build main.go
./main
```
Ardından, host üzerinden:
```bash
docker exec -it <container-name> /bin/sh
```
Ana ders, tam olarak tarihsel exploit uygulaması değil, değerlendirme açısından ortaya çıkan sonuçtur: runtime sürümü vulnerable ise görünür container configuration açıkça zayıf görünmese bile, sıradan bir container içi code execution host'u compromise etmek için yeterli olabilir.

`runc` içindeki `CVE-2024-21626`, BuildKit mount race'leri ve containerd parsing bug'ları gibi yakın tarihli runtime CVE'leri aynı noktayı güçlendirir. Runtime sürümü ve patch seviyesi yalnızca önemsiz bakım ayrıntıları değil, security boundary'nin bir parçasıdır.

## References

- [1] [runC üzerinden Docker'dan kaçış – CVE-2019-5736 açıklaması](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
