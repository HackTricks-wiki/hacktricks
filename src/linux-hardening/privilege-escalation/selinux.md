# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux, **etiket tabanlı Zorunlu Erişim Kontrolü (MAC)** sistemidir. Uygulamada bu, bir işlem için DAC izinleri, gruplar veya Linux capabilities yeterli görünse bile, çekirdek talep edilen sınıf/izin ile **kaynak bağlam**ın **hedef bağlam**a erişmesine izin verilmediği için yine de reddedebileceği anlamına gelir.

Bir bağlam genellikle şu şekilde görünür:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
From a privesc perspective, the `type` (işlemler için domain, nesneler için type) genellikle en önemli alandır:

- Bir işlem `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t` gibi bir **domain** içinde çalışır
- Dosyalar ve soketlerin `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t` gibi bir **type**'ı vardır
- Policy, bir domainin diğerini okuyup/yazıp/çalıştırıp/diğerine geçiş yapıp yapamayacağını belirler

## Fast Enumeration

If SELinux is enabled, enumerate it early because it can explain why common Linux privesc paths fail or why a privileged wrapper around a "harmless" SELinux tool is actually critical:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Faydalı takip kontrolleri:
```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```
İlginç bulgular:

- `Disabled` veya `Permissive` modu, SELinux'un bir sınır olarak sağladığı değerin çoğunu ortadan kaldırır.
- `unconfined_t` genellikle SELinux'un var olduğunu ama o süreci anlamlı şekilde kısıtlamadığını gösterir.
- `default_t`, `file_t` veya özel yollar üzerinde açıkça yanlış etiketler genellikle yanlış etiketleme veya eksik dağıtımı gösterir.
- `file_contexts.local` içindeki yerel geçersiz kılmalar politika varsayılanlarına üstünlük sağlar; bunları dikkatle inceleyin.

## Politika Analizi

İki soruyu cevaplayabiliyorsanız SELinux'a saldırmak veya atlatmak çok daha kolaydır:

1. **Mevcut domain'im hangi kaynaklara erişebilir?**
2. **Hangi domainlere geçiş yapabilirim?**

Bunun için en kullanışlı araçlar `sepolicy` ve **SETools** (`seinfo`, `sesearch`, `sedta`):
```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```
Bu, bir host herkesi `unconfined_u`'ye eşlemek yerine **kısıtlı kullanıcılar** kullanıyorsa özellikle faydalıdır. Bu durumda, şunlara bakın:

- `semanage login -l` ile kullanıcı eşlemeleri
- `semanage user -l` ile izin verilen roller
- `sysadm_t`, `secadm_t`, `webadm_t` gibi erişilebilir yönetici domainleri
- `ROLE=` veya `TYPE=` kullanan `sudoers` girdileri

Eğer `sudo -l` bu tür girdiler içeriyorsa, SELinux yetki sınırının bir parçasıdır:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Ayrıca `newrole`'ün kullanılabilir olup olmadığını kontrol edin:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` ve `newrole` otomatik olarak sömürülebilir değiller; ancak ayrıcalıklı bir wrapper veya bir `sudoers` kuralı size daha iyi bir role/type seçme imkanı veriyorsa, yüksek değere sahip escalation primitives haline gelirler.

## Dosyalar, Yeniden Etiketleme ve Yüksek Değerli Yanlış Yapılandırmalar

Yaygın SELinux araçları arasındaki en önemli operasyonel fark şudur:

- `chcon`: belirli bir yol üzerindeki geçici etiket değişikliği
- `semanage fcontext`: kalıcı yol→etiket kuralı
- `restorecon` / `setfiles`: politikayı/varsayılan etiketi tekrar uygular

Bu, privesc sırasında çok önemlidir çünkü **yeniden etiketleme sadece kozmetik değildir**. Bu, bir dosyayı "policy tarafından engellenmiş" durumundan "ayrıcalıklı, kısıtlı bir servis tarafından okunabilir/çalıştırılabilir" duruma dönüştürebilir.

Yerel yeniden etiketleme kurallarını ve yeniden etiketleme sapmasını kontrol edin:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Araştırılacak yüksek değerli komutlar `sudo -l`, root wrappers, otomasyon betikleri veya file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Özellikle ilgi çekici:

- `semanage fcontext`: persistently changes what label a path should receive
- `restorecon` / `setfiles`: reapplies those changes at scale
- `semodule -i`: loads a custom policy module
- `semanage permissive -a <domain_t>`: makes one domain permissive without flipping the whole host
- `setsebool -P`: permanently changes policy booleans
- `load_policy`: reloads the active policy

Bunlar genellikle **helper primitives**, tek başına root exploits değildir. Değerleri şunları yapabilmeleridir:

- hedef bir domaini permissive hale getirmek
- kendi domaininiz ile korunan bir type arasındaki erişimi genişletmek
- saldırgan-kontrolündeki dosyaları yeniden labellayıp ayrıcalıklı bir servisin bunları okuyup/çalıştırabilmesini sağlamak
- sınırlı bir servisi o kadar zayıflatmak ki mevcut bir local bug exploit edilebilir hale gelsin

Örnek kontroller:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Eğer root olarak bir policy module yükleyebiliyorsanız, genellikle SELinux sınırını kontrol edersiniz:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Bu yüzden `audit2allow`, `semodule` ve `semanage permissive` post-exploitation sırasında hassas yönetici yüzeyleri olarak ele alınmalıdır. Klasik UNIX izinlerini değiştirmeden bir engellenmiş zinciri sessizce çalışan bir hale dönüştürebilirler.

## Denetim İpuçları

AVC denials genellikle sadece savunma gürültüsü değil, aynı zamanda ofansif bir işarettir. Size şunları söyler:

- hangi hedef nesne/tipine denk geldiğinizi
- hangi iznin reddedildiğini
- şu anda hangi domain'i kontrol ettiğinizi
- küçük bir politika değişikliğinin zinciri çalışır hale getirip getirmeyeceğini
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
If a local exploit or persistence attempt keeps failing with `EACCES` or strange "permission denied" errors despite root-looking DAC permissions, SELinux is usually worth checking before discarding the vector.

## SELinux Users

Normal Linux kullanıcılarına ek olarak SELinux kullanıcıları vardır. Her Linux kullanıcısı politikanın bir parçası olarak bir SELinux kullanıcısına eşlenir; bu, sistemin farklı hesaplara farklı izinli roller ve domain'ler uygulamasına olanak tanır.

Hızlı kontroller:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Birçok yaygın sistemde kullanıcılar `unconfined_u`'ye eşlenir; bu, kullanıcı sınırlamasının pratik etkisini azaltır. Ancak sertleştirilmiş dağıtımlarda, sınırlandırılmış kullanıcılar `sudo`, `su`, `newrole` ve `runcon`'u çok daha ilginç hale getirebilir çünkü **yükseltme yolu yalnızca UID 0 olmakla sınırlı olmayıp daha iyi bir SELinux rolüne/tipine girilmesine bağlı olabilir**.

## Konteynerlerde SELinux

Container runtime'ları genellikle iş yüklerini `container_t` gibi sınırlandırılmış bir alan içinde başlatır ve konteyner içeriğini `container_file_t` olarak etiketler. Eğer bir konteyner süreci kaçar fakat hâlâ konteyner etiketiyle çalışıyorsa, etiket sınırı korunmuş olduğundan host üzerine yazma işlemleri yine başarısız olabilir.

Kısa örnek:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Dikkate değer modern container işlemleri:

- `--security-opt label=disable` iş yükünü `spc_t` gibi unconfined container-related bir type'a etkili şekilde taşıyabilir
- bind mounts with `:z` / `:Z` host path'in shared/private container kullanımı için relabeling'ini tetikler
- host içeriğinin geniş kapsamlı relabeling'i kendi başına bir güvenlik sorunu haline gelebilir

Bu sayfa, tekrarın önlenmesi için container içeriğini kısa tutar. Container-specific kötüye kullanım vakaları ve runtime örnekleri için bakınız:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Referanslar

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
