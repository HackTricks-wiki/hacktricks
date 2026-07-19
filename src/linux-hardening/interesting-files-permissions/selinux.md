# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux, **label tabanlı Zorunlu Erişim Denetimi (MAC)** sistemidir. Pratikte bu, DAC izinleri, gruplar veya Linux capabilities bir işlem için yeterli görünse bile, **source context** istenen sınıf/izin ile **target context** erişimine izin vermediği için kernel'in işlemi yine de reddedebileceği anlamına gelir.

Bir context genellikle şu şekilde görünür:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Privesc açısından `type` (processes için domain, objects için type) genellikle en önemli alandır:

- Bir process, `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t` gibi bir **domain** içinde çalışır
- Dosyalar ve socket'ler, `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t` gibi bir **type** değerine sahiptir
- Policy, bir domain'in diğer domain'e read/write/execute/transition yapıp yapamayacağına karar verir

## Fast Enumeration

SELinux etkinse, yaygın Linux privesc yollarının neden başarısız olduğunu veya "zararsız" bir SELinux tool'u etrafındaki privileged wrapper'ın neden aslında kritik olduğunu açıklayabildiği için SELinux'u erkenden enumerate edin:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Yararlı takip kontrolleri:
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

- `Disabled` veya `Permissive` modu, bir sınır olarak SELinux'un değerinin çoğunu ortadan kaldırır.
- `unconfined_t` genellikle SELinux'un mevcut olduğu, ancak bu process'i anlamlı şekilde kısıtlamadığı anlamına gelir.
- Özel path'lerdeki `default_t`, `file_t` veya bariz şekilde yanlış label'lar çoğunlukla yanlış label'lama ya da eksik deployment olduğunu gösterir.
- `file_contexts.local` içindeki yerel override'lar policy varsayılanlarına göre önceliklidir; bu nedenle bunları dikkatle inceleyin.

## Policy Analysis

SELinux'u attack etmek veya bypass etmek, şu iki soruyu yanıtlayabildiğinizde çok daha kolaydır:

1. **Mevcut domain'im nelere erişebilir?**
2. **Hangi domain'lere transition yapabilirim?**

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
Bu, özellikle bir host herkesi `unconfined_u` ile eşlemek yerine **confined users** kullandığında faydalıdır. Bu durumda şunları arayın:

- `semanage login -l` ile kullanıcı eşlemeleri
- `semanage user -l` ile izin verilen roller
- `sysadm_t`, `secadm_t`, `webadm_t` gibi erişilebilen admin domain'leri
- `ROLE=` veya `TYPE=` kullanan `sudoers` girdileri

`sudo -l` şuna benzer girdiler içeriyorsa SELinux, ayrıcalık sınırının bir parçasıdır:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Ayrıca `newrole` komutunun kullanılabilir olup olmadığını kontrol edin:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` ve `newrole` otomatik olarak exploitable değildir; ancak ayrıcalıklı bir wrapper veya bir `sudoers` kuralı daha iyi bir role/type seçmenize izin veriyorsa, yüksek değerli escalation primitive'lerine dönüşürler.

## Dosyalar, Yeniden Etiketleme ve Yüksek Değerli Yanlış Yapılandırmalar

Yaygın SELinux araçları arasındaki en önemli operasyonel fark şudur:

- `chcon`: belirli bir path üzerindeki geçici label değişikliği
- `semanage fcontext`: kalıcı path-to-label kuralı
- `restorecon` / `setfiles`: policy/default label'ı yeniden uygular

Bu, privesc sırasında büyük önem taşır çünkü **relabeling yalnızca kozmetik değildir**. Bir dosyayı "policy tarafından engellenen" durumdan "ayrıcalıklı bir confined service tarafından okunabilir/executable" duruma dönüştürebilir.

Local relabel kurallarını ve relabel drift'i kontrol edin:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
İnce ancak faydalı bir ayrıntı: düz `restorecon`, **şüpheli bir etiketi her zaman tamamen geri almaz**. Hedef tür `customizable_types` içindeyse, tam sıfırlamayı zorlamak için `-F` kullanmanız gerekebilir. Saldırı perspektifinden bu, alışılmadık bir `chcon` işleminin "restorecon'u zaten çalıştırdık" şeklindeki yüzeysel bir temizleme işleminden bazen neden kurtulabildiğini açıklar.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`, root wrapper'ları, otomasyon script'leri veya file capabilities içinde aranacak öncelikli komutlar:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Herhangi bir MAC capability görünüyorsa [Linux capabilities page](linux-capabilities.md) sayfasını da kontrol edin; `cap_mac_admin` ve `cap_mac_override` alışılmadık olsa da SELinux sınırın bir parçası olduğunda doğrudan ilgilidir.

Özellikle ilgi çekici olanlar:

- `semanage fcontext`: bir path'in alması gereken label'ı kalıcı olarak değiştirir
- `restorecon` / `setfiles`: bu değişiklikleri geniş ölçekte yeniden uygular
- `semodule -i`: özel bir policy module yükler
- `semanage permissive -a <domain_t>`: tüm host'u değiştirmeden tek bir domain'i permissive yapar
- `setsebool -P`: policy boolean'larını kalıcı olarak değiştirir
- `load_policy`: aktif policy'yi yeniden yükler

Bunlar çoğu zaman **tek başına root exploit'leri değil, helper primitive'lerdir**. Değerleri, şunları yapabilmelerinden kaynaklanır:

- bir hedef domain'i permissive yapmak
- domain'iniz ile korumalı bir type arasındaki erişimi genişletmek
- privileged bir service'in okuyabilmesi veya çalıştırabilmesi için attacker-controlled dosyaları yeniden label'lamak
- mevcut bir local bug'ın exploit edilebilmesi için confined bir service'i yeterince zayıflatmak

Örnek kontroller:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Bir policy module'ünü root olarak yükleyebiliyorsanız, genellikle SELinux sınırını kontrol edersiniz:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Bu nedenle `audit2allow`, `semodule` ve `semanage permissive`, post-exploitation sırasında hassas admin yüzeyleri olarak değerlendirilmelidir. Klasik UNIX izinlerini değiştirmeden, engellenmiş bir zinciri sessizce çalışan bir zincire dönüştürebilirler.

## Gizli Denials ve Module Extraction

Çok yaygın bir offensive frustration, beklenen AVC denial görünmeden basit bir `EACCES` ile başarısız olan bir zincirdir. `dontaudit` kuralları, ihtiyacınız olan tam izni gizliyor olabilir. `semodule` komutunu `sudo` veya başka bir privileged wrapper üzerinden çalıştırabiliyorsanız, `dontaudit` özelliğini geçici olarak devre dışı bırakmak sessiz bir hatayı kesin bir policy ipucuna dönüştürebilir:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Bu, yerel yöneticilerin daha önce neleri değiştirdiğini incelemek için de kullanışlıdır. Küçük bir custom module veya tek bir domain için permissive rule, hedef servisin temel policy'nin işaret ettiğinden çok daha gevşek davranmasının nedeni olabilir.

## Audit İpuçları

AVC denials yalnızca savunma amaçlı gürültü değil, çoğu zaman saldırı açısından bir sinyaldir. Size şunları gösterir:

- hangi target object/type'a eriştiğiniz
- hangi iznin reddedildiği
- şu anda hangi domain'i kontrol ettiğiniz
- küçük bir policy değişikliğinin chain'i çalışır hâle getirip getirmeyeceği
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Yerel bir exploit veya persistence denemesi, root izinlerine benzer DAC izinlerine rağmen sürekli `EACCES` ya da garip "permission denied" hatalarıyla başarısız oluyorsa, vector'ü gözden çıkarmadan önce SELinux'u kontrol etmek genellikle faydalıdır.

## SELinux Kullanıcıları

Normal Linux kullanıcılarına ek olarak SELinux kullanıcıları da bulunur. Her Linux kullanıcısı, policy'nin bir parçası olarak bir SELinux kullanıcısıyla eşleştirilir; bu da sistemin farklı hesaplara farklı izin verilen roller ve domain'ler uygulamasını sağlar.

Hızlı kontroller:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Birçok mainstream sistemde kullanıcılar `unconfined_u` ile eşlenir; bu da kullanıcı confinement'ının pratik etkisini azaltır. Ancak hardened deployment'larda confined kullanıcılar `sudo`, `su`, `newrole` ve `runcon` komutlarını çok daha ilginç hâle getirebilir; çünkü **escalation path yalnızca UID 0 olmaya değil, daha yetkili bir SELinux role/type'a geçmeye de bağlı olabilir**. Ayrıca bazı confined kullanıcıların policy, temel setuid transition'a açıkça izin vermediği sürece `sudo`/`su` komutlarını hiç çalıştıramayacağını unutmayın. Bu nedenle `staff_u` + `sysadm_r` kullanan bir host, görünüşte küçük bir `sudo ROLE=` / `TYPE=` kuralını gerçek privilege boundary hâline getirebilir.

## Container'larda SELinux

Container runtime'ları genellikle workload'ları `container_t` gibi confined bir domain'de başlatır ve container içeriğini `container_file_t` olarak etiketler. Bir container process'i escape etse ancak container label'ı ile çalışmaya devam etse bile, label boundary korunduğu için host'a yazma işlemleri yine başarısız olabilir.

Hızlı örnek:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` kısmı dekorasyon değildir. Birçok container deployment'ında runtime'lar, `container_t` olarak çalışan iki process'in birbirinden ayrılmaya devam etmesi için MCS kategorilerini dinamik olarak atar. Bir escape sizi host namespace'ine taşısa ancak orijinal category set'ini korusa bile category uyuşmazlıkları, bazı host path'lerinin neden okunamaz veya yazılamaz durumda kaldığını açıklayabilir.

Dikkate alınması gereken modern container operasyonları:

- `--security-opt label=disable`, workload'u `spc_t` gibi unconfined, container ile ilişkili bir type'a etkili biçimde taşıyabilir
- `:z` / `:Z` içeren bind mount'lar, shared/private container kullanımı için host path'inin yeniden etiketlenmesini tetikler
- Host içeriğinin geniş kapsamlı biçimde yeniden etiketlenmesi, tek başına bir security issue haline gelebilir

Bu sayfa, tekrarları önlemek için container içeriğini kısa tutar. Container'a özgü abuse senaryoları ve runtime örnekleri için şuraya bakın:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Referanslar

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
