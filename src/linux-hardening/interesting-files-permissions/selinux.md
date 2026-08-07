# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux, **label-based Mandatory Access Control (MAC)** sistemidir. Pratikte bu, DAC izinleri, gruplar veya Linux capabilities bir işlem için yeterli görünüyor olsa bile kernel'in işlemi yine de reddedebileceği anlamına gelir; çünkü **source context**, istenen class/permission ile **target context**'e erişemez.

Bir context genellikle şu şekilde görünür:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
privesc perspektifinden bakıldığında, `type` alanı (process'ler için domain, object'ler için type) genellikle en önemli alandır:

- Bir process, `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t` gibi bir **domain** içinde çalışır
- Dosyalar ve socket'ler `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t` gibi bir **type** değerine sahiptir
- Policy, bir domain'in diğer domain'e veya type'a read/write/execute/transition yapıp yapamayacağına karar verir

## Fast Enumeration

SELinux etkinse, bunu erken aşamada enumerate edin; çünkü yaygın Linux privesc yollarının neden başarısız olduğunu veya "zararsız" bir SELinux tool etrafındaki privileged wrapper'ın aslında neden kritik olduğunu açıklayabilir:
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

- `Disabled` veya `Permissive` mode, bir sınır olarak SELinux değerinin çoğunu ortadan kaldırır.
- `unconfined_t` genellikle SELinux'un mevcut olduğu, ancak ilgili process'i anlamlı bir şekilde kısıtlamadığı anlamına gelir.
- Özel path'lerde `default_t`, `file_t` veya bariz şekilde yanlış label'lar, çoğunlukla yanlış labeling ya da eksik deployment olduğunu gösterir.
- `file_contexts.local` içindeki yerel override'lar policy varsayılanlarına göre önceliklidir; bu nedenle bunları dikkatle inceleyin.

## Policy Analizi

SELinux, şu iki soruyu yanıtlayabildiğinizde saldırılması veya bypass edilmesi çok daha kolay hale gelir:

1. **Mevcut domain'im neye erişebilir?**
2. **Hangi domain'lere transition yapabilirim?**

Bunun için en kullanışlı araçlar `sepolicy` ve **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)</sup>
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
Bu, bir host herkesi `unconfined_u` ile eşlemek yerine **confined users** kullandığında özellikle faydalıdır. Bu durumda şunları arayın:<sup>[[3]](#references)</sup>

- `semanage login -l` ile user mappings
- `semanage user -l` ile izin verilen roller
- `sysadm_t`, `secadm_t`, `webadm_t` gibi erişilebilir admin domains
- `ROLE=` veya `TYPE=` kullanan `sudoers` entries

`sudo -l` çıktısında bunun gibi entries varsa SELinux privilege boundary'nin bir parçasıdır:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Ayrıca `newrole` komutunun kullanılabilir olup olmadığını kontrol edin:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` ve `newrole` otomatik olarak exploit edilebilir değildir; ancak ayrıcalıklı bir wrapper veya bir `sudoers` kuralı daha iyi bir role/type seçmenize izin veriyorsa, bunlar yüksek değerli escalation primitive'lerine dönüşür.

## Dosyalar, Yeniden Etiketleme ve Yüksek Değerli Yanlış Yapılandırmalar

Yaygın SELinux araçları arasındaki en önemli operasyonel fark şudur:<sup>[[1]](#references)</sup>

- `chcon`: belirli bir path üzerindeki etiketi geçici olarak değiştirir
- `semanage fcontext`: kalıcı path-to-label kuralı
- `restorecon` / `setfiles`: policy/default label'ı yeniden uygular

Bu, privesc sırasında büyük önem taşır çünkü **yeniden etiketleme yalnızca kozmetik değildir**. Bir dosyayı "policy tarafından engellenen" durumdan "ayrıcalıklı confined bir servis tarafından okunabilir/executable" duruma dönüştürebilir.

Yerel yeniden etiketleme kurallarını ve yeniden etiketleme sapmasını kontrol edin:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
İnce ancak faydalı bir ayrıntı: düz `restorecon`, şüpheli bir etiketi **her zaman tamamen geri almaz**. Hedef tür `customizable_types` içindeyse, tam sıfırlamayı zorlamak için `-F` kullanmanız gerekebilir. Offensive açıdan bu, alışılmadık bir `chcon` işleminin yüzeysel bir "restorecon'u zaten çalıştırdık" temizliğinden bazen nasıl kurtulabildiğini açıklar.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`, root wrapper'ları, otomasyon script'leri veya file capabilities içinde aranacak yüksek değerli komutlar:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Herhangi bir MAC capability ortaya çıkarsa, [Linux capabilities page](linux-capabilities.md) sayfasını da kontrol edin; `cap_mac_admin` ve `cap_mac_override` alışılmadık olsa da SELinux sınırın bir parçası olduğunda doğrudan önemlidir.

Özellikle ilgi çekici olanlar:

- `semanage fcontext`: bir path'in alması gereken label'ı kalıcı olarak değiştirir
- `restorecon` / `setfiles`: bu değişiklikleri geniş ölçekte yeniden uygular
- `semodule -i`: özel bir policy module yükler
- `semanage permissive -a <domain_t>`: tüm host'u değiştirmeden tek bir domain'i permissive yapar
- `setsebool -P`: policy boolean'larını kalıcı olarak değiştirir
- `load_policy`: etkin policy'yi yeniden yükler

Bunlar çoğunlukla **yardımcı primitive'lerdir**, tek başına root exploitleri değildir. Değerleri, şunları yapabilmenizi sağlamalarından gelir:

- hedef domain'i permissive yapmak
- kendi domain'iniz ile korunan bir type arasındaki erişimi genişletmek
- attacker-controlled dosyaları, privileged bir servisin okuyabilmesi veya çalıştırabilmesi için yeniden label'lamak
- mevcut bir local bug'ın exploitable hâle gelmesi için confined bir servisin kısıtlamalarını yeterince zayıflatmak

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

## Gizli Reddetmeler ve Modül Çıkarma

Yaygın bir offensive frustration, beklenen AVC denial görünmeden, belirsiz bir `EACCES` ile başarısız olan bir zincirdir. `dontaudit` kuralları, ihtiyacınız olan tam izni gizliyor olabilir. `semodule` komutunu `sudo` veya başka bir privileged wrapper üzerinden çalıştırabiliyorsanız, `dontaudit` özelliğini geçici olarak devre dışı bırakmak, sessiz bir hatayı kesin bir policy ipucuna dönüştürebilir:<sup>[[4]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Bu, yerel admin'lerin daha önce neleri değiştirdiğini incelemek için de kullanışlıdır. Küçük bir custom module veya tek-domain permissive rule, hedef service'in base policy'nin önerdiğinden çok daha gevşek davranmasının genellikle nedenidir.

## Audit Clues

AVC denials çoğu zaman yalnızca defensive noise değil, offensive signal'dir. Size şunları söyler:

- hangi target object/type'a ulaştığınız
- hangi permission'ın reddedildiği
- şu anda hangi domain'i kontrol ettiğiniz
- küçük bir policy değişikliğinin chain'i çalışır hâle getirip getirmeyeceği
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Bir local exploit veya persistence girişimi, root gibi görünen DAC izinlerine rağmen `EACCES` ya da garip "permission denied" hatalarıyla başarısız olmaya devam ediyorsa, vector'ü gözden çıkarmadan önce SELinux'u kontrol etmek genellikle faydalıdır.

## SELinux Kullanıcıları

Normal Linux kullanıcılarına ek olarak SELinux kullanıcıları da vardır. Her Linux kullanıcısı, policy'nin bir parçası olarak bir SELinux kullanıcısıyla eşleştirilir; bu da sistemin farklı hesaplara farklı izin verilen roller ve domain'ler uygulamasını sağlar.<sup>[[3]](#references)</sup>

Hızlı kontroller:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Birçok yaygın sistemde kullanıcılar `unconfined_u` ile eşleştirilir; bu da kullanıcı confinement'ının pratik etkisini azaltır. Ancak hardened deployment'larda confined kullanıcılar `sudo`, `su`, `newrole` ve `runcon` komutlarını çok daha ilginç hâle getirebilir; çünkü **escalation path yalnızca UID 0 olmaya değil, daha uygun bir SELinux role/type'a geçmeye de bağlı olabilir**. Ayrıca bazı confined kullanıcıların, policy temel setuid transition'a açıkça izin vermediği sürece `sudo`/`su` komutlarını hiç çalıştıramayacağını unutmayın. Bu nedenle `staff_u` + `sysadm_r` kullanan bir host, görünüşte küçük bir `sudo ROLE=` / `TYPE=` kuralını gerçek privilege boundary hâline getirebilir.<sup>[[3]](#references)</sup>

## Container'larda SELinux

Container runtime'ları genellikle workload'ları `container_t` gibi confined bir domain'de başlatır ve container içeriğini `container_file_t` olarak label'lar. Bir container process'i escape etse ancak container label'ı ile çalışmaya devam etse bile, label boundary korunduğu için host write işlemleri yine başarısız olabilir.

Hızlı örnek:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` kısmı dekorasyon değildir. Birçok container dağıtımında runtime'lar, `container_t` olarak çalışan iki işlemin yine de birbirinden ayrılması için MCS kategorilerini dinamik olarak atar. Bir escape sizi host namespace'ine taşır ancak özgün kategori kümesini korursa, kategori uyumsuzlukları bazı host yollarının neden hâlâ okunamadığını veya yazılamadığını açıklayabilir.

Dikkate alınması gereken modern container işlemleri:

- `--security-opt label=disable`, workload'u `spc_t` gibi unconfined, container ile ilişkili bir tipe taşıyabilir
- `:z` / `:Z` içeren bind mount'lar, host yolunun shared/private container kullanımı için yeniden etiketlenmesini tetikler
- Host içeriğinin geniş kapsamlı yeniden etiketlenmesi tek başına bir security issue hâline gelebilir

Bu sayfa, tekrarı önlemek için container içeriğini kısa tutar. Container'a özgü abuse case'ler ve runtime örnekleri için şuraya bakın:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Referanslar

- [1] [Red Hat docs: SELinux Kullanımı](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: SELinux için Policy analysis araçları](https://github.com/SELinuxProject/setools)
- [3] [Confined ve unconfined kullanıcıları yönetme - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)

{{#include ../../banners/hacktricks-training.md}}
