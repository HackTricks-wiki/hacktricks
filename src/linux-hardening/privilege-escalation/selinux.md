# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux, **label-based Mandatory Access Control (MAC)** sistemidir. Pratikte bu, DAC permissions, gruplar veya Linux capabilities bir işlem için yeterli görünse bile, kernel’in yine de bunu reddedebileceği anlamına gelir; çünkü **source context**, istenen class/permission ile **target context**e erişmeye izinli değildir.

Bir context genelde şöyle görünür:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Privesc perspektifinden, `type` (işlemler için domain, nesneler için type) genellikle en önemli alandır:

- Bir process, `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t` gibi bir **domain** içinde çalışır
- Files ve sockets, `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t` gibi bir **type**'a sahiptir
- Policy, bir domain'in diğerini okuyup/yazıp/yürütüp/yürütmeyeceğine veya ona transition yapıp yapamayacağına karar verir

## Fast Enumeration

SELinux etkinse, bunu erken enumerate et çünkü bu, neden yaygın Linux privesc yollarının başarısız olduğunu veya neden "zararsız" bir SELinux tool etrafındaki privileged wrapper'ın aslında kritik olduğunu açıklayabilir:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Faydalı sonraki kontroller:
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

- `Disabled` veya `Permissive` modu, SELinux’un sınır olarak değerinin çoğunu ortadan kaldırır.
- `unconfined_t` genellikle SELinux’un mevcut olduğu ama o process’i anlamlı şekilde kısıtlamadığı anlamına gelir.
- Custom path’lerde `default_t`, `file_t` veya bariz şekilde yanlış label’lar, çoğu zaman mislabeling veya eksik deployment işaret eder.
- `file_contexts.local` içindeki local overrides, policy defaults üzerinde önceliklidir; bu yüzden dikkatlice inceleyin.

## Policy Analysis

SELinux, şu iki soruya cevap verebildiğinizde saldırması veya bypass etmesi çok daha kolay olur:

1. **Mevcut domain’im nelere erişebilir?**
2. **Hangi domain’lere transition yapabilirim?**

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
Bu, özellikle bir host herkes için `unconfined_u` kullanmak yerine **confined users** kullandığında faydalıdır. Bu durumda şunlara bakın:

- `semanage login -l` ile user mappings
- `semanage user -l` ile allowed roles
- `sysadm_t`, `secadm_t`, `webadm_t` gibi reachable admin domains
- `ROLE=` veya `TYPE=` kullanan `sudoers` entries

Eğer `sudo -l` bunun gibi entries içeriyorsa, SELinux privilege boundary’nin bir parçasıdır:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Ayrıca `newrole` mevcut mu diye kontrol edin:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` ve `newrole` otomatik olarak exploitable değildir, ancak ayrıcalıklı bir wrapper veya bir `sudoers` kuralı daha iyi bir role/type seçmenize izin veriyorsa, bunlar yüksek değerli escalation primitive'lerine dönüşür.

## Files, Relabeling, and High-Value Misconfigurations

Yaygın SELinux araçları arasındaki en önemli operasyonel fark şudur:

- `chcon`: belirli bir path üzerinde geçici label değişikliği
- `semanage fcontext`: kalıcı path-to-label kuralı
- `restorecon` / `setfiles`: policy/default label'ı tekrar uygular

Bu, privesc sırasında çok önemlidir çünkü **relabeling yalnızca kozmetik değildir**. Bir file'ı "policy tarafından blocked" durumundan "ayrıcalıklı bir confined service tarafından readable/executable" hale getirebilir.

Local relabel kurallarını ve relabel drift'i kontrol edin:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Bir ince ama yararlı detay: sıradan `restorecon` **her zaman şüpheli bir label'ı tamamen geri almaz**. Hedef type `customizable_types` içindeyse, tam bir sıfırlama zorlamak için `-F` gerekebilir. Saldırgan bakış açısından bu, alışılmadık bir `chcon`'un bazen sıradan bir "zaten restorecon çalıştırdık" temizliğinden sağ çıkabilmesini açıklar.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`, root wrapper'lar, automation script'leri veya dosya capability'lerinde aramak için yüksek değerli komutlar:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Eğer herhangi bir MAC capability görünürse, [Linux capabilities page](linux-capabilities.md) sayfasını da kontrol edin; `cap_mac_admin` ve `cap_mac_override` sıra dışıdır ama SELinux sınırın bir parçası olduğunda doğrudan ilişkilidir.

Özellikle ilginç olanlar:

- `semanage fcontext`: bir path'in hangi label'ı alması gerektiğini kalıcı olarak değiştirir
- `restorecon` / `setfiles`: bu değişiklikleri geniş ölçekte yeniden uygular
- `semodule -i`: özel bir policy module yükler
- `semanage permissive -a <domain_t>`: tüm host'u değiştirmeden tek bir domain'i permissive yapar
- `setsebool -P`: policy boolean'larını kalıcı olarak değiştirir
- `load_policy`: aktif policy'yi yeniden yükler

Bunlar çoğu zaman **helper primitive**'lerdir, tek başına root exploit'leri değildir. Değerleri şudur: size şunları yapma imkanı verirler:

- hedef domain'i permissive yapmak
- domain'iniz ile korunan bir type arasındaki erişimi genişletmek
- attacker-controlled dosyaları yeniden label'layarak ayrıcalıklı bir service'in onları okumasını veya çalıştırmasını sağlamak
- kısıtlanmış bir service'i, mevcut yerel bir bug'un exploit edilebilir hale geleceği kadar zayıflatmak

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
Bu yüzden `audit2allow`, `semodule` ve `semanage permissive`, post-exploitation sırasında hassas admin yüzeyleri olarak ele alınmalıdır. Bunlar, klasik UNIX permissions değiştirmeden blocked bir chain'i sessizce çalışan bir chain'e dönüştürebilir.

## Hidden Denials and Module Extraction

Çok yaygın bir offensive frustration, beklenen AVC denial hiç görünmezken sıradan bir `EACCES` ile başarısız olan bir chain'dir. `dontaudit` kuralları tam olarak ihtiyacınız olan permission'ı gizliyor olabilir. `semodule`'ü `sudo` veya başka bir privileged wrapper üzerinden çalıştırabiliyorsanız, `dontaudit`'i geçici olarak disable etmek sessiz bir failure'ı kesin bir policy clue'suna dönüştürebilir:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Bu, yerel adminlerin zaten neyi değiştirdiğini gözden geçirmek için de kullanışlıdır. Küçük bir custom module veya tek-domain permissive rule çoğu zaman bir target service’in base policy’nin ima edeceğinden çok daha gevşek davranmasının nedenidir.

## Audit Clues

AVC denials genellikle sadece defensive noise değil, offensive signal’dır. Sana şunları söylerler:

- hangi target object/type’a vurduğun
- hangi permission’ın denied edildiği
- şu anda hangi domain’i kontrol ettiğin
- küçük bir policy change’in chain’i çalışır hale getirip getirmeyeceği
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Eğer yerel bir exploit veya persistence girişimi, root gibi görünen DAC izinlerine rağmen `EACCES` ya da garip "permission denied" hatalarıyla sürekli başarısız oluyorsa, vectorü tamamen elemeden önce SELinux kontrol etmeye değer.

## SELinux Users

Normal Linux users'a ek olarak SELinux users vardır. Her Linux user, policy'nin bir parçası olarak bir SELinux user'a map edilir; bu da sistemin farklı hesaplara farklı allowed roles ve domains uygulamasını sağlar.

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Birçok yaygın sistemde kullanıcılar `unconfined_u` ile eşlenir, bu da kullanıcı confinement’ının pratik etkisini azaltır. Ancak hardened deployments üzerinde confined kullanıcılar, `sudo`, `su`, `newrole` ve `runcon`’u çok daha ilginç hale getirebilir çünkü **escalation path yalnızca UID 0 olmaya değil, daha iyi bir SELinux role/type içine girmeye bağlı olabilir**. Ayrıca bazı confined kullanıcıların `sudo`/`su` çağırmasının policy underlying setuid transition’ı açıkça izin vermedikçe hiç mümkün olmadığını unutmayın; bu yüzden `staff_u` + `sysadm_r` kullanan bir host, görünüşte küçük bir `sudo ROLE=` / `TYPE=` kuralını gerçek privilege boundary haline getirebilir.

## Containers içinde SELinux

Container runtime’ları genellikle workload’ları `container_t` gibi confined bir domain içinde başlatır ve container içeriğini `container_file_t` olarak label eder. Bir container process escape etse bile hala container label’ı ile çalışıyorsa, label boundary sağlam kaldığı için host yazmaları yine başarısız olabilir.

Hızlı örnek:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` kısmı süsleme değildir. Birçok container dağıtımında, runtime'lar MCS kategorilerini dinamik olarak atar; böylece `container_t` olarak çalışan iki süreç yine de birbirinden ayrılmış olur. Bir escape sizi host namespace içine düşürüp orijinal kategori setini koruyorsa, kategori uyuşmazlıkları bazı host yollarının neden hâlâ okunamaz veya yazılamaz olduğunu açıklayabilir.

Belirtmeye değer modern container işlemleri:

- `--security-opt label=disable` iş yükünü etkisiz kılınmış bir container ile ilgili tipe, örneğin `spc_t`'ye taşıyabilir
- `:z` / `:Z` ile bind mount'lar, paylaşılan/özel container kullanımı için host path'in yeniden etiketlenmesini tetikler
- host içeriğinin geniş kapsamlı yeniden etiketlenmesi tek başına bir güvenlik sorunu haline gelebilir

Bu sayfa, tekrarları önlemek için container içeriğini kısa tutar. Container'a özgü abuse case'ler ve runtime örnekleri için şuna bakın:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
