# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux, **etiket tabanlı Zorunlu Erişim Kontrolü (MAC)** sistemidir. Pratikte bu, DAC permissions, groups veya Linux capabilities bir işlem için yeterli görünse bile çekirdeğin yine de bunu reddedebileceği anlamına gelir; çünkü **kaynak bağlam**'ın istenen sınıf/izin ile **hedef bağlam**'a erişmesine izin verilmemiş olabilir.

Bir bağlam genellikle şöyle görünür:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Privesc açısından, `type` (domain for processes, type for objects) genellikle en önemli alandır:

- Bir işlem `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t` gibi bir **domain** içinde çalışır
- Dosyalar ve soketlerin `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t` gibi bir **type**'ı vardır
- Policy, bir domainin diğerine okuma/yazma/çalıştırma veya transition yapma izni verip vermediğini belirler

## Hızlı Keşif

Eğer SELinux etkinse, bunu erken enumerate edin çünkü bu, yaygın Linux privesc yollarının neden başarısız olduğunu veya "harmless" görünen bir SELinux aracının etrafındaki yetkili bir wrapper'ın neden aslında kritik olduğunu açıklayabilir:
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

- `Disabled` or `Permissive` modu SELinux'un bir sınır olarak sağladığı değerin çoğunu ortadan kaldırır.
- `unconfined_t` genellikle SELinux'ün kurulu olduğunu ancak o süreci anlamlı şekilde kısıtlamadığını gösterir.
- `default_t`, `file_t` veya özel yollar üzerindeki bariz şekilde yanlış etiketler genellikle yanlış etiketleme veya eksik dağıtımı gösterir.
- `file_contexts.local` içindeki yerel geçersiz kılmalar politika varsayılanlarından önceliklidir, bu yüzden bunları dikkatle inceleyin.

## Politika Analizi

SELinux'a saldırmak veya atlatmak, iki soruyu cevaplayabildiğinizde çok daha kolaydır:

1. **Mevcut domain'im hangi kaynaklara erişebilir?**
2. **Hangi domain'lere geçiş yapabilirim?**

Bunun için en faydalı araçlar `sepolicy` ve **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Bu, bir host herkesi `unconfined_u`'ya eşlemek yerine **sınırlı kullanıcılar** kullanıyorsa özellikle faydalıdır. Bu durumda, şunlara bakın:

- kullanıcı eşlemeleri için `semanage login -l`
- izin verilen roller için `semanage user -l`
- erişilebilir yönetici domainleri ör. `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` girdileri `ROLE=` veya `TYPE=` kullanan

Eğer `sudo -l` bu gibi girdiler içeriyorsa, SELinux ayrıcalık sınırının bir parçasıdır:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Ayrıca `newrole`'in kullanılabilir olup olmadığını kontrol edin:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` and `newrole` otomatik olarak sömürülebilir değiller, ancak yetkili bir wrapper veya bir `sudoers` kuralı size daha iyi bir role/type seçme imkanı veriyorsa, bunlar yüksek değerli yükseltme ilkellerine dönüşür.

## Dosyalar, Yeniden Etiketleme ve Yüksek Değerli Yanlış Yapılandırmalar

Yaygın SELinux araçları arasındaki en önemli operasyonel fark şudur:

- `chcon`: belirli bir yol üzerinde geçici etiket değişikliği
- `semanage fcontext`: kalıcı yol-etiket kuralı
- `restorecon` / `setfiles`: politikayı/varsayılan etiketi yeniden uygular

Bu, privesc sırasında çok önemlidir çünkü **yeniden etiketleme sadece kozmetik değildir**. Bir dosyayı "blocked by policy" durumundan "yetkili sınırlandırılmış bir servis tarafından okunabilir/çalıştırılabilir" hale getirebilir.

Yerel yeniden etiketleme kurallarını ve yeniden etiketleme sapmasını kontrol edin:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
`sudo -l`, root wrappers, automation scripts veya file capabilities içinde aranacak yüksek değerli komutlar:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Özellikle ilginç:

- `semanage fcontext`: bir yolun alacağı label'ı kalıcı olarak değiştirir
- `restorecon` / `setfiles`: bu değişiklikleri topluca yeniden uygular
- `semodule -i`: özel bir policy modülünü yükler
- `semanage permissive -a <domain_t>`: tüm sistemi permissive hale getirmeden tek bir domain'i permissive yapar
- `setsebool -P`: policy boolean'larını kalıcı olarak değiştirir
- `load_policy`: aktif policy'i yeniden yükler

Bunlar genellikle **yardımcı primitifler**dir, tek başına root exploitleri değiller. Sağladıkları şunlardır:

- hedef bir domain'i permissive yapmak
- kendi domain'iniz ile korunan bir type arasındaki erişimi genişletmek
- saldırgan tarafından kontrol edilen dosyaları yeniden etiketleyerek ayrıcalıklı bir servisin bunları okuyup/çalıştırabilmesini sağlamak
- sınırlandırılmış bir servisi, mevcut bir yerel hatanın exploit edilebilir hale gelmesi için yeterince zayıflatmak

Örnek kontroller:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Eğer bir politika modülünü root olarak yükleyebiliyorsanız, genellikle SELinux sınırını kontrol edersiniz:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Bu yüzden `audit2allow`, `semodule` ve `semanage permissive` post-exploitation sırasında hassas yönetici yüzeyleri olarak ele alınmalıdır. Klasik UNIX izinlerini değiştirmeden, engellenmiş bir zinciri sessizce çalışan bir zincire dönüştürebilirler.

## Denetim İpuçları

AVC denials genellikle sadece savunma gürültüsü değil, aynı zamanda saldırgan bir işarettir. Size şunları söylerler:

- hangi hedef nesne/tipi ile karşılaştığınız
- hangi iznin reddedildiği
- şu anda hangi domain'i kontrol ettiğiniz
- küçük bir politika değişikliğinin zinciri çalışır hale getirip getirmeyeceği
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Eğer bir local exploit veya persistence denemesi, root görünümünde DAC izinlerine rağmen `EACCES` veya garip "permission denied" hatalarıyla sürekli başarısız oluyorsa, vektörü tamamen terk etmeden önce SELinux'u kontrol etmek genellikle faydalıdır.

## SELinux Kullanıcıları

Normal Linux kullanıcılarına ek olarak SELinux kullanıcıları vardır. Her Linux kullanıcısı politikanın bir parçası olarak bir SELinux kullanıcısına eşlenir; bu, sistemin farklı hesaplara farklı izinli roller ve domainler uygulamasına olanak tanır.

Hızlı kontroller:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Birçok yaygın sistemde kullanıcılar `unconfined_u`'ya eşlenir; bu, kullanıcı sınırlandırmasının pratik etkisini azaltır. Hardened dağıtımlarda ise sınırlandırılmış kullanıcılar `sudo`, `su`, `newrole` ve `runcon`'u çok daha ilginç hâle getirebilir; çünkü **yükseltme yolu sadece UID 0 olmakla değil, daha iyi bir SELinux rolüne/tipine girme gerekliliğine de bağlı olabilir**.

## Konteynerlerde SELinux

Container runtime'ları genellikle iş yüklerini `container_t` gibi sınırlandırılmış bir domain'de başlatır ve konteyner içeriğini `container_file_t` olarak etiketler. Eğer bir konteyner süreci kaçar ama hâlâ konteyner etiketiyle çalışıyorsa, host üzerine yazmalar yine başarısız olabilir çünkü etiket sınırı korunmuş olur.

Kısa örnek:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Modern container işlemleri — dikkat edilmesi gerekenler:

- `--security-opt label=disable` iş yükünü `spc_t` gibi kısıtlanmamış container-ilişkili bir tipe etkili şekilde taşıyabilir
- bind mount'lar `:z` / `:Z` ile paylaşılan/özel container kullanımı için host yolunun yeniden etiketlenmesini tetikler
- Host içeriğinin geniş çaplı yeniden etiketlenmesi kendi başına bir güvenlik sorunu haline gelebilir

Bu sayfa, tekrarları önlemek için container içeriğini kısa tutar. Container'a özgü kötüye kullanım vakaları ve çalışma zamanı örnekleri için bakınız:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Referanslar

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
