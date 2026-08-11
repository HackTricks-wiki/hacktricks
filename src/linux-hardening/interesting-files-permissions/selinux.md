# SELinux

SELinux, **etiket tabanlı Zorunlu Erişim Denetimi (MAC)** sistemidir. Pratikte bu, DAC izinleri, gruplar veya Linux capabilities bir işlem için yeterli görünse bile, **kaynak bağlamının** istenen sınıf/izinle **hedef bağlamına** erişmesine izin verilmediği için kernel'in işlemi yine de reddedebileceği anlamına gelir.<sup>[[1]](#references)</sup>

Bir bağlam genellikle şu şekilde görünür:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
From a privesc perspektifinden, `type` (process'ler için domain, nesneler için type) genellikle en önemli alandır:<sup>[[1]](#references)</sup>

- Bir process, `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t` gibi bir **domain** içinde çalışır
- Dosyalar ve socket'ler `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t` gibi bir **type** değerine sahiptir
- Policy, bir domain'in diğerine read/write/execute/transition yapıp yapamayacağını belirler

## Hızlı Enumeration

SELinux etkinse, yaygın Linux privesc yollarının neden başarısız olduğunu veya "zararsız" bir SELinux tool etrafındaki privileged wrapper'ın aslında neden kritik olduğunu açıklayabildiği için erken aşamada enumerate edin:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Yararlı takip kontrolleri:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
İlginç bulgular:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- `Disabled` veya `Permissive` modu, SELinux'un bir sınır olarak değerinin çoğunu ortadan kaldırır.
- `unconfined_t` genellikle SELinux'un mevcut olduğu, ancak ilgili süreci anlamlı biçimde kısıtlamadığı anlamına gelir.
- Özel yollardaki `default_t`, `file_t` veya bariz şekilde yanlış etiketler çoğunlukla yanlış etiketlemeye ya da eksik deployment'a işaret eder.
- `file_contexts.local` içindeki yerel geçersiz kılmalar policy varsayılanlarına göre önceliklidir; bu nedenle bunları dikkatle inceleyin.

## Policy Analizi

SELinux'a saldırmak veya onu bypass etmek, şu iki soruyu yanıtlayabildiğinizde çok daha kolaydır:

1. **Mevcut domain'im nelere erişebilir?**
2. **Hangi domain'lere transition yapabilirim?**

Bunun için en kullanışlı araçlar `sepolicy` ve **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>
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
Bu, bir host herkes için `unconfined_u` eşlemesi yapmak yerine **confined users** kullandığında özellikle faydalıdır. Bu durumda şunları arayın:<sup>[[3]](#references)</sup>

- `semanage login -l` aracılığıyla kullanıcı eşlemeleri
- `semanage user -l` aracılığıyla izin verilen roller
- `sysadm_t`, `secadm_t`, `webadm_t` gibi erişilebilir yönetici domain'leri
- `ROLE=` veya `TYPE=` kullanan `sudoers` girdileri

`sudo -l` içinde bunun gibi girdiler varsa SELinux, privilege boundary'nin bir parçasıdır:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Ayrıca `newrole` komutunun kullanılabilir olup olmadığını kontrol edin:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` ve `newrole` otomatik olarak exploitable değildir, ancak ayrıcalıklı bir wrapper veya bir `sudoers` kuralı daha iyi bir role/type seçmenize izin veriyorsa, yüksek değerli escalation primitive'leri haline gelirler.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Dosyalar, Yeniden Etiketleme ve Yüksek Değerli Yanlış Yapılandırmalar

Yaygın SELinux araçları arasındaki en önemli operasyonel fark şudur:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: belirli bir path üzerindeki geçici label değişikliği
- `semanage fcontext`: kalıcı path-to-label kuralı
- `restorecon` / `setfiles`: policy/default label'ı yeniden uygular

Bu, privesc sırasında büyük önem taşır çünkü **relabeling yalnızca kozmetik değildir**. Bir dosyayı "policy tarafından engellenen" durumdan "ayrıcalıklı confined service tarafından okunabilir/executable" duruma dönüştürebilir.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Yerel relabel kurallarını ve relabel drift'i kontrol edin:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
İnce fakat kullanışlı bir ayrıntı: düz `restorecon`, şüpheli bir etiketi **her zaman tamamen geri döndürmez**. Hedef tür `customizable_types` içindeyse, tam sıfırlamayı zorlamak için `-F` kullanmanız gerekebilir. Saldırı perspektifinden bu durum, alışılmadık bir `chcon` işleminin bazen sıradan bir "restorecon'u zaten çalıştırdık" temizliğinden sonra neden varlığını sürdürebildiğini açıklar.<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`, root sarmalayıcıları, otomasyon betikleri veya dosya yeteneklerinde aranacak yüksek değerli komutlar:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Herhangi bir MAC capability görünürse [Linux capabilities page](linux-capabilities.md) sayfasını da çapraz kontrol edin; Linux capabilities documentation, `cap_mac_admin` ve `cap_mac_override` değerlerini Smack-specific olarak tanımlar; bu nedenle yalnızca adlarına bakarak SELinux'u bypass ettiklerini varsaymayın.<sup>[[5]](#references)</sup>

Özellikle ilgi çekici:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: bir path'in hangi label'ı alması gerektiğini kalıcı olarak değiştirir
- `restorecon` / `setfiles`: bu değişiklikleri geniş ölçekte yeniden uygular
- `semodule -i`: custom policy module yükler
- `semanage permissive -a <domain_t>`: tüm host'u değiştirmeden tek bir domain'i permissive yapar
- `setsebool -P`: policy boolean'larını kalıcı olarak değiştirir
- `load_policy`: active policy'yi yeniden yükler

Bunlar çoğunlukla **helper primitives**'tir; tek başlarına root exploit değildir. Değerleri, şunları yapabilmenizi sağlamalarıdır:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- bir target domain'i permissive yapmak
- domain'iniz ile korunan bir type arasındaki erişimi genişletmek
- attacker-controlled file'ları, privileged bir service'in okuyabilmesi veya execute edebilmesi için yeniden label'lamak
- mevcut bir local bug'ın exploitable hâle gelmesi için confined bir service'i yeterince zayıflatmak

Örnek kontroller:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
root olarak bir policy module yükleyebiliyorsanız, genellikle SELinux sınırını kontrol edersiniz:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Bu nedenle `audit2allow`, `semodule` ve `semanage permissive`, post-exploitation sırasında hassas yönetici yüzeyleri olarak değerlendirilmelidir. Klasik UNIX izinlerini değiştirmeden, engellenen bir zinciri sessizce çalışan bir zincire dönüştürebilirler.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Gizli Reddetmeler ve Modül Çıkarma

Çok yaygın bir offensive frustration, beklenen AVC denial görünmeden bir zincirin sıradan bir `EACCES` ile başarısız olmasıdır. `dontaudit` kuralları, ihtiyacınız olan tam izni gizliyor olabilir. `sudo` veya başka bir ayrıcalıklı wrapper üzerinden `semodule` çalıştırabiliyorsanız, `dontaudit` özelliğini geçici olarak devre dışı bırakmak sessiz bir hatayı kesin bir policy ipucuna dönüştürebilir:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Bu, yerel yöneticilerin daha önce neleri değiştirdiğini gözden geçirmek için de kullanışlıdır. Küçük bir custom module veya tek-domain permissive rule, hedef servisin temel policy'nin düşündürdüğünden çok daha gevşek davranmasının çoğu zaman nedenidir.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Audit İpuçları

AVC denials yalnızca savunma amaçlı gürültü değil, çoğu zaman saldırı açısından bir sinyaldir. Size şunları söyler:<sup>[[1]](#references)[[15]](#references)</sup>

- hangi hedef object/type'a eriştiğiniz
- hangi permission'ın reddedildiği
- şu anda hangi domain'i kontrol ettiğiniz
- küçük bir policy değişikliğinin zincirin çalışmasını sağlayıp sağlamayacağı
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Bir local exploit veya persistence girişimi, root gibi görünen DAC izinlerine rağmen `EACCES` ya da garip "permission denied" hatalarıyla başarısız olmaya devam ediyorsa, vector'ü gözden çıkarmadan önce SELinux'u kontrol etmek genellikle faydalıdır.<sup>[[1]](#references)</sup>

## SELinux Users

Normal Linux kullanıcılarına ek olarak SELinux users da vardır. Her Linux user, policy'nin bir parçası olarak bir SELinux user ile eşlenir; bu da sistemin farklı hesaplarda farklı izin verilen rolleri ve domain'leri uygulamasına olanak tanır.<sup>[[3]](#references)</sup>

Quick checks:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Birçok mainstream sistemde kullanıcılar `unconfined_u` ile eşleştirilir; bu da kullanıcı confinement'ının pratik etkisini azaltır. Ancak hardened deployment'larda confined kullanıcılar `sudo`, `su`, `newrole` ve `runcon` komutlarını çok daha ilginç hâle getirebilir; çünkü **escalation path yalnızca UID 0 olmaya değil, daha uygun bir SELinux role/type'a geçmeye de bağlı olabilir**. Ayrıca bazı confined kullanıcıların, policy temel setuid geçişine açıkça izin vermediği sürece `sudo`/`su` komutlarını hiç çalıştıramayacağını unutmayın. Bu nedenle `staff_u` + `sysadm_r` kullanan bir host, görünüşte küçük bir `sudo ROLE=` / `TYPE=` kuralını gerçek privilege boundary'ye dönüştürebilir.<sup>[[3]](#references)</sup>

## Containerlarda SELinux

Container runtime'ları genellikle workload'ları `container_t` gibi confined bir domain'de başlatır ve container içeriğini `container_file_t` olarak label'lar. Bir container process'i escape etse, ancak hâlâ container label'ı ile çalışsa bile host üzerindeki write işlemleri başarısız olabilir; çünkü label boundary aynı kalmıştır.<sup>[[1]](#references)[[17]](#references)</sup>

Hızlı örnek:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` bölümü dekorasyon değildir. Birçok konteyner deployment'ında runtime'lar, `container_t` olarak çalışan iki process'in yine de birbirinden ayrılması için MCS kategorilerini dinamik olarak atar. Bir escape sizi host namespace'ine sokar ancak orijinal category set'ini korursa, category uyuşmazlıkları bazı host path'lerinin neden hâlâ okunamadığını veya yazılamadığını açıklayabilir.<sup>[[17]](#references)</sup>

Dikkate değer modern konteyner işlemleri:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable`, konteyner için SELinux label ayrımını devre dışı bırakır
- `:z` / `:Z` içeren bind mount'lar, paylaşımlı/özel konteyner kullanımı için host path'inin relabeling işlemine tabi tutulmasını tetikler
- Host içeriğinin geniş kapsamlı relabeling işlemine tabi tutulması, tek başına bir security issue hâline gelebilir

Bu sayfa, tekrarı önlemek için konteyner içeriğini kısa tutar. Konteynere özgü abuse cases ve runtime örnekleri için şuraya bakın:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Red Hat docs: SELinux Kullanımı](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: SELinux için policy analysis tools](https://github.com/SELinuxProject/setools)
- [3] [Kısıtlanmış ve kısıtlanmamış kullanıcıları yönetme - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Linux manual page](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Linux manual page](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Linux manual page](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Linux manual page](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Linux manual page](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Linux manual page](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Linux manual page](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman run documentation](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Linux konteynerleriniz için Multi-Category Security kullanmanızın nedeni](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman top documentation](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Linux manual page](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
