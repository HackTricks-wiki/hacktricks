# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux, **etiket tabanlı Zorunlu Erişim Denetimi (MAC)** sistemidir. Uygulamada bu, DAC izinleri, gruplar veya Linux capabilities bir işlem için yeterli görünse bile, **kaynak bağlamı** istenen sınıf/izinle **hedef bağlama** erişmeye yetkili olmadığından kernel'in işlemi yine de reddedebileceği anlamına gelir.<sup>[[1]](#references)</sup>

Bir bağlam genellikle şu şekilde görünür:<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

privesc açısından `type` (process'ler için domain, nesneler için type) genellikle en önemli alandır:<sup>[[1]](#references)</sup>

- Bir process, `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t` gibi bir **domain** içinde çalışır
- Dosyalar ve socket'ler `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t` gibi bir **type**'a sahiptir
- Policy, bir domain'in diğerine okuma/yazma/çalıştırma/geçiş yapıp yapamayacağına karar verir

## Hızlı Keşif

SELinux etkinse, yaygın Linux privesc yollarının neden başarısız olduğunu veya "zararsız" bir SELinux aracının etrafındaki ayrıcalıklı bir wrapper'ın neden kritik olduğunu açıklayabileceğinden, SELinux'u erkenden keşfedin:<sup>[[1]](#references)</sup>

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

- `Disabled` veya `Permissive` modu, SELinux'un bir sınır olarak sağladığı değerin çoğunu ortadan kaldırır.
- `unconfined_t` genellikle SELinux'un mevcut olduğu ancak söz konusu süreci anlamlı biçimde kısıtlamadığı anlamına gelir.
- `default_t`, `file_t` veya özel yollardaki bariz şekilde yanlış etiketler, genellikle yanlış etiketlemeye ya da eksik dağıtıma işaret eder.
- `file_contexts.local` içindeki yerel geçersiz kılmalar, policy varsayılanlarına göre önceliklidir; bu nedenle bunları dikkatle inceleyin.

## Policy Analizi

Şu iki soruyu yanıtlayabildiğinizde SELinux'a saldırmak veya onu atlatmak çok daha kolaydır:

1. **Mevcut domain'im nelere erişebilir?**
2. **Hangi domain'lere geçiş yapabilirim?**

Bunun için en kullanışlı araçlar `sepolicy` ve **SETools**'tur (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>

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

Bu, özellikle bir host herkesi `unconfined_u` ile eşlemek yerine **kısıtlanmış kullanıcılar** kullanıyorsa faydalıdır. Bu durumda şunlara bakın:<sup>[[3]](#references)</sup>

- `semanage login -l` ile kullanıcı eşlemeleri
- `semanage user -l` ile izin verilen roller
- `sysadm_t`, `secadm_t`, `webadm_t` gibi erişilebilir admin domain'leri
- `ROLE=` veya `TYPE=` kullanan `sudoers` girdileri

`sudo -l` böyle girdiler içeriyorsa SELinux, ayrıcalık sınırının bir parçasıdır:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

`newrole` komutunun kullanılabilir olup olmadığını da kontrol edin:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` ve `newrole` otomatik olarak istismar edilebilir değildir; ancak ayrıcalıklı bir wrapper veya `sudoers` kuralı daha uygun bir role/type seçmenize izin veriyorsa, yüksek değerli ayrıcalık yükseltme araçlarına dönüşürler.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### Yazılabilir geçiş giriş noktalarını denetleyin

Bir geçiş grafiği yalnızca bir politika ipucudur. Bunu bir saldırı yoluna dönüştürmek için daha kullanışlı bir domain’e giren yürütülebilir dosyanın türünü belirleyin, ardından bu etikete sahip bir yürütülebilir dosyayı değiştirebilir veya üst dizini üzerinden onun yerine başka bir dosya koyabilir misiniz, kontrol edin.<sup>[[9]](#references)[[20]](#references)</sup> Otomatik bir `execve` geçişi için uygulanabilir bir `type_transition` kuralı, kaynak domain’de yürütme erişimi, hedef domain’de `entrypoint` erişimi ve domain’ler arasında geçiş izni gerekir.<sup>[[20]](#references)</sup> Hedef domain SELinux erişimi kazanabilir, ancak yürütme tek başına Linux UID’sini değiştirmez; [SUID/SGID and ACLs](suid-sgid-and-acl-triage.md) konusunu ayrıca kontrol edin.<sup>[[20]](#references)[[21]](#references)</sup>

Bildirilen giriş noktası türünü kullanarak temel kuralları kontrol edin, ardından yazma erişimi için yolu ve üst dizinini inceleyin.<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

Giriş noktası türünü gerçek bir çalıştırılabilir dosya yoluyla ilişkilendirin. Bir policy bağlantısını erişilebilir kabul etmeden önce DAC'i, ACL'leri, dosya veya üst dizin üzerindeki SELinux yazma iznini, dosya etiketini ve koşullu boolean'ları inceleyin.<sup>[[20]](#references)[[22]](#references)</sup> Bir yol yerinde düzenlenmek yerine değiştirilirse yeni inode'un bağlamını doğrulayın: dosya sistemi etiketleri genişletilmiş öznitelikler olarak saklanır ve değiştirilen dosya giriş noktası türünü korumayabilir.<sup>[[21]](#references)</sup> SELinux-aware programlar `setexeccon` ile geçiş isteğinde bulunabilir; bu nedenle otomatik bir `type_transition` kuralının bulunmaması her tür geçişi dışlamaz.<sup>[[20]](#references)</sup>

## Dosyalar, Yeniden Etiketleme ve Önemli Yanlış Yapılandırmalar

Yaygın SELinux araçları arasındaki en önemli operasyonel fark şudur:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: belirli bir yolda geçici etiket değişikliği
- `semanage fcontext`: kalıcı yol-etiket kuralı
- `restorecon` / `setfiles`: policy/varsayılan etiketi yeniden uygular

Bu, privesc sırasında çok önemlidir çünkü **yeniden etiketleme yalnızca kozmetik değildir**. Bir dosyayı "policy tarafından engellenen" durumdan "ayrıcalıklı, kısıtlanmış bir servis tarafından okunabilir/çalıştırılabilir" duruma getirebilir.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Yerel yeniden etiketleme kurallarını ve etiket sapmalarını kontrol edin:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

İnce ama faydalı bir ayrıntı: `restorecon`, şüpheli bir etiketi **her zaman tamamen geri almaz**. Hedef tür `customizable_types` içindeyse tam sıfırlamayı zorlamak için `-F` kullanmanız gerekebilir. Saldırgan bakış açısından bu, alışılmadık bir `chcon` etiketinin “zaten restorecon çalıştırdık” şeklindeki yüzeysel bir temizliğe rağmen neden bazen kalıcı olabildiğini açıklar.<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

`sudo -l` çıktısında, root wrapper'larında, otomasyon scriptlerinde veya file capabilities içinde aranacak yüksek değerli komutlar:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

MAC capability'lerden herhangi biri görünürse [Linux capabilities sayfasını](linux-capabilities.md) da çapraz kontrol edin; Linux capabilities belgeleri `cap_mac_admin` ve `cap_mac_override` değerlerini Smack'e özgü olarak tanımlar, bu nedenle yalnızca adlarına bakarak SELinux'u atladıklarını varsaymayın.<sup>[[5]](#references)</sup>

Özellikle ilgi çekici:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: bir path'in hangi etiketi alması gerektiğini kalıcı olarak değiştirir
- `restorecon` / `setfiles`: bu değişiklikleri geniş ölçekte yeniden uygular
- `semodule -i`: özel bir policy modülünü yükler
- `semanage permissive -a <domain_t>`: tüm host'u değiştirmeden tek bir domain'i permissive yapar
- `setsebool -P`: policy boolean'larını kalıcı olarak değiştirir
- `load_policy`: etkin policy'yi yeniden yükler

Bunlar genellikle tek başına root exploit'leri değil, **yardımcı primitive'lerdir**. Değerleri, şunları yapmanıza olanak tanımalarıdır:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- hedef domain'i permissive yapmak
- domain'iniz ile korunan bir type arasındaki erişimi genişletmek
- ayrıcalıklı bir servisin okuyabilmesi veya çalıştırabilmesi için saldırganın kontrolündeki dosyaları yeniden etiketlemek
- mevcut bir local bug'ın exploit edilebilir hâle gelmesi için kısıtlanmış bir servisin güvenliğini zayıflatmak

Örnek kontroller:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

Root olarak bir policy modülü yükleyebiliyorsanız, genellikle SELinux sınırını kontrol edebilirsiniz:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

Bu nedenle `audit2allow`, `semodule` ve `semanage permissive`, post-exploitation sırasında hassas yönetici arayüzleri olarak ele alınmalıdır. Bunlar, klasik UNIX izinlerini değiştirmeden engellenen bir zinciri sessizce çalışır hâle getirebilir.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Gizli Reddetmeler ve Modül Çıkarma

Saldırı sırasında sık karşılaşılan bir sorun, beklenen AVC reddi görünmezken zincirin belirsiz bir `EACCES` hatasıyla başarısız olmasıdır. `dontaudit` kuralları, ihtiyaç duyduğunuz tam izni gizliyor olabilir. `sudo` veya başka bir ayrıcalıklı sarmalayıcı üzerinden `semodule` çalıştırabiliyorsanız, `dontaudit` özelliğini geçici olarak devre dışı bırakmak sessiz bir hatayı kesin bir politika ipucuna dönüştürebilir:<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

Bu, yerel admin'lerin daha önce neleri değiştirdiğini incelemek için de faydalıdır. Küçük bir custom module veya tek bir domain için tanımlanmış permissive kural, hedef hizmetin temel politikanın düşündürdüğünden çok daha gevşek davranmasının nedeni olabilir.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Audit Clues

AVC denials çoğu zaman yalnızca savunma amaçlı gürültü değil, saldırı açısından bir sinyaldir. Şunları gösterir:<sup>[[1]](#references)[[15]](#references)</sup>

- hangi hedef nesne/türe eriştiğinizi
- hangi iznin reddedildiğini
- şu anda hangi domain'i kontrol ettiğinizi
- küçük bir policy değişikliğinin zinciri çalıştırıp çalıştırmayacağını

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

Yerel bir exploit veya persistence girişimi, root gibi görünen DAC izinlerine rağmen sürekli `EACCES` ya da garip "permission denied" hataları veriyorsa, bu vektörden vazgeçmeden önce genellikle SELinux'u kontrol etmek gerekir.<sup>[[1]](#references)</sup>

## SELinux Kullanıcıları

Normal Linux kullanıcılarına ek olarak SELinux kullanıcıları da vardır. Politikanın bir parçası olarak her Linux kullanıcısı bir SELinux kullanıcısıyla eşleştirilir; böylece sistem farklı hesaplara farklı izin verilen rolleri ve domain'leri uygulayabilir.<sup>[[3]](#references)</sup>

Hızlı kontroller:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Birçok yaygın sistemde kullanıcılar `unconfined_u` ile eşleştirilir; bu da kullanıcı kısıtlamasının pratik etkisini azaltır. Ancak güvenliği sıkılaştırılmış dağıtımlarda, kısıtlanmış kullanıcılar için `sudo`, `su`, `newrole` ve `runcon` çok daha ilgi çekici olabilir; çünkü **yükseltme yolu yalnızca UID 0 olmakla değil, daha yetkili bir SELinux rolüne/türüne geçmekle de ilgili olabilir**. Ayrıca, bazı kısıtlanmış kullanıcıların politika temelindeki setuid geçişine açıkça izin vermediği sürece `sudo`/`su` kullanamayacağını unutmayın; bu nedenle `staff_u` + `sysadm_r` kullanan bir ana makinede, görünüşte önemsiz bir `sudo ROLE=` / `TYPE=` kuralı asıl ayrıcalık sınırını oluşturabilir.<sup>[[3]](#references)</sup>

## SELinux in Containers

Container runtime'ları genellikle iş yüklerini `container_t` gibi kısıtlanmış bir domain içinde başlatır ve container içeriğini `container_file_t` olarak etiketler. Bir container process'i kaçsa bile container etiketiyle çalışmaya devam ederse, etiket sınırı korunduğundan ana makineye yazma işlemleri yine başarısız olabilir.<sup>[[1]](#references)[[17]](#references)</sup>

Hızlı örnek:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

`c647,c780` kısmı dekorasyon değildir. Birçok container dağıtımında runtime'lar MCS kategorilerini dinamik olarak atar; böylece `container_t` olarak çalışan iki process bile birbirinden yalıtılır. Bir escape sizi host namespace'ine taşısa ancak özgün kategori kümesini korusa bile kategori uyuşmazlıkları, bazı host yollarının neden okunamadığını veya yazılamadığını açıklayabilir.<sup>[[17]](#references)</sup>

Dikkate değer modern container işlemleri:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable`, container için SELinux label yalıtımını kapatır
- `:z` / `:Z` ile yapılan bind mount'lar, host yolunun paylaşımlı/özel container kullanımı için yeniden etiketlenmesini tetikler
- Host içeriğinin geniş kapsamlı şekilde yeniden etiketlenmesi başlı başına bir güvenlik sorununa dönüşebilir

Bu sayfa, tekrarları önlemek için container içeriğini kısa tutuyor. Container'a özgü kötüye kullanım senaryoları ve runtime örnekleri için şuraya bakın:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Red Hat docs: SELinux Kullanımı](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: SELinux için Policy analiz araçları](https://github.com/SELinuxProject/setools)
- [3] [Kısıtlı ve kısıtlanmamış kullanıcıları yönetme - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman run belgeleri](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Linux container'larınızda neden Multi-Category Security kullanmalısınız](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman top belgeleri](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [SELinux Notebook: Domain ve Object geçişleri](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: SELinux Kullanımı](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [SETools sesearch(1) kılavuzu](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
