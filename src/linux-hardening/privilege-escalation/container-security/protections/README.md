# Container Koruma Genel Bakışı

{{#include ../../../../banners/hacktricks-training.md}}

Container hardening'deki en önemli fikir, "container security" adında tek bir kontrolün olmadığıdır. İnsanların container isolation dediği şey, aslında birkaç Linux güvenlik ve kaynak yönetimi mekanizmasının birlikte çalışmasının sonucudur. Dokümantasyon yalnızca bunlardan birini açıklıyorsa, okuyucular onun gücünü fazla tahmin etme eğilimindedir. Dokümantasyon hepsini listeleyip bunların nasıl etkileştiğini açıklamıyorsa, okuyucular sadece isimlerden oluşan bir katalog alır ama gerçek bir model elde edemezler. Bu bölüm her iki hatadan da kaçınmaya çalışır.

Modelin merkezinde iş yükünün neyi görebileceğini izole eden **namespaces** vardır. Bunlar sürece dosya sistemi mount'ları, PID'ler, networking, IPC nesneleri, host isimleri, user/group eşlemeleri, cgroup yolları ve bazı clock'ların özel veya kısmen özel bir görünümünü verir. Ancak sadece namespaces tek başına bir sürecin ne yapmasına izin verildiğini belirlemez. Burada bir sonraki katmanlar devreye girer.

**cgroups** kaynak kullanımını yönetir. Mount veya PID namespaces ile aynı anlamda bir izolasyon sınırı olmayabilirler, ancak bellek, CPU, PID'ler, I/O ve cihaz erişimini kısıtladıkları için operasyonel olarak kritik öneme sahiptirler. Ayrıca geçmişte writable cgroup özelliklerinin, özellikle cgroup v1 ortamlarında, breakout tekniklerinde kötüye kullanılması nedeniyle güvenlikle ilgili önemi vardır.

**Capabilities** eski her şeye kadir root modelini daha küçük ayrıcalık birimlerine böler. Bu, içeride birçok iş yükünün hala container içinde UID 0 olarak çalıştığı durumlarda containerlar için temeldir. Dolayısıyla soru yalnızca "process root mu?" değil, aynı zamanda "hangi capabilities hayatta kaldı, hangi namespaces içinde, hangi seccomp ve MAC kısıtlamaları altında?" şeklindedir. Bu yüzden bir container'daki bir root süreci nispeten kısıtlı olabilirken, başka bir container'daki root süreci pratikte host root ile neredeyse ayırt edilemez olabilir.

**seccomp** syscall'ları filtreler ve iş yüküne açılan kernel saldırı yüzeyini azaltır. Bu, genellikle `unshare`, `mount`, `keyctl` veya breakout zincirlerinde kullanılan diğer syscall'lar gibi açıkça tehlikeli çağrıları engelleyen mekanizmadır. Bir süreç, bir işlemi normalde yapmasına izin verecek bir capability'e sahip olsa bile, seccomp kernel işlemi tam olarak işlemeden önce syscall yolunu engelleyebilir.

**AppArmor** ve **SELinux** normal dosya sistemi ve ayrıcalık kontrollerinin üzerine Mandatory Access Control ekler. Bu mekanizmalar özellikle önemlidir çünkü bir container olması gerektiğinden daha fazla capability'e sahip olsa bile etkili olmaya devam ederler. Bir iş yükü teorik olarak bir eylemi deneme ayrıcalığına sahip olabilir fakat etiketine veya profilinin ilgili yol, nesne veya işlemi yasaklaması nedeniyle yine de bunu gerçekleştirmesi engellenebilir.

Son olarak, daha az ilgi gören ama gerçek saldırılarda düzenli olarak önemli olan ek sertleştirme katmanları vardır: `no_new_privs`, masked procfs yolları, salt okunur sistem yolları, salt okunur root dosya sistemleri ve dikkatle seçilmiş runtime varsayılanları. Bu mekanizmalar genellikle bir ele geçirmenin "son milini" durdurur, özellikle saldırgan kod yürütmeyi daha geniş bir ayrıcalık kazanımına çevirmeye çalıştığında.

Bu klasörün geri kalanı, kernel ilkelinin gerçekte ne yaptığı, yerelde nasıl gözlemleneceği, yaygın runtime'ların bunu nasıl kullandığı ve operatörlerin bunu kazara nasıl zayıflattığı dahil olmak üzere bu mekanizmaları daha ayrıntılı açıklar.

## Read Next

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Many real escapes also depend on what host content was mounted into the workload, so after reading the core protections it is useful to continue with:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
