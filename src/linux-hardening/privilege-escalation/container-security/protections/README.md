# Konteyner Koruma Genel Bakışı

{{#include ../../../../banners/hacktricks-training.md}}

Konteyner hardening'ındaki en önemli fikir, "container security" diye tek bir kontrolün olmadığıdır. İnsanların container isolation dediği şey aslında birkaç Linux güvenlik ve kaynak yönetimi mekanizmasının birlikte çalışmasının sonucudur. Eğer dokümantasyon bunlardan yalnızca birini açıklıyorsa, okuyucular onun gücünü fazla tahmin etme eğilimindedir. Eğer dokümantasyon hepsinin adını listeliyorsa ama bunların nasıl etkileştiğini açıklamıyorsa, okuyucular adlar kataloğu alır ama gerçek bir model elde edemez. Bu bölüm her iki hatadan da kaçınmaya çalışır.

Modelin merkezinde iş yükünün neyi görebileceğini izole eden **namespaces** vardır. Bunlar process'e filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths ve bazı clocks için özel veya kısmen özel bir görünüm sağlar. Ancak namespaces tek başına bir process'in ne yapmasına izin verileceğini belirlemez. İşte burada sonraki katmanlar devreye girer.

**cgroups** kaynak kullanımını yönetir. Mount veya PID namespaces ile aynı anlamda bir izolasyon sınırı olmasalar da operasyonel olarak bellek, CPU, PIDs, I/O ve cihaz erişimini kısıtladıkları için çok önemlidirler. Ayrıca tarihsel breakout tekniklerinin özellikle cgroup v1 ortamlarında yazılabilir cgroup özelliklerini kötüye kullanması nedeniyle güvenlik açısından da önem taşırlar.

**Capabilities** eski her şeye gücü yeten root modelini daha küçük ayrıcalık birimlerine böler. Bu, birçok iş yükü hala container içinde UID 0 olarak çalıştığı için konteynerlerde temel bir konudur. Bu yüzden soru sadece "process root mu?" değil; daha ziyade "hangi capabilities hayatta kaldı, hangi namespaces içinde, hangi seccomp ve MAC kısıtlamaları altında?" olduğudur. Bu nedenle bir konteynerdeki root process nispeten kısıtlı olabilirken başka bir konteynerdeki root process pratikte host root'undan neredeyse ayırt edilemez hale gelebilir.

**seccomp** syscall'ları filtreler ve iş yüküne karşı açılan kernel saldırı yüzeyini azaltır. Bu genellikle `unshare`, `mount`, `keyctl` veya breakout zincirlerinde kullanılan diğer syscall'lar gibi bariz olarak tehlikeli çağrıları engelleyen mekanizma olur. Bir process'in bir işlemi yapmaya izin verecek bir capability'i olsa bile, seccomp syscall yolunu kernel tamamen işlemden geçirmeden önce engelleyebilir.

**AppArmor** ve **SELinux** normal filesystem ve ayrıcalık kontrollerinin üzerine Mandatory Access Control ekler. Bunlar özellikle önemlidir çünkü bir konteyner olması gerekenden daha fazla capability'ye sahip olsa bile hâlâ etkili olmaya devam ederler. Bir iş yükü teorik olarak bir eylemi deneme ayrıcalığına sahip olabilir ama etiketinin veya profilinin ilgili yol, obje veya işleve erişimi yasaklaması nedeniyle bunu gerçekleştirmesi engellenebilir.

Son olarak daha az ilgi gören ama gerçek saldırılarda sıkça önemli olan ek sertleştirme katmanları vardır: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems ve dikkatli runtime varsayılanları. Bu mekanizmalar genellikle bir komprominin "son adımını" engeller, özellikle bir saldırgan kod yürütmeyi daha geniş bir ayrıcalık kazanımına çevirmeye çalıştığında.

Bu klasörün geri kalanı bu mekanizmaların her birini daha detaylı açıklar: kernel primitifinin gerçekte ne yaptığı, yerelde nasıl gözlemleneceği, yaygın runtime'ların nasıl kullandığı ve operatörlerin kazara nasıl zayıflattığı dahil.

## Sonraki Okuma

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
{{#include ../../../../banners/hacktricks-training.md}}
