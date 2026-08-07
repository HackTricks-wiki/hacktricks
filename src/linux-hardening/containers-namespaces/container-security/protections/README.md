# Container Protections Overview

{{#include ../../../../banners/hacktricks-training.md}}

Container hardening'deki en önemli fikir, "container security" olarak adlandırılan tek bir kontrolün bulunmamasıdır. İnsanların container isolation olarak adlandırdığı şey, aslında birlikte çalışan çeşitli Linux security ve resource-management mekanizmalarının sonucudur. Belgeler bunlardan yalnızca birini açıklarsa, okuyucular gücünü olduğundan fazla tahmin etme eğiliminde olur. Belgeler hepsini, nasıl etkileştiklerini açıklamadan listelerse, okuyucular gerçek bir model yerine yalnızca isimlerden oluşan bir katalog elde eder. Bu bölüm her iki hatadan da kaçınmaya çalışır.

Modelin merkezinde, workload'un görebileceği şeyleri izole eden **namespaces** bulunur. Bunlar sürece filesystem mount'ları, PID'ler, networking, IPC objects, hostname'ler, user/group mapping'leri, cgroup path'leri ve bazı clock'lar için özel veya kısmen özel bir görünüm sağlar. Ancak namespaces tek başına bir sürecin neler yapmasına izin verildiğine karar vermez. Sonraki katmanlar burada devreye girer.

**cgroups** resource usage'ı yönetir. Mount veya PID namespaces ile aynı anlamda öncelikle bir isolation boundary değildir, ancak memory, CPU, PID, I/O ve device access'i sınırladıkları için operasyonel açıdan kritik öneme sahiptir. Ayrıca historical breakout technique'leri writable cgroup özelliklerini, özellikle cgroup v1 ortamlarında, kötüye kullandığı için security açısından da önem taşırlar.

**Capabilities**, eski her şeye gücü yeten root modelini daha küçük privilege unit'lerine ayırır. Bu, birçok workload'un container içinde hâlâ UID 0 olarak çalışması nedeniyle container'lar için temel önemdedir. Bu nedenle soru yalnızca "process root mu?" değil, "hangi capabilities, hangi namespaces içinde, hangi seccomp ve MAC kısıtlamaları altında hayatta kaldı?" sorusudur. Bu nedenle bir container'daki root process'i görece kısıtlı olabilirken başka bir container'daki root process'i pratikte host root'tan neredeyse ayırt edilemez olabilir.

**seccomp**, syscall'ları filtreler ve workload'un maruz kaldığı kernel attack surface'i azaltır. Bu genellikle `unshare`, `mount`, `keyctl` gibi açıkça tehlikeli çağrıları veya breakout chain'lerinde kullanılan diğer syscall'ları engelleyen mekanizmadır. Bir process normalde bir işlemi gerçekleştirmesine izin verecek bir capability'ye sahip olsa bile seccomp, kernel syscall yolunu tamamen işleme almadan önce yine de engelleyebilir.

**AppArmor** ve **SELinux**, normal filesystem ve privilege kontrollerinin üzerine Mandatory Access Control ekler. Bunlar özellikle önemlidir; çünkü bir container sahip olmaması gereken sayıda capability'ye sahip olduğunda bile etkili olmaya devam ederler. Bir workload bir işlemi denemek için teorik privilege'a sahip olabilir, ancak label veya profile ilgili path'e, object'e ya da operation'a erişimi yasakladığı için bunu gerçekleştirmesi yine de engellenebilir.

Son olarak, daha az ilgi gören ancak gerçek saldırılarda düzenli olarak önem taşıyan ek hardening katmanları vardır: `no_new_privs`, masked procfs path'leri, read-only system path'leri, read-only root filesystem'ler ve dikkatle belirlenmiş runtime default'ları. Bu mekanizmalar çoğu zaman compromise'ın "son adımını" durdurur; özellikle bir attacker code execution'ı daha geniş bir privilege gain'e dönüştürmeye çalıştığında.

Bu folder'ın geri kalanı, kernel primitive'inin gerçekte ne yaptığı, bunun local olarak nasıl gözlemleneceği, common runtime'ların bunu nasıl kullandığı ve operator'ların bunu yanlışlıkla nasıl zayıflattığı dahil olmak üzere bu mekanizmaların her birini daha ayrıntılı şekilde açıklar.

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

Birçok gerçek escape, workload'a hangi host içeriğinin mount edildiğine de bağlıdır; bu nedenle core protection'ları okuduktan sonra şu bölüme devam etmek faydalıdır:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

{{#include ../../../../banners/hacktricks-training.md}}
