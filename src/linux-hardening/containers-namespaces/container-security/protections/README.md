# Container Protections Overview

{{#include ../../../../banners/hacktricks-training.md}}

Container hardening alanındaki en önemli fikir, "container security" adında tek bir kontrolün bulunmadığıdır. İnsanların container isolation olarak adlandırdığı şey, aslında birlikte çalışan çeşitli Linux security ve resource-management mekanizmalarının sonucudur. Dokümantasyon bunlardan yalnızca birini açıklarsa okuyucular gücünü olduğundan fazla tahmin etme eğiliminde olur. Dokümantasyon hepsini, nasıl etkileşime girdiklerini açıklamadan listelerse okuyucular gerçek bir model yerine yalnızca isimlerden oluşan bir katalog elde eder. Bu bölüm her iki hatadan da kaçınmaya çalışır.

Modelin merkezinde, workload'un neleri görebileceğini izole eden **namespaces** bulunur. Bunlar prosese filesystem mount'ları, PID'ler, networking, IPC nesneleri, hostname'ler, user/group mapping'leri, cgroup path'leri ve bazı clock'lar için private veya kısmen private bir görünüm sağlar. Ancak namespaces tek başına bir prosesin ne yapmasına izin verildiğine karar vermez. Bir sonraki katmanlar burada devreye girer.

**cgroups** resource usage'ı yönetir. Mount veya PID namespaces ile aynı anlamda öncelikli olarak bir isolation boundary değildirler, ancak memory, CPU, PID'ler, I/O ve device access'i kısıtladıkları için operasyonel açıdan kritik öneme sahiptirler. Ayrıca geçmişteki breakout teknikleri writable cgroup özelliklerini, özellikle cgroup v1 ortamlarında, kötüye kullandığı için security açısından da önem taşırlar.

**Capabilities**, eski her şeye gücü yeten root modelini daha küçük privilege birimlerine ayırır. Bu, birçok workload'un container içinde hâlâ UID 0 ile çalışması nedeniyle container'lar için temel öneme sahiptir. Bu nedenle soru yalnızca "proses root mu?" değildir; asıl soru "hangi capabilities, hangi namespaces içinde ve hangi seccomp ile MAC kısıtlamaları altında korundu?" sorusudur. Bir container'daki root prosesinin görece kısıtlı kalabilmesinin, başka bir container'daki root prosesinin ise pratikte host root'tan neredeyse ayırt edilememesinin nedeni budur.

**seccomp**, syscall'ları filtreler ve workload'a sunulan kernel attack surface'i azaltır. Bu çoğu zaman `unshare`, `mount`, `keyctl` gibi açıkça tehlikeli çağrıları veya breakout chain'lerinde kullanılan diğer syscall'ları engelleyen mekanizmadır. Bir proses aksi takdirde bir operasyona izin verecek bir capability'ye sahip olsa bile seccomp, kernel syscall path'ini tamamen işleme almadan önce engelleyebilir.

**AppArmor** ve **SELinux**, normal filesystem ve privilege kontrollerinin üzerine Mandatory Access Control ekler. Bunlar özellikle önemlidir çünkü bir container olması gerekenden daha fazla capability'ye sahip olduğunda bile etkilerini sürdürürler. Bir workload bir eylemi gerçekleştirmeyi denemek için teorik privilege'a sahip olabilir, ancak label'ı veya profile'ı ilgili path'e, nesneye ya da operasyona erişimi yasakladığı için eylemi gerçekleştirmesi yine de engellenebilir.

Son olarak, daha az ilgi gören ancak gerçek saldırılarda düzenli olarak önem taşıyan ek hardening katmanları vardır: `no_new_privs`, masked procfs path'leri, read-only system path'leri, read-only root filesystem'ler ve dikkatle belirlenmiş runtime default'ları. Bu mekanizmalar, özellikle bir attacker code execution'ı daha geniş bir privilege gain'e dönüştürmeye çalıştığında, çoğu zaman compromise'ın "son adımını" engeller.

Bu klasörün geri kalanı, kernel primitive'in gerçekte ne yaptığını, yerel olarak nasıl gözlemleneceğini, yaygın runtime'ların onu nasıl kullandığını ve operator'ların onu nasıl istemeden zayıflattığını da kapsayacak şekilde bu mekanizmaların her birini daha ayrıntılı açıklar.

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

Gerçek escape'lerin çoğu, workload'a hangi host içeriğinin mount edildiğine de bağlıdır; bu nedenle core protections'ı okuduktan sonra şu bölüme devam etmek faydalı olacaktır:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
