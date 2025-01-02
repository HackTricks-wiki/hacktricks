# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**macOS'in temeli XNU'dur**, bu "X is Not Unix" anlamına gelir. Bu çekirdek esasen **Mach mikro çekirdeği** (daha sonra tartışılacak) ve **Berkeley Software Distribution** (**BSD**) unsurlarından oluşmaktadır. XNU ayrıca **I/O Kit adı verilen bir sistem aracılığıyla çekirdek sürücüleri için bir platform sağlar**. XNU çekirdeği, **kaynak kodu serbestçe erişilebilir** olan Darwin açık kaynak projesinin bir parçasıdır.

Bir güvenlik araştırmacısı veya Unix geliştiricisi perspektifinden, **macOS** oldukça **benzer** bir **FreeBSD** sistemi gibi görünebilir; şık bir GUI ve birçok özel uygulama ile. BSD için geliştirilen çoğu uygulama, Unix kullanıcılarına aşina olan komut satırı araçlarının tamamı macOS'ta mevcut olduğundan, macOS'ta derlenip çalıştırılabilir. Ancak, XNU çekirdeği Mach'ı içerdiğinden, geleneksel bir Unix benzeri sistem ile macOS arasında bazı önemli farklılıklar vardır ve bu farklılıklar potansiyel sorunlara neden olabilir veya benzersiz avantajlar sağlayabilir.

XNU'nun açık kaynak versiyonu: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach, **UNIX uyumlu** olacak şekilde tasarlanmış bir **mikro çekirdek**'tir. Ana tasarım ilkelerinden biri, **çekirdek** alanında çalışan **kod** miktarını **minimize** etmek ve bunun yerine dosya sistemi, ağ ve I/O gibi birçok tipik çekirdek işlevinin **kullanıcı düzeyinde görevler olarak çalışmasına** izin vermekti.

XNU'da, Mach, bir çekirdeğin genellikle ele aldığı birçok kritik düşük seviyeli işlemin **sorumlusudur**, örneğin işlemci zamanlaması, çoklu görev ve sanal bellek yönetimi.

### BSD

XNU **çekirdeği** ayrıca **FreeBSD** projesinden türetilmiş önemli miktarda kodu **içermektedir**. Bu kod, Mach ile birlikte çekirdek parçası olarak **aynı adres alanında çalışır**. Ancak, XNU içindeki FreeBSD kodu, Mach ile uyumluluğunu sağlamak için gerekli değişiklikler yapıldığından, orijinal FreeBSD kodundan önemli ölçüde farklı olabilir. FreeBSD, aşağıdakiler dahil birçok çekirdek işlemi için katkıda bulunur:

- Süreç yönetimi
- Sinyal işleme
- Kullanıcı ve grup yönetimi dahil temel güvenlik mekanizmaları
- Sistem çağrısı altyapısı
- TCP/IP yığını ve soketler
- Güvenlik duvarı ve paket filtreleme

BSD ve Mach arasındaki etkileşimi anlamak karmaşık olabilir, çünkü farklı kavramsal çerçevelere sahiptirler. Örneğin, BSD, temel yürütme birimi olarak süreçleri kullanırken, Mach, iş parçacıkları temelinde çalışır. Bu tutarsızlık, XNU'da **her BSD sürecini tam olarak bir Mach iş parçacığı içeren bir Mach görevi ile ilişkilendirerek** uzlaştırılır. BSD'nin fork() sistem çağrısı kullanıldığında, çekirdek içindeki BSD kodu, bir görev ve bir iş parçacığı yapısı oluşturmak için Mach işlevlerini kullanır.

Ayrıca, **Mach ve BSD her biri farklı güvenlik modelleri** sürdürmektedir: **Mach'ın** güvenlik modeli **port haklarına** dayanırken, BSD'nin güvenlik modeli **süreç sahipliğine** dayanır. Bu iki model arasındaki farklılıklar zaman zaman yerel ayrıcalık yükseltme güvenlik açıklarına neden olmuştur. Tipik sistem çağrılarının yanı sıra, **kullanıcı alanı programlarının çekirdek ile etkileşimde bulunmasına izin veren Mach tuzakları** da vardır. Bu farklı unsurlar bir araya gelerek macOS çekirdeğinin çok yönlü, hibrit mimarisini oluşturur.

### I/O Kit - Sürücüler

I/O Kit, XNU çekirdeğinde açık kaynaklı, nesne yönelimli bir **cihaz sürücüsü çerçevesidir**, **dinamik olarak yüklenen cihaz sürücülerini** yönetir. Farklı donanımları destekleyerek çekirdeğe modüler kod eklenmesine olanak tanır.

{{#ref}}
macos-iokit.md
{{#endref}}

### IPC - Süreçler Arası İletişim

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS, kodun yüksek ayrıcalıklarla çalışması nedeniyle **Çekirdek Uzantılarını** (.kext) yüklemek için **son derece kısıtlayıcıdır**. Aslında, varsayılan olarak neredeyse imkansızdır (bir geçiş bulunmadıkça).

Aşağıdaki sayfada, macOS'un **kernelcache** içinde yüklediği `.kext`'i nasıl geri alabileceğinizi de görebilirsiniz:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

macOS, Çekirdek Uzantılarını kullanmak yerine, çekirdek ile etkileşimde bulunmak için kullanıcı düzeyinde API'ler sunan Sistem Uzantılarını oluşturmuştur. Bu şekilde, geliştiriciler çekirdek uzantılarını kullanmaktan kaçınabilirler.

{{#ref}}
macos-system-extensions.md
{{#endref}}

## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
