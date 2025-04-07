# Docker Soketini İstismar Ederek Yetki Yükseltme

{{#include ../../../banners/hacktricks-training.md}}

Bazı durumlarda sadece **docker soketine erişiminiz** vardır ve bunu **yetki yükseltmek** için kullanmak istersiniz. Bazı eylemler çok şüpheli olabilir ve bunlardan kaçınmak isteyebilirsiniz, bu nedenle burada yetki yükseltmek için faydalı olabilecek farklı bayraklar bulabilirsiniz:

### Mount Üzerinden

Bir konteynerde root olarak çalışan **dosya sisteminin** farklı kısımlarını **mount** edebilir ve onlara **erişebilirsiniz**.\
Ayrıca konteyner içinde **yetki yükseltmek için bir mount'ı istismar edebilirsiniz**.

- **`-v /:/host`** -> Konteynerde ana bilgisayar dosya sistemini mount edin, böylece **ana bilgisayar dosya sistemini okuyabilirsiniz.**
- Eğer **ana bilgisayarda olduğunuzu hissetmek** ama konteynerde olmak istiyorsanız, aşağıdaki bayrakları kullanarak diğer savunma mekanizmalarını devre dışı bırakabilirsiniz:
- `--privileged`
- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `-security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- **`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined`** -> Bu, önceki yönteme benzer, ancak burada **cihaz diskini mount ediyoruz**. Daha sonra konteyner içinde `mount /dev/sda1 /mnt` komutunu çalıştırın ve **/mnt** içinde **ana bilgisayar dosya sistemine erişebilirsiniz.**
- Mount etmek için `</dev/sda1>` cihazını bulmak için ana bilgisayarda `fdisk -l` komutunu çalıştırın.
- **`-v /tmp:/host`** -> Eğer bir nedenle sadece ana bilgisayardan **bir dizini mount edebiliyorsanız** ve ana bilgisayar içinde erişiminiz varsa. Mount edin ve mount edilen dizinde **suid** ile bir **`/bin/bash`** oluşturun, böylece **ana bilgisayardan çalıştırabilir ve root'a yükselebilirsiniz.**

> [!NOTE]
> `/tmp` klasörünü mount edemeyebileceğinizi, ancak **farklı bir yazılabilir klasörü** mount edebileceğinizi unutmayın. Yazılabilir dizinleri bulmak için: `find / -writable -type d 2>/dev/null` komutunu kullanabilirsiniz.
>
> **Unutmayın ki bir linux makinesindeki tüm dizinler suid bitini desteklemeyecektir!** Hangi dizinlerin suid bitini desteklediğini kontrol etmek için `mount | grep -v "nosuid"` komutunu çalıştırın. Örneğin genellikle `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` ve `/var/lib/lxcfs` suid bitini desteklemez.
>
> Ayrıca **`/etc`** veya **konfigürasyon dosyalarını içeren** başka bir klasörü **mount edebiliyorsanız**, bunları docker konteynerinden root olarak değiştirip **ana bilgisayarda istismar edebilir** ve yetki yükseltebilirsiniz (belki `/etc/shadow` dosyasını değiştirerek).

### Konteynerden Kaçış

- **`--privileged`** -> Bu bayrak ile [konteynerden tüm izolasyonu kaldırırsınız](docker-privileged.md#what-affects). [Yetkili konteynerlerden root olarak kaçış tekniklerini](docker-breakout-privilege-escalation/index.html#automatic-enumeration-and-escape) kontrol edin.
- **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> [yetki istismarını yükseltmek için](../linux-capabilities.md), **o yetkiyi konteynere verin** ve istismarın çalışmasını engelleyebilecek diğer koruma yöntemlerini devre dışı bırakın.

### Curl

Bu sayfada docker bayraklarını kullanarak yetki yükseltme yollarını tartıştık, **curl** komutunu kullanarak bu yöntemleri istismar etmenin **yollarını** sayfada bulabilirsiniz:

{{#include ../../../banners/hacktricks-training.md}}
