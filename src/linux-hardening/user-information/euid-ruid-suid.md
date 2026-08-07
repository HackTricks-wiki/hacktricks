# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Kullanıcı Tanımlama Değişkenleri

- **`ruid`**: **Gerçek kullanıcı kimliği**, işlemi başlatan kullanıcıyı belirtir.
- **`euid`**: **Etkin kullanıcı kimliği** olarak bilinir ve sistemin işlem ayrıcalıklarını belirlemek için kullandığı kullanıcı kimliğini temsil eder. Genel olarak `euid`, `ruid` ile aynıdır. Ancak SetUID binary çalıştırılması gibi durumlarda `euid`, dosya sahibinin kimliğini alır ve böylece belirli işlemsel izinler sağlar.
- **`suid`**: Bu **kaydedilmiş kullanıcı kimliği**, yüksek ayrıcalıklı bir işlem (genellikle root olarak çalışan) belirli görevleri gerçekleştirmek için ayrıcalıklarından geçici olarak vazgeçmek ve daha sonra başlangıçtaki yüksek ayrıcalıklı durumunu yeniden kazanmak istediğinde kritik bir rol oynar.

#### Önemli Not

root altında çalışmayan bir işlem, `euid` değerini yalnızca mevcut `ruid`, `euid` veya `suid` değerine eşit olacak şekilde değiştirebilir.

### set\*uid Fonksiyonlarını Anlama

- **`setuid`**: İlk varsayımların aksine, `setuid` öncelikle `ruid` yerine `euid` değerini değiştirir. Özellikle ayrıcalıklı işlemler için `ruid`, `euid` ve `suid` değerlerini belirtilen kullanıcıyla (çoğunlukla root) aynı hizaya getirir ve `suid` tarafından geçersiz kılınmaları nedeniyle bu kimlikleri kalıcı hale getirir. Ayrıntılı bilgiler [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html) içinde bulunabilir.<sup>[[2]](#references)</sup>
- **`setreuid`** ve **`setresuid`**: Bu fonksiyonlar `ruid`, `euid` ve `suid` değerlerinin daha hassas şekilde ayarlanmasına olanak tanır. Ancak yetenekleri işlemin ayrıcalık seviyesine bağlıdır. root olmayan işlemler için değişiklikler mevcut `ruid`, `euid` ve `suid` değerleriyle sınırlıdır. Buna karşılık root işlemleri veya `CAP_SETUID` yeteneğine sahip işlemler bu kimliklere rastgele değerler atayabilir. Daha fazla bilgi [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) ve [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html) sayfalarında bulunabilir.<sup>[[3]](#references)[[4]](#references)</sup>

Bu işlevler bir güvenlik mekanizması olarak değil, bir programın etkin kullanıcı kimliğini değiştirerek başka bir kullanıcının kimliğini benimsemesi gibi amaçlanan işlem akışını kolaylaştırmak için tasarlanmıştır.

Özellikle `setuid`, tüm kimlikleri root ile aynı hizaya getirdiği için root'a privilege elevation sağlamak amacıyla yaygın olarak kullanılsa da, farklı senaryolarda kullanıcı kimliği davranışlarını anlamak ve değiştirmek için bu fonksiyonlar arasındaki farkları ayırt etmek kritik önem taşır.

### Linux'ta Program Çalıştırma Mekanizmaları

#### **`execve` System Call**

- **İşlevsellik**: `execve`, ilk argüman tarafından belirlenen bir programı başlatır. Argümanlar için `argv` ve ortam için `envp` olmak üzere iki dizi argümanı alır.
- **Davranış**: Çağıranın memory space'ini korur ancak stack, heap ve data segment'lerini yeniler. Programın kodu yeni programla değiştirilir.
- **Kullanıcı Kimliği Koruması**:
- `ruid`, `euid` ve supplementary group ID'leri değişmeden kalır.
- Yeni programda SetUID biti ayarlanmışsa `euid` üzerinde nüanslı değişiklikler olabilir.
- Çalıştırma sonrasında `suid`, `euid` değerinden güncellenir.
- **Dokümantasyon**: Ayrıntılı bilgiler [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html) içinde bulunabilir.<sup>[[5]](#references)</sup>

#### **`system` Function**

- **İşlevsellik**: `execve`'den farklı olarak `system`, `fork` kullanarak bir child process oluşturur ve bu child process içinde `execl` kullanarak bir komut çalıştırır.
- **Komut Çalıştırma**: Komutu `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` aracılığıyla `sh` kullanarak çalıştırır.
- **Davranış**: `execl`, `execve`'nin bir biçimi olduğundan benzer şekilde çalışır, ancak yeni bir child process bağlamında.
- **Dokümantasyon**: Daha fazla bilgi [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html) sayfasında bulunabilir.

#### **SUID ile `bash` ve `sh` Davranışı**

- **`bash`**:
- `euid` ve `ruid` değerlerinin nasıl ele alınacağını etkileyen bir `-p` seçeneğine sahiptir.
- `-p` olmadan, başlangıçta farklılarsa `bash`, `euid` değerini `ruid` ile aynı olacak şekilde ayarlar.
- `-p` ile başlangıçtaki `euid` korunur.
- Daha fazla ayrıntı [`bash` man page](https://linux.die.net/man/1/bash) sayfasında bulunabilir.
- **`sh`**:
- `bash` içindeki `-p` seçeneğine benzer bir mekanizmaya sahip değildir.
- Kullanıcı kimlikleriyle ilgili davranış, `euid` ve `ruid` eşitliğinin korunmasını vurgulayan `-i` seçeneği dışında açıkça belirtilmemiştir.
- Ek bilgiler [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html) sayfasında bulunabilir.

İşleyişleri birbirinden farklı olan bu mekanizmalar, programları çalıştırmak ve programlar arasında geçiş yapmak için çok çeşitli seçenekler sunar. Ayrıca kullanıcı kimliklerinin nasıl yönetildiği ve korunduğu konusunda belirli nüanslara sahiptir.

### Çalıştırmalarda Kullanıcı Kimliği Davranışlarını Test Etme

https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail adresinden alınan örnekler; daha fazla bilgi için inceleyin<sup>[[1]](#references)</sup>

#### Case 1: `setuid` ile `system` Kullanımı

**Amaç**: `setuid` fonksiyonunun `system` ve `sh` olarak `bash` ile birlikte etkisini anlamak.

**C Code**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Derleme ve İzinler:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

- `ruid` ve `euid` başlangıçta sırasıyla 99 (nobody) ve 1000 (frank) değerlerindedir.
- `setuid` her ikisini de 1000 ile hizalar.
- `system`, sh'den bash'e olan sembolik bağlantı nedeniyle `/bin/bash -c id` komutunu çalıştırır.
- `bash`, `-p` olmadan çalıştırıldığında `euid` değerini `ruid` ile eşleşecek şekilde ayarlar; bunun sonucunda her ikisi de 99 (nobody) olur.

#### Case 2: system ile setreuid kullanımı

**C Code**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Derleme ve İzinler:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Çalıştırma ve Sonuç:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

- `setreuid`, hem ruid hem de euid değerlerini 1000 olarak ayarlar.
- `system`, bash'i çağırır; bash, bu değerler eşit olduğu için kullanıcı kimliklerini korur ve etkin olarak frank olarak çalışır.

#### Case 3: setuid ve execve Kullanımı

Amaç: setuid ile execve arasındaki etkileşimi incelemek.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Çalıştırma ve Sonuç:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

- `ruid` 99 olarak kalır, ancak euid 1000 olarak ayarlanır; bu da setuid'nin etkisiyle uyumludur.

**C Kodu Örneği 2 (Bash Çağırma):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Çalıştırma ve Sonuç:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

- `euid`, `setuid` tarafından 1000 olarak ayarlanmış olsa da `bash`, `-p` seçeneğinin bulunmaması nedeniyle euid'yi ruid (99) olarak sıfırlar.

**C Code Example 3 (bash -p kullanımı):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Çalıştırma ve Sonuç:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Referanslar

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve man page](https://man7.org/linux/man-pages/man2/execve.2.html)

{{#include ../../banners/hacktricks-training.md}}
