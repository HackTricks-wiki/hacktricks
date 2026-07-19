# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### Kullanıcı Tanımlama Değişkenleri

- **`ruid`**: **Gerçek kullanıcı kimliği**, işlemi başlatan kullanıcıyı belirtir.
- **`euid`**: **Etkin kullanıcı kimliği** olarak bilinir ve sistemin işlem ayrıcalıklarını belirlemek için kullandığı kullanıcı kimliğini temsil eder. Genel olarak `euid`, `ruid` ile aynıdır. Bunun istisnası, SetUID binary çalıştırılması gibi durumlardır; bu durumda `euid`, dosya sahibinin kimliğini alır ve böylece belirli işlem izinleri sağlar.
- **`suid`**: Bu **kaydedilmiş kullanıcı kimliği**, yüksek ayrıcalıklı bir işlemin (genellikle root olarak çalışır) belirli görevleri gerçekleştirmek için ayrıcalıklarından geçici olarak vazgeçmesi ve daha sonra başlangıçtaki yükseltilmiş durumunu yeniden kazanması gerektiğinde kritik öneme sahiptir.

#### Önemli Not

root altında çalışmayan bir işlem, `euid` değerini yalnızca mevcut `ruid`, `euid` veya `suid` değerlerinden biriyle aynı olacak şekilde değiştirebilir.

### set\*uid Fonksiyonlarını Anlama

- **`setuid`**: İlk varsayımların aksine, `setuid` öncelikle `ruid` yerine `euid` değerini değiştirir. Özellikle ayrıcalıklı işlemler için `ruid`, `euid` ve `suid` değerlerini belirtilen kullanıcıyla (genellikle root) aynı hizaya getirir ve `suid` tarafından geçersiz kılındıkları için bu kimlikleri kalıcı hale getirir. Ayrıntılı bilgiler [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html) içinde bulunabilir.
- **`setreuid`** ve **`setresuid`**: Bu fonksiyonlar `ruid`, `euid` ve `suid` değerlerinin hassas biçimde ayarlanmasına olanak tanır. Ancak bu yetenekler işlemin ayrıcalık düzeyine bağlıdır. root olmayan işlemler için değişiklikler mevcut `ruid`, `euid` ve `suid` değerleriyle sınırlıdır. Buna karşılık root işlemleri veya `CAP_SETUID` capability değerine sahip işlemler, bu kimliklere rastgele değerler atayabilir. Daha fazla bilgi [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) ve [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html) içinde bulunabilir.

Bu işlevler bir security mekanizması olarak değil, bir programın effective user ID değerini değiştirerek başka bir kullanıcının kimliğini benimsemesi gibi amaçlanan operasyonel akışı kolaylaştırmak için tasarlanmıştır.

Özellikle `setuid`, tüm kimlikleri root ile aynı hizaya getirdiği için root'a privilege elevation amacıyla yaygın olarak tercih edilebilse de, farklı senaryolarda kullanıcı kimliği davranışlarını anlamak ve değiştirmek için bu fonksiyonlar arasındaki ayrımı kavramak önemlidir.

### Linux'ta Program Çalıştırma Mekanizmaları

#### **`execve` System Call**

- **İşlevsellik**: `execve`, ilk argümanla belirlenen bir programı başlatır. Biri argümanlar için `argv`, diğeri environment için `envp` olmak üzere iki array argümanı alır.
- **Davranış**: Çağıranın memory space alanını korur ancak stack, heap ve data segmentlerini yeniler. Programın code alanı yeni programla değiştirilir.
- **User ID Koruması**:
- `ruid`, `euid` ve supplementary group ID değerleri değiştirilmeden kalır.
- Yeni programda SetUID biti ayarlanmışsa `euid` üzerinde nüanslı değişiklikler olabilir.
- `suid`, çalıştırma sonrasında `euid` değerinden güncellenir.
- **Documentation**: Ayrıntılı bilgiler [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html) içinde bulunabilir.

#### **`system` Function**

- **İşlevsellik**: `execve` işlevinden farklı olarak `system`, `fork` kullanarak bir child process oluşturur ve bu child process içinde `execl` kullanarak bir command çalıştırır.
- **Command Execution**: Command, `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` ile `sh` üzerinden çalıştırılır.
- **Davranış**: `execl`, `execve` biçimlerinden biri olduğundan benzer şekilde çalışır; ancak bu kez yeni bir child process bağlamında çalışır.
- **Documentation**: Daha fazla bilgi [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html) içinde bulunabilir.

#### **`bash` ve `sh`'nin SUID ile Davranışı**

- **`bash`**:
- `euid` ve `ruid` değerlerinin nasıl ele alınacağını etkileyen bir `-p` seçeneğine sahiptir.
- `-p` olmadan `bash`, başlangıçta farklılarsa `euid` değerini `ruid` olarak ayarlar.
- `-p` ile başlangıçtaki `euid` korunur.
- Daha fazla ayrıntı [`bash` man page](https://linux.die.net/man/1/bash) içinde bulunabilir.
- **`sh`**:
- `bash` içindeki `-p` seçeneğine benzer bir mekanizmaya sahip değildir.
- User ID değerleriyle ilgili davranış, `euid` ve `ruid` eşitliğinin korunmasını vurgulayan `-i` seçeneği dışında açıkça belirtilmemiştir.
- Ek bilgiler [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html) içinde bulunabilir.

Operasyonları bakımından birbirinden farklı olan bu mekanizmalar, programları çalıştırmak ve programlar arasında geçiş yapmak için çok çeşitli seçenekler sunar. Ayrıca user ID değerlerinin nasıl yönetilip korunduğuna ilişkin belirli nüanslara sahiptir.

### Çalıştırmalar Sırasında User ID Davranışlarını Test Etme

Örnekler https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail adresinden alınmıştır; daha fazla bilgi için inceleyin.

#### Case 1: `setuid` ile `system` Kullanımı

**Amaç**: `setuid` kullanımının `system` ve `sh` olarak `bash` ile birlikte etkisini anlamak.

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
- `setuid`, her ikisini de 1000 ile hizalar.
- `system`, sh'den bash'e olan symlink nedeniyle `/bin/bash -c id` komutunu çalıştırır.
- `bash`, `-p` olmadan çalıştırıldığında `euid` değerini `ruid` ile eşleşecek şekilde ayarlar; bunun sonucunda her ikisi de 99 (nobody) olur.

#### system ile setreuid Kullanımı

**C Kodu**:
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
**Yürütme ve Sonuç:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

- `setreuid`, hem ruid hem de euid değerlerini 1000 olarak ayarlar.
- `system`, ruid ve euid eşitliklerini koruyan bash'i çağırır ve etkin olarak frank kullanıcısı olarak çalışır.

#### Case 3: setuid ile execve kullanımı

Amaç: setuid ve execve arasındaki etkileşimi incelemek.
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
**Yürütme ve Sonuç:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

- `ruid` 99 olarak kalır, ancak euid, setuid etkisi doğrultusunda 1000 olarak ayarlanır.

**C Code Örneği 2 (Bash Çağırma):**
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
**Yürütme ve Sonuç:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

- `euid`, `setuid` tarafından 1000 olarak ayarlanmış olsa da `bash`, `-p` seçeneğinin bulunmaması nedeniyle euid'yi `ruid` (99) olarak sıfırlar.

**C Code Example 3 (bash -p Kullanımı):**
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
**Yürütme ve Sonuç:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Referanslar

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
