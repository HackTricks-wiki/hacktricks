# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Kullanıcı Tanımlama Değişkenleri

- **`ruid`**: **Gerçek kullanıcı kimliği**, süreci başlatan kullanıcıyı belirtir.<sup>[[1]](#references)</sup>
- **`euid`**: **Etkin kullanıcı kimliği** olarak bilinir ve sistemin süreç ayrıcalıklarını belirlemek için kullandığı kullanıcı kimliğini temsil eder. Genel olarak `euid`, `ruid` ile aynıdır; ancak SetUID binary çalıştırılması gibi durumlarda (set-user-ID geçişine izin verildiğinde) `euid`, dosya sahibinin kimliğini alır ve böylece belirli işlemsel izinler sağlar.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: Bu **kaydedilmiş kullanıcı kimliği**, yüksek ayrıcalıklı bir sürecin (genellikle root olarak çalışan) belirli görevleri gerçekleştirmek için ayrıcalıklarından geçici olarak vazgeçmesi ve daha sonra başlangıçtaki yüksek ayrıcalık durumunu yeniden kazanması gerektiğinde kritik bir rol oynar.<sup>[[1]](#references)</sup>

#### Önemli Not

Ayrıcalıksız bir süreç, `euid` değerini yalnızca mevcut `ruid`, `euid` veya `suid` değeriyle eşleşecek şekilde değiştirebilir.<sup>[[3]](#references)</sup>

### set\*uid Fonksiyonlarını Anlama

- **`setuid`**: İlk varsayımların aksine, `setuid` çağrıyı yapan sürecin `euid` değerini ayarlar. Ayrıcalıklı bir süreç için ayrıca `ruid` ve `suid` değerlerini belirtilen kullanıcıya ayarlar; tüm kimlikler root olarak ayarlandıktan sonra süreç, `setuid` kullanarak önceki kimliğini yeniden kazanamaz. Ayrıntılı bilgiler [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html) içinde bulunabilir.<sup>[[2]](#references)</sup>
- **`setreuid`** ve **`setresuid`**: `setreuid`, `ruid` ve `euid` değerlerini değiştirirken `setresuid` üç kimliğin tamamını değiştirir. Ayrıcalıksız bir süreç için `setresuid`, her hedefi mevcut `ruid`, `euid` veya `suid` ile sınırlar; `setreuid` ise `euid` değerini bu değerlerle, `ruid` değerini de mevcut `ruid` veya `euid` ile sınırlar. `CAP_SETUID` yeteneğine sahip bir süreç, her çağrı tarafından desteklenen kimliklere rastgele değerler atayabilir. Daha fazla bilgi [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) ve [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html) içinde bulunabilir.<sup>[[3]](#references)[[4]](#references)</sup>

Bu işlevler bir security mechanism olarak değil, bir programın etkin kullanıcı kimliğini değiştirerek başka bir kullanıcının kimliğini benimsemesi gibi amaçlanan işlemsel akışı kolaylaştırmak için tasarlanmıştır.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Özellikle, ayrıcalıklı bir `setuid` çağrısı üç kimliğin tamamını atayabilirken `setreuid` ve `setresuid` farklı denetimler sunar; bu işlevleri birbirinden ayırmak, kullanıcı kimliği geçişlerini anlamak için kritik öneme sahiptir.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Linux'ta Program Çalıştırma Mekanizmaları

#### **`execve` System Call**

- **İşlevsellik**: `execve`, ilk argüman tarafından belirlenen bir programı başlatır. Argümanlar için `argv` ve environment için `envp` olmak üzere iki dizi argümanı alır.<sup>[[5]](#references)</sup>
- **Davranış**: Çağrıyı yapanın memory space alanını korur ancak stack, heap ve data segmentlerini yeniler. Programın kodu yeni programla değiştirilir.<sup>[[5]](#references)</sup>
- **Kullanıcı Kimliği Koruma**:
- `ruid` ve supplementary group ID değerleri değiştirilmeden kalır.<sup>[[5]](#references)</sup>
- `euid` normalde değiştirilmez ancak yeni programda SetUID biti ayarlanmışsa değişebilir.<sup>[[5]](#references)</sup>
- `suid`, çalıştırma sonrasında `euid` değerinden güncellenir.<sup>[[5]](#references)</sup>
- **Dokümantasyon**: Ayrıntılı bilgiler [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html) içinde bulunabilir.<sup>[[5]](#references)</sup>

#### **`system` Function**

- **İşlevsellik**: `execve` işlevinden farklı olarak `system`, `fork` kullanarak bir child process oluşturur ve komutu bu child process içinde `execl` kullanarak çalıştırırmış gibi davranır.<sup>[[6]](#references)</sup>
- **Komut Çalıştırma**: Komutu `sh` üzerinden `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` ile çalıştırır.<sup>[[6]](#references)</sup>
- **Davranış**: `execl` bir `exec`-family çağrısı olduğundan, yeni bir child process bağlamında `execve` ile benzer şekilde çalışır.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Dokümantasyon**: Daha fazla bilgi [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html) içinde bulunabilir.<sup>[[6]](#references)</sup>

#### **SUID ile `bash` ve `sh` Davranışı**

- **`bash`**:
- `euid` ve `ruid` değerlerinin nasıl ele alınacağını etkileyen bir `-p` seçeneğine sahiptir.<sup>[[7]](#references)</sup>
- `-p` olmadan, başlangıçta farklı olmaları durumunda `bash`, `euid` değerini `ruid` olarak ayarlar.<sup>[[7]](#references)</sup>
- `-p` ile başlangıçtaki `euid` korunur.<sup>[[7]](#references)</sup>
- Daha fazla ayrıntı [`bash` man page](https://linux.die.net/man/1/bash) içinde bulunabilir.<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX `sh`, Bash tarzı bir `-p` privilege-preservation seçeneği tanımlamaz.<sup>[[8]](#references)</sup>
- POSIX seçenek listesinde interactive mode seçen `-i` bulunur ve gerçek ile etkin kimlikler farklı olduğunda reddedilebilir.<sup>[[8]](#references)</sup>
- Ek bilgiler [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html) içinde bulunabilir.<sup>[[8]](#references)</sup>

İşleyişleri bakımından birbirinden farklı olan bu mekanizmalar, programları çalıştırmak ve programlar arasında geçiş yapmak için çok çeşitli seçenekler sunar; kullanıcı kimliklerinin nasıl yönetildiği ve korunduğu konusunda belirli farklılıklar bulunur.

### Çalıştırmalarda Kullanıcı Kimliği Davranışlarını Test Etme

https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail adresinden alınan örnekler; daha fazla bilgi için inceleyin.<sup>[[1]](#references)</sup>

#### Durum 1: `setuid` ile `system` Kullanımı

**Amaç**: `setuid` kullanımının `system` ve `sh` olarak `bash` ile birlikte etkisini anlamak.

**C Kodu**:
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

- `ruid` ve `euid` sırasıyla başlangıçta 99 (nobody) ve 1000 (frank) değerindedir.
- Bu unprivileged context içinde, `setuid(1000)` `ruid` değerini 99'da bırakır ve `euid` değerini 1000 yapar.<sup>[[1]](#references)</sup>
- `sh`'den `bash`'e olan symlink nedeniyle `system`, `/bin/bash -c id` komutunu çalıştırır.
- `-p` olmadan `bash`, `euid` değerini `ruid` ile eşleşecek şekilde ayarlar; bunun sonucunda her ikisi de 99 (nobody) olur.<sup>[[1]](#references)</sup>

#### Case 2: system ile setreuid Kullanımı

**C Kodu:**
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

- `setreuid`, hem ruid hem de euid değerini 1000 olarak ayarlar.
- `system`, bash'i çağırır; bash, bu kullanıcı kimliklerini eşit oldukları için korur ve etkin olarak frank olarak çalışır.<sup>[[1]](#references)</sup>

#### Durum 3: setuid ile execve kullanımı

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
**Çalıştırma ve Sonuç:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

- `ruid` 99 olarak kalır, ancak euid 1000 olarak ayarlanır; bu, setuid'in etkisiyle uyumludur.<sup>[[1]](#references)</sup>

**C Kod Örneği 2 (Bash Çağırma):**
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

- `euid`, `setuid` tarafından 1000 olarak ayarlanmış olsa da, `-p` seçeneğinin bulunmaması nedeniyle `bash`, euid değerini `ruid` (99) olarak sıfırlar.<sup>[[1]](#references)</sup>

**C Code Example 3 (`bash -p` Kullanımı):**
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
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID Tavşan Deliği - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid man sayfası](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid man sayfası](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid man sayfası](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve man sayfası](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - system man sayfası](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - bash man sayfası](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - POSIX sh man sayfası](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
