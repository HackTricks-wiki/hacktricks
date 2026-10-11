# Linux Temelleri

{{#include ../../banners/hacktricks-training.md}}

Bu, Linux host değerlendirmesi için başlangıç noktasıdır. Sayfalar; kapsamlı bir privilege escalation iş akışını, pratik komutları, ortam değişkenlerini ve host üzerinde nelerin çalıştırılabileceğini etkileyen yaygın kısıtlamaları kapsar.

- [Linux privilege escalation](linux-privilege-escalation/README.md), enumeration ve olası yerel yükseltme yollarını adım adım ele alır. Daha kısa bir görev listesi için [privilege escalation kontrol listesini](../main-system-information/linux-privilege-escalation-checklist.md) kullanın.
- [Shell başlangıcı, takma adlar ve geçmiş](shell-startup-aliases-and-history.md), komut çözümlemeyi, başlangıç dosyalarının çalıştırılmasını ve geçmişteki ipuçlarını açıklar.
- [Yararlı Linux komutları](useful-linux-commands.md), dosyaları, süreçleri, servisleri ve ortamı incelemeye yönelik komutları bir araya getirir.
- [Linux ortam değişkenleri](linux-environment-variables.md), ortam değerlerinin çalıştırmayı nasıl etkilediğini ve hassas değerlerin nerelerde bulunabileceğini açıklar.
- [Linux kısıtlamalarını aşma](bypass-linux-restrictions/README.md), dosya sistemi korumaları, `noexec` ve distroless sistemler dahil olmak üzere kısıtlı shell'leri ve çalıştırma ortamlarını ele alır.

## Native binary exploitation

Bir değerlendirme savunmasız bir Linux executable dosyasına yönlendirirse, Binary Exploitation bölümündeki ilgili materyalleri kullanın:

- [ELF biçimi ve loader davranışı](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) ile [binary korumaları ve aşma yöntemleri](../../binary-exploitation/common-binary-protections-and-bypasses/README.md), executable dosyanın düzenini ve azaltıcı önlemleri açıklar.
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) ve [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md), kontrol akışı saldırılarını ele alır.
- [Libc heap exploitation](../../binary-exploitation/libc-heap/README.md) ve [format string'ler](../../binary-exploitation/format-strings/README.md), belleğin bozulmasına dayalı diğer yaygın yolları ele alır.

Kernel'e özgü vaka incelemelerine [Kernel/LPE/CVE materyali](../main-system-information/kernel-lpe-cves/README.md) üzerinden ulaşabilirsiniz.
{{#include ../../banners/hacktricks-training.md}}
