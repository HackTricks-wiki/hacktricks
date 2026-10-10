# Linux Temelleri

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, Linux host değerlendirmesi için başlangıç noktasıdır. Sayfalarda geniş kapsamlı bir privilege escalation iş akışı, pratik komutlar, ortam değişkenleri ve bir host üzerinde çalıştırılabilecekleri etkileyen yaygın kısıtlamalar ele alınır.

- [Linux privilege escalation](linux-privilege-escalation/README.md), keşif ve olası yerel yetki yükseltme yollarını açıklar. Daha kısa bir görev listesi için [privilege escalation kontrol listesini](../main-system-information/linux-privilege-escalation-checklist.md) kullanın.
- [Shell başlangıcı, takma adlar ve geçmiş](shell-startup-aliases-and-history.md), komut çözümlemeyi, başlangıç dosyalarının yürütülmesini ve geçmiş kayıtlarındaki ipuçlarını açıklar.
- [Faydalı Linux komutları](useful-linux-commands.md), dosyaları, süreçleri, servisleri ve ortamı incelemeye yönelik komutları bir araya getirir.
- [Linux ortam değişkenleri](linux-environment-variables.md), ortam değerlerinin yürütmeyi nasıl etkilediğini ve hassas değerlerin nerelerde bulunabileceğini açıklar.
- [Linux kısıtlamalarını aşma](bypass-linux-restrictions/README.md), dosya sistemi korumaları, `noexec` ve distroless sistemler dahil kısıtlı shell'leri ve yürütme ortamlarını ele alır.

## Yerel ikili dosya exploitation'ı

Bir değerlendirme sonucunda savunmasız bir Linux executable'ı tespit edilirse Binary Exploitation bölümündeki ilgili materyalleri kullanın:

- [ELF biçimi ve loader davranışı](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) ile [binary korumaları ve bypass yöntemleri](../../binary-exploitation/common-binary-protections-and-bypasses/README.md), executable yerleşimini ve azaltma önlemlerini açıklar.
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) ve [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md), kontrol akışı saldırılarını ele alır.
- [Libc heap exploitation](../../binary-exploitation/libc-heap/README.md) ve [format string'ler](../../binary-exploitation/format-strings/README.md), yaygın diğer bellek bozulması yollarını ele alır.

Kernel'e özgü vaka incelemelerinin bağlantıları [Kernel/LPE/CVE materyali](../main-system-information/kernel-lpe-cves/README.md) altında verilmiştir.
{{#include ../../banners/hacktricks-training.md}}
