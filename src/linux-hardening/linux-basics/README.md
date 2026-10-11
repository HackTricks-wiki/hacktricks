# Linux Temelleri

{{#include ../../banners/hacktricks-training.md}}

Bu bölüm, Linux ana makinelerinin değerlendirilmesi için başlangıç noktasıdır. Sayfalarda kapsamlı bir privilege escalation iş akışı, pratik komutlar, ortam değişkenleri ve ana makinede nelerin çalıştırılabileceğini etkileyen yaygın kısıtlamalar ele alınır.

- [Linux privilege escalation](linux-privilege-escalation/README.md), keşif ve olası yerel yükseltme yollarını adım adım açıklar. Daha kısa bir görev listesi için [privilege escalation kontrol listesini](../main-system-information/linux-privilege-escalation-checklist.md) kullanın.
- [Shell başlangıcı, aliases ve geçmiş](shell-startup-aliases-and-history.md), komut çözümlemesini, başlangıç dosyalarının yürütülmesini ve geçmişteki ipuçlarını açıklar.
- [Yararlı Linux komutları](useful-linux-commands.md), dosyaları, süreçleri, servisleri ve ortamı incelemeye yarayan komutları bir araya getirir.
- [Linux ortam değişkenleri](linux-environment-variables.md), ortam değerlerinin yürütmeyi nasıl etkilediğini ve hassas değerlerin nerelerde bulunabileceğini açıklar.
- [Linux kısıtlamalarını Bypass etme](bypass-linux-restrictions/README.md), dosya sistemi korumaları, `noexec` ve distroless sistemler dahil olmak üzere kısıtlı shell'leri ve yürütme ortamlarını ele alır.

## Native binary exploitation

Değerlendirme sonucunda savunmasız bir Linux yürütülebilir dosyasıyla karşılaşırsanız, Binary Exploitation bölümündeki ilgili içeriklerden yararlanın:

- [ELF biçimi ve yükleyici davranışı](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) ile [ikili dosya korumaları ve bypass yöntemleri](../../binary-exploitation/common-binary-protections-and-bypasses/README.md), yürütülebilir dosyanın düzenini ve azaltımları açıklar.
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) ve [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md), kontrol akışı saldırılarını ele alır.
- [Libc heap exploitation](../../binary-exploitation/libc-heap/README.md) ve [format strings](../../binary-exploitation/format-strings/README.md), yaygın diğer bellek bozulması yollarını ele alır.

Çekirdeğe özgü vaka incelemelerine [Kernel/LPE/CVE içeriğinden](../main-system-information/kernel-lpe-cves/README.md) ulaşabilirsiniz.
{{#include ../../banners/hacktricks-training.md}}
