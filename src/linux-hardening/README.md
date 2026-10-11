# Linux Güçlendirme

{{#include ../banners/hacktricks-training.md}}

Bu bölümü Linux hostlarını incelemek, ayrıcalık sınırlarını anlamak ve yerel erişimi kısıtlayan kontrolleri gözden geçirmek için kullanın. Genel bir değerlendirme için [Linux temelleri](linux-basics/README.md) ve [ayrıcalık yükseltme kontrol listesi](main-system-information/linux-privilege-escalation-checklist.md) ile başlayın, ardından aşağıdaki ilgili konuya geçin.

- [Linux temelleri](linux-basics/README.md): ayrıcalık yükseltme metodolojisi, kullanışlı komutlar, ortam değişkenleri ve kısıtlamaları aşma yöntemleri.
- [Temel sistem bilgileri](main-system-information/README.md): kernel, modüller, sudo, dosya sistemi davranışı, jail'ler ve ayrıcalık yükseltme kontrol listesi.
- [Kullanıcı bilgileri](user-information/README.md): Linux kimlikleri, gruplar, SSH agent forwarding ve Active Directory entegrasyonu.
- [İlgi çekici dosyalar ve izinler](interesting-files-permissions/README.md): yazılabilir yollar, capabilities, SUID davranışı, NFS, wildcard genişletme ve SELinux.
- [Ağ bilgileri](network-information/README.md): yerel servisler, soketler ve ağla ilgili exploitation örnekleri.
- [Yazılım bilgileri](software-information/README.md): kimlik doğrulama modülleri ve uygulamaya özgü saldırı yüzeyleri.
- [Process'ler, crontab, systemd ve D-Bus](processes-crontab-systemd-dbus/README.md): zamanlanmış çalıştırma ve process'ler arası iletişim.
- [Container'lar ve namespace'ler](containers-namespaces/README.md): runtime'lar, izolasyon sınırları ve container hardening.
- [Post-exploitation](post-exploitation/README.md): kimlik bilgilerini bulma, kalıcılık ve host düzeyinde takip teknikleri.
{{#include ../banners/hacktricks-training.md}}
