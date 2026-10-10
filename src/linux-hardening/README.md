# Linux Güvenliğini Sıkılaştırma

{{#include ../banners/hacktricks-training.md}}

Linux ana makinelerini incelemek, yetki sınırlarını anlamak ve yerel erişimi kısıtlayan denetimleri gözden geçirmek için bu bölümü kullanın. Genel bir değerlendirme için [Linux temelleri](linux-basics/README.md) ve [yetki yükseltme kontrol listesi](main-system-information/linux-privilege-escalation-checklist.md) ile başlayın, ardından aşağıdaki ilgili konuyu inceleyin.

- [Linux temelleri](linux-basics/README.md): yetki yükseltme metodolojisi, yararlı komutlar, ortam değişkenleri ve kısıtlamaları aşma yöntemleri.
- [Ana sistem bilgileri](main-system-information/README.md): kernel, modüller, sudo, dosya sistemi davranışı, jail'ler ve yetki yükseltme kontrol listesi.
- [Kullanıcı bilgileri](user-information/README.md): Linux kimlikleri, gruplar, SSH agent forwarding ve Active Directory entegrasyonu.
- [İlginç dosyalar ve izinler](interesting-files-permissions/README.md): yazılabilir yollar, capabilities, SUID davranışı, NFS, wildcard genişletmesi ve SELinux.
- [Ağ bilgileri](network-information/README.md): yerel servisler, soketler ve ağla ilgili exploitation örnekleri.
- [Yazılım bilgileri](software-information/README.md): kimlik doğrulama modülleri ve uygulamaya özgü saldırı yüzeyleri.
- [İşlemler, crontab, systemd ve D-Bus](processes-crontab-systemd-dbus/README.md): zamanlanmış yürütme ve işlemler arası iletişim.
- [Container'lar ve namespace'ler](containers-namespaces/README.md): çalışma zamanları, izolasyon sınırları ve container güvenliğini sıkılaştırma.
- [Post-exploitation](post-exploitation/README.md): kimlik bilgisi keşfi, kalıcılık ve ana makine düzeyinde takip teknikleri.
{{#include ../banners/hacktricks-training.md}}
