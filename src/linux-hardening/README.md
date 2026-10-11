# Linux Güçlendirme

{{#include ../banners/hacktricks-training.md}}

Linux hostlarını incelemek, yetki sınırlarını anlamak ve yerel erişimi kısıtlayan denetimleri gözden geçirmek için bu bölümü kullanın. Genel bir değerlendirme için [Linux temelleri](linux-basics/README.md) ve [yetki yükseltme kontrol listesi](main-system-information/linux-privilege-escalation-checklist.md) ile başlayın, ardından aşağıdaki ilgili konuyu izleyin.

- [Linux temelleri](linux-basics/README.md): privilege escalation metodolojisi, kullanışlı komutlar, ortam değişkenleri ve kısıtlamaları atlatma yöntemleri.
- [Temel sistem bilgileri](main-system-information/README.md): kernel, modüller, sudo, dosya sistemi davranışları, jails ve privilege escalation kontrol listesi.
- [Kullanıcı bilgileri](user-information/README.md): Linux kimlikleri, gruplar, SSH agent forwarding ve Active Directory entegrasyonu.
- [İlginç dosyalar ve izinler](interesting-files-permissions/README.md): yazılabilir yollar, capabilities, SUID davranışı, NFS, wildcard genişletme ve SELinux.
- [Ağ bilgileri](network-information/README.md): yerel servisler, soketler ve ağla ilgili exploitation örnekleri.
- [Yazılım bilgileri](software-information/README.md): authentication modülleri ve uygulamalara özgü saldırı yüzeyleri.
- [İşlemler, crontab, systemd ve D-Bus](processes-crontab-systemd-dbus/README.md): zamanlanmış çalıştırma ve süreçler arası iletişim.
- [Containers ve namespaces](containers-namespaces/README.md): çalışma ortamları, izolasyon sınırları ve container hardening.
- [Post-exploitation](post-exploitation/README.md): kimlik bilgilerini bulma, persistence ve host düzeyinde sonraki teknikler.
{{#include ../banners/hacktricks-training.md}}
