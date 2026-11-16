# Linux Sertleştirme

{{#include ../banners/hacktricks-training.md}}

Linux sistemlerini incelemek, yetki sınırlarını anlamak ve yerel erişimi kısıtlayan denetimleri gözden geçirmek için bu bölümü kullanın. Genel bir değerlendirme için [Linux temelleri](linux-basics/README.md) ve [yetki yükseltme kontrol listesi](main-system-information/linux-privilege-escalation-checklist.md) ile başlayın, ardından aşağıdaki ilgili konuya geçin.

- [Linux temelleri](linux-basics/README.md): yetki yükseltme metodolojisi, kullanışlı komutlar, ortam değişkenleri ve kısıtlama atlatmaları.
- [Temel sistem bilgileri](main-system-information/README.md): kernel, modüller, sudo, dosya sistemi davranışı, jail'ler ve yetki yükseltme kontrol listesi.
- [Kullanıcı bilgileri](user-information/README.md): Linux kimlikleri, gruplar, SSH agent forwarding ve Active Directory entegrasyonu.
- [İlgi çekici dosyalar ve izinler](interesting-files-permissions/README.md): yazılabilir yollar, capabilities, SUID davranışı, NFS, wildcard genişletme ve SELinux.
- [Ağ bilgileri](network-information/README.md): yerel hizmetler, socket'ler ve ağla ilgili exploitation örnekleri.
- [Yazılım bilgileri](software-information/README.md): authentication modülleri ve uygulamaya özgü saldırı yüzeyleri.
- [Süreçler, crontab, systemd ve D-Bus](processes-crontab-systemd-dbus/README.md): zamanlanmış yürütme ve süreçler arası iletişim.
- [Container'lar ve namespace'ler](containers-namespaces/README.md): runtime'lar, izolasyon sınırları ve container hardening.
- [AppArmor policy-control dosyalarının kötüye kullanımı](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): ayrıcalıklı bir yardımcı programın yerel bir kullanıcı tarafından açılmış bir AppArmor kontrol dosyasına yazıp yazamayacağını değerlendirin.
- [Post-exploitation](post-exploitation/README.md): kimlik bilgisi bulma, kalıcılık ve ana makine düzeyinde takip teknikleri.

Etkilenen kernel'lerde, bir AppArmor securityfs policy-control dosyasını ayrıcalıksız bir kullanıcı olarak açmak, doğrudan yazma işlemi reddedilse bile başarılı olabilir. Ayrıcalıklı bir yardımcı program bu dosyayı stdout olarak devralırsa, yazma işlemi yüklenmiş policy'yi değiştirebilir; bu, yalnızca zayıf bir container profili bulmaktan farklı bir yerel saldırı yoludur. Test etmeden önce satıcı kernel'inin ve yardımcı programın düzeltmelerini kontrol edin.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Qualys CrackArmor teknik duyurusu](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Ubuntu CrackArmor güvenlik açığı bilgi bankası](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
