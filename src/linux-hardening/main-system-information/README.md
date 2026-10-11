# Ana Sistem Bilgileri

{{#include ../../banners/hacktricks-training.md}}

Bir local escalation tekniği seçmeden önce host'un kernel'ini, dosya sistemini, ayrıcalıklı yardımcılarını ve mevcut kaçış yollarını inceleyin. [privilege escalation checklist](linux-privilege-escalation-checklist.md), uygulanacak adımlar için kısa bir sıralama sunar.

- [Kernel güvenlik açığı değerlendirmesi ve çalışma zamanı maruziyeti](kernel-vulnerability-assessment.md), derlemenin uygulanabilirliğini, erişilebilirliği ve etkin azaltma önlemlerini kontrol eder.
- [Kernel modülleri ve modprobe kötüye kullanımı](kernel-modules-and-modprobe.md), modül yüklemeyi ve yardımcı program yolu maruziyetini ele alır.
- [Sudo komutu kötüye kullanımı](sudo-command-abuse.md), devredilen komutların ayrıcalık sınırlarını aşma yollarını inceler.
- [Symlink'ler, hardlink'ler ve dosya tanımlayıcıları](filesystem-links-and-file-descriptors.md), yol yönlendirmeyi ve devralınan ya da silinmiş ama açık dosyaları ele alır.
- [Dosya sistemi, inode'lar ve kurtarma](filesystem-inodes-and-recovery.md), inceleme sırasında yararlı olabilecek dosya sistemi davranışlarını açıklar.
- [Kontrol listesi: Linux privilege escalation](linux-privilege-escalation-checklist.md), host kontrollerini sıralar ve daha ayrıntılı kaynaklara bağlantılar verir.
- [Jail'lerden kaçış](escaping-from-limited-bash.md), kısıtlı shell'leri ve sınırlandırılmış ortamları ele alır.
- [Kernel/LPE/CVE içerikleri](kernel-lpe-cves/README.md), local privilege escalation ve güvenlik açıklarıyla ilgili odaklı yazıları bir araya getirir.
{{#include ../../banners/hacktricks-training.md}}
