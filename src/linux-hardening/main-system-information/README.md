# Ana Sistem Bilgileri

{{#include ../../banners/hacktricks-training.md}}

Yerel bir yetki yükseltme tekniği seçmeden önce ana sistemin kernel'ını, dosya sistemini, ayrıcalıklı yardımcı programlarını ve mevcut kaçış yollarını inceleyin. [Yetki yükseltme kontrol listesi](linux-privilege-escalation-checklist.md), işlemleri izlemek için kısa bir sıra sunar.

- [Kernel güvenlik açığı değerlendirmesi ve çalışma zamanı maruziyeti](kernel-vulnerability-assessment.md), derleme uygunluğunu, erişilebilirliği ve etkin azaltımları kontrol eder.
- [Kernel modülleri ve modprobe kötüye kullanımı](kernel-modules-and-modprobe.md), modül yüklemeyi ve yardımcı program yolu maruziyetini ele alır.
- [Sudo komutlarının kötüye kullanımı](sudo-command-abuse.md), yetki devredilmiş komutların yetki sınırlarını aşma yollarını inceler.
- [Sembolik ve sabit bağlantılar ile dosya tanımlayıcıları](filesystem-links-and-file-descriptors.md), yol yönlendirmeyi ve devralınan ya da silinmiş-açık dosyaları ele alır.
- [Dosya sistemi, inode'lar ve kurtarma](filesystem-inodes-and-recovery.md), inceleme sırasında işe yarayan dosya sistemi davranışlarını açıklar.
- [Kontrol listesi: Linux yetki yükseltme](linux-privilege-escalation-checklist.md), ana sistem kontrollerini listeler ve daha ayrıntılı kaynaklara bağlantı verir.
- [Jail'lerden kaçış](escaping-from-limited-bash.md), kısıtlı shell'leri ve kısıtlı ortamları ele alır.
- [Kernel/LPE/CVE kaynakları](kernel-lpe-cves/README.md), yerel yetki yükseltme ve güvenlik açıkları hakkındaki odaklı yazıları bir araya getirir.
{{#include ../../banners/hacktricks-training.md}}
