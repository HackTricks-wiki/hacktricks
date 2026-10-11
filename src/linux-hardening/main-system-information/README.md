# Ana Sistem Bilgileri

{{#include ../../banners/hacktricks-training.md}}

Yerel yetki yükseltme tekniği seçmeden önce ana makinenin kernel'ini, dosya sistemini, ayrıcalıklı yardımcı programlarını ve kullanılabilir kaçış yollarını inceleyin. [Yetki yükseltme kontrol listesi](linux-privilege-escalation-checklist.md), izlenecek adımları kısa ve öz şekilde sıralar.

- [Kernel zafiyeti değerlendirmesi ve çalışma zamanı maruziyeti](kernel-vulnerability-assessment.md), derlemenin uygulanabilirliğini, erişilebilirliği ve etkin azaltımları kontrol eder.
- [Kernel modülleri ve modprobe istismarı](kernel-modules-and-modprobe.md), modül yüklemeyi ve yardımcı program yolu maruziyetini ele alır.
- [Sudo komutlarının istismarı](sudo-command-abuse.md), yetki devredilen komutların yetki sınırlarını aşma yollarını inceler.
- [Symlink'ler, hardlink'ler ve dosya tanımlayıcıları](filesystem-links-and-file-descriptors.md), yol yönlendirmeyi ve devralınan ya da silinmiş açık dosyaları ele alır.
- [Dosya sistemi, inode'lar ve kurtarma](filesystem-inodes-and-recovery.md), inceleme sırasında yararlanılabilecek dosya sistemi davranışını açıklar.
- [Kontrol listesi: Linux yetki yükseltme](linux-privilege-escalation-checklist.md), ana makine kontrollerini sıralar ve daha ayrıntılı kaynaklara bağlantı verir.
- [Jail'lerden kaçış](escaping-from-limited-bash.md), kısıtlı shell'leri ve kısıtlı ortamları ele alır.
- [Kernel/LPE/CVE materyalleri](kernel-lpe-cves/README.md), yerel yetki yükseltmeye ve zafiyetlere odaklanan yazıları bir araya getirir.
{{#include ../../banners/hacktricks-training.md}}
