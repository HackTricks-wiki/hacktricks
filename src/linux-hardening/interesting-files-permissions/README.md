# İlginç Dosyalar ve İzinler

{{#include ../../banners/hacktricks-training.md}}

Dosya sahipliği, yazma erişimi, bağlama seçenekleri ve yürütme ayrıcalıkları, yerel bir kullanıcının etkin erişimini değiştirebilir. Önce hedef dosyayı veya yürütme yolunu belirleyin, ardından ilgili sayfayı inceleyin:

- [SUID, SGID, ACL'ler ve hassas dosyalar](suid-sgid-and-acl-triage.md), yürütme ayrıcalıkları ve gizli erişim izinleri için başlangıç niteliğinde bir iş akışı sunar.
- [Root'a rastgele dosya yazma](write-to-root.md), ayrıcalıklı yollara yazmanın nasıl yetki yükseltmeye dönüştürülebileceğini açıklar.
- [Linux capabilities](linux-capabilities.md), süreç başına ve dosya başına capabilities konusunu açıklar.
- [SUID paylaşılan kütüphane ve linker kötüye kullanımı](suid-shared-library-and-linker-abuse.md), ayrıcalıklı ikili dosyaların çevresindeki dinamik yüklemeyi ele alır.
- [`ld.so` ile yetki yükseltme örneği](ld.so.conf-example.md), bir linker yapılandırma örneğini inceler.
- [NFS `no_root_squash` ve `no_all_squash` yanlış yapılandırması](nfs-no_root_squash-misconfiguration-pe.md), uzak dosya sistemlerinde kimlik eşlemesini ele alır.
- [Wildcard spare hileleri](wildcards-spare-tricks.md), ayrıcalıklı komutlardaki argüman genişletmesini ele alır.
- [SELinux](selinux.md), ilke uygulamasını ve ilgili inceleme adımlarını açıklar.
{{#include ../../banners/hacktricks-training.md}}
