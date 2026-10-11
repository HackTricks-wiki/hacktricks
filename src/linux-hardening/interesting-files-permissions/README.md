# İlginç Dosyalar ve İzinler

{{#include ../../banners/hacktricks-training.md}}

Dosya sahipliği, yazma erişimi, mount seçenekleri ve yürütme ayrıcalıkları, yerel bir kullanıcının etkin erişim kapsamını değiştirebilir. Önce hedef dosyayı veya yürütme yolunu belirleyin, ardından ilgili sayfayı kullanın:

- [SUID, SGID, ACL'ler ve hassas dosyalar](suid-sgid-and-acl-triage.md), yürütme ayrıcalıkları ve gizli erişim izinleri için başlangıç iş akışını sunar.
- [Root olarak rastgele dosya yazma](write-to-root.md), ayrıcalıklı yollara yazma işlemlerinin yükseltmeye nasıl dönüştürülebileceğini açıklar.
- [Linux capabilities](linux-capabilities.md), süreç başına ve dosya başına capabilities'i açıklar.
- [SUID paylaşımlı kütüphane ve linker kötüye kullanımı](suid-shared-library-and-linker-abuse.md), ayrıcalıklı ikililerde dinamik yüklemeyi ele alır.
- [`ld.so` ayrıcalık yükseltme örneği](ld.so.conf-example.md), bir linker yapılandırması vakasını inceler.
- [NFS `no_root_squash` ve `no_all_squash` yanlış yapılandırması](nfs-no_root_squash-misconfiguration-pe.md), uzak dosya sistemlerinde kimlik eşlemesini ele alır.
- [Wildcard hileleri](wildcards-spare-tricks.md), ayrıcalıklı komutlarda argüman genişletmeyi ele alır.
- [SELinux](selinux.md), ilke uygulamasını ve ilgili inceleme adımlarını açıklar.
{{#include ../../banners/hacktricks-training.md}}
