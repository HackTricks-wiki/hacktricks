# SUSE Oturumu ve Disk Hizmeti Yetki Yükseltme Göstergeleri

{{#include ../../banners/hacktricks-training.md}}

## PAM üzerinden SSH oturum yetkilendirmesi

CVE-2025-6018, SSH kimlik doğrulama yığınının `pam_env` modülünü, oturum yığını `pam_systemd` modülünü yüklemeden önce yüklediği SUSE 15 PAM yapılandırmalarını etkiledi. `pam_env`, kullanıcının `.pam_environment` dosyasını okuduğunda kullanıcı, SSH oturumunun Polkit tarafından fiziksel olarak etkin görünmesine neden olan `XDG_SEAT` ve `XDG_VTNR` değerleri sağlayabiliyordu. Böylece `allow_active=yes` eylemi uzak bir kullanıcı için kullanılabilir hâle gelebiliyordu. Bu, oturum yetkilendirmesini değiştirir; tek başına root erişimini garanti etmez. SUSE, `pam` içindeki varsayılan kullanıcı ortamı davranışını ve `pam-config` tarafından oluşturulan modül sıralamasını düzeltti.<sup>[[1]](#references)[[2]](#references)</sup>

Etkin `/etc/pam.d/sshd` include zincirini, `pam_env.so` ile `pam_systemd.so` modüllerinin sıralamasını ve açıkça belirtilmiş `user_readenv=1` seçeneğini inceleyin. Yamalanmış bir `pam` paketi varsayılan davranışı değiştirir, ancak açıkça belirtilen bir seçenek yine de kullanıcı ortamının okunmasını isteyebilir. Daha yeni bir `pam-config` paketi, yerel olarak değiştirilmiş veya güncelliğini yitirmiş bir PAM yığınının yeniden oluşturulduğunu kanıtlamaz. Tedarikçi paket sürümünü ve gerçek yapılandırmayı birlikte kontrol edin.<sup>[[1]](#references)[[2]](#references)</sup>

## Etkin kullanıcı disk hizmeti yolu

CVE-2025-6019, `udisks2` üzerinden kullanılan `libblockdev` içinde bir yetki yükseltme yoluydu: XFS yeniden boyutlandırması sırasında saldırganın sağladığı bir dosya sistemi, beklenen `nosuid` kısıtlaması olmadan geçici olarak bağlanabiliyordu. Bu yol için kullanılabilir bir UDisks D-Bus hizmeti, XFS yeniden boyutlandırma desteği, ilgili Polkit eyleminin çağıran için kullanılabilir olması ve etkilenen bir kitaplık paketi gerekir. CVE-2025-6018, etkin kullanıcı oturumu elde etmenin bir yoludur; ancak zaten etkin olan bir kullanıcı disk hizmeti yoluna bundan bağımsız olarak erişebilir.<sup>[[3]](#references)</sup>

Pasif bir inceleme için UDisks hizmet meta verilerini, `org.freedesktop.udisks2.modify-device` politikasını, `xfs_growfs` aracını ve kurulu `libbd_fs2` paketini kontrol edin. SUSE, openSUSE Leap 15.6 için `libbd_fs2` sürümü `2.26-150400.3.5.1` paketini düzeltilmiş olarak listeliyor; düzeltilmiş kesin sürüm ürüne bağlıdır. Yalnızca politika ve paketin mevcut olması, çağıranın bir aygıtı bağlayabileceğini veya yeniden boyutlandırabileceğini kanıtlamaz. Envanter çıkarırken bağlama noktalarını değiştirmekten veya D-Bus yöntemlerini çağırmaktan kaçının.<sup>[[3]](#references)</sup>

## References

- [1] [SUSE CVE-2025-6018 güvenlik duyurusu](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [SUSE pam-config güvenlik güncellemesi](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [SUSE CVE-2025-6019 güvenlik duyurusu](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
