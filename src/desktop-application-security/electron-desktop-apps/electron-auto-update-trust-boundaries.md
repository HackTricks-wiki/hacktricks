# Electron Otomatik Güncelleme Güven Sınırları

{{#include ../../banners/hacktricks-training.md}}

## Electron otomatik güncelleme saldırı yüzeyi

Bir updater'ı uzaktan kod çalıştırma sınırı olarak ele alın: çalıştırılabilir içerik alır, bu içeriğin daha yeni ve güvenilir olup olmadığına karar verir, yerel olarak hazırlar ve bir installer'a teslim eder. Yalnızca son `.app` dosyasının imzalı olup olmadığını değil; sürüm dizini, sürüm başına metadata, artifact, detached signature'lar, gömülü doğrulama anahtarı, cache, geçici yol ve installer dahil tüm güven grafiğini inceleyin.<sup>[[1]](#references)[[2]](#references)</sup>

### Yüksek değerli testler

- **Rollback/replay:** Daha önce geçerli olan bir manifest'i ve hâlâ imzalı artifact'ini yeniden oynatın. İmza, girdisini doğrular ancak güncellik sağlamaz; kimliği doğrulanmış bir kurtarma politikası rollback'e açıkça izin vermediği sürece istemci, kalıcı monoton tabanın altındaki sürümleri reddetmelidir.<sup>[[2]](#references)</sup>
- **Metadata/artifact değiştirme:** Sürümü, URL'yi, beklenen hash'i, artifact'i ve detached signature'ı birbirinden bağımsız olarak değiştirin. Ayrıca bir sürümden alınmış geçerli bir artifact/imza çiftini başka bir sürümün metadata'sıyla eşleştirmeyi deneyin. Sürüm metadata'sı imzasızsa TLS veya imzalı bir son çalıştırılabilir dosya, ele geçirilmiş bir origin/CDN'nin seçim mantığını değiştirmesini engellemez.<sup>[[1]](#references)[[2]](#references)</sup>
- **İmzalı kanal karışıklığı:** Üretim feed'i üzerinden meşru biçimde imzalanmış bir alpha, beta, development veya debug build sunun. Ortamlar arasında aynı anahtarı ve politikayı yeniden kullanmak, artifact'in yalnızca imzalayanı kontrol eden bir denetimden geçmesini sağlar; üretim kimliği/kanalı, kimliği doğrulanmış politikanın parçası olmalı veya ayrı bir trust root kullanılmalıdır.<sup>[[2]](#references)</sup>
- **Geçici dosyada TOCTOU:** Doğrulamanın bir pathname açıp açmadığını ve kurulumun daha sonra aynı pathname'i yeniden açıp açmadığını belirleyin. Yerel bir saldırgan bu işlemler arasında hazırlanan nesneyi yeniden adlandırabilir, değiştirebilir veya yönlendirebilirse installer, hiç doğrulanmamış baytları kullanabilir. `0700` modundaki bir hazırlama dizini erişimi sınırlar ancak iki işlemi atomik hâle getirmez.<sup>[[2]](#references)</sup>

Statik ve çalışma zamanı triyajı bu sınırları hızla bulabilir.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

Yetkili bir test sırasında update check'i araya girerek yakalayın, her yanıtı arşivleyin ve her seferinde tek bir alanı değiştirin. Ardından staging dizininin sahipliğini/izinlerini inceleyin ve indirme işleminden kuruluma kadar dosya açma işlemlerini izleyin. macOS'ta akış ayrıcalıklı bir yardımcı programa ulaşıyorsa [installer trust-boundary testing](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md) ile devam edin ve “imzalı” olmayı eksiksiz bir kimlik doğrulaması olarak değerlendirmek yerine [code-signing weaknesses](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md) konusunu inceleyin.<sup>[[2]](#references)</sup>

### Beklenen bağlama ve politika

Savunulabilir bir tasarım, hem seçim meta verilerinin hem de artifact baytlarının kimliğini doğrular. SafeUpdater referans tasarımı; gömülü bir Ed25519 public key, imzalı manifestler ve artifact'lar, `SHA-256(file)` ile sürümden türetilen imzalı bir mesaj ve imzalı meta verilerde tutulan bir SHA-512 artifact özeti kullanıldığını gösterir; bu tasarımın üretime hazır bir paket değil, açıkça bir araştırma referansı olduğu belirtilmiştir.<sup>[[1]](#references)[[2]](#references)</sup>

Hedefin ayrıca aşağıdaki özellikleri sağladığını doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>

- artifact özetini kanonik sürümüne ve yayın ortamına bağlayan, belirsizliğe yer vermeyen imzalı bir gösterim kullanır;
- downgrade işlemini varsayılan olarak devre dışı bırakır ve yetkili rollback için kabul edilen minimum sürümü uygular;
- üretim ortamını üretim dışı ortamlardan farklı anahtarlar/kanallar veya kimliği doğrulanmış yayın politikası verileriyle ayırır; ve
- aynı pathname'i yeniden çözümlemek yerine, önceden doğrulanmış açık dosyayı (veya eşdeğer bir değişmez handle/nesneyi) yükler.

## References

- [1] [Doyensec ElectronSafeUpdater referans uygulaması](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater: Güvenli bir Electron Otomatik Güncelleme Mekanizması Tasarlama](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
