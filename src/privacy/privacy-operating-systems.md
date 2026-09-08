# Privacy İşletim Sistemleri

{{#include ../banners/hacktricks-training.md}}

Privacy odaklı işletim sistemleri routing ve persistence hatalarını azaltır, ancak hiçbiri kimlik belirleyici davranışları veya compromise edilmiş donanımı telafi edemez.

## İzolasyon modelini seçin

| Sistem | En uygun kullanım | Persistence | Network enforcement | Ana ödünleşim |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | Ara sıra anonim web browsing | Browser state normalde session kapsamındadır | Yalnızca browser trafiği | Diğer uygulamalar ve host Tor dışında kalır |
| **Tails** | Taşınabilir, amnesic, tek amaçlı oturumlar | İsteğe bağlı şifreli Persistent Storage | Internet trafiği Tor üzerinden zorlanır | Yeniden başlatma/workflow zorluğu; firmware/donanım güveni |
| **Whonix** | Zorunlu Tor routing gerektiren kalıcı uygulamalar | Persistent VM'ler | Gateway/workstation ayrımı | Host/hypervisor ve identity mixing devam eder |
| **Qubes-Whonix** | İleri düzey kullanıcılar için güçlü compartment separation | Her qube için ayrı | Özel network qube'ları ve Whonix | Donanım gereksinimleri ve operasyonel karmaşıklık |

## Tails

Tails, removable media üzerinden bağımsız olarak boot edilir, Internet trafiğini Tor üzerinden yönlendirir ve yerel state'i minimumda bırakacak şekilde tasarlanmıştır. Kendi uyarıları, compromise edilmiş bir BIOS/firmware/donanıma, kimlik belirleyici ifşalara, dosya metadata'sına veya her iki ucu korelasyonlandırabilen güçlü bir gözlemciye karşı koruma sağlayamayacağını vurgular.<sup>[[1]](#references)</sup>

### Tek amaçlı Tails workflow'u

1. Tails'i resmi siteden güvenilir ve güncel bir bilgisayarla indirin ve resmi doğrulama/kurulum sürecini izleyin.
2. Yalnızca Tails'i boot etmek için desteklenen bir USB drive kullanın; bunu genel amaçlı file-transfer drive olarak da kullanmayın.
3. Fiziksel olarak kontrol ettiğiniz hardware üzerinde boot edin. Bir live OS, hardware keylogger'ı veya kötü amaçlı firmware'i etkisiz hale getiremez.
4. Workflow gerçekten gerektirmiyorsa Persistent Storage'ı devre dışı bırakın. Etkinleştirilmişse yalnızca gerekli kategorileri persist edin ve güçlü bir passphrase kullanın.
5. Yasal bir network'e bağlanın. Captive portal kaçınılmazsa Tails' Unsafe Browser'ını yalnızca portal için kullanın, gereksiz hiçbir identity bilgisini paylaşmayın, hemen kapatın ve hassas herhangi bir aktiviteden önce Tor'a bağlanın.<sup>[[2]](#references)</sup>
6. Doğrudan Tor görünürlüğü veya engelleme önemliyse bir Tor bridge yapılandırın.
7. Her session için **tek bir bağlamsal identity/amaç** kullanın. Tails, birbirine bağlanmaması gereken aktiviteler arasında restart yapılmasını önerir.<sup>[[1]](#references)</sup>
8. Dosyaları yayınlamadan önce inceleyin ve sanitize edin. İndirilen active dokümanları, amaçlanan context'i bypass edebilecek bir application içinde açmayın.
9. İşiniz bittiğinde tamamen shutdown edin ve USB'yi fiziksel olarak güvenli tutun.

## Whonix

Whonix, Tor routing yapan bir **Gateway** ile uygulamaları external IP'yi doğrudan öğrenemeyen bir **Workstation**'ı birbirinden ayırır. Bu, proxy/DNS hatalarını anlamlı ölçüde azaltır; ancak host, hypervisor, davranışlar ve dokümanlar yine de identity'yi açığa çıkarabilir. Whonix, bir Workstation'ı birden fazla identity için kullanmaya veya anonymous ve non-anonymous aktiviteleri birleştirmeye karşı açıkça uyarır.<sup>[[3]](#references)</sup>

### Compartment workflow'u

1. Whonix image'ını ve virtualization platform'unu resmi kaynaklardan doğrulayın.
2. Kullanmadan önce host'u, hypervisor'ı, Gateway'i ve Workstation'ı patch edin.
3. Her identity veya engagement için yeni bir Workstation clone'layın; identity içeren state tanıtıldıktan sonra bir VM'i asla clone'lamayın.
4. Personal account'ları, host shared folder'larını, clipboard synchronization'ı, USB cihazlarını ve time/location verilerini Workstation'dan uzak tutun.
5. Snapshot'ları recovery için kullanın; bunları backup veya identity separation yerine kullanmayın.
6. Gateway durdurulduğunda Workstation'ın Internet'e erişemediğini doğrulayın.
7. Özellikle riskli dosyalar için disposable bir VM/qube kullanın ve yalnızca sanitize edilmiş sonucu dışarı aktarın.

## Qubes OS ve Qubes-Whonix

Qubes, Xen-backed qube'larla compartmentalization kullanarak security uygular. Tasarımı, bir domain'deki compromise'ın otomatik olarak diğerlerine ulaşmasını sınırlar; ancak **aynı** qube içindeki uygulamalar birbirlerinden izole değildir.<sup>[[4]](#references)</sup> Disposable qube'lar güvenilmeyen siteler, dosyalar ve cihazlar için fresh state sağlar.<sup>[[5]](#references)</sup>

Pratik bir yerleşim:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
Kurallar:

- Her qube'a bir güven düzeyi ve kimlik amacı verin.
- Secret'ları çevrimdışı bir vault qube'da tutun ve qubeler arası açık kopyalama/dosya işlemleri kullanın.
- İstenmeyen dosyaları ve linkleri disposable'larda açın.
- Yalnızca amaçlanan qube'ları Whonix veya özel bir VPN qube üzerinden yönlendirin.
- Pencereleri belirgin şekilde etiketleyin ve hassas çalışmalar sırasında ilgisiz qube'ları durdurun.
- İki qube'un aynı hesapları, içerikleri, zamanlamaları veya ödemeleri paylaşmaları hâlinde correlation'ı önleyeceğini varsaymayın.

## Verification and maintenance

- Installer signature'larını/checksum'larını resmi talimatlar üzerinden doğrulayın.
- Önce template'leri patch'leyin, ardından bunlara bağlı qube'ları/VM'leri yeniden başlatın.
- Network-deny davranışını, DNS'i, IPv6'yı, saati, clipboard'ı, paylaşılan dizinleri ve USB atamasını doğrulayın.
- Persistent Storage'ı ve eski kimlik bilgileri içeren veriler için VM snapshot'larını inceleyin.
- Seed'lerin/anahtarların şifrelenmiş offline backup'larını tutun ve geri yüklemeyi izole bir ortamda test edin.
- Şüpheli compromise sonrasında bir compartment'ı yeniden oluşturun; egress IP'sini değiştirmek yeterli değildir.

## References

- [1] [Tails — Uyarılar: Tails güvenlidir ancak sihirli değildir](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Captive portal kullanarak bir ağa giriş yapma](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix ve Tor sınırlamaları](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Security design goals](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Disposable'lar nasıl kullanılır](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
{{#include ../banners/hacktricks-training.md}}
