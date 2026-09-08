# Privacy Operating Systems

Privacy odaklı işletim sistemleri routing ve persistence hatalarını azaltır, ancak hiçbiri kimlik belirleyici davranışları veya güvenliği ihlal edilmiş donanımı telafi edemez.

## İzolasyon modelini seçin

| Sistem | En uygun kullanım | Persistence | Network enforcement | Temel ödünleşim |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | Ara sıra anonim web browsing | Browser state normalde session-scoped | Yalnızca browser trafiği | Diğer uygulamalar ve host Tor dışında kalır |
| **Tails** | Taşınabilir, amnesic, tek amaçlı session'lar | İsteğe bağlı şifreli Persistent Storage | Internet trafiği Tor üzerinden zorlanır | Yeniden başlatma/workflow zorluğu; firmware/donanım güveni |
| **Whonix** | Zorunlu Tor routing gerektiren kalıcı uygulamalar | Persistent VM'ler | Gateway/Workstation ayrımı | Host/hypervisor ve identity mixing devam eder |
| **Qubes-Whonix** | İleri düzey kullanıcılar için güçlü compartment separation | Qube başına | Özel network qube'ları ve Whonix | Donanım gereksinimleri ve operasyonel karmaşıklık |

## Tails

Tails, removable media üzerinden bağımsız olarak boot eder, Internet trafiğini Tor üzerinden yönlendirir ve minimum miktarda yerel state bırakacak şekilde tasarlanmıştır. Kendi uyarıları, güvenliği ihlal edilmiş bir BIOS/firmware/donanıma, kimlik açığa çıkaran paylaşımlara, file metadata'sına veya her iki ucu ilişkilendiren güçlü bir gözlemciye karşı koruma sağlayamayacağını vurgular.<sup>[[1]](#references)</sup>

### Tek amaçlı Tails workflow'u

1. Tails'i resmi siteden güvenilir ve güncel bir bilgisayarla indirin ve resmi doğrulama/kurulum sürecini izleyin.
2. Desteklenen bir USB drive'ı yalnızca Tails'i boot etmek için kullanın; aynı drive'ı genel file-transfer drive'ı olarak da kullanmayın.
3. Fiziksel olarak kontrol ettiğiniz donanımda boot edin. Live OS, hardware keylogger'ı veya kötü amaçlı firmware'i etkisiz hale getiremez.
4. Workflow gerçekten gerektirmedikçe Persistent Storage'ı devre dışı bırakın. Etkinse yalnızca gerekli kategorileri persist edin ve güçlü bir passphrase kullanın.
5. Hukuka uygun bir network'e bağlanın. Captive portal kaçınılmazsa Tails' Unsafe Browser'ını yalnızca portal için kullanın, gereksiz kimlik bilgilerini açıklamayın, hemen kapatın ve herhangi bir hassas faaliyetten önce Tor'a bağlanın.<sup>[[2]](#references)</sup>
6. Doğrudan Tor görünürlüğü veya engelleme önemliyse bir Tor bridge yapılandırın.
7. Her session için **tek bir bağlamsal identity/purpose** kullanın. Tails, ilişkilendirilmemesi gereken faaliyetler arasında restart yapılmasını önerir.<sup>[[1]](#references)</sup>
8. File'ları yayınlamadan önce inceleyin ve sanitize edin. İndirilen active document'ları amaçlanan context'i bypass edebilecek bir uygulamada açmayın.
9. İşiniz bittiğinde tamamen shut down edin ve USB'yi fiziksel olarak güvenli tutun.

## Whonix

Whonix, Tor routing yapan bir **Gateway** ile uygulamaları external IP'yi doğrudan öğrenemeyen bir **Workstation**'ı birbirinden ayırır. Bu, proxy/DNS hatalarını anlamlı ölçüde azaltır, ancak host, hypervisor, davranışlar ve document'lar yine de kimliği açığa çıkarabilir. Whonix, bir Workstation'ı birden fazla identity için kullanmaya veya anonim ve anonim olmayan faaliyetleri birleştirmeye karşı açıkça uyarır.<sup>[[3]](#references)</sup>

### Compartment workflow'u

1. Whonix image'ını ve virtualization platform'unu resmi kaynaklardan doğrulayın.
2. Kullanmadan önce host'u, hypervisor'ı, Gateway'i ve Workstation'ı patch edin.
3. Her identity veya engagement için fresh bir Workstation clone'layın; identity taşıyan state oluşturulduktan sonra bir VM'i asla clone'lamayın.
4. Personal account'ları, host shared folder'larını, clipboard synchronization'ı, USB device'larını ve time/location data'sını Workstation'dan uzak tutun.
5. Snapshot'ları recovery için kullanın; bunları backup veya identity separation yerine koymayın.
6. Gateway durdurulduğunda Workstation'ın Internet'e erişemediğini doğrulayın.
7. Özellikle riskli file'lar için disposable bir VM/qube kullanın ve yalnızca sanitize edilmiş sonucu export edin.

## Qubes OS ve Qubes-Whonix

Qubes, Xen-backed qube'larla compartmentalization yoluyla security uygular. Tasarımı, bir domain'deki compromise'ın otomatik olarak diğerlerine ulaşmasını sınırlar, ancak **aynı** qube içindeki uygulamalar birbirlerinden izole değildir.<sup>[[4]](#references)</sup> Disposable qube'lar güvenilmeyen site'lar, file'lar ve device'lar için fresh state sağlar.<sup>[[5]](#references)</sup>

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
- Sırları offline vault qube'da tutun ve qube'lar arası açık copy/file işlemleri kullanın.
- İstenmeyen dosyaları ve linkleri disposables içinde açın.
- Yalnızca amaçlanan qube'ları Whonix veya özel bir VPN qube üzerinden yönlendirin.
- Pencereleri belirgin şekilde etiketleyin ve hassas çalışma sırasında ilgisiz qube'ları durdurun.
- İki qube'ın aynı hesapları, içeriği, zamanlamaları veya ödemeleri paylaşmaları hâlinde correlation'ı önlediğini varsaymayın.

## Verification and maintenance

- Installer imzalarını/checksum'larını resmi talimatlar üzerinden doğrulayın.
- Önce template'leri patch'leyin, ardından bağımlı qube'ları/VM'leri yeniden başlatın.
- Network-deny davranışını, DNS'i, IPv6'yı, saati, clipboard'ı, paylaşılan dizinleri ve USB atamasını doğrulayın.
- Eski kimlik verileri için Persistent Storage'ı ve VM snapshot'larını inceleyin.
- Seed'lerin/key'lerin şifrelenmiş offline yedeklerini tutun ve geri yüklemeyi izole bir ortamda test edin.
- Şüpheli compromise sonrasında compartment'ı yeniden oluşturun; egress IP'sini değiştirmek yeterli değildir.

## References

- [1] [Tails — Uyarılar: Tails güvenlidir ancak sihirli değildir](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Captive portal kullanarak bir network'e giriş yapma](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix ve Tor sınırlamaları](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Security design goals](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Disposables kullanma](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
