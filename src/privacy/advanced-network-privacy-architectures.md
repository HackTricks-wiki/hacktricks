# Gelişmiş Ağ Gizliliği Mimarileri

Karmaşıklık, yalnızca belirli bir gözlemciyi veya arıza modunu ortadan kaldırıyorsa faydalıdır. Benzersiz bir tünel yığını, özel paket biçimi, nadir bir user agent veya sıkça döndürülen altyapı, binlerce kişi tarafından kullanılan standart bir yapılandırmadan daha güçlü bir fingerprint haline gelebilir.

[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md), yaygın `Pros`/`Cons`/`Procedure`/`Detection` şemasını sağlar. Bu sayfa, daha karmaşık mimarileri ve trust boundary'lerini genişletir.

Bu nedenle gelişmiş hedef **bilginin ayrıştırılmasıdır**: hiçbir sıradan bileşen aynı anda kullanıcı kimliğine, hedefe, plaintext'e ve uzun vadeli etkinlik geçmişine sahip olmamalıdır. Bu görünmezlik değildir; collusion, legal process, endpoint compromise veya uçtan uca trafik korelasyonu yine de yolu yeniden oluşturabilir.

## Mimari seçimi

| Pattern | Kazanılan özellik | Yeni trust/failure | Uygun kullanım |
|---|---|---|---|
| Standard Tor Browser | Paylaşılan browser fingerprint ve çoklu relay yolu | Düşük latency, trafik korelasyonuna olanak tanır | Genel anonim web browsing |
| Tor bridge + pluggable transport | Doğrudan Tor engellemesini/sınıflandırmasını zorlaştırır | Bridge/transport yine de tespit edilebilir; bridge source'u öğrenir | Sansür uygulanan ağlar |
| Onion service | Service IP'sini gizler; exit'i ortadan kaldırır; onion identity'yi doğrular | Onion key ve server endpoint kritik varlıklara dönüşür | Özel yayınlama, intake veya administration |
| Independent ingress + egress relays | Normalde hiçbir relay source'u ve destination'ı birlikte görmez | Operator'ler collude edebilir; timing her ikisinden geçer | Yüksek performanslı desteklenen uygulamalar |
| Oblivious HTTP | Source IP'yi encrypted stateless HTTP request'ten ayırır | Application, relay ve gateway desteği gerektirir | Session state olmadan telemetry, sorgular, gönderimler |
| VPN-only workload namespace | Kernel tarafından clear-network route bulunmaması zorunlu kılınır | VPN yine de her iki ucu görür; host/root güvenilir kalır | Yetkilendirilmiş engagement araçları ve sabit egress |
| Disposable remote browser | Destination'ı yerel browser/endpoint'ten izole eder | Workspace provider etkinliği ve login identity'yi görür | Güvenilmeyen siteler/dosyalar ve kontrollü araştırma |
| I2P internal service | Ayrı inbound/outbound overlay tünelleri; resmi exit yoktur | Daha küçük/farklı ecosystem; uzun süreli peer davranışı | Ordinary web replacement yerine I2P'ye özgü servisler |
| Mixnet/asynchronous delivery | Delay, batching ve cover traffic timing analysis'e direnç gösterir | Yüksek latency, sınırlı uygulamalar ve düşük maturity | Etkileşim gerektirmeyen mesajlar/görevler |

## Split-knowledge relays

İki operator'lü bir relay modeli, dar kapsamlı bir uygulama için tek bir VPN'den daha iyi performans gösterebilir:
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Apple Private Relay dağıtılmış bir örnektir: Apple ingress'i işletirken farklı bir içerik sağlayıcı egress'i işletir; bu nedenle normal koşullarda hiçbiri hem istemci IP'sini hem de gezinme hedefini görmez.<sup>[[1]](#references)</sup> Bu, tüm cihazlarda çalışan bir anonymity network değil, ürüne özgü bir Safari/DNS privacy service'tir ve coarse region bilgisini kasıtlı olarak korur.

Oblivious HTTP (OHTTP) daha dar bir application pattern standardize eder. Relay istemciyi ve şifrelenmiş gateway trafiğini görür; gateway HTTP mesajının şifresini çözer ancak istemciyi değil relay'i görür. RFC 9458, bunun relay/gateway desteği gerektirdiği, cookies/authentication/session state içermeyen request'ler için en uygun olduğu ve traffic analysis'i garantilerinin dışında bıraktığı konusunda uyarır.<sup>[[2]](#references)</sup>

### Design checklist

1. Korunacak application message'larını tam olarak tanımlayın; authenticated web session'larını fark ettirmeden proxy'lemeyin.
2. Mümkün olduğunda ayrı administration, credentials, logging ve legal control kullanan, bağımsız şekilde işletilen ingress ve egress kuruluşları kullanın.
3. Ingress'in okuyamaması için application request'i gateway'e şifreleyin.
4. Uygun katmanda client-derived forwarding header'larını, TLS identifier'larını ve stable per-user token'larını kaldırın.
5. Transport separation'a rağmen gateway'in request'leri yeniden ilişkilendirmesine olanak tanıyan unique key, cookie veya payload field'larından kaçının.
6. Her iki taraftaki log'ları aggregate edin, minimize edin ve süresini doldurun; collusion ve compelled-disclosure risk'ini belgeleyin.
7. Padding veya batching'i yalnızca gözden geçirilmiş bir protocol'e göre uygulayın. Homemade traffic shaping, correlation'ı durdurmadan unique signature oluşturabilir.
8. Controlled canary request'lerle test edin ve client, ingress, gateway ile target'ın her birinin ne kaydettiğini karşılaştırın.

Sıradan interactive browsing için private OHTTP proxy icat etmek yerine Tor Browser kullanın. OHTTP, desteklenen bir application transaction'ını korur; tam bir browser identity'sini değil.

## Enforce the route per workload

Yalnızca mutable host route'larına dayanan bir kill switch, DHCP renewal, sleep/wake, IPv6 değişiklikleri veya tunnel crash sırasında başarısız olabilir. Daha güçlü bir Linux pattern, bir container veya network namespace'e yalnızca bir loopback interface'i ve bir tunnel interface'i verir. WireGuard, bir interface'in physical namespace'te oluşturulup bir workload namespace'ine taşınabileceğini ve encrypted UDP socket'ini original namespace'te tutabileceğini belgeler.<sup>[[3]](#references)</sup>

### Deployment pattern

1. Bunu önce disposable/local-console bir host'ta oluşturun; namespace hataları remote access'i kaldırabilir.
2. Physical Ethernet/Wi-Fi interface'i ve DHCP/supplicant'ı **physical** namespace'e koyun.
3. Encrypted transport socket'inin physical-network access'e sahip olması için WireGuard interface'ini burada oluşturun.
4. Yalnızca WireGuard interface'ini **workload** namespace'ine taşıyın ve onu tek default route yapın.
5. Workload'a yalnızca tunnel üzerinden erişilebilen namespace-specific bir resolver verin. IPv6'yı açıkça hesaba katın.
6. Browser/tool container'ını bu namespace'te; host networking, privileged capability, shared browser directory veya personal credential agent olmadan çalıştırın.
7. Tunnel'ı durdurun ve workload'un controlled bir IPv4 veya IPv6 endpoint'ini resolve edemediğini ya da ona bağlanamadığını doğrulayın.
8. Endpoint roaming, DHCP renewal, suspend/resume ve captive-portal handling'i workload namespace'i dışında test edin.
9. Engagement accountability için namespace/tunnel configuration hash'ini ve onaylanmış egress address'i log'layın.

Bu, **route enforcement** sağlar; VPN'den veya engagement bastion'ından anonymity sağlamaz. Compromised bir host/root namespace'leri inceleyebilir veya değiştirebilir.

## Tor bridges and pluggable transports

Bridges, public olmayan Tor entry relay'leridir. Pluggable transports, basit blocking veya protocol classification'ı zorlaştırmak için first-hop trafiğini değiştirir. Entry'den sonra anonymous relay layer'ları eklemezler ve daha geniş timing correlation yapabilen bir observer'ı etkisizleştirmezler.

| Transport | First-hop approach | Practical tradeoff |
|---|---|---|
| **obfs4** | Trafiği random görünür hale getirir ve active probing'e direnç gösterir | Known bir bridge address yine de block'lanabilir |
| **Snowflake** | Bir bridge'e ulaşmak için kısa ömürlü volunteer WebRTC proxy'leri kullanır | Performance değişkendir; broker/STUN/WebRTC pattern'leri vardır |
| **WebTunnel** | Bridge trafiğini HTTPS benzeri bir WebSocket tunnel'ı içinde taşır | Erişilebilir bir web front'a bağlıdır ve yine de classify edilebilir |

Tor Project, Snowflake ve WebTunnel'ı perfect indistinguishability değil, censorship-circumvention transport'ları olarak tanımlar.<sup>[[4]](#references)</sup>

### Safe workflow

1. Tor Browser'ın direct connection'ıyla başlayın. Local observer model'inde blocking veya visibility bunu haklı çıkardığında bridge ekleyin.
2. Tor Project channel'larından edinilen built-in transport'ları veya bridge line'larını kullanın. Random transport binary'lerini veya forumlardaki public bridge listelerini indirmeyin.
3. Güvenilir şekilde bağlanan, desteklenen en az karmaşık seçeneği deneyin; neden seçildiğini kaydedin.
4. Tor Browser'ı diğer açılardan standard tutun. Bridge; custom extension'ları, account login'lerini veya unusual browser setting'lerini güvenli hale getirmez.
5. Reconnect ve clock correctness'ı test edin. Aynı local observer'a distinctive bir sequence gönderecek şekilde transport'ları tekrar tekrar değiştirmeyin.
6. Censor veya network policy değişirse yeniden değerlendirin; bazı konumlarda kullanımın kendisi sensitive veya restricted olabilir.

## Onion services as a private rendezvous

Bir onion service, introduction point'lere ve rendezvous relay'lerine outbound Tor circuit'leri kurar; bu nedenle public inbound port'a ihtiyaç duymaz ve server IP'sini onion protocol üzerinden açığa çıkarmaz. Client-to-service trafiği Tor içinde kalır ve onion address, service key'i doğrular.<sup>[[5]](#references)</sup>

Lawful bir intake portal, private repository, administrative interface veya engagement evidence drop için:

1. Application'ı dedicated bir host/VM üzerinde çalıştırın ve loopback'e veya isolated bir Unix socket'e bind edin.
2. Tor'u official repository'sinden kurun ve official v3 onion-service setup'ını izleyin; obsolete v2 instruction'larını asla kullanmayın.
3. Onion service private key'ini TLS/signing key gibi koruyun. Stable identity gerekli olmadıkça yedeklemeyin.
4. Closed group için onion-service client authorization ekleyin ve credentials'ı independently authenticated bir channel üzerinden iletin.<sup>[[6]](#references)</sup>
5. Origin'in public IP'sini veya operator account'unu açığa çıkaran third-party font, analytics, update veya webhook'ları fetch etmesini engelleyin.
6. Authentication ve authorization'ı application içinde de uygulayın; onion address'e sahip olmak access control değildir.
7. Service'i third-party telemetry eklemeden patch'leyin, rate-limit uygulayın ve monitor edin.
8. Ayrı bir test context'inden DNS, email, error page, file metadata ve response header'larının origin'i disclose etmediğini doğrulayın.
9. Red-team kullanımı için service'i, owner'ını, purpose'unu ve shutdown time'ını ROE'de listeleyin. Bunu out-of-scope C2'yi gizlemek için kullanmayın.

## Remote browser and disposable workspace

Remote browser, rendering'ı ve risky content'i local endpoint'ten uzaklaştırır ve engagement-specific bir cloud egress sunabilir. Local device'i bazı content ve persistence türlerine karşı korur; operator'ı workspace provider'a karşı anonymous hale getirmez. Örneğin AWS, disposable browser instance'ı session sonunda silinse bile portal, identity, policy, preference ve session-log data topladığını belgeler.<sup>[[7]](#references)</sup>

Her engagement için organization-controlled tek bir workspace kullanın; downloads/uploads/clipboard'i kısıtlayın, personal identity provider'larını devre dışı bırakın, fixed egress'ini approved bastion üzerinden gönderin ve evidence export sonrasında workspace'i expire edin. Provider console, IdP ve administrator'ı observer olarak değerlendirin.

## I2P and internal overlays

I2P, ayrı unidirectional inbound ve outbound tunnel'lar oluşturur ve official network-layer exit'lere sahip değildir; öncelikle I2P içindeki service'ler içindir.<sup>[[8]](#references)</sup> Public Internet'te browsing için drop-in ve daha hızlı bir yöntem değildir. Outproxy'ler bir trust point oluşturur ve official threat model daha fazla research yapılması gerektiğini açıkça belirtir; perfect anonymity iddiasında bulunmaz.

I2P'yi yalnızca her iki uç da bunu kasıtlı olarak desteklediğinde kullanın; long-lived router'ını personal application'lardan izole edin ve peer'ların/local network'lerin I2P participation'ı gözlemleyebileceğini anlayın. Kanıt olmadan hop count'larını artırmayın veya peer selection'ı ayarlamayın: unusual setting'ler performance'ı ve anonymity set'i azaltabilir.

## Correlation-resistant operations

- Unique build yerine common, supported client configuration'ı tercih edin.
- Identity'leri endpoint'te ayırın; hiçbir routing topology account, payment, recovery veya content reuse sorununu onaramaz.
- Non-interactive task'ler için manuel sleep veya fake traffic eklemek yerine reviewed asynchronous protocol/mixnet tercih edin.
- Supposedly separate identity'leri aynı physical context'ten synchronized pattern ile işletmekten kaçının.
- One-way export gate kullanın: untrusted content disposable renderer'a girsin; yalnızca reviewed, sanitized result dışarı çıksın.
- Protocol security için clock'ları doğru tutun, ancak published artifact'lardan gereksiz precise timestamp'ları kaldırın.
- Session duration'ı ve stale infrastructure'ı minimize edin; conspicuous olan ve accountability'ye zarar veren hızlı “fast-flux” rotation kullanmayın.

## Techniques that cannot use uninvolved third parties

Bunlar gerçek adversary technique'leridir; hayali veya önemsiz değildirler. Mekanikleri ve detection'ları [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) ve [APT case studies](government-and-apt-case-studies.md) içinde ele alınmıştır. Authorized bir exercise sırasında gözlemlenebilir davranışlarını owned substitute'larla yeniden oluşturun:

- Residential/mobile exit churn'ü, consent'i belirsiz market'ler yerine controlled relay pool'larıyla modelleyin;
- Open proxy'leri, compromised router'ları ve botnet'leri owned VM/router'larla modelleyin;
- Stolen cloud account'larını designated bir exercise tenant'ı ve synthetic victim identity ile modelleyin;
- Domain fronting'i unwilling bir CDN yerine owned reverse proxy üzerinde modelleyin;
- Third-party Wi-Fi'yi lab'a ait iki isolated AP ile modelleyin;
- Custom encryption, multi-VPN chain ve identifier rotation'ı, flow, account ve endpoint artifact'leri detectable kalan test hypothesis'leri olarak değerlendirin.

Authorized bir red team için trafiği daha az recognizable hale getirmeye yönelik her girişim ROE'de explicit bir detection objective olmalı, controller'ın elinde tutulan bir attribution map'e sahip olmalı ve bir stop/deconfliction mechanism içermelidir.

## Verification matrix

| Test | Expected result | Failure means |
|---|---|---|
| Tunnel/bridge stopped | Workload'un direct IPv4/IPv6/DNS path'i yok | Route enforcement incomplete |
| Target log inspected | Yalnızca planned egress/application identity görünür | Header, route veya account leak |
| Ingress log inspected | Source mevcut; clear target/request yok | Trust split ingress'te başarısız |
| Egress log inspected | Relay/request mevcut; source identity yok | Trust split egress'te başarısız |
| Onion origin scanned externally | Public origin service reachable/linked değil | Origin leak veya dual-homed |
| Disposable session ended | Instance state yok; approved evidence ayrı şekilde korunmuş | Persistence boundary başarısız |
| Controller lookup exercised | Activity hızla engagement/operator'a eşleniyor | Red-team accountability başarısız |

## References

- [1] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake and pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — How Onion Services work](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Onion Service advanced settings and client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Data encryption in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
