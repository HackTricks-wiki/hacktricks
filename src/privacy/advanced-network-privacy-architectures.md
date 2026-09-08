# Gelişmiş Network Privacy Mimarileri

{{#include ../banners/hacktricks-training.md}}

Complexity yalnızca belirli bir gözlemciyi veya failure mode'u ortadan kaldırıyorsa faydalıdır. Benzersiz bir tunnel stack'i, özel packet shape'i, nadir bir user agent veya sıkça değiştirilen infrastructure, binlerce kişi tarafından kullanılan standart bir configuration'dan daha güçlü bir fingerprint haline gelebilir.

[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md), yaygın `Pros`/`Cons`/`Procedure`/`Detection` şemasını sunar. Bu sayfa, daha karmaşık mimarileri ve trust boundary'lerini genişletir.

Bu nedenle ileri düzey hedef **bilginin ayrıştırılmasıdır**: hiçbir ordinary component aynı anda user identity'ye, destination'a, plaintext'e ve uzun vadeli activity history'ye sahip olmamalıdır. Bu görünmezlik anlamına gelmez; collusion, legal process, endpoint compromise veya end-to-end traffic correlation yine de yolu yeniden oluşturabilir.

## Mimari seçimi

| Pattern | Elde edilen özellik | Yeni trust/failure | Uygun kullanım |
|---|---|---|---|
| Standard Tor Browser | Paylaşılan browser fingerprint ve çoklu relay path | Düşük latency, traffic correlation'a olanak tanır | Genel anonymous web browsing |
| Tor bridge + pluggable transport | Doğrudan Tor blocking/classification işlemlerini zorlaştırır | Bridge/transport yine de tespit edilebilir; bridge source'u öğrenir | Censored networks |
| Onion service | Service IP'yi gizler; exit'i ortadan kaldırır; onion identity'yi doğrular | Onion key ve server endpoint kritik asset'lere dönüşür | Private publishing, intake veya administration |
| Independent ingress + egress relays | Normalde hiçbir tek relay source ve destination'ı birlikte görmez | Operator'lar collude edebilir; timing her ikisinden de geçer | High-performance supported applications |
| Oblivious HTTP | Source IP'yi encrypted stateless HTTP request'ten ayırır | Application, relay ve gateway desteği gerektirir | Session state olmadan telemetry, queries ve submissions |
| VPN-only workload namespace | Kernel tarafından clear-network route bulunmamasını zorunlu kılar | VPN yine her iki ucu görür; host/root hâlâ trusted durumdadır | Authorized engagement tools ve fixed egress |
| Disposable remote browser | Destination'ı local browser/endpoint'ten izole eder | Workspace provider activity'yi ve login identity'yi görür | Untrusted sites/files ve kontrollü research |
| I2P internal service | Ayrı inbound/outbound overlay tunnel'ları; official exit yoktur | Daha küçük/farklı ecosystem; uzun süre çalışan peer davranışı | I2P'ye özgü services, ordinary web replacement değil |
| Mixnet/asynchronous delivery | Delay, batching ve cover traffic timing analysis'e direnç gösterir | Yüksek latency, sınırlı applications ve maturity | Interaction gerektirmeyen messages/tasks |

## Split-knowledge relays

İki operator'lü relay pattern'i, dar kapsamlı bir application için tek bir VPN'den daha iyi performans gösterebilir:
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
Apple Private Relay dağıtılmış bir örnektir: Apple ingress işlemini yürütürken farklı bir content provider egress işlemini yürütür; bu nedenle normalde hiçbiri hem istemci IP adresini hem de browsing hedefini görmez.<sup>[[1]](#references)</sup> Bu, tüm cihazlar için bir anonymity network değil, ürüne özgü bir Safari/DNS privacy service'tir ve coarse region bilgisini kasıtlı olarak korur.

Oblivious HTTP (OHTTP) daha dar bir application pattern'i standartlaştırır. Relay istemciyi ve şifrelenmiş gateway trafiğini görür; gateway HTTP mesajının şifresini çözer ancak istemciyi değil relay'i görür. RFC 9458, bunun relay/gateway desteği gerektirdiği, cookie/authentication/session state içermeyen request'ler için en uygun olduğu ve traffic analysis'i garantilerinin dışında bıraktığı konusunda uyarır.<sup>[[2]](#references)</sup>

### Tasarım kontrol listesi

1. Korunacak kesin application message'larını tanımlayın; authenticated web session'larını sessizce proxy'lemeyin.
2. Mümkün olduğunda ayrı administration, credentials, logging ve legal control kullanan, bağımsız şekilde işletilen ingress ve egress kuruluşları kullanın.
3. Ingress'in okuyamaması için application request'i gateway'e şifreleyin.
4. Uygun layer'da client-derived forwarding header'larını, TLS identifier'larını ve stable per-user token'larını kaldırın.
5. Transport separation'a rağmen gateway'in request'leri yeniden ilişkilendirmesine olanak veren unique key, cookie veya payload field'larından kaçının.
6. Her iki taraftaki log'ları aggregate edin, minimize edin ve expire edin; collusion ve compelled-disclosure risk'ini belgeleyin.
7. Yalnızca incelenmiş bir protocol'e göre padding veya batching uygulayın. Homemade traffic shaping, correlation'ı durdurmadan unique bir signature oluşturabilir.
8. Controlled canary request'lerle test yapın ve client, ingress, gateway ve target'ın her birinin ne kaydettiğini karşılaştırın.

Sıradan interactive browsing için private bir OHTTP proxy icat etmek yerine Tor Browser kullanın. OHTTP, desteklenen bir application transaction'ını korur; tam bir browser identity'sini değil.

## Workload başına route'u zorunlu kılma

Yalnızca mutable host route'larına dayanan bir kill switch, DHCP renewal, sleep/wake, IPv6 değişiklikleri veya tunnel crash sırasında başarısız olabilir. Daha güçlü bir Linux pattern'i, bir container'a veya network namespace'e yalnızca loopback interface'i ve tunnel interface'i verir. WireGuard, bir interface'in physical namespace'te oluşturulabileceğini, bir workload namespace'e taşınabileceğini ve encrypted UDP socket'ini original namespace'te koruyabileceğini belgeler.<sup>[[3]](#references)</sup>

### Deployment pattern'i

1. Bunu önce disposable/local-console bir host üzerinde oluşturun; namespace hataları remote access'i kaldırabilir.
2. Physical Ethernet/Wi-Fi interface'ini ve DHCP/supplicant'ı bir **physical** namespace'e yerleştirin.
3. Encrypted transport socket'inin physical-network access'e sahip olması için WireGuard interface'ini burada oluşturun.
4. Yalnızca WireGuard interface'ini **workload** namespace'e taşıyın ve bunu tek default route yapın.
5. Workload'a yalnızca tunnel üzerinden erişilebilen namespace-specific bir resolver verin. IPv6'yı açıkça hesaba katın.
6. Browser/tool container'ını bu namespace'te host networking, privileged capability, shared browser directory veya personal credential agent olmadan çalıştırın.
7. Tunnel'ı durdurun ve workload'un controlled bir IPv4 veya IPv6 endpoint'ini resolve edemediğini ya da ona bağlanamadığını doğrulayın.
8. Endpoint roaming, DHCP renewal, suspend/resume ve captive-portal handling işlemlerini workload namespace'in dışında test edin.
9. Engagement accountability için namespace/tunnel configuration hash'ini ve approved egress address'i log'layın.

Bu, VPN veya engagement bastion'ından anonymity değil, **route enforcement** sağlar. Compromised bir host/root namespace'leri inceleyebilir veya değiştirebilir.

## Tor bridges ve pluggable transports

Bridges, public olmayan Tor entry relay'leridir. Pluggable transports, basit blocking veya protocol classification'ı zorlaştırmak için first-hop trafiğini değiştirir. Entry'den sonra anonymous relay layer'ları eklemez ve daha geniş timing correlation yapabilen bir observer'ı etkisizleştirmez.

| Transport | First-hop yaklaşımı | Pratik tradeoff |
|---|---|---|
| **obfs4** | Trafiği random görünecek şekilde biçimlendirir ve active probing'e karşı koyar | Bilinen bir bridge address yine de block edilebilir |
| **Snowflake** | Bir bridge'e ulaşmak için kısa ömürlü volunteer WebRTC proxy'leri kullanır | Performance değişkendir; broker/STUN/WebRTC pattern'leri vardır |
| **WebTunnel** | Bridge trafiğini HTTPS benzeri bir WebSocket tunnel'ı içinde taşır | Ulaşılabilir bir web front'a bağlıdır ve yine de classify edilebilir |

Tor Project, Snowflake ve WebTunnel'ı perfect indistinguishability değil, censorship-circumvention transport'ları olarak tanımlar.<sup>[[4]](#references)</sup>

### Güvenli workflow

1. Tor Browser'ın direct connection'ıyla başlayın. Local observer model'inde blocking veya visibility bunu haklı çıkardığında bridge ekleyin.
2. Tor Project channel'larından edinilen built-in transport'ları veya bridge line'larını kullanın. Forum'lardan random transport binary'leri ya da public bridge list'leri indirmeyin.
3. Güvenilir şekilde bağlanan en az complex supported option'ı deneyin; neden seçildiğini kaydedin.
4. Tor Browser'ı diğer açılardan standard tutun. Bridge, custom extension'ları, account login'lerini veya unusual browser setting'lerini güvenli hale getirmez.
5. Reconnect ve clock correctness'ı test edin. Aynı local observer'a distinctive bir sequence gönderecek şekilde transport'ları tekrar tekrar değiştirmeyin.
6. Censor veya network policy değişirse yeniden değerlendirin; bazı konumlarda kullanımın kendisi sensitive veya restricted olabilir.

## Private rendezvous olarak Onion services

Bir onion service, introduction point'lere ve rendezvous relay'lere outbound Tor circuit'ları oluşturur; bu nedenle public inbound port'a ihtiyaç duymaz ve onion protocol üzerinden server IP'sini açığa çıkarmaz. Client-to-service trafiği Tor içinde kalır ve onion address service key'i authenticate eder.<sup>[[5]](#references)</sup>

Lawful bir intake portal, private repository, administrative interface veya engagement evidence drop için:

1. Application'ı dedicated bir host/VM üzerinde çalıştırın ve loopback'e veya isolated bir Unix socket'e bind edin.
2. Tor'u official repository'den kurun ve official v3 onion-service setup'ını izleyin; obsolete v2 instruction'larını asla kullanmayın.
3. Onion service private key'ini TLS/signing key gibi koruyun. Stable identity gerekli değilse yedeklemeyin.
4. Closed group için onion-service client authorization ekleyin ve credential'ları independently authenticated bir channel üzerinden teslim edin.<sup>[[6]](#references)</sup>
5. Origin'in public IP'sini veya operator account'unu açığa çıkaran third-party font, analytics, update veya webhook'ları fetch etmesini engelleyin.
6. Authentication ve authorization'ı application'a da ekleyin; onion address'e sahip olmak access control değildir.
7. Third-party telemetry gömmeksizin service'i patch edin, rate-limit uygulayın ve monitor edin.
8. Ayrı bir test context'inden DNS, email, error page, file metadata ve response header'larının origin'i disclose etmediğini doğrulayın.
9. Red-team kullanımı için service'i, owner'ını, amacını ve shutdown time'ını ROE'de listeleyin. Bunu out-of-scope C2'yi gizlemek için kullanmayın.

## Remote browser ve disposable workspace

Remote browser, rendering'i ve riskli content'i local endpoint'ten uzaklaştırır ve engagement-specific bir cloud egress sunabilir. Local device'ı bazı content ve persistence türlerinden korur; operator'ı workspace provider'a karşı anonymous hale getirmez. Örneğin AWS, disposable browser instance session sonunda atılsa bile portal, identity, policy, preference ve session-log data topladığını belgeler.<sup>[[7]](#references)</sup>

Her engagement için organization-controlled tek bir workspace kullanın; download/upload/clipboard işlemlerini kısıtlayın, personal identity provider'larını devre dışı bırakın, fixed egress'ini approved bastion üzerinden gönderin ve evidence export sonrasında workspace'i expire edin. Provider console, IdP ve administrator'ı observer olarak kabul edin.

## I2P ve internal overlay'ler

I2P, ayrı unidirectional inbound ve outbound tunnel'lar oluşturur ve official network-layer exit'lere sahip değildir; temel olarak I2P içindeki service'ler içindir.<sup>[[8]](#references)</sup> Public Internet'te browsing yapmak için drop-in ve daha hızlı bir yöntem değildir. Outproxy'ler bir trust point oluşturur ve official threat model daha fazla research gerektiğini açıkça belirtir; perfect anonymity iddiasında bulunmaz.

I2P'yi yalnızca her iki uç da bunu kasıtlı olarak desteklediğinde kullanın, long-lived router'ını personal application'larından izole edin ve peer'ların/local network'lerin I2P participation'ını gözlemleyebileceğini anlayın. Kanıt olmadan hop count'u artırmayın veya peer selection'ı ayarlamayın: unusual setting'ler performance'ı ve anonymity set'i azaltabilir.

## Correlation-resistant operations

- Unique bir build yerine common ve supported bir client configuration'ı tercih edin.
- Identity'leri endpoint'te ayırın; hiçbir routing topology'si account, payment, recovery veya content reuse sorunlarını düzeltemez.
- Non-interactive task'ler için manually sleep veya fake traffic eklemek yerine incelenmiş bir asynchronous protocol/mixnet tercih edin.
- Sözde ayrı identity'leri aynı physical context'ten synchronized pattern ile işletmekten kaçının.
- One-way export gate kullanın: untrusted content disposable bir renderer'a girer; yalnızca incelenmiş ve sanitized bir result çıkar.
- Protocol security için clock'ları doğru tutun; ancak published artifact'lardan gereksiz precise timestamp'leri kaldırın.
- Session duration'ı ve stale infrastructure'ı minimize edin; conspicuous olan ve accountability'ye zarar veren hızlı “fast-flux” rotation kullanmayın.

## İlgisiz üçüncü tarafları kullanamayan teknikler

Bunlar gerçek adversary technique'lerdir; hayali veya önemsiz değildir. Mekanikleri ve detection yöntemleri [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) ve [APT case studies](government-and-apt-case-studies.md) içinde ele alınır. Authorized exercise sırasında gözlemlenebilir davranışlarını owned substitute'larla yeniden oluşturun:

- residential/mobile exit churn'ü, consent'i belirsiz market'ler yerine controlled relay pool'larıyla modelleyin;
- open proxy'leri, compromised router'ları ve botnet'leri owned VM/router'larla modelleyin;
- stolen cloud account'larını designated bir exercise tenant ve synthetic victim identity ile modelleyin;
- domain fronting'i unwilling bir CDN yerine owned reverse proxy üzerinde modelleyin;
- third-party Wi-Fi'yi lab'a ait iki isolated AP ile modelleyin;
- custom encryption, multi-VPN chain ve identifier rotation'ı, flow, account ve endpoint artifact'leri detectable kalacak test hypothesis'leri olarak ele alın.

Authorized bir red team için trafiği daha az recognizable hale getirme girişimi ROE'de explicit bir detection objective olmalı, controller'ın tuttuğu bir attribution map'e sahip olmalı ve bir stop/deconfliction mechanism içermelidir.

## Verification matrix

| Test | Beklenen sonuç | Failure anlamı |
|---|---|---|
| Tunnel/bridge durduruldu | Workload'un doğrudan IPv4/IPv6/DNS path'i yok | Route enforcement eksik |
| Target log'u incelendi | Yalnızca planlanan egress/application identity görünüyor | Header, route veya account leak |
| Ingress log'u incelendi | Source mevcut; clear target/request yok | Trust split ingress'te başarısız |
| Egress log'u incelendi | Relay/request mevcut; source identity yok | Trust split egress'te başarısız |
| Onion origin dışarıdan tarandı | Public origin service'e erişilemiyor/bağlantı kurulamıyor | Origin leak oldu veya dual-homed |
| Disposable session sona erdi | Instance state yok; approved evidence ayrı olarak korundu | Persistence boundary başarısız |
| Controller lookup uygulandı | Activity hızlı biçimde engagement/operator'a eşlendi | Red-team accountability başarısız |

## References

- [1] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake ve pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Onion Services nasıl çalışır](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Onion Service gelişmiş ayarları ve client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Amazon WorkSpaces Secure Browser'da data encryption](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
