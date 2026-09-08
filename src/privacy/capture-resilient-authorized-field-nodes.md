# Ele Geçirmeye Dayanıklı Yetkili Saha Düğümleri

{{#include ../banners/hacktricks-training.md}}

Sahaya yerleştirilen bir Raspberry Pi, mini-PC, travel router veya cellular appliance, yetkili bir red team'e kalıcı bir erişim noktası sağlayabilir. Ancak aynı zamanda keşfedilme, çalınma ve attribution açısından da olası bir noktadır. Bu nedenle doğru tasarım hedefi, izlenemez bir implant değil, **saha düğümünde çok az yetkiyle istikrarlı ve kontrollü erişim** sağlamaktır.

Bu kılavuz yalnızca site sahibinin yazılı yetkilendirmesiyle yerleştirilen ekipmanlar için geçerlidir. Bir coffee shop, komşu, otel veya ortak kullanılan bir bina, yalnızca ağına erişilebildiği için kapsam dahilinde değildir. Donanımı rıza göstermeyen bir mekânda gizlemeyin, captive portal'ı bypass etmeyin, başka bir kişinin kimlik bilgilerini kullanmayın, monitoring faaliyetlerini engellemeyin veya keşfedildikten sonra kanıtları silmeye çalışmayın.

{% hint style="warning" %}
Güvenilir bir “geride iz bırakmama” ayarı yoktur. Radio association, DHCP/NAT, carrier, kamera, satın alma, cihaz, provider, controller ve hedef kayıtları cihazdan sonra da varlığını sürdürebilir. Sorumlu bir red team bunun yerine düğümden **kişisel ve ilgisiz secret'ları** kaldırır, korunan controller tarafı attribution bilgisini saklar ve ele geçirilmeyi kontrol altına almayı kolaylaştırır.
{% endhint %}

## Artıları ve eksileri

**Artıları:** gerçekçi bir internal veya hedefe yakın kaynak; istikrarlı yüksek hızlı testing; NAC, egress, fiziksel envanter ve SOC kapsamını doğrulama; operator adres değişiklikleri boyunca çalışmaya devam edebilme; bounded access merkezi olarak revoke edilebilir.

**Eksileri:** fiziksel yerleştirme güçlü kanıt oluşturur; kayıp, device credential'larını, network profile'larını ve toplanan verileri açığa çıkarabilir; tekrarlanan control traffic tespit edilebilir; güç, portal'lar ve radio değişiklikleri güvenilirliği azaltır; geniş bir tunnel kontrolsüz bir pivot'a dönüşebilir.

## Threat model ve tasarım değişmezleri

Bir bulucunun storage'ı çıkarabileceğini, firmware'ı inceleyebileceğini, software tarafından tutulan her secret'ı kopyalayabileceğini, sonraki network behavior'ı gözlemleyebileceğini ve cihazı client'a veya law enforcement'a teslim edebileceğini varsayın. Full-disk encryption, yalnızca belirtilen threat model kapsamında kapalı bir cihazı korur; çalışan ve kilidi açılmış bir node ile memory'ye bırakılmış key'ler farklı durumlardır.

| Değişmez | Pratik sonuç |
|---|---|
| Operator ile node arasında doğrudan identity yok | Operator organization gateway'e sign in olur; node farklı bir device identity'ye sahiptir |
| Kişisel workstation materyali yok | Kişisel SSH key'i, browser profile'ı, email, password manager, phone pairing veya cloud CLI cache'i yoktur |
| Controller master secret yok | Tek bir node başka bir node'u enroll edemez, policy'yi değiştiremez veya diğer engagement'ların şifresini çözemez |
| Yalnızca outbound ve dar kapsamlı | Field network hiçbir management listener kabul etmez; node yalnızca adı belirtilmiş rendezvous/update/time service'larına erişir |
| Kısa ömürlü, kapsamı belirlenmiş authority | Her credential tek bir device, audience, service ve expiry ile tek bir immediate revocation path'e sahiptir |
| Minimum yerel veri | Sonuçlar controller'a stream edilir; cache'ler encrypted durumdadır, size/TTL sınırlandırılmıştır ve authoritative değildir |
| Controller accountability capture sonrasında da sürer | Asset-to-engagement mapping, approvals, operator access ve command'lar merkezi olarak saklanır ve access-controlled durumdadır |
| Kayıp çalışmayı durdurur | Discovery veya açıklanamayan state change; remote destruction yerine stop, revoke, notify ve evidence preservation işlemlerini tetikler |

NIST'in IoT baseline'ı device identification, configuration, data protection, logical access, secure software update ve cybersecurity-state awareness özelliklerini temel yetenekler olarak gruplandırır. Özellikle state awareness ve off-device event record'larını compromise investigation için destek olarak ele alır.<sup>[[1]](#references)</sup>

## Reference architecture
```text
operator workstation
|  phishing-resistant MFA; named user; no field-device key
v
organization access gateway ----> immutable audit / alerting
|  per-engagement authorization          ^
v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
|                                                     |-- approved site Wi-Fi/Ethernet
+---- allowlisted owned test services                 +-- organization cellular fallback
```
Gateway, hangi adlandırılmış operatörün hangi adlandırılmış cihaza ulaştığını bilmelidir. Saha düğümünün rendezvous için yalnızca bir cihaz kimlik bilgisine ihtiyacı vardır. Operatörün kaynak adresini veya kimlik doğrulama sırrını hiçbir zaman öğrenmez ve operatör de özel bir yönetim anahtarını cihaza kopyalamaz. Bu, tatbikat hesap verebilirliğini yok etmeden **saha depolamasından** kurtarılabilir kişisel bağlantıyı azaltır.

Daha büyük bir filo için workload-identity sistemi, kısa ömürlü X.509 kimlikleri yayınlayabilir ve anahtarları otomatik olarak döndürebilir. SPIFFE, mümkün olduğunda X.509 SVID'lerini önerir ve kısa ömürler ile sık rotasyonun anahtar ele geçirilmesine maruz kalmayı sınırladığını açıklar.<sup>[[2]](#references)</sup> Küçük bir ekip aynı özellikleri özel bir CA ve cihaz başına otomatik sertifikalarla uygulayabilir; yalnızca bu deseni karşılamak için SPIRE kurulması gerekmez.

## Adım 1: yerleştirmeyi yetkilendirin ve kaydedin

1. Sahibi, siteyi, izin verilen kesin yerleştirme bölgesini, izin verilen ağları, değerlendirme aralığını, izin verilen hedefleri/eylemleri ve acil durum irtibatlarını kaydedin.
2. Modeli, seri numarasını, depolama seri numarasını, kablolu/kablosuz MAC'leri, modem IMEI/eSIM veya SIM ICCID'sini, güç kaynağını ve güncel bir fotoğrafı kaydedin.
3. Cihaza kişisel olmayan bir engagement identifier verin; örneğin `E2026-014-DROP03`. Yayınlanan hostname'lerde veya SSID'lerde müşteri adı kodlamayın.
4. Egzersiz kontrolörüne ve gerekli en küçük fiziksel güvenlik/SOC deconfliction grubuna bu test için “kayıp,” “taşınmış” ve “bulunmuş” ifadelerinin ne anlama geldiğini bildirin.
5. Cihazı kimin geri alabileceğini ve bulan kişinin bunu nasıl bildirebileceğini önceden kararlaştırın. Bir güvenlik etiketi, kontrollü bir geri dönüş numarası sağlarken hassas müşteri ayrıntılarını içermeyebilir.
6. Otomatik bir yetkilendirme sona erme zamanı belirleyin. Kapsam sona erdikten sonra bağlantının devam etmesi izni uzatmamalıdır.

## Adım 2: kurtarılabilirliği en aza indirilmiş bir imaj oluşturun

Desteklenen bir OS image kullanın, imzasını/checksum'ını üreticinin belgelenmiş kanalı üzerinden doğrulayın, security update'lerini yükleyin ve yeniden üretilebilir bir build manifest'i tutun. Yazılım izin veriyorsa, küçük bir yazılabilir veri bölümüne sahip salt okunur veya immutable bir temel tercih edin.

1. Yetkilendirilmiş workload için gerekmeyen varsayılan hesapları, demo servislerini, derleyicileri ve paketleri kaldırın.
2. Egzersiz açıkça birini gerektirmediği sürece yerel GUI'yi, Bluetooth'u, discovery protokollerini, file sharing'i, Wi-Fi P2P'yi ve inbound administration'ı devre dışı bırakın.
3. Donanım bunları gerçekten destekliyorsa secure boot'u ve measured boot/TPM-backed key release'ı etkinleştirin; kesin modeli doğrulamadan bir Raspberry Pi yapılandırmasının PC sınıfı measured boot'a sahip olduğunu iddia etmeyin.
4. Yerel yazılabilir durumu şifreleyin ve katı bir maksimum boyut ile saklama süresi yapılandırın. Şifreleme, çalışan bir düğümün hiçbir şeyi açığa çıkarmadığının kanıtı değil, geciktirme/sınırlama kontrolüdür.
5. Önemli log'ları cihaz dışına gönderin. Storage exhaustion'ı önlemek için yerel journal'ları sınırlandırın, ancak log wiping veya anti-forensic deletion yapılandırmayın.
6. İmaj manifest'ini, paket sürümlerini, yapılandırma hash'ini ve recovery talimatlarını kontrolörde saklayın.
7. Bir yedeği manifest'ten yeniden image'layın ve aynı health test'i çalıştırın. Yalnızca oluşturan kişinin kurtarabildiği bir tasarım field-ready değildir.

## Adım 3: one-way trust ile kimlikler yayınlayın

Üç farklı kimlik oluşturun:

- yalnızca bu cihazın rendezvous'u tarafından kabul edilen bir **cihaz kimliği**;
- organization gateway tarafından kabul edilen ve phishing-resistant MFA ile korunan bir **operatör kimliği**; ve
- onaylanmış job'ları veya configuration'ı imzalamak için kullanılan, hem operatörden hem de saha düğümünden ayrı tutulan bir **controller/deployment kimliği**.

Düğüm, imzalanmış job'ları doğrulamak için gereken public key'e sahip olmalıdır; signing key'e hiçbir zaman sahip olmamalıdır. Ele geçirilmiş bir cihaz credential'ı cloud console'larında, source repository'lerinde, payment account'larında, diğer düğümlerde veya müşteri production ortamında authentication yapamamalıdır.

Otomatik yenilemenin güvenilir olduğu yerlerde kısa sertifika ömürleri kullanın. Uzun ömürlü bir WireGuard key operasyonel olarak gerekli olduğunda, public key'i revocation handle olarak kabul edin ve bunu peer-specific tunnel address, firewall policy ve broker authorization ile kısıtlayın. Bu peer'i hemen kaldıran, test edilmiş bir controller action'ı bulundurun.

## Adım 4: kararlı dışa giden rendezvous

Aşağıdaki organization-owned lab pattern'i, inbound service açığa çıkarmadan NAT üzerinden kararlı management sağlar. Bu, covert reverse shell değil, sıradan WireGuard networking'dir. Documentation address'lerini kullanın ve bunları yalnızca organization-owned endpoint'lerle değiştirin.

Organization rendezvous'unda `10.77.0.1/32` atayın; saha düğümüne `10.77.0.20/32` atayın. Gateway peer entry yalnızca düğümün tek adresini kabul etmelidir:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Node, rendezvous'a dışa yönlü bağlantı kurar ve NAT mapping'i yalnızca gerektiğinde korur:
```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```
WireGuard, persistence gerektiğinde birçok NAT/firewall uygulamasında 25 saniyeyi makul bir keepalive aralığı olarak belgeler; gerekli olmadığı durumlarda devre dışı bırakılması tercih edilir.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32`, bunun varsayılan rota pivot'u değil, kasıtlı olarak bir yönetim yolu olmasını sağlar.

Ardından kontrolleri WireGuard dışında uygulayın:

1. `vpn.redteam.example` adresini onaylı bootstrap DNS yolu üzerinden çözümleyin ve beklenen kuruluş endpoint'ini deployment kayıtlarına sabitleyin.
2. Node üzerinde yalnızca çıkış yönlü DHCP/RA, gerekli DNS/NTP, rendezvous endpoint'i ve onaylanmış minimum update yoluna izin verin. Her uplink üzerinde istenmeyen inbound trafiği engelleyin.
3. Rendezvous üzerinde `10.77.0.20` adresinin yalnızca exercise için gereken broker/health service'e erişmesine izin verin. Bu adresi genel olarak bir client network'e forward etmeyin.
4. Interactive operator erişimini kuruluş gateway'inin arkasına alın. Signed pull-job interface değerlendirme için yeterliyse, node üzerinden tunnel aracılığıyla SSH açmaktan kaçının.
5. Service manager'ı tunnel'ı networking sonrasında başlatacak, failure sonrasında sınırlı backoff ile yeniden başlatacak ve tekrarlanan failure durumunda alert gönderecek şekilde yapılandırın. Bir restart loop, venue'yu aşırı yüklememeli veya temel fault'u gizlememelidir.
6. Peer'in latest handshake bilgisini doğrulayın; ancak “handshake mevcut” durumunu cihazın ele geçirilmediğinin kanıtı olarak kullanmayın.

TURN, amaca özel bir WebRTC control plane için yalnızca relay üzerinden erişilebilirlik sağlayabilir; bir message queue ise aralıklı service durumlarına dayanabilir. TURN, NAT arkasındaki client'a açık bir relay adresi verir; server'ı ise observer olarak kalır.<sup>[[4]](#references)</sup> Observer veya reliability benefit açıkça belirtilmeden tunnel'ları üst üste eklemek yerine tek bir control architecture seçin.

## Step 5: personal links olmadan uplink stability

Yetkilendirilmiş bir venue node için şu sırayı tercih edin:

1. client tarafından sağlanan wired veya dedicated test VLAN;
2. owner tarafından onaylanmış enterprise/guest Wi-Fi profile;
3. kuruluşun sözleşme yaptığı cellular/private APN fallback.

Buna asla personal phone hotspot, home SSID, personal eSIM, personal Apple/Google account veya günlük kullanılan bir laptop'tan export edilmiş Wi-Fi profile yüklemeyin. Bir capture'ın bağlanacağı artifact'ler tam olarak bunlardır.

Her onaylanmış uplink için:

- SSID/BSSID veya switch/VLAN bilgisini ve beklenen captive-portal davranışını kaydedin;
- deterministic priority ve owner tarafından işletilen bir endpoint'e health check ayarlayın;
- failover yalnızca underlay'i değiştirsin; cihaz ve operator identity'leri broker'da kalmalıdır;
- geçiş sırasında DNS, IPv6 ve application trafiğinin rendezvous'u bypass etmediğinden emin olun;
- unknown SSID/BSSID, SIM değişikliği, yeni default gateway, public-IP/ASN değişikliği veya eşzamanlı uplink durumlarında alert üretin;
- deployment öncesinde power loss, DHCP renewal, AP restart, public-IP değişikliği, 24-hour idle, tunnel loss ve primary-to-secondary-to-primary recovery senaryolarını test edin.

Private MAC addressing, rastgele ağlar arası tracking'i azaltabilir; ancak authorized NAC için network başına stable bir MAC çoğu zaman gereklidir. Seçilen OS'in gerçekte ne yaptığını kaydedin ve bir owner'ın access control'ü etrafında rotation yapmayın.

## Step 6: work ve data'yı sınırlandırma

Güvenli bir field node, mailbox'tan arbitrary shell text kabul etmemelidir. `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` gibi signed job type'ları veya rules of engagement içinde açıkça belirtilen başka bir action tanımlayın. Destination, duration, rate, output size ve scope'u node üzerinde tekrar doğrulayın.

1. Her job için unique ID, device audience, issue time, expiry, scope reference ve maximum output belirleyin.
2. Job'ı controller/deployment identity ile sign edin.
3. Unknown field'ları, expired/replayed job'ları ve başka bir cihaza ait job'ları reddedin.
4. Result'ları owner tarafından işletilen bir collector'a stream edin; kaçınılmaz local spool verilerini encrypt edin ve TTL uygulayın.
5. Accepted/rejected job ID ve result hash bilgilerini controller'da loglayın. Sensitive command parameter'larını public monitoring channel'a koymayın.
6. Authorization sona erdiğinde, identity rotation başarısız olduğunda veya controller cihazı quarantined olarak işaretlediğinde processing'i durdurun.

## Discovery, loss veya compromise için monitoring

Monitoring, controller'a observed state'in değiştiğini bildirebilir. Ancak “investigators cihazı buldu” durumunu güvenilir biçimde kanıtlayamaz; responders'ı surveil etmeye veya sistemlerini probe etmeye çalışmak authorized assessment sınırlarını aşar.

### Off-device state toplama

Controller'a randomized ancak bounded bir operational interval ile signed, low-volume bir health record gönderin. Yalnızca controller'ın ihtiyaç duyduğu bilgileri ekleyin:

- device ID, boot ID/counter ve monotonic uptime;
- configuration/image hash ve software version;
- device-certificate serial ve renewal state;
- uplink class, interface, authorized olduğu ölçüde BSSID veya switch context, default-gateway hash ve owner tarafından işletilen bir service'in gözlemlediği public IP/ASN;
- tunnel handshake age, packet counters ve queue depth;
- owner sensor'ı onayladıysa enclosure switch veya hardware-tamper state;
- disk pressure, temperature, clock-offset estimate ve last successful job ID;
- replay veya gap durumlarını ortaya çıkarmak için sequence number ve signature.

Gateway authentication, policy decision, operator access, job submission, result hash, provider audit event ve alert kayıtlarını merkezi olarak saklayın. CISA; log'ların merkezileştirilmesini, silinmeye karşı korunmasını, normal activity için baseline oluşturulmasını ve incident-response contact'larının belirlenmesini önerir.<sup>[[5]](#references)</sup>

### Discovery/compromise göstergeleri

| Signal | Possible explanations | Controller action |
|---|---|---|
| Heartbeat absent | power/network failure, portal change, damage, deliberate blocking or removal | provider/site state'i doğrulayın; onaylanmamış bir path üzerinden yeniden bağlanmayın |
| Boot counter changed unexpectedly | power cut, crash, removal or maintenance | job'ları quarantine edin; time ve site event'lerini karşılaştırın |
| Config/image hash changed | update error, storage fault or tampering | work'ü durdurun; controller-approved release değilse revoke edin |
| New uplink/BSSID/gateway/ASN | AP replacement, roaming, moved device or interception | approved inventory ile karşılaştırın; açıklanamayan transition'ı quarantine edin |
| Repeated rejected job/signature | corruption, replay or unauthorized controller | processing'i durdurun ve gateway/controller log'larını inceleyin |
| Device credential used twice or from incompatible paths | cloned key, snapshot reuse or network transition | derhal revoke edin; her iki session kaydını saklayın |
| Unexpected local login, interface, process or privilege event | maintenance or compromise | broker policy üzerinden isolate edin; evidence'ı koruyun |
| Enclosure switch/state transition | service, movement or discovery | named site contact'a bildirin; destructive action tetiklemeyin |
| Provider abuse notice/account query or SOC alert | detection, misconfiguration or out-of-scope traffic | activity'yi durdurun ve deconfliction/incident process'i başlatın |
| Sentinel credential touched | someone read a no-privilege decoy secret unique to this node | gerçek device identity'yi revoke edin ve alert trail'i koruyun |

Bir sentinel credential **hiçbir access vermemeli**, yalnızca kuruluşun sahip olduğu bir alert service'i çağırmalı ve rules of engagement içinde açıklanmalıdır. Bu, unauthorized reading için bir tripwire'dır; equipment'ı bulan kişiyi tracking etmek için kullanılan bir beacon değildir.

### Alert thresholds

Tek bir dramatik “caught” alarmı yerine stateful rule'lar kullanın:

- **warning:** bir missed interval, normal address change veya queue growth;
- **degraded:** art arda üç miss, renewal delay, primary-uplink loss veya tekrarlanan restart;
- **quarantine:** onaylanmamış hash/boot/uplink change, duplicate credential, sentinel use veya beklenmeyen privileged event;
- **confirmed discovery/loss:** site/controller report, physical inventory mismatch, cihazın plansız bir party tarafından bulunması veya doğrulanmış provider/SOC escalation.

Alert delivery'yi field node'dan bağımsız bir channel üzerinden test edin. Sensitive client/device detail'larını personal messaging veya consumer push account'larına göndermekten kaçının.

## Suspected discovery veya capture runbook

1. **Stop:** yeni job'ları ve operator session'larını suspend edin. “Watched olup olmadığını kontrol eden” bir probe göndermeyin.
2. **Quarantine:** mevcut log'ları korurken broker'ın device identity'yi ve route'larını deny etmesini sağlayın.
3. **Revoke:** device certificate/key, queue token, update credential ve single-purpose service token'ları revoke edin. Physical loss olasıysa organization SIM'i suspend edin.
4. **Preserve:** controller, gateway, provider ve alert kayıtlarının snapshot'ını alın; trusted time'ı, işlemi kimin yaptığını ve son known configuration'ı kaydedin. Node'u clear etmeyin veya remote wipe uygulamayın.
5. **Notify:** exercise controller, client incident contact ve authorization içinde tanımlanan legal/privacy contact'ları bilgilendirin. Bir third party cihazı bulduysa önceden kararlaştırılmış recovery process'i kullanın.
6. **Assess:** node üzerindeki her secret'ın ve cached result'ın exposed olduğunu varsayın. Her secret'ın tam olarak nelere access sağlayabildiğini ve suspicious event sonrasında kullanılıp kullanılmadığını belirleyin.
7. **Contain downstream:** etkilenen service credential'larını rotate edin, pending job'ları invalidate edin ve beklenmeyen activity için owned target/provider log'larını inceleyin.
8. **Recover safely:** yalnızca authorized bir kişi aracılığıyla retrieve edin; photograph/package işlemi yapın, custody'yi kaydedin ve client'ın yönlendirdiği şekilde forensic evidence alın.
9. **Resume with a new identity:** captured credential'ı asla sessizce yeniden etkinleştirmeyin. Known manifest'ten rebuild edin, control failure'ı düzeltin ve explicit approval alın.

NIST'in güncel incident-response guidance'ı preparation, detection, response ve recovery süreçlerini organization-wide cybersecurity risk management ile bütünleştirir; client'ın ne olduğunu belirleyebilmesi ve uygun response'u seçebilmesi için önce preservation yapın.<sup>[[6]](#references)</sup>

## Deployment öncesi capture drill

Unlocked bir test unit'i veya storage kopyasını ayrı bir reviewer'a verin ve şunları enumerate etmesini isteyin:

1. device/site/engagement identifier'ları;
2. operator name'leri, personal account'lar, home/workstation network'leri ve recovery contact'ları;
3. controller/broker destination'ları ve credential'ları;
4. client network profile'ları ve cached result'lar;
5. her secret ile erişilebilen diğer device/project'ler;
6. value veya payment credential'ları;
7. controller'ın neyi revoke edebildiği ve bunu ne kadar hızlı yapabildiği;
8. hangi activity'nin central log'lardan attributable olarak kaldığı.

Pass criteria: sıfır personal account/workstation key; sıfır cross-engagement veya enrollment authority; payment credential yok; bounded encrypted cache; belgelenmiş tek bir device-revocation action; eksiksiz controller-side accountability. Beklenmeyen her personal link'i veya lateral capability'yi release blocker olarak ele alın.

## Closeout

1. Scope sona erdiğinde job'ları durdurun ve broker route'unu disable edin.
2. Exact inventory'yi retrieve edip reconcile edin; eksik olan her şeyi raporlayın.
3. Engagement retention plan'a uygun olarak log/result'ları ve gerekiyorsa forensic image'ı koruyun.
4. Hardware recovery edilmiş olsa bile device, SIM, queue, update ve service identity'lerini revoke edin.
5. Yalnızca preservation/acceptance sonrasında media'yı owner'ın onaylı data-disposal process'i ile sanitize veya destroy edin ve tamamlanmasını kaydedin. Bu, concealment değil lifecycle management'tır.
6. Venue NAC/DHCP reservation'larını, broker route'larını, DNS'i, cloud role'larını, alert rule'larını ve temporary contact'ları kaldırın.
7. Observed detection'ı, kaçırılan telemetry'yi, quarantine süresini ve capture'ın ortaya çıkardığı her artifact'i belgeleyin.

## References

- [1] [NIST — IoT Device Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts and short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
