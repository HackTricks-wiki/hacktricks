# Capture-Resilient Authorized Field Nodes

Sahaya yerleştirilen bir Raspberry Pi, mini-PC, travel router veya cellular appliance, yetkili bir red team için kalıcı bir bakış noktası sağlayabilir. Aynı zamanda keşfedilme, çalınma ve ilişkilendirilme olasılığı yüksek bir noktadır. Bu nedenle doğru tasarım hedefi, izlenemez bir implant değil, **saha node'unda az yetkiyle istikrarlı ve kontrollü erişim** sağlamaktır.

Bu kılavuz yalnızca tesis sahibinin yazılı yetkilendirmesiyle yerleştirilen ekipmanlar için geçerlidir. Bir coffee shop, komşu, otel veya ortak kullanılan bir bina, yalnızca ağına erişilebildiği için kapsam dahilinde değildir. Donanımı rıza göstermeyen bir mekanda saklamayın, captive portal'ı bypass etmeyin, başka birinin kimlik bilgilerini kullanmayın, monitoring faaliyetlerine müdahale etmeyin veya keşfedildikten sonra kanıtları silmeye çalışmayın.

{% hint style="warning" %}
Güvenilir bir “hiç iz bırakma” ayarı yoktur. Radio association, DHCP/NAT, carrier, kamera, satın alma, cihaz, provider, controller ve destination kayıtları cihazdan sonra da varlığını sürdürebilir. Sorumlu bir red team bunun yerine node'dan **kişisel ve ilgisiz secret'ları** kaldırır, korunan controller-side ilişkilendirme kayıtlarını saklar ve ele geçirilmenin kontrol altına alınmasını kolaylaştırır.
{% endhint %}

## Pros and cons

**Pros:** gerçekçi bir internal veya hedefe yakın kaynak; istikrarlı yüksek hızlı testing; NAC, egress, physical inventory ve SOC kapsamını doğrular; operator adres değişiklikleri boyunca çalışmaya devam edebilir; sınırlandırılmış erişim merkezi olarak iptal edilebilir.

**Cons:** fiziksel yerleştirme güçlü kanıt oluşturur; kayıp, cihaz credentials'larını, network profiles'larını ve toplanan verileri açığa çıkarabilir; tekrarlanan control traffic tespit edilebilir; güç, portal'lar ve radio değişiklikleri güvenilirliği azaltır; geniş bir tunnel, kontrolsüz bir pivot'a dönüşebilir.

## Threat model and design invariants

Bir bulan kişinin storage'ı çıkarabileceğini, firmware'ı inceleyebileceğini, software tarafından tutulan her secret'ı kopyalayabileceğini, sonraki network behavior'ı gözlemleyebileceğini ve cihazı müşteriye veya law enforcement'a teslim edebileceğini varsayın. Full-disk encryption, yalnızca belirtilen threat model kapsamında kapalı bir cihazı korur; çalışan ve kilidi açılmış bir node ile memory'ye bırakılmış anahtarlar farklı durumlardır.

| Invariant | Practical consequence |
|---|---|
| No direct operator-to-node identity | Operator, organization gateway'e giriş yapar; node farklı bir device identity'ye sahiptir |
| No personal workstation material | Kişisel SSH key, browser profile, email, password manager, phone pairing veya cloud CLI cache bulunmaz |
| No controller master secret | Tek bir node başka bir node'u enroll edemez, policy'yi değiştiremez veya diğer engagement'ların şifresini çözemez |
| Outbound-only and narrow | Field network hiçbir management listener kabul etmez; node yalnızca adı belirtilmiş rendezvous/update/time servislerine ulaşır |
| Short-lived, scoped authority | Her credential tek bir device, audience, service, expiry ve anında revocation path ile sınırlandırılır |
| Minimal local data | Sonuçlar controller'a aktarılır; cache'ler şifrelenir, boyut/TTL ile sınırlandırılır ve authority kaynağı değildir |
| Controller accountability survives capture | Asset-to-engagement mapping, approvals, operator access ve commands merkezi olarak saklanır ve access-controlled durumdadır |
| Loss stops work | Discovery veya açıklanamayan state change; remote destruction yerine stop, revoke, notify ve evidence preservation işlemlerini tetikler |

NIST'in IoT baseline'ı device identification, configuration, data protection, logical access, secure software update ve cybersecurity-state awareness özelliklerini temel yetenekler olarak gruplandırır. Özellikle state awareness ve off-device event records özelliklerini compromise investigation için destek olarak ele alır.<sup>[[1]](#references)</sup>

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
Gateway, hangi adlandırılmış operatorün hangi adlandırılmış cihaza ulaştığını bilmelidir. Field node, rendezvous için yalnızca bir cihaz kimlik bilgisine ihtiyaç duyar. Operatorün kaynak adresini veya authentication secret'ını hiçbir zaman öğrenmez ve operator de private management key'i cihaza kopyalamaz. Bu, exercise accountability'yi yok etmeden **field storage'dan** kurtarılabilen kişisel bağlantıyı azaltır.

Daha büyük bir fleet için workload-identity sistemi, kısa ömürlü X.509 kimlikleri sağlayabilir ve key'leri otomatik olarak rotate edebilir. SPIFFE, mümkün olduğunda X.509 SVID'leri önerir ve kısa ömürlerle sık rotation'ın key-compromise maruziyetini sınırladığını açıklar.<sup>[[2]](#references)</sup> Küçük bir team, private CA ve otomatik device başına certificates ile aynı özellikleri uygulayabilir; yalnızca bu pattern'i karşılamak için SPIRE kurulması gerekmez.

## Adım 1: placement'ı authorize edin ve register edin

1. Owner'ı, site'ı, izin verilen exact placement zone'u, izin verilen network'leri, assessment window'u, izin verilen destination/action'ları ve emergency contact'ları kaydedin.
2. Modeli, serial'ı, storage serial'ını, wired/wireless MAC'leri, modem IMEI/eSIM veya SIM ICCID'sini, power supply'ı ve güncel bir fotoğrafı kaydedin.
3. Cihaza kişisel olmayan bir engagement identifier verin; örneğin `E2026-014-DROP03`. Broadcast hostname'lerinde veya SSID'lerde client adı encode etmeyin.
4. Exercise controller'a ve gerekli en küçük physical-security/SOC deconfliction grubuna, bu test için “lost”, “moved” ve “discovered” ifadelerinin ne anlama geldiğini bildirin.
5. Cihazı kimin retrieve edebileceğini ve bulan kişinin nasıl report edebileceğini önceden kararlaştırın. Bir safety label, kontrollü bir callback sağlarken hassas client ayrıntılarını içermeyebilir.
6. Automatic authorization expiry ayarlayın. Scope sona erdikten sonra devam eden connectivity, permission'ı uzatmamalıdır.

## Adım 2: minimum recoverable image oluşturun

Supported bir OS image kullanın, signature/checksum'ını vendor'ın documented channel'ı üzerinden doğrulayın, security update'lerini install edin ve reproducible build manifest tutun. Software izin veriyorsa, küçük bir writable data partition içeren read-only veya immutable bir base tercih edin.

1. Authorized workload için gerekli olmayan default account'ları, demo service'lerini, compiler'ları ve package'ları kaldırın.
2. Exercise açıkça gerektirmedikçe local GUI'yi, Bluetooth'u, discovery protocol'lerini, file sharing'i, Wi-Fi P2P'yi ve inbound administration'ı disable edin.
3. Hardware gerçekten destekliyorsa secure boot'u ve measured boot/TPM-backed key release'ı enable edin; exact model'i doğrulamadan bir Raspberry Pi configuration'ının PC-class measured boot'a sahip olduğunu iddia etmeyin.
4. Local writable state'i encrypt edin ve strict maximum size ile retention time configure edin. Encryption bir delay/containment control'dür; running node'un hiçbir şeyi reveal etmediğinin kanıtı değildir.
5. Önemli log'ları off-device gönderin. Storage exhaustion'ı önlemek için local journal'ları sınırlandırın, ancak log wiping veya anti-forensic deletion configure etmeyin.
6. Image manifest'i, package version'larını, configuration hash'ini ve recovery instruction'larını controller'da saklayın.
7. Bir spare'i manifest'ten reimage edin ve aynı health test'i çalıştırın. Yalnızca builder'ının recover edebildiği bir design field-ready değildir.

## Adım 3: one-way trust ile identity issue edin

Üç farklı identity oluşturun:

- yalnızca bu device için rendezvous tarafından kabul edilen bir **device identity**;
- organization gateway tarafından kabul edilen ve phishing-resistant MFA ile korunan bir **operator identity**; ve
- approved job'ları veya configuration'ı sign etmek için kullanılan, hem operator hem de field node dışında tutulan bir **controller/deployment identity**.

Node, signed job'ları verify etmek için gereken public key'e sahip olmalıdır; signing key'e hiçbir zaman sahip olmamalıdır. Captured bir device credential; cloud console'larda, source repository'lerinde, payment account'larında, diğer node'larda veya client production'da authenticate olmamalıdır.

Automatic renewal güvenilir olduğunda short certificate lifetime'ları kullanın. Long-lived WireGuard key operational olarak gerekli olduğunda, public key'ini revocation handle olarak değerlendirin ve peer-specific tunnel address, firewall policy ve broker authorization ile kısıtlayın. Bu peer'i hemen kaldıran tested bir controller action bulundurun.

## Adım 4: stable outbound rendezvous

Aşağıdaki owned-lab pattern'i, inbound service expose etmeden NAT üzerinden stable management sağlar. Bu, covert reverse shell değil, sıradan WireGuard networking'dir. Documentation address'lerini kullanın ve bunları yalnızca organization-owned endpoint'lerle değiştirin.

Organization rendezvous'ta `10.77.0.1/32` atayın; field node'a `10.77.0.20/32` atayın. Gateway peer entry yalnızca node'un tek address'ini kabul etmelidir:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Node, rendezvous'a dışarıya doğru yönelir ve NAT eşlemesini yalnızca gerektiğinde korur:
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
WireGuard, persistence gerektiğinde birçok NAT/firewall uygulamasında 25 saniyeyi makul bir keepalive aralığı olarak belgeler; gerekmediğinde devre dışı bırakmak tercih edilir.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32`, bunun default-route pivot değil, kasıtlı olarak bir yönetim yolu olmasını sağlar.

Ardından kontrolleri WireGuard dışında uygulayın:

1. `vpn.redteam.example` adresini onaylı bootstrap DNS yolu üzerinden çözümleyin ve beklenen kuruluş endpoint'ini deployment kayıtlarına sabitleyin.
2. Node üzerinde outbound DHCP/RA, gerekli DNS/NTP, rendezvous endpoint'i ve onaylanmış minimum update yoluna izin verin. Her uplink üzerinde istenmeyen inbound trafiği engelleyin.
3. Rendezvous üzerinde `10.77.0.20` adresinin yalnızca exercise için gereken broker/health service'e erişmesine izin verin. Genel olarak bir client network'e forward etmeyin.
4. Interactive operator erişimini kuruluş gateway'inin arkasına alın. Signed pull-job interface assessment için yeterliyse node üzerinden tunnel aracılığıyla SSH sunmaktan kaçının.
5. Service manager'ı tunnel'ı networking sonrasında başlatacak, failure sonrasında sınırlı backoff ile yeniden başlatacak ve tekrarlanan failure durumunda alert gönderecek şekilde yapılandırın. Bir restart loop venue'yu aşırı yüklememeli veya temel hatayı gizlememelidir.
6. Peer'ın latest handshake bilgisini doğrulayın; ancak “handshake exists” bilgisini cihazın compromise edilmediğinin kanıtı olarak kullanmayın.

TURN, amaca özel bir WebRTC control plane için yalnızca relay erişilebilirliği sağlayabilir ve bir message queue kesintili service'i tolere edebilir. TURN, NAT arkasındaki bir client'a açıkça public relay address verir; server'ı ise gözlemci olarak kalır.<sup>[[4]](#references)</sup> Belirtilmiş bir gözlemci veya reliability avantajı olmadan tunnel'ları üst üste eklemek yerine tek bir control architecture seçin.

## Step 5: kişisel linkler olmadan uplink kararlılığı

Yetkili bir venue node için şu sırayı tercih edin:

1. client tarafından sağlanan wired veya dedicated test VLAN;
2. owner tarafından onaylanmış enterprise/guest Wi-Fi profile;
3. kuruluşun sözleşmeli cellular/private APN fallback'i.

Buna asla personal phone hotspot, home SSID, personal eSIM, personal Apple/Google account veya günlük kullanılan laptop'tan export edilmiş Wi-Fi profile yüklemeyin. Bunlar tam olarak bir capture'ın bağlanacağı artifact'lerdir.

Onaylanan her uplink için:

- SSID/BSSID veya switch/VLAN ile beklenen captive-portal davranışını kaydedin;
- deterministic priority ve owner olunan bir endpoint'e health check ayarlayın;
- failover yalnızca underlay'i değiştirsin; device ve operator identity'leri broker'da kalmalıdır;
- geçiş sırasında DNS, IPv6 ve application traffic'in rendezvous'u bypass etmediğinden emin olun;
- bilinmeyen SSID/BSSID, SIM değişikliği, yeni default gateway, public-IP/ASN değişikliği veya eşzamanlı uplink durumlarında alert gönderin;
- deployment öncesinde power loss, DHCP renewal, AP restart, public-IP değişikliği, 24 saatlik idle, tunnel loss ve primary-to-secondary-to-primary recovery durumlarını test edin.

Private MAC addressing, sıradan cross-network tracking'i azaltabilir; ancak authorized NAC için network başına sabit bir MAC çoğu zaman gereklidir. Seçilen OS'nin gerçekte ne yaptığını kaydedin ve bir owner's access control çevresinde rotation yapmayın.

## Step 6: işi ve veriyi sınırlandırma

Güvenli bir field node, mailbox'tan rastgele shell text kabul etmemelidir. `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` gibi signed job type'ları veya rules of engagement içinde açıkça adlandırılmış başka bir action tanımlayın. Destination, duration, rate, output size ve scope'u node üzerinde tekrar doğrulayın.

1. Her job için unique ID, device audience, issue time, expiry, scope reference ve maximum output verin.
2. Job'ı controller/deployment identity ile sign edin.
3. Bilinmeyen field'ları, süresi dolmuş/replayed job'ları ve başka bir device için hazırlanmış job'ları reddedin.
4. Sonuçları owner olunan bir collector'a stream edin; kaçınılmaz local spool verisini encrypt edin ve TTL uygulayın.
5. Kabul edilen/reddedilen job ID'sini ve result hash'ini controller'da loglayın. Sensitive command parameter'larını public monitoring channel'a koymayın.
6. Authorization sona erdiğinde, identity rotation başarısız olduğunda veya controller device'ı quarantined olarak işaretlediğinde processing'i durdurun.

## Discovery, loss veya compromise için monitoring

Monitoring, controller'a gözlemlenen state'in değiştiğini bildirebilir. “Investigators found the device” durumunu güvenilir biçimde kanıtlayamaz; responders'ı surveil etmeye veya sistemlerini probe etmeye çalışmak da authorized assessment kapsamını aşar.

### Off-device state toplayın

Randomized ancak bounded bir operational interval ile controller'a signed, düşük hacimli bir health record gönderin. Yalnızca controller'ın ihtiyaç duyduğu bilgileri ekleyin:

- device ID, boot ID/counter ve monotonic uptime;
- configuration/image hash ve software version;
- device-certificate serial ve renewal state;
- uplink class, yetki verilen interface, BSSID veya switch context, default-gateway hash ve owner olunan bir service tarafından gözlemlenen public IP/ASN;
- tunnel handshake age, packet counter'ları ve queue depth;
- owner sensor'ı onayladıysa enclosure switch veya hardware-tamper state;
- disk pressure, temperature, clock-offset estimate ve son başarılı job ID'si;
- replay veya gap durumunu ortaya çıkarmak için sequence number ve signature.

Gateway authentication, policy decision, operator access, job submission, result hash, provider audit event ve alert'leri merkezi olarak saklayın. CISA, log'ların merkezileştirilmesini, silinmeye karşı korunmasını, normal activity için baseline oluşturulmasını ve incident-response contact'larının belirlenmesini önerir.<sup>[[5]](#references)</sup>

### Discovery/compromise göstergeleri

| Signal | Olası açıklamalar | Controller action |
|---|---|---|
| Heartbeat absent | power/network failure, portal değişikliği, damage, deliberate blocking veya removal | provider/site state'i corroborate edin; onaylanmamış bir path üzerinden reconnect etmeyin |
| Boot counter beklenmedik şekilde değişti | power cut, crash, removal veya maintenance | job'ları quarantine edin; time ve site event'lerini karşılaştırın |
| Config/image hash değişti | update error, storage fault veya tampering | işi durdurun; controller-approved release değilse revoke edin |
| New uplink/BSSID/gateway/ASN | AP replacement, roaming, moved device veya interception | approved inventory ile karşılaştırın; açıklanamayan geçişi quarantine edin |
| Repeated rejected job/signature | corruption, replay veya unauthorized controller | processing'i durdurun ve gateway/controller log'larını inceleyin |
| Device credential iki kez veya uyumsuz path'lerden kullanıldı | cloned key, snapshot reuse veya network transition | derhal revoke edin; her iki session record'unu saklayın |
| Unexpected local login, interface, process veya privilege event | maintenance veya compromise | broker policy üzerinden isolate edin; evidence'i koruyun |
| Enclosure switch/state transition | service, movement veya discovery | belirtilen site contact'ına bildirin; destructive action tetiklemeyin |
| Provider abuse notice/account query veya SOC alert | detection, misconfiguration veya out-of-scope traffic | activity'yi durdurun ve deconfliction/incident process'i başlatın |
| Sentinel credential'a erişildi | biri bu node'a özgü, privilege içermeyen decoy secret'ı okudu | gerçek device identity'yi revoke edin ve alert trail'i koruyun |

Bir sentinel credential **hiçbir access vermemeli**, yalnızca kuruluşun sahip olduğu bir alert service'i çağırmalı ve rules of engagement içinde açıklanmalıdır. Bu, equipment'ı bulan kişiyi tracking etmek için bir beacon değil, unauthorized reading için bir tripwire'dır.

### Alert eşikleri

Tek bir dramatik “caught” alarmı yerine stateful rule'lar kullanın:

- **warning:** bir interval kaçırıldı, normal address change veya queue growth;
- **degraded:** art arda üç miss, renewal delay, primary-uplink loss veya tekrarlanan restart;
- **quarantine:** onaylanmamış hash/boot/uplink değişikliği, duplicate credential, sentinel kullanımı veya beklenmeyen privileged event;
- **confirmed discovery/loss:** site/controller report, physical inventory mismatch, device'ın plansız bir party tarafından recovery edilmesi veya doğrulanmış provider/SOC escalation.

Alert delivery'yi field node'dan bağımsız bir channel üzerinden test edin. Sensitive client/device detail'ını personal messaging veya consumer push account'larına göndermekten kaçının.

## Şüpheli discovery veya capture runbook'u

1. **Stop:** yeni job'ları ve operator session'larını suspend edin. “Watched olup olmadığını kontrol eden” bir probe göndermeyin.
2. **Quarantine:** mevcut log'ları korurken broker'ın device identity'yi ve route'larını deny etmesini sağlayın.
3. **Revoke:** device certificate/key, queue token, update credential ve single-purpose service token'ların tümünü revoke edin. Physical loss olasıysa organization SIM'i suspend edin.
4. **Preserve:** controller, gateway, provider ve alert record'larının snapshot'ını alın; trusted time'ı, işlemi gerçekleştiren kişiyi ve son known configuration'ı kaydedin. Node'u clear etmeyin veya remotely wipe etmeyin.
5. **Notify:** exercise controller, client incident contact ve authorization içinde tanımlanan legal/privacy contact'ları bilgilendirin. Üçüncü bir party cihazı bulduysa önceden kararlaştırılan recovery process'i kullanın.
6. **Assess:** node üzerindeki her secret'ın ve cached result'ın exposed olduğunu varsayın. Her secret'ın tam olarak hangi access'leri sağlayabileceğini ve suspicious event sonrasında kullanılıp kullanılmadığını belirleyin.
7. **Contain downstream:** etkilenen service credential'larını rotate edin, pending job'ları invalidate edin ve beklenmeyen activity için owned target/provider log'larını inceleyin.
8. **Recover safely:** yalnızca authorized person aracılığıyla retrieve edin; fotoğraflayın/package edin, custody'yi kaydedin ve client'ın yönlendirdiği şekilde forensic evidence elde edin.
9. **Resume with a new identity:** captured credential'ı asla sessizce yeniden etkinleştirmeyin. Known manifest'ten rebuild edin, control failure'ı düzeltin ve explicit approval alın.

NIST'in güncel incident-response guidance'ı preparation, detection, response ve recovery süreçlerini organization-wide cybersecurity risk management ile bütünleştirir; client'ın ne olduğunu belirleyebilmesi ve uygun response'u seçebilmesi için önce preserve edin.<sup>[[6]](#references)</sup>

## Deployment öncesi capture drill

Unlocked bir test unit'i veya storage kopyasını ayrı bir reviewer'a verin ve aşağıdakileri enumerate etmesini isteyin:

1. device/site/engagement identifier'ları;
2. operator adları, personal account'lar, home/workstation network'leri ve recovery contact'ları;
3. controller/broker destination'ları ve credential'ları;
4. client network profile'ları ve cached result'lar;
5. her secret ile erişilebilen diğer device/project'ler;
6. value veya payment credential'ları;
7. controller'ın neleri revoke edebildiği ve bunun ne kadar hızlı yapılabildiği;
8. hangi activity'nin central log'lar üzerinden attributable olarak kaldığı.

Pass criteria: sıfır personal account/workstation key; sıfır cross-engagement veya enrollment authority; hiçbir payment credential; bounded encrypted cache; belgelenmiş tek bir device-revocation action; eksiksiz controller-side accountability. Beklenmeyen herhangi bir personal link'i veya lateral capability'yi release blocker olarak değerlendirin.

## Closeout

1. Job'ları durdurun ve scope sona erdiğinde broker route'u disable edin.
2. Tam inventory'yi retrieve edip reconcile edin; eksik olan her şeyi report edin.
3. Log/result'ları ve gerekliyse engagement retention planına uygun forensic image'ı preserve edin.
4. Hardware recovery edilmiş olsa bile device, SIM, queue, update ve service identity'lerini revoke edin.
5. Ancak preservation/acceptance sonrasında media'yı owner'ın onaylı data-disposal process'i ile sanitize veya destroy edin ve tamamlanmayı kaydedin. Bu lifecycle management'tır, concealment değildir.
6. Venue NAC/DHCP reservation'larını, broker route'larını, DNS'i, cloud role'larını, alert rule'larını ve temporary contact'ları kaldırın.
7. Gözlemlenen detection'ı, kaçırılan telemetry'yi, quarantine'a kadar geçen süreyi ve capture'ın açığa çıkardığı her artifact'i document edin.

## References

- [1] [NIST — IoT Device Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Kavramlar ve kısa ömürlü workload identity'leri](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — NAT çevresinde Relay kullanarak geçiş (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Business System'lerde Logging kullanımı](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response önerileri ve değerlendirmeleri](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
