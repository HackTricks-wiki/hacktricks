# Ağ Gizliliği ve Anonim Bağlantı

{{#include ../banners/hacktricks-training.md}}

Ağ gizliliği bir yönlendirme kararıdır; tam kimlik gizliliği sağlamaz. Bir yol seçerken **kaynak**, **hedef**, **içerik** ve **zamanlama** unsurlarını kimin birbirine bağlayamaması gerektiğini sorun.

Her erişim yolu ailesi için standartlaştırılmış `Pros`, `Cons`, adım adım `Procedure` ve `Detection` envanteri için [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) ile başlayın. Bu sayfa, yaygın olarak dağıtılabilen seçenekleri genişletir.

## Her gözlemcinin genellikle görebildikleri

| Yol | Yerel ağ / ISP | Aracı | Hedef | Temel sınırlama | Göreli hız |
|---|---|---|---|---|---|
| Doğrudan HTTPS | Kaynak, hedef metadata'sı, zamanlama/hacim | Hosting/CDN bağlantıyı görür | Kaynak IP'si, browser/app verileri | Kaynak IP'si gizliliği yok | En hızlı |
| Ticari VPN | Kaynağın VPN'e bağlandığını görür; olağan hedef metadata'sını görmez | VPN, kaynak ve hedef metadata'sını görür | VPN çıkış IP'si | Bir provider korelasyon noktası hâline gelir | Genellikle hızlı |
| Self-hosted VPN/VPS | Kaynağın VPS'e bağlandığını görür | Host/account/payment/control-plane logları | VPS çıkış IP'si | Kiralanan sunucuya/account'a kolayca bağlanabilir | Genellikle hızlı |
| Tor Browser | Kaynağın Tor/bridge'e bağlandığını; zamanlama/hacmi görür | Her relay sınırlı bir bölümü görür | Tor exit, browser verileri | Daha yavaş; account/endpoint/korelasyon riskleri | Orta/yavaş |
| Tails/Whonix | Daha güçlü yönlendirme sınırlarına sahip benzer Tor yolu | Aynı Tor sınırlamaları | Tor exit/application verileri | Operasyonel hatalar ve host/hardware etkilenmeye devam eder | Orta/yavaş |
| Genel misafir Wi-Fi + HTTPS | Mekân, yerel cihazı/zamanlamayı ve hedefleri görür | Mekânın ISP'si metadata'yı görür | Misafir genel IP'si | Fiziksel/captive-portal/cihaz korelasyonu | Hızlı/değişken |
| Cellular hotspot | Carrier, subscriber/device/location ve hedefleri görür | Kullanılıyorsa VPN/Tor | Carrier, VPN veya Tor çıkış IP'si | Mobil abonelik ve konum kalıcı identifier'lardır | Hızlı/değişken |
| Mixnet | Erişim, mixnet kullanımını; zamanlama/hacmi görür | Birden çok mixing node | Gateway/egress | Gelişmekte olan ekosistem; gecikme ve bandwidth maliyeti | En yavaş |

HTTPS, aktarım sırasında içeriği korur ancak tüm metadata'yı korumaz. EFF, sayfa yolları, credentials ve mesajlar şifrelenmiş olsa bile domain, zaman ve traffic size bilgilerinin aracılar tarafından görünür kalabileceğini belirtir.<sup>[[1]](#references)</sup>

## VPN'ler: yoğunlaştırılmış güven ile hızlı gizlilik

VPN, hedef metadata'sını access ISP'den gizlemek, güvenilmeyen bir ağdaki ilk hop'u korumak, istikrarlı bir engagement egress adresi sunmak veya özel bir ağa ulaşmak için kullanışlıdır. Ancak kullanıcıyı **anonymous** hâle getirmez. VPN, kaynak bağlantısını görür ve hedef metadata'sını gözlemleyebilir; account'lar, cookie'ler, GPS, fingerprint'ler ve ödeme bilgileri varlığını korur.<sup>[[1]](#references)</sup>

### Provider değerlendirme kontrol listesi

1. **Ownership ve jurisdiction:** Tüzel kişiyi, ana şirketi, faaliyet gösterilen ülkeleri, altyapı subcontractor'larını ve geçerli legal process'i belirleyin.
2. **Toplanan veriler:** Account/billing, source IP, connection timestamp'leri, bandwidth, crash telemetry, DNS query'leri ve destination log'larını birbirinden ayırın. “No browsing logs”, “no data” anlamına gelmez.
3. **Retention ve deletion:** Kesin süreleri ve backup'ların, fraud sistemlerinin ve processor'ların aynı takvime uyup uymadığını bulun.
4. **Kanıt:** Kapsamı, tarihi, bulguları ve remediation'ı belirten public audit'leri; reproducible/open client'ları; transparency report'larını ve belgelenmiş incident'ları tercih edin.
5. **Protocol ve client:** Güncel WireGuard, OpenVPN veya incelenmiş başka bir protocol; automatic update'ler; DNS ve IPv6 yönetimi; kill switch ve platform başına leak test'leri.
6. **Business model:** Ücretsiz veya subsidized bir service'in nasıl finanse edildiğini anlayın. App-store'da bulunması tek başına güvenilir operation kanıtı değildir.
7. **Payment uyumu:** Alternatif payment, billing bilgilerinin VPN'e açıklanmasını azaltabilir ancak her bağlantıda gözlemlenen source IP'yi ortadan kaldırmaz.

### VPN'i yapılandırma ve doğrulama

1. Provider/organization tarafından imzalanmış client'ı resmi kaynağından kurun.
2. Belgelenmiş bir route'un bypass etmesi gerekmiyorsa **full tunnel** seçin. Split tunneling korelasyon ve leak yolları oluşturur.
3. Fail-closed/always-on davranışını etkinleştirin ve reconnect sırasında traffic'i engelleyin.
4. DNS'i tunnel üzerinden gönderin ve hem IPv4 hem IPv6'yı test edin. Bir protocol'ü yalnızca güvenli şekilde tunnel edilemiyorsa ve işlev kaybı kabul ediliyorsa devre dışı bırakın.
5. Sleep/wake, network switching, captive-portal login, tunnel crash ve hotspot tethering durumlarını test edin. NCSC, bazı platformlarda tethered client'ların telefonun VPN'ini bypass edebileceği konusunda uyarır.<sup>[[2]](#references)</sup>
6. Gözlemlenen IPv4, IPv6, DNS resolver ve connection timing bilgilerini kaydetmek için organization-controlled bir test endpoint'i kullanın. Hassas bir engagement'ı rastgele “leak test” sitelerine açmayın.
7. Client, OS, network veya policy değişikliklerinden sonra yeniden test edin.

## Tor Browser: daha güçlü web unlinkability

Tor, tek bir relay'in normalde hem kaynağı hem de hedefi bilmemesi için birden çok relay üzerinden circuit oluşturur. Hedef, kullanıcının IP'si yerine bir Tor exit görür; yerel ağ ise normalde bir Tor bağlantısı görür.<sup>[[3]](#references)</sup> Tor, düşük gecikmeli TCP application'ları için tasarlanmıştır; bu nedenle daha yavaştır ve her iki ucu correlate edebilen bir adversary'ye karşı koruma garantisi veremez.<sup>[[4]](#references)</sup>

### Güvenli Tor Browser iş akışı

1. Tor Browser'ı yalnızca Tor Project veya resmi bir mirror'dan indirin ve mümkün olduğunda signature'ı doğrulayın.
2. Normal bir browser'ı Tor SOCKS port'una yönlendirmek yerine **Tor Browser** kullanın. Sıradan browser'lar DNS/WebRTC ve tanımlayıcı state leak'leri yapabilir.<sup>[[5]](#references)</sup>
3. Varsayılan size, font'lar, extension'lar ve privacy setting'lerini koruyun. Ek add-on'lar browser'ı daha unique hâle getirebilir.<sup>[[6]](#references)</sup>
4. Artan breakage kabul edilebilirse **Safer** veya **Safest** security level'ı seçin.
5. Doğrudan Tor engelleniyorsa veya sıradan relay IP'leri kabul edilemez bir yerel görünürlük oluşturacaksa bridge kullanın. Bridge'ler kolay tanınmayı azaltır; traffic analysis'i ortadan kaldırmaz.<sup>[[7]](#references)</sup>
6. Tanımlayıcı bir account'a login olmayın, tanımlayıcı bilgi vermeyin veya indirilen active document'ları harici, networked bir application'da açmayın.
7. Her identity için ayrı bir session/context kullanın. “New circuit”, browser/application identity'sini silmekle aynı şey değildir; uygun şekilde **New Identity** kullanın veya izole environment'ı yeniden başlatın.
8. Authenticated HTTPS veya authenticated onion service tercih edin. Bir Tor exit, şifrelenmemiş HTTP traffic'ini gözlemleyebilir.

### Tor ve VPN birlikte kullanımı

Bunları birlikte kullanmak otomatik olarak daha güvenli değildir. Tor'dan önce VPN kullanmak, ISP'den doğrudan Tor relay bağlantılarını gizleyebilir; ancak VPN source'u görür. Tor'dan sonra VPN kullanmak, VPN'e Tor sonrası activity'nin istikrarlı bir görünümünü verir ve anonymity set'i küçültebilir. Yanlış configuration leak'ler oluşturabilir. Tor Project, bu tür kombinasyonları yalnızca advanced ve açık threat model'ler için önerir.<sup>[[8]](#references)</sup>

## Genel ve misafir Wi-Fi

Modern HTTPS, pasif komşuların düzgün şekilde şifrelenmiş web içeriğini genellikle okuyamamasını sağlar; ancak misafir Wi-Fi anonymity değildir. Mekân association time'larını, device identifier'larını, captive-portal verilerini, hedefleri ve DHCP ayrıntılarını kaydedebilir; kameralar, purchases, ulaşım ve fiziksel gözlem kullanıcıyı tanımlayabilir. Benzer isimli sahte bir hotspot, portal credential'larını ele geçirebilir veya şifrelenmemiş traffic'i değiştirebilir.<sup>[[9]](#references)</sup>

### Hukuka uygun misafir ağı iş akışı

1. Yalnızca misafirlere sunulan veya sahibinin açıkça izin verdiği bir ağı kullanın. Personelden kesin SSID'yi ve portal prosedürünü isteyin.
2. Endpoint'i ve travel router'ı varıştan önce güncelleyin. File/printer sharing, inbound discovery, auto-join ve remembered-network probing'i devre dışı bırakın.
3. OS'nin private/randomized Wi-Fi address özelliğini etkinleştirin. Güncel Apple sistemleri açık/zayıf ağlarda rotating address kullanabilir; modern Android randomization genellikle SSID başına kalıcıdır. Bu, yalnızca bir yerel identifier'ı azaltır.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Privileged workstation ile misafir ağı arasına organization-controlled bir travel router veya low-trust bridge device koymayı tercih edin. Bu, firewall/VPN policy'sini merkezileştirir ancak router'ı mekândan gizlemez.<sup>[[12]](#references)</sup>
5. Captive portal'ı yalnızca belirlenmiş low-trust device/browser üzerinden tamamlayın. Sözde anonymous bir context için kişisel veya yeniden kullanılan credential'ları asla girmeyin. Bağlantı kurulduktan sonra portal browser'ını kapatın.
6. Hassas activity'den önce full-tunnel VPN veya Tor başlatın ve fail-closed davranışını doğrulayın.
7. Kullanımdan sonra ağı unutun ve portal account/data-retention policy'sini inceleyin.

{% hint style="danger" %}
Komşunun Wi-Fi'ını crack etmek, portal'ı bypass etmek, leaked misafir credential'larını kullanmak, başka bir misafirin access'ini clone etmek veya bir café'ye Raspberry Pi gizlemek yetkisiz activity'dir; privacy technique değildir. Güvenli eşdeğerleri hukuka uygun bir misafir ağı, client-approved bir site veya mülk sahibinin yazılı izniyle yerleştirilip geri alınan documented bir drop node'dur.
{% endhint %}

## Travel router'lar

Travel router, bir workstation'ı hostile local broadcast'lardan izole edebilir, firewall uygulayabilir, tutarlı bir internal SSID sağlayabilir ve VPN'i otomatik olarak yeniden bağlayabilir. **Anonymous** değildir: upstream, radio identity'sini ve traffic timing'ini görür; VPN provider'ı tunnel source'unu görür.

- Desteklenen OpenWrt/vendor firmware kullanın ve kullanılmayan service'leri kaldırın.
- Ethernet veya unique password içeren özel bir management SSID üzerinden administer edin.
- WAN-side administration, UPnP, WPS, file sharing ve istenmeyen inbound traffic'i devre dışı bırakın.
- Yalnızca desteklendiği ve izin verildiği durumlarda randomized/private WAN MAC kullanın.
- DNS ve IPv6 dahil olmak üzere router üzerinde VPN policy uygulayın ve tunnel başarısız olduğunda egress'i engelleyin.
- Bir phone hotspot'un tethered device'ları telefonun VPN'i üzerinden tunnel edeceğini varsaymayın; test edin.

## Cellular, SIM'ler ve eSIM'ler

Cellular kullanışlıdır ancak anonymous değildir. Operator'lar subscriber/device identifier'larını ve network attachment'tan türetilen konumu tutar; eSIM hâlâ bir mobile subscription'dır. Prepaid, güvenilir biçimde unregistered anlamına gelmez; gereksinimler ülkeye göre değişir ve değişebilir.<sup>[[13]](#references)</sup>

Operasyonel olarak:

- Kişisel verilerin exposure'ını azaltmak için ayrı ve desteklenen bir device kullanın; fictional bir subscriber oluşturmak için değil.
- Threat model'de co-location varsa “ayrı” bir device'ı kişisel phone'un yanında sürekli taşımayın.
- Kullanılmayan cellular, Wi-Fi, Bluetooth ve location access'i devre dışı bırakın; power off, UI toggle'larından daha güçlü bir radio boundary'dir.
- Hassas traffic'i approved VPN/Tor path içine alın; carrier'ın subscription/device location'ını ve tunnel endpoint'ini hâlâ bildiğini unutmayın.
- Güncel registration ve retention kurallarını national regulator veya local counsel ile doğrulayın; “anonymous SIM countries” çevrim içi listelerine güvenmeyin.

## DNS ve TLS metadata'sı

- **DoH/DoT/DoQ**, client ile resolver arasındaki DNS'i şifreleyerek basit yerel okuma veya değiştirmeyi engeller; ancak resolver query'leri ve transport identifier'larını yine görür. Güveni taşırlar; anonymity sağlamazlar.<sup>[[14]](#references)</sup>
- **ODoH**, proxy ekleyerek proxy ile target'ın collude etmediği varsayımıyla resolver'ın client IP'sini öğrenmesine gerek bırakmaz. Traffic analysis açıkça kapsam dışıdır.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)**, client, DNS ve server desteklediğinde TLS handshake içindeki inner server name'i koruyabilir. Destination IP, timing, volume ve endpoint görünür kalır.<sup>[[16]](#references)</sup>
- Doğru yapılandırılmış bir VPN veya Tor environment'ında DNS, environment'ın desteklenen route'unu izlemelidir. Ayrı bir resolver eklemek yeni bir observer veya fingerprint oluşturabilir.

### Encrypted-DNS/ECH doğrulama iş akışı

1. DNS'in VPN/Tor environment'ı, OS veya application tarafından mı kontrol edildiğine karar verin. İlişkisiz resolver'ları üst üste eklemek yerine **tek** amaçlanan layer'da yapılandırın.
2. Published privacy/retention policy'sinden bir resolver seçin ve platform destekliyorsa strict encrypted mode'u etkinleştirin. Opportunistic fallback sessizce plaintext'e dönebilir.
3. Kontrolünüzdeki authoritative test zone altında unique bir subdomain sorgulayın; authoritative log'un amaçlanan recursive resolver'ı gördüğünü doğrulayın.
4. Yalnızca test device'ının traffic'ini authorization ile capture edin. Access network'ün plaintext DNS'i okuyamadığını doğrulayın; encrypted resolver/tunnel endpoint'ini görebileceğini unutmayın.
5. Blocked/unreachable encrypted resolver'ı test edin. Pass koşulu, seçilen fail-closed veya documented fallback davranışıdır; tesadüfi bir clear query değildir.
6. ECH için kontrollü bir ECH-enabled host kullanın ve **inner** ClientHello'nun kabul edildiğini doğrulamak üzere client/server diagnostics'i inceleyin. Yalnızca HTTPS record sunmak, ECH'nin başarılı olduğunu kanıtlamaz.
7. Network changes, captive portal, browser update'leri ve VPN reconnect'lerinden sonra tekrarlayın. Daha sonraki administrator'ların bypass oluşturmaması için DNS/ECH'nin hangi component'e ait olduğunu kaydedin.

## Mixnet'ler

Nym veya Katzenpost gibi mixnet'ler, timing correlation'a karşı koymak için fixed-size packet'lar, delay, reordering ve cover traffic ekler. Bu özellikler latency ve bandwidth maliyetine yol açar; bağımsız deployment-scale kanıtı sınırlıdır. Mevcut consumer mixnet'lerini Tor/VPN'lerin daha hızlı veya guaranteed replacement'ları olarak değil, **emerging/high-latency options** olarak değerlendirin.<sup>[[17]](#references)</sup>

### Değerlendirme iş akışı

1. Güncel bir client'ı ve tam olarak desteklenen application'ı belirleyin; arbitrary browser/system traffic'ini documented olmayan bir proxy üzerinden zorla geçirmeyin.
2. Entry, mix node'lar, gateway, destination ve collusion varsayımları için güncel threat model'i okuyun.
3. Official signed source'tan ayrı bir test compartment'ına kurun ve yalnızca size ait benign bir endpoint kullanın.
4. Delivery latency, message-size limit'leri, reliability, retransmission ve gateway kullanılamadığında ne olduğunu ölçün.
5. Amaçlanan path'i ve source'u doğrulamak için local traffic'i ve size ait endpoint'i inceleyin. Reply'ların aynı privacy design'ını kullanıp kullanmadığını kontrol edin.
6. Shutdown/failure durumunu test edin: application sessizce direct Internet access'e fallback yapmamalıdır.
7. Sırf hız için cover traffic'i devre dışı bırakmayın, delay'leri azaltmayın veya alışılmadık fixed route'lar seçmeyin; bu değişiklikler belirtilen anonymity model'ini geçersiz kılabilir.
8. Belirli deployment, bağımsız analysis ve operasyonel reliability, consequence level'ı karşılayana kadar bunu experimental olarak tutun.

## Ağ preflight kontrol listesi

- [ ] Authorization; access network, target, dates ve source infrastructure'ı kapsıyor.
- [ ] Endpoint, ilgisiz identity'ler veya active sync session'ları içermiyor.
- [ ] IPv4, IPv6, DNS ve reconnect davranışı planla eşleşiyor.
- [ ] Destination yalnızca beklenen egress'i görüyor.
- [ ] Captive portal ve hotspot davranışı hassas traffic olmadan test edildi.
- [ ] Local sharing/discovery ve automatic network joining devre dışı.
- [ ] Observer table ve kalan traffic-correlation riski kabul edildi.
- [ ] Provider policy, retention ve emergency contact güncel.

Split-knowledge relay'ler, route-enforced workload'lar, pluggable transport'lar, onion service'ler, I2P ve disposable remote browser'lar için [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) sayfasına geçin.

## References

- [1] [EFF — Sizin için doğru VPN'i seçme](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Cihaz güvenliği rehberi: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor'un sunduğu privacy ve anonymity protections](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Tor'a kısa bir giriş](https://spec.torproject.org/intro/)
- [5] [Tor Project — Tor'u diğer browser'larla kullanma](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser'da plugin'ler ve add-on'lar](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Tor'un engelini kaldırma](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Tor Browser'ı VPN ile kullanma](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Genel Wi-Fi network'leri güvenli mi?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple cihazlarıyla Wi-Fi privacy](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC randomization uygulama](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Secure Privileged Access Workstation'lar için principles](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Zorunlu SIM registration: policy ve regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Privacy Service Operator'ları için recommendations](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
