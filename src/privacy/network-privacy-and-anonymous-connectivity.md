# Ağ Gizliliği ve Anonim Bağlantı

Ağ gizliliği bir yönlendirme kararıdır; eksiksiz bir kimlik değildir. Bir yol seçerken **kaynağı**, **hedefi**, **içeriği** ve **zamanlamayı** kimin birbirine bağlayamaması gerektiğini sorun.

Her erişim yolu ailesi için normalize edilmiş envanter—`Pros`, `Cons`, adım adım `Procedure` ve `Detection`—için [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) ile başlayın. Bu sayfa, yaygın olarak dağıtılabilir seçenekleri genişletir.

## Her gözlemcinin genellikle görebildikleri

| Yol | Yerel ağ / ISP | Aracı | Hedef | Temel sınırlama | Göreli hız |
|---|---|---|---|---|---|
| Doğrudan HTTPS | Kaynak, hedef metadata'sı, zamanlama/hacim | Hosting/CDN bağlantıyı görür | Kaynak IP'si, browser/app verileri | Kaynak-IP gizliliği yok | En hızlı |
| Commercial VPN | VPN'e bağlı kaynak; normal hedef metadata'sı yok | VPN kaynak ve hedef metadata'sını görür | VPN çıkış IP'si | Bir sağlayıcı korelasyon noktası olur | Genellikle hızlı |
| Self-hosted VPN/VPS | VPS'e bağlı kaynak | Host/account/payment/control-plane logları | VPS çıkış IP'si | Kiralanan server/account'a atfedilmesi kolay | Genellikle hızlı |
| Tor Browser | Tor/bridge'e bağlı kaynak; zamanlama/hacim | Her relay sınırlı bir bölümü görür | Tor exit, browser verileri | Daha yavaş; account/endpoint/korelasyon riskleri | Orta/yavaş |
| Tails/Whonix | Daha güçlü routing sınırlarıyla benzer Tor yolu | Aynı Tor sınırlamaları | Tor exit/application verileri | Operasyonel hatalar ve host/hardware etkilenmeye devam eder | Orta/yavaş |
| Public guest Wi-Fi + HTTPS | Mekân yerel cihazı/zamanlamayı ve hedefleri görür | Mekânın ISP'si metadata'yı görür | Guest public IP'si | Fiziksel/captive-portal/device korelasyonu | Hızlı/değişken |
| Cellular hotspot | Carrier subscriber/device/location ve hedefleri görür | Kullanılmışsa VPN/Tor | Carrier, VPN veya Tor çıkış IP'si | Mobile subscription ve location kalıcı tanımlayıcılardır | Hızlı/değişken |
| Mixnet | Erişim, mixnet kullanımını; zamanlama/hacmi görür | Birden fazla mixing node | Gateway/egress | Gelişmekte olan ekosistem; latency ve bandwidth maliyeti | En yavaş |

HTTPS aktarım sırasında içeriği korur, ancak tüm metadata'yı korumaz. EFF, sayfa yolları, kimlik bilgileri ve mesajlar şifrelenmiş olsa bile domain, zaman ve trafik boyutunun aracılar tarafından görünür kalabileceğini belirtir.<sup>[[1]](#references)</sup>

## VPN'ler: yoğunlaştırılmış güven ile hızlı gizlilik

VPN; erişim ISP'sinden hedef metadata'sını gizlemek, güvenilmeyen bir ağdaki ilk hop'u korumak, sabit bir engagement egress adresi sunmak veya private network'e erişmek için kullanışlıdır. Ancak kullanıcıyı anonymous yapmaz. VPN kaynak bağlantısını görür ve hedef metadata'sını gözlemleyebilir; account'lar, cookie'ler, GPS, fingerprint'ler ve payment bilgileri varlığını korur.<sup>[[1]](#references)</sup>

### Provider değerlendirme checklist'i

1. **Ownership ve jurisdiction:** legal entity'yi, parent company'yi, faaliyet gösterilen ülkeleri, infrastructure subcontractor'larını ve geçerli legal process'i belirleyin.
2. **Toplanan veriler:** account/billing, source IP, connection timestamp'leri, bandwidth, crash telemetry, DNS query'leri ve destination loglarını birbirinden ayırın. “No browsing logs”, “no data” anlamına gelmez.
3. **Retention ve deletion:** kesin süreleri ve backup'ların, fraud system'larının ve processor'ların aynı takvime uyup uymadığını bulun.
4. **Kanıt:** kapsamı, tarihi, bulguları ve remediation'ı açıkça belirten public audit'leri; reproducible/open client'ları; transparency report'larını ve belgelenmiş incident'ları tercih edin.
5. **Protocol ve client:** bakımı yapılan WireGuard, OpenVPN veya incelenmiş başka bir protocol; automatic update'ler; DNS ve IPv6 handling; kill switch; her platform için leak test'leri.
6. **Business model:** ücretsiz veya sübvanse edilen bir service'in nasıl finanse edildiğini anlayın. App-store'da bulunması tek başına güvenilir operation kanıtı değildir.
7. **Payment uyumu:** alternative payment, billing disclosure'ı VPN'e azaltabilir ancak her connection'da gözlemlenen source IP'yi ortadan kaldırmaz.

### VPN'i yapılandırma ve doğrulama

1. Provider/organization tarafından imzalanmış client'ı official source'undan kurun.
2. Belgelenmiş bir route'un VPN'i bypass etmesi gerekmiyorsa **full tunnel** seçin. Split tunneling korelasyon ve leak yolları oluşturur.
3. Fail-closed/always-on davranışını etkinleştirin ve reconnect sırasında trafiği block edin.
4. DNS'i tunnel üzerinden gönderin ve hem IPv4 hem de IPv6'yı test edin. Bir protocol güvenli biçimde tunnel edilemiyorsa ve functionality kaybı kabul ediliyorsa yalnızca o zaman devre dışı bırakın.
5. Sleep/wake, network switching, captive-portal login, tunnel crash ve hotspot tethering durumlarını test edin. NCSC, bazı platformlarda tethered client'ların telefonun VPN'ini bypass edebileceği konusunda uyarır.<sup>[[2]](#references)</sup>
6. Gözlemlenen IPv4, IPv6, DNS resolver ve connection timing bilgilerini kaydetmek için organization-controlled bir test endpoint'i kullanın. Hassas bir engagement'ı rastgele “leak test” sitelerine açmayın.
7. Client, OS, network veya policy değişikliklerinden sonra yeniden test edin.

## Tor Browser: daha güçlü web unlinkability

Tor, tek bir relay'in normalde hem kaynağı hem de hedefi bilmemesi için birden fazla relay üzerinden bir circuit oluşturur. Hedef, kullanıcının IP'si yerine bir Tor exit görür; local network ise normalde bir Tor bağlantısı görür.<sup>[[3]](#references)</sup> Tor, düşük latency'li TCP application'lar için tasarlanmıştır; bu nedenle daha yavaştır ve her iki ucu correlate edebilen bir adversary'ye karşı korumayı garanti edemez.<sup>[[4]](#references)</sup>

### Güvenli Tor Browser workflow'u

1. Tor Browser'ı yalnızca Tor Project veya official mirror'dan indirin ve mümkün olduğunda signature'ı doğrulayın.
2. Normal bir browser'ı Tor SOCKS port'una yönlendirmek yerine **Tor Browser** kullanın. Ordinary browser'lar DNS/WebRTC ve identifying state leak edebilir.<sup>[[5]](#references)</sup>
3. Varsayılan size, font, extension ve privacy setting'lerini koruyun. Ek add-on'lar browser'ı daha unique hale getirebilir.<sup>[[6]](#references)</sup>
4. Artan breakage kabul edilebilir olduğunda **Safer** veya **Safest** security level'ı seçin.
5. Direct Tor block ediliyorsa veya ordinary relay IP'leri local visibility açısından kabul edilemezse bridge kullanın. Bridge'ler kolay tanınmayı azaltır; traffic analysis'i ortadan kaldırmaz.<sup>[[7]](#references)</sup>
6. Identifying bir account'a login yapmayın, identifying bilgi vermeyin veya indirilen active document'ları harici networked application'da açmayın.
7. Her identity için ayrı bir session/context kullanın. “New circuit”, browser/application identity'sini silmekle aynı değildir; uygun şekilde **New Identity** kullanın veya isolated environment'ı yeniden başlatın.
8. Authenticated HTTPS veya authenticated onion service tercih edin. Tor exit, şifrelenmemiş HTTP trafiğini gözlemleyebilir.

### Tor ve VPN birlikte

Bunları birleştirmek otomatik olarak daha güvenli değildir. Tor'dan önce VPN kullanmak, ISP'den direct Tor relay bağlantılarını gizleyebilir; ancak VPN source'u görür. Tor'dan sonra VPN kullanmak, VPN'e Tor sonrası activity'nin sabit bir görünümünü verir ve anonymity set'i küçültebilir. Hatalı yapılandırma leak'lere yol açabilir. Tor Project, bu tür kombinasyonları yalnızca advanced ve açıkça tanımlanmış threat model'ler için önerir.<sup>[[8]](#references)</sup>

## Public ve guest Wi-Fi

Modern HTTPS, pasif komşuların düzgün şekilde şifrelenmiş web içeriğini genellikle okuyamaması anlamına gelir; ancak guest Wi-Fi anonymity değildir. Mekân association time'larını, device identifier'larını, captive-portal verilerini, destination'ları ve DHCP ayrıntılarını kaydedebilir; camera'lar, purchase'lar, transport ve physical observation kullanıcıyı identify edebilir. Sahte, benzer adlı bir hotspot portal credential'larını da ele geçirebilir veya şifrelenmemiş trafiği manipüle edebilir.<sup>[[9]](#references)</sup>

### Yasal guest-network workflow'u

1. Yalnızca guest'ler için sunulan veya sahibinin explicit permission verdiği bir network kullanın. Personelden exact SSID ve portal procedure'ünü isteyin.
2. Endpoint'i ve travel router'ı varıştan önce update edin. File/printer sharing, inbound discovery, auto-join ve remembered-network probing'i devre dışı bırakın.
3. OS'in private/randomized Wi-Fi address özelliğini etkinleştirin. Güncel Apple system'leri open/weak network'lerde rotating address kullanabilir; modern Android randomization genellikle SSID başına persistent'tır. Bu yalnızca bir local identifier'ı azaltır.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Privileged workstation ile guest network arasında organization-controlled travel router veya low-trust bridge device kullanmayı tercih edin. Bu, firewall/VPN policy'sini merkezileştirir ancak router'ı mekândan gizlemez.<sup>[[12]](#references)</sup>
5. Captive portal'ı yalnızca belirlenmiş low-trust device/browser üzerinden tamamlayın. Anonymous olduğu varsayılan bir context için hiçbir zaman personal veya reused credential girmeyin. Connectivity sağlandıktan sonra portal browser'ını kapatın.
6. Hassas activity'den önce full-tunnel VPN veya Tor başlatın ve fail-closed davranışını doğrulayın.
7. Kullanımdan sonra network'ü unutun ve portal account/data-retention policy'sini inceleyin.

{% hint style="danger" %}
Komşunun Wi-Fi'ını crack etmek, portal'ı bypass etmek, leaked guest credential'larını kullanmak, başka bir guest'in access'ini clone etmek veya bir café'ye Raspberry Pi gizlemek unauthorized activity'dir; privacy technique değildir. Güvenli karşılıklar lawful guest network, client-approved site veya property owner'ın yazılı consent'iyle yerleştirilip geri alınan documented drop node'dur.
{% endhint %}

## Travel router'lar

Travel router, bir workstation'ı hostile local broadcast'lardan izole edebilir, firewall uygulayabilir, tutarlı bir internal SSID sağlayabilir ve VPN'e automatic olarak yeniden bağlanabilir. **Anonymous değildir:** upstream, radio identity'sini ve traffic timing'ini görür; VPN provider'ı ise tunnel source'unu görür.

- Desteklenen OpenWrt/vendor firmware kullanın ve kullanılmayan service'leri kaldırın.
- Ethernet veya unique password'lü özel bir management SSID üzerinden administer edin.
- WAN-side administration, UPnP, WPS, file sharing ve unsolicited inbound traffic'i devre dışı bırakın.
- Yalnızca desteklendiği ve izin verildiği durumlarda randomized/private WAN MAC kullanın.
- DNS ve IPv6 dahil VPN policy'sini router üzerinde enforce edin ve tunnel başarısız olduğunda egress'i block edin.
- Telefon hotspot'unun tethered device'ları telefonun VPN'inden geçirdiğini varsaymayın; test edin.

## Cellular, SIM ve eSIM'ler

Cellular kullanışlıdır ancak anonymous değildir. Operator'ler subscriber/device identifier'larını ve network attachment'tan türetilen location bilgisini tutar; eSIM hâlâ bir mobile subscription'dır. Prepaid, güvenilir biçimde unregistered anlamına gelmez; gereklilikler ülkeye göre değişir ve güncellenir.<sup>[[13]](#references)</sup>

Operasyonel olarak:

- Personal data exposure'ını azaltmak için ayrı ve desteklenen bir device kullanın; fictional bir subscriber oluşturmak için değil.
- Threat model'de co-location varsa “ayrı” bir device'ı personal phone'un yanında sürekli taşımayın.
- Kullanılmayan cellular, Wi-Fi, Bluetooth ve location access'i devre dışı bırakın; power off, UI toggle'larından daha güçlü bir radio boundary'dir.
- Hassas trafiği approved VPN/Tor path içine alın; carrier'ın subscription/device location'ını ve tunnel endpoint'ini hâlâ bildiğini unutmayın.
- Güncel registration ve retention rules'ı national regulator veya local counsel ile doğrulayın; “anonymous SIM countries” online listelerine güvenmeyin.

## DNS ve TLS metadata'sı

- **DoH/DoT/DoQ**, client ile resolver arasındaki DNS'i şifreleyerek basit local reading veya modification'ı engeller; ancak resolver query'leri ve transport identifier'larını görmeye devam eder. Trust'ı taşırlar; anonymity sağlamazlar.<sup>[[14]](#references)</sup>
- **ODoH**, resolver'ın client IP'sini öğrenmemesi için bir proxy ekler; proxy ve target'ın collude etmediği varsayılır. Traffic analysis açıkça kapsam dışıdır.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)**, client, DNS ve server desteklediğinde TLS handshake içindeki inner server name'i koruyabilir. Destination IP, timing, volume ve endpoint görünür kalır.<sup>[[16]](#references)</sup>
- Doğru yapılandırılmış bir VPN veya Tor environment'ında DNS, o environment'ın desteklenen route'unu izlemelidir. Ayrı bir resolver eklemek yeni bir observer veya fingerprint oluşturabilir.

### Encrypted-DNS/ECH doğrulama workflow'u

1. DNS'in VPN/Tor environment'ı, OS veya application tarafından kontrol edilip edilmediğine karar verin. İlişkisiz resolver'ları üst üste eklemek yerine **tek** bir intended layer'da yapılandırın.
2. Resolver'ı yayınlanmış privacy/retention policy'sine göre seçin ve platform destekliyorsa strict encrypted mode'u etkinleştirin. Opportunistic fallback sessizce plaintext'e dönebilir.
3. Kontrol ettiğiniz authoritative test zone altında unique bir subdomain sorgulayın; authoritative log'un intended recursive resolver'ı gördüğünü doğrulayın.
4. Yalnızca test device'ının trafiğini authorization ile capture edin. Access network'ün plaintext DNS'i okuyamadığını doğrulayın; ancak encrypted resolver/tunnel endpoint'ini görebileceğini unutmayın.
5. Blocked/unreachable bir encrypted resolver'ı test edin. Pass condition, seçilen fail-closed veya documented fallback davranışıdır; accidental clear query değildir.
6. ECH için kontrollü bir ECH-enabled host kullanın ve **inner** ClientHello'nun kabul edildiğini doğrulamak üzere client/server diagnostic'lerini inceleyin. Sadece bir HTTPS record sunulması ECH'nin başarılı olduğunu kanıtlamaz.
7. Network değişikliklerinden, captive portal'lardan, browser update'lerinden ve VPN reconnect'lerinden sonra tekrarlayın. Daha sonraki administrator'ların bypass oluşturmaması için DNS/ECH'nin hangi component'e ait olduğunu kaydedin.

## Mixnet'ler

Nym veya Katzenpost gibi mixnet'ler, timing correlation'a direnmek için fixed-size packet'lar, delay, reordering ve cover traffic ekler. Bu özellikler latency ve bandwidth maliyetine yol açar; bağımsız deployment-scale kanıtı sınırlıdır. Güncel consumer mixnet'lerini Tor/VPN'lerin daha hızlı veya guaranteed replacement'ları olarak değil, **emerging/high-latency options** olarak değerlendirin.<sup>[[17]](#references)</sup>

### Evaluation workflow'u

1. Maintained bir client'ı ve desteklenen exact application'ı belirleyin; undocumented bir proxy üzerinden arbitrary browser/system traffic'i zorlamayın.
2. Entry, mix node'lar, gateway, destination ve collusion varsayımları için güncel threat model'i okuyun.
3. Official signed source'tan ayrı bir test compartment'ına kurun ve yalnızca size ait benign bir endpoint kullanın.
4. Delivery latency, message-size limit'leri, reliability, retransmission ve gateway kullanılamadığında ne olduğunu ölçün.
5. Intended path ve source'u doğrulamak için local traffic'i ve size ait endpoint'i inceleyin. Reply'ların aynı privacy design'ını kullanıp kullanmadığını kontrol edin.
6. Shutdown/failure durumunu test edin: application sessizce direct Internet access'e fallback yapmamalıdır.
7. Sırf speed için cover traffic'i devre dışı bırakmayın, delay'leri azaltmayın veya unusual fixed route'lar seçmeyin; bu değişiklikler belirtilen anonymity model'ini geçersiz kılabilir.
8. Belirli deployment, independent analysis ve operational reliability consequence level'ı karşılayana kadar bunu experimental olarak tutun.

## Network preflight checklist'i

- [ ] Authorization; access network'ü, target'ı, tarihleri ve source infrastructure'ı kapsıyor.
- [ ] Endpoint, ilgisiz identity'ler veya active sync session'ları içermiyor.
- [ ] IPv4, IPv6, DNS ve reconnect davranışı planla uyumlu.
- [ ] Destination yalnızca beklenen egress'i görüyor.
- [ ] Captive portal ve hotspot davranışı hassas traffic olmadan test edildi.
- [ ] Local sharing/discovery ve automatic network joining devre dışı.
- [ ] Observer table ve kalan traffic-correlation risk'i kabul edildi.
- [ ] Provider policy, retention ve emergency contact güncel.

Split-knowledge relay'ler, route-enforced workload'lar, pluggable transport'lar, onion service'ler, I2P ve disposable remote browser'lar için [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) sayfasına devam edin.

## References

- [1] [EFF — Size Uygun VPN'i Seçme](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Device security guidance: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor'un sunduğu privacy ve anonymity protections](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Tor'a kısa bir giriş](https://spec.torproject.org/intro/)
- [5] [Tor Project — Tor'u diğer browser'larla kullanma](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser'da plugin'ler ve add-on'lar](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Tor'un engelini kaldırma](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Tor Browser'ı VPN ile kullanma](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Public Wi-Fi Network'leri güvenli mi?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple device'larıyla Wi-Fi privacy](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC randomization uygulama](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Secure Privileged Access Workstation'lar için principles](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: policy ve regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Privacy Service Operator'ları için recommendations](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
