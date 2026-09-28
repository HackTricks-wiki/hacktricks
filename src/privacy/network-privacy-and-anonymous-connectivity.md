# Network Privacy & Anonymous Connectivity

{{#include ../banners/hacktricks-training.md}}

Network privacy bir routing kararıdır, tam bir kimlik değildir. Bir yol seçerken **source**, **destination**, **content** ve **timing** bilgilerinin kim tarafından ilişkilendirilememesi gerektiğini sorun.

Normalize edilmiş envanter—her access-path ailesi için `Pros`, `Cons`, adım adım `Procedure` ve `Detection`—için [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) ile başlayın. Bu sayfa, yaygın olarak kullanılabilir seçenekleri genişletir.

## What each observer can usually see

| Path | Local network / ISP | Intermediary | Destination | Main limitation | Relative speed |
|---|---|---|---|---|---|
| Direct HTTPS | Source, destination metadata, timing/volume | Hosting/CDN bağlantıyı görür | Source IP, browser/app data | Source-IP privacy yok | Fastest |
| Commercial VPN | Source VPN'e bağlı; usual destination metadata görünmez | VPN source ve destination metadata'yı görür | VPN egress IP | Tek bir provider correlation point haline gelir | Usually fast |
| Self-hosted VPN/VPS | Source VPS'e bağlı | Host/account/payment/control-plane logs | VPS egress IP | Kiralanan server/account ile ilişkilendirmek kolaydır | Usually fast |
| Tor Browser | Source Tor/bridge'e bağlı; timing/volume | Her relay sınırlı bir bölümü görür | Tor exit, browser data | Daha yavaş; account/endpoint/correlation riskleri | Moderate/slow |
| Tails/Whonix | Daha güçlü routing boundaries ile benzer Tor yolu | Aynı Tor limitations | Tor exit/application data | Operational mistakes ve host/hardware etkilenmeye devam eder | Moderate/slow |
| Public guest Wi-Fi + HTTPS | Venue local device/timing ve destination'ları görür | Venue ISP metadata'yı görür | Guest public IP | Physical/captive-portal/device correlation | Fast/variable |
| Cellular hotspot | Carrier subscriber/device/location ve destination'ları görür | Kullanılıyorsa VPN/Tor | Carrier, VPN veya Tor egress IP | Mobile subscription ve location kalıcı identifier'lardır | Fast/variable |
| Mixnet | Access mixnet kullanımını; timing/volume'u görür | Birden fazla mixing node | Gateway/egress | Gelişmekte olan ecosystem; latency ve bandwidth maliyeti | Slowest |

HTTPS, transit sırasındaki content'i korur ancak tüm metadata'yı korumaz. EFF, page path'leri, credentials ve messages encrypted olsa bile domain, time ve traffic size bilgilerinin intermediary'ler tarafından görünür kalabileceğini belirtir.<sup>[[1]](#references)</sup>

## VPNs: fast privacy with concentrated trust

VPN, destination metadata'yı access ISP'den gizlemek, güvenilmeyen bir network üzerindeki first hop'u korumak, stable bir engagement egress address sunmak veya private network'e erişmek için kullanışlıdır. Kullanıcıyı **anonymous** yapmaz. VPN source connection'ı görür ve destination metadata'yı gözlemleyebilir; accounts, cookies, GPS, fingerprints ve payment information varlığını korur.<sup>[[1]](#references)</sup>

### Provider evaluation checklist

1. **Ownership and jurisdiction:** Legal entity'yi, parent company'yi, operating countries'ı, infrastructure subcontractors'ı ve geçerli legal process'i belirleyin.
2. **Collected data:** Account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries ve destination logs'u birbirinden ayırın. “No browsing logs” ifadesi “no data” anlamına gelmez.
3. **Retention and deletion:** Kesin süreleri ve backups, fraud systems ve processors'ın aynı schedule'a uyup uymadığını bulun.
4. **Evidence:** Kapsamı, tarihi, bulguları ve remediation'ı belirten public audits; reproducible/open clients; transparency reports ve belgelenmiş incidents'ı tercih edin.
5. **Protocol and client:** Maintained WireGuard, OpenVPN veya başka bir reviewed protocol; automatic updates; DNS ve IPv6 handling; kill switch ve platform başına leak tests bulunmalıdır.
6. **Business model:** Free veya subsidized bir service'in nasıl finanse edildiğini anlayın. App-store presence tek başına trustworthy operation kanıtı değildir.
7. **Payment fit:** Alternative payment, billing disclosure'ı VPN'den azaltabilir ancak her connection'da gözlemlenen source IP'yi ortadan kaldırmaz.

### Configure and verify a VPN

1. Provider/organization'ın signed client'ını official source'undan yükleyin.
2. Belgelendirilmiş bir route'un bypass etmesi gerekmiyorsa **full tunnel** seçin. Split tunneling correlation ve leak path'leri oluşturur.
3. Fail-closed/always-on davranışını etkinleştirin ve reconnect sırasında traffic'i block edin.
4. DNS'i tunnel üzerinden gönderin ve hem IPv4 hem de IPv6'yı test edin. Bir protocol'ü yalnızca güvenli şekilde tunnel edilemiyorsa ve functionality kaybı kabul ediliyorsa disable edin.
5. Sleep/wake, network switching, captive-portal login, tunnel crash ve hotspot tethering'i test edin. NCSC, tethered client'ların bazı platformlarda telefonun VPN'ini bypass edebileceği konusunda uyarır.<sup>[[2]](#references)</sup>
6. Observed IPv4, IPv6, DNS resolver ve connection timing bilgilerini kaydetmek için organization-controlled bir test endpoint'i kullanın. Sensitive bir engagement'ı rastgele “leak test” sitelerine expose etmeyin.
7. Client, OS, network veya policy değişikliklerinden sonra yeniden test edin.

### Hostile-LAN routing bypasses

VPN, seçili packet'ler VPN üzerinden bypass edildiği halde görünürde “connected” kalabilir; çünkü operating system, packet VPN tarafından encrypt edilmeden **önce** bir route seçer. TunnelCrack, yaygın routing exceptions'ı abuse etmek için iki yol gösterdi: **LocalNet**, bir Internet destination'ının directly connected subnet üzerinde görünmesini sağlar; **ServerIP** ise VPN-gateway resolution'ı spoof ederek target address'in VPN transport için gereken clear-network exception'ı devralmasını sağlar. Bunlar WireGuard, OpenVPN, IPsec veya TLS'in kırılması değil, client/routing failures'tır; HTTPS payload'ları end-to-end encrypted olarak kalır, ancak local observer destination/timing metadata'yı ve cleartext protocol data'yı elde edebilir.<sup>[[18]](#references)</sup>

TunnelVision, aynı pre-encryption primitive'i DHCP option 121 üzerinden uygular. Malicious veya compromised bir DHCP server, VPN'in catch-all route'undan daha specific olan bir classless route yükleyerek arbitrary bir host veya range için physical interface'ı seçebilir. VPN control channel çalışmaya devam edebilir; bu nedenle yalnızca tunnel disconnection ile tetiklenen bir kill switch etkinleşmeyebilir ve tek bir public “IP leak” check'i selective bypass'ları gözden kaçırabilir.<sup>[[19]](#references)</sup>

Physical interface üzerinde yalnızca DHCP'ye ve authenticated VPN transport'a izin veren bir packet-filter kill switch bunu fail-closed behavior'a dönüştürmelidir; ancak targeted route injection hâlâ selective-denial side channel oluşturabilir. High-consequence Linux workloads için, application namespace'in physical interface'a veya clear-network default route'a sahip olmadığı daha güçlü [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload) yaklaşımını tercih edin.<sup>[[19]](#references)</sup>

#### Owned-lab verification

Exact client/OS/version'ı owned AP, DHCP server, VPN endpoint ve destination üzerinde test edin; routing ve packet-filter implementations platforma özgü olduğundan product-wide claims hızla geçerliliğini yitirir. Endpoint'in kendisinde ve test server'da capture alın—tek başına bir egress-IP website'i, her destination'ın tunnel'ı izlediğini kanıtlamaz.<sup>[[18]](#references)[[19]](#references)</sup>

1. VPN'e bağlanın, VPN-server address'i kaydedin ve tüm IPv4/IPv6 routing table'larını ve policy-routing rule'larını saklayın. Windows'ta `route print`; macOS'ta `netstat -rn`; Linux'ta aşağıdaki commands'leri kullanın.
2. Birkaç owned destination IP için selected route'u sorgulayın. Documented VPN transport endpoint'i haricinde next hop/interface tunnel olmalıdır.
3. TunnelVision için controlled DHCP network üzerindeki lease'i renew edin ve option 121 route'unu **yalnızca owned test destination için** yükleyin. Başarılı sonuç, traffic'in hâlâ tunneled veya blocked olmasıdır—physical interface üzerinde destination traffic olarak asla gönderilmemelidir.
4. LocalNet için client'a `203.0.113.0/24` gibi yalnızca lab'a ait bir public documentation subnet atayın ve owned test destination'ı bunun içine yerleştirin. LAN access'in etkinleştirilmesinin Internet-class destination'ların tunnel'ı bypass etmesine neden olmadığını doğrulayın.
5. ServerIP için VPN connection'dan önce controlled DNS'in owned VPN hostname'i owned test destination'a resolve etmesini sağlayın; lab gateway ise VPN transport'ı gerçek owned VPN endpoint'ine forward etsin. Client, spoofed address'e yönelik unrelated application traffic'i exempt etmemelidir.
6. “local network access” hem enabled hem de disabled durumdayken; reconnect, sleep/wake, network switching ve VPN-process crash sonrasında tekrarlayın. IPv4, IPv6 ve DNS'i bağımsız olarak test edin.
7. Physical-interface capture'ı inceleyin. Capture DHCP ve VPN server'a giden encrypted packets içermeli, owned test destination'a doğrudan adreslenmiş packets içermemelidir. Ayrıca rejected bir bypass'ın user prompts veya connectivity repair sonrasında sessizce fallback yapamadığını doğrulayın.
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser: daha güçlü web unlinkability

Tor, tek bir relay'in normalde hem kaynağı hem de hedefi bilmemesi için birden fazla relay üzerinden bir circuit oluşturur. Hedef, kullanıcının IP'si yerine bir Tor exit görür; yerel ağ ise normalde bir Tor bağlantısı görür.<sup>[[3]](#references)</sup> Tor, düşük gecikmeli TCP uygulamaları için tasarlanmıştır; bu nedenle daha yavaştır ve her iki ucu da ilişkilendirebilen bir adversary'ye karşı korumayı garanti edemez.<sup>[[4]](#references)</sup>

### Güvenli Tor Browser workflow'u

1. Tor Browser'ı yalnızca Tor Project'ten veya resmi bir mirror'dan indirin ve mümkün olduğunda signature'ı doğrulayın.
2. Normal bir browser'ı Tor SOCKS portuna yönlendirmek yerine **Tor Browser** kullanın. Standart browser'lar DNS/WebRTC ve kimlik belirleyici state leak'lerine neden olabilir.<sup>[[5]](#references)</sup>
3. Varsayılan boyutu, fontları, extension'ları ve privacy settings'i koruyun. Ek add-on'lar browser'ı daha benzersiz hale getirebilir.<sup>[[6]](#references)</sup>
4. Artan breakage kabul edilebilir olduğunda **Safer** veya **Safest** security level'ı seçin.
5. Doğrudan Tor engellendiğinde veya normal relay IP'leri kabul edilemez bir yerel görünürlük oluşturacağında bir bridge kullanın. Bridge'ler kolay tanınmayı azaltır; traffic analysis'i ortadan kaldırmaz.<sup>[[7]](#references)</sup>
6. Kimlik belirleyen bir account'a giriş yapmayın, kimlik belirleyici bilgi vermeyin veya indirilen active document'ları harici, ağa bağlı bir uygulamada açmayın.
7. Her identity için ayrı bir session/context kullanın. “New circuit”, browser/application identity'sini silmekle aynı şey değildir; uygun şekilde **New Identity** kullanın veya izole edilmiş environment'ı yeniden başlatın.
8. Authenticated HTTPS veya authenticated onion service kullanmayı tercih edin. Bir Tor exit, şifrelenmemiş HTTP trafiğini gözlemleyebilir.

### Tor ve VPN

Bunları birleştirmek otomatik olarak daha güvenli değildir. Tor'dan önce kullanılan bir VPN, ISP'den doğrudan Tor relay bağlantılarını gizleyebilir; ancak VPN source'u görür. Tor'dan sonra kullanılan bir VPN ise VPN'e Tor sonrası activity hakkında istikrarlı bir görünüm verir ve anonymity set'i küçültebilir. Yanlış yapılandırma leak'lere yol açabilir. Tor Project, bu tür kombinasyonları yalnızca advanced ve açık threat model'lar için önerir.<sup>[[8]](#references)</sup>

## Public ve guest Wi-Fi

Modern HTTPS, pasif komşuların düzgün şekilde şifrelenmiş web içeriğini genellikle okuyamamasını sağlar; ancak guest Wi-Fi anonymity değildir. Mekan; association zamanlarını, device identifier'larını, captive-portal verilerini, destination'ları ve DHCP ayrıntılarını kaydedebilir. Kameralar, satın alımlar, ulaşım ve fiziksel gözlem kullanıcıyı belirleyebilir. Benzer isimli sahte bir hotspot da portal credential'larını ele geçirebilir veya şifrelenmemiş trafiği değiştirebilir.<sup>[[9]](#references)</sup>

### Lawful guest-network workflow'u

1. Yalnızca misafirlere sunulan veya sahibinin açıkça izin verdiği bir network kullanın. Personelden tam SSID'yi ve portal prosedürünü isteyin.
2. Endpoint'i ve travel router'ı varıştan önce güncelleyin. File/printer sharing, inbound discovery, auto-join ve hatırlanan network probing'i devre dışı bırakın.
3. OS'nin private/randomized Wi-Fi address özelliğini etkinleştirin. Güncel Apple sistemleri açık/zayıf network'lerde rotating address kullanabilir; modern Android randomization genellikle SSID başına kalıcıdır. Bu yalnızca bir yerel identifier'ın açığa çıkmasını azaltır.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Privileged workstation ile guest network arasında organization-controlled bir travel router veya low-trust bridge device kullanmayı tercih edin. Bu, firewall/VPN policy'sini merkezileştirir ancak router'ı mekandan gizlemez.<sup>[[12]](#references)</sup>
5. Captive portal'ı yalnızca belirlenmiş low-trust device/browser üzerinden tamamlayın. Sözde anonymous bir context için kişisel veya yeniden kullanılan credential'ları asla girmeyin. Bağlantı kurulduktan sonra portal browser'ını kapatın.
6. Hassas activity'den önce full-tunnel VPN veya Tor başlatın ve fail-closed davranışını doğrulayın.
7. Kullanımdan sonra network'ü unutun ve portal account/data-retention policy'sini inceleyin.

{% hint style="danger" %}
Bir komşunun Wi-Fi'ını cracking yapmak, portal'ı bypass etmek, leak edilmiş guest credential'larını kullanmak, başka bir guest'in access'ini clone etmek veya bir café'ye Raspberry Pi gizlemek yetkisiz activity'dir; bunlar privacy technique değildir. Güvenli karşılıkları lawful guest network, client-approved site veya property owner's written consent ile yerleştirilen ve geri alınan documented drop node'dur.
{% endhint %}

## Travel router'lar

Bir travel router, workstation'ı hostile local broadcast'lerden izole edebilir, firewall uygulayabilir, tutarlı bir internal SSID sağlayabilir ve VPN'e otomatik olarak yeniden bağlanabilir. **Anonymous** değildir: upstream, radio identity'sini ve traffic timing'ini görür; VPN provider'ı ise tunnel source'unu görür.

- Desteklenen OpenWrt/vendor firmware kullanın ve kullanılmayan service'leri kaldırın.
- Ethernet veya benzersiz bir password'e sahip dedicated management SSID üzerinden administer edin.
- WAN-side administration, UPnP, WPS, file sharing ve istenmeyen inbound traffic'i devre dışı bırakın.
- Yalnızca desteklendiği ve izin verildiği yerlerde randomized/private WAN MAC kullanın.
- DNS ve IPv6 dahil olmak üzere router üzerinde VPN policy uygulayın ve tunnel başarısız olduğunda egress'i block edin.
- Bir phone hotspot'ın tethered device'ları telefonun VPN'i üzerinden tunnel ettiğini varsaymayın; test edin.

## Cellular, SIM'ler ve eSIM'ler

Cellular kullanışlıdır ancak anonymous değildir. Operator'lar subscriber/device identifier'larını ve network attachment'tan türetilen location bilgisini tutar; eSIM hâlâ bir mobile subscription'dır. Prepaid, güvenilir biçimde unregistered anlamına gelmez; gereklilikler ülkeye göre değişir ve değişebilir.<sup>[[13]](#references)</sup>

Operational olarak:

- Kişisel verilerin exposure'ını azaltmak için ayrı ve desteklenen bir device kullanın; fictional bir subscriber oluşturmak için değil.
- Threat model'da co-location varsa “ayrı” bir device'ı kişisel phone'un yanında sürekli taşımayın.
- Kullanılmayan cellular, Wi-Fi, Bluetooth ve location access'i devre dışı bırakın; power off, UI toggle'larından daha güçlü bir radio boundary sağlar.
- Hassas trafiği approved VPN/Tor path içine alın; carrier'ın subscription/device location'ını ve tunnel endpoint'ini hâlâ bildiğini unutmayın.
- Güncel registration ve retention kurallarını national regulator veya local counsel ile doğrulayın; “anonymous SIM countries” hakkındaki online listelere güvenmeyin.

## DNS ve TLS metadata'sı

- **DoH/DoT/DoQ**, client ile resolver arasındaki DNS'i şifreleyerek basit yerel okuma veya değiştirmeyi önler; ancak resolver query'leri ve transport identifier'larını görmeye devam eder. Trust'ı taşırlar; anonymity sağlamazlar.<sup>[[14]](#references)</sup>
- **ODoH**, proxy ekleyerek proxy ve target'ın collude etmediği varsayımıyla resolver'ın client IP'sini öğrenmek zorunda kalmamasını sağlar. Traffic analysis açıkça kapsam dışıdır.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)**, client, DNS ve server desteklediğinde TLS handshake içindeki inner server name'i koruyabilir. Destination IP, timing, volume ve endpoint görünür kalır.<sup>[[16]](#references)</sup>
- Doğru yapılandırılmış bir VPN veya Tor environment'ında DNS, o environment'ın desteklenen route'unu izlemelidir. Ayrı bir resolver eklemek yeni bir observer veya fingerprint oluşturabilir.

### Encrypted-DNS/ECH verification workflow'u

1. DNS'in VPN/Tor environment'ı, OS veya application tarafından kontrol edilip edilmediğine karar verin. İlişkisiz resolver'ları üst üste eklemek yerine bunu **tek** bir intended layer'da yapılandırın.
2. Resolver'ı yayımlanmış privacy/retention policy'sine göre seçin ve platform destekliyorsa strict encrypted mode'u etkinleştirin. Opportunistic fallback sessizce plaintext'e dönebilir.
3. Kontrol ettiğiniz authoritative test zone altında benzersiz bir subdomain sorgulayın; authoritative log'un intended recursive resolver'ı gördüğünü doğrulayın.
4. Yalnızca test device'ının trafiğini authorization ile capture edin. Access network'ün plaintext DNS'i okuyamadığını doğrularken, encrypted resolver/tunnel endpoint'ini görebileceğini kabul edin.
5. Blocked/unreachable bir encrypted resolver'ı test edin. Pass condition, seçilen fail-closed veya documented fallback davranışıdır; kazara gerçekleşen clear query değildir.
6. ECH için controlled ve ECH-enabled bir host kullanın; **inner** ClientHello'nun kabul edildiğini doğrulamak üzere client/server diagnostics'i inceleyin. Yalnızca bir HTTPS record sunulması ECH'nin başarılı olduğunu kanıtlamaz.
7. Network değişiklikleri, captive portal'lar, browser update'leri ve VPN reconnect'lerinden sonra tekrarlayın. Daha sonraki administrator'ların bypass oluşturmaması için DNS/ECH'nin hangi component tarafından yönetildiğini kaydedin.

## Mixnet'ler

Nym veya Katzenpost gibi mixnet'ler, timing correlation'a direnmek için fixed-size packet'ler, delay, reordering ve cover traffic ekler. Bu özellikler latency ve bandwidth maliyetine sahiptir ve bağımsız deployment-scale kanıtları sınırlıdır. Güncel consumer mixnet'lerini Tor/VPN'lerin daha hızlı veya guaranteed replacement'ları olarak değil, **emerging/high-latency options** olarak değerlendirin.<sup>[[17]](#references)</sup>

### Evaluation workflow'u

1. Maintained bir client'ı ve tam olarak desteklenen application'ı belirleyin; belgelenmemiş bir proxy üzerinden arbitrary browser/system traffic'i zorla geçirmeyin.
2. Entry, mix node'lar, gateway, destination ve collusion varsayımları için güncel threat model'ı okuyun.
3. Official signed source'tan ayrı bir test compartment'ına yükleyin ve yalnızca size ait benign bir endpoint kullanın.
4. Delivery latency, message-size limits, reliability, retransmission ve gateway kullanılamadığında ne olduğunu ölçün.
5. Intended path ve source'u doğrulamak için local traffic'i ve size ait endpoint'i inceleyin. Reply'lerin aynı privacy design'ı kullanıp kullanmadığını kontrol edin.
6. Shutdown/failure'ı test edin: application sessizce direct Internet access'e fallback yapmamalıdır.
7. Sırf hız için cover traffic'i devre dışı bırakmayın, delay'leri azaltmayın veya unusual fixed route'lar seçmeyin; bu değişiklikler belirtilen anonymity model'ini geçersiz kılabilir.
8. Specific deployment, independent analysis ve operational reliability consequence level'ı karşılayana kadar bunu experimental olarak tutun.

## Network preflight checklist

- [ ] Authorization; access network'ü, target'ı, tarihleri ve source infrastructure'ı kapsıyor.
- [ ] Endpoint'te unrelated identity veya active sync session bulunmuyor.
- [ ] IPv4, IPv6, DNS ve reconnect davranışı planla eşleşiyor.
- [ ] Controlled DHCP/local-subnet route injection, test traffic'ini physical interface'e taşıyamıyor.
- [ ] Destination yalnızca beklenen egress'i görüyor.
- [ ] Captive portal ve hotspot davranışı hassas traffic olmadan test edildi.
- [ ] Local sharing/discovery ve automatic network joining devre dışı.
- [ ] Observer table ve residual traffic-correlation risk kabul edildi.
- [ ] Provider policy, retention ve emergency contact güncel.

Split-knowledge relay'ler, route-enforced workload'lar, pluggable transport'lar, onion service'ler, I2P ve disposable remote browser'lar için [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) bölümüne devam edin.



## References

- [1] [EFF — Sizin için doğru VPN'i seçme](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Device security guidance: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor'un sunduğu privacy ve anonymity protections](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Tor'a kısa bir giriş](https://spec.torproject.org/intro/)
- [5] [Tor Project — Tor'u diğer browser'larla kullanma](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser'da plugin ve add-on'lar](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Tor'un engelini kaldırma](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Tor Browser'ı VPN ile kullanma](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Public Wi-Fi network'leri güvenli mi?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple device'larıyla Wi-Fi privacy](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC randomization uygulama](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Secure Privileged Access Workstation'lar için principles](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: policy and regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Privacy Service Operator'ları için recommendations](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Bypassing Tunnels: Routing Table'ları Abuse ederek VPN Client Traffic Leak'lerini Bypass Etme](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: Attackers'ın Routing-Based VPN'leri Total VPN Leak için Decloak Etmesi](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
