# Anonymous Internet Access Technique Catalog

Bu, canonical access-path envanteridir. Her vendor adını değil, protocol ve operational **families** kapsamaktadır. Hiçbir Internet path anonymity garanti etmez: account, browser, endpoint, timing, payment, cloud-control-plane ve physical evidence, kusursuz görünen bir route'u etkisiz hâle getirebilir.

Her entry aynı fields yapısını kullanır. “Procedure”, lawful deployment veya owned-lab emulation anlamına gelir. Gerçek technique bir router'ı compromise etmeye, access çalmaya veya istemeyen bir intermediary'yi kötüye kullanmaya dayanıyorsa reproduction, exercise için sahip olunan sistemleri kullanır.

## Coverage matrix

| Family | Destination sees | Strongest property | Speed | Treatment |
|---|---|---|---|---|
| Shared NAT/CGNAT | paylaşılan public address | aboneler arasındaki belirsizlik | yüksek | deployable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | relay address | hızlı source-address separation | yüksek | deployable |
| Multi-hop/split relay, MASQUE | final proxy | bilgi ayrımı veya full-IP tunnel | yüksek/orta | trusted relays ile deployable |
| Tor, bridge, onion service | exit veya onion identity | çok taraflı path ve ortak browser | orta | deployable |
| I2P, GNUnet, mixnet | overlay peer/gateway | overlay veya timing resistance | düşük/değişken | application-specific |
| OHTTP/ODoH, Private Relay | gateway/egress | source/request partitioning | yüksek | yalnızca supported applications |
| Public Wi-Fi, travel router | venue/tunnel address | location/access-path change | yüksek | permission required |
| Cellular/eSIM, satellite | carrier/provider address | bağımsız physical uplink | yüksek/değişken | subscription/provider observes |
| Remote browser/jump host | remote workspace | endpoint ve egress separation | yüksek | deployable |
| Residential/mobile proxy | consumer/carrier address | consumer-network appearance | yüksek | consent/provenance critical |
| ORB/compromised relay | başka bir victim'ın address'i | origin concealment ve borrowed reputation | yüksek | owned-lab reproduction only |
| CDN/fronting/redirector | CDN/front address | back-end infrastructure protection | yüksek | provider/owner approval required |
| Fast flux/DGA/dead drop | rotating node/service | infrastructure discovery resistance | değişken | owned-lab reproduction only |
| Drop/nearest-neighbor | local target-adjacent address | geographic/network boundary crossing | yüksek | owned-site lab only |
| Store-and-forward/offline | gateway veya physical receiver | interactive timing linkage azaltma | düşük | application-specific |
| Pluggable/refraction transport | Tor entry veya cooperating diversion proxy | censorship-resistant reachability | değişken | supported client veya research lab |
| IPFS gateway/PIR/remote fetcher | gateway veya application service | publisher/query/request partitioning | değişken | bounded application only |
| Anycast/QUIC/MPTCP | stable broker veya multiple subflows | rendezvous ve session continuity | yüksek | availability, not anonymity |
| CI/CD automation runner | hosted runner address | disposable accountable egress | yüksek | owned workflow only |
| Non-IP local first hop | organization gateway | Internet stack'i sensor'dan kaldırma | düşük | owner-approved deployment |

## Direct shared NAT and carrier-grade NAT

**Mechanics:** Birden çok user aynı public address'i paylaşır; access provider, subscriber-side address ve port'ları public tuple'a map eder.

**Pros:** hızlıdır; özel client gerekmez; destination-side IP tek başına yalnızca bir household, venue veya carrier pool tanımlayabilir.

**Cons:** provider subscriber/port/time mappings tutabilir; account ve fingerprint'ler kalır; diğer user'lar address reputation'ını bozabilir.

**Procedure:** (1) authorized access'in NAT/CGNAT kullanıp kullanmadığını doğrulayın; (2) owned endpoint'te exact public IP ve source port'u kaydedin; (3) application identities'yi ayrı tutun; (4) shared addressing'i privacy control olarak görmeyin; (5) ISP'nin destinations'ı öğrenmemesi gerekiyorsa daha güçlü bir path kullanın.

**Detection:** Destinations yalnızca IP'yi değil source port'u ve precise time'ı saklamalıdır. Providers NAT allocation logs'u correlate eder; investigators account/device/browser evidence'ını birleştirir.

## Commercial VPN

**Mechanics:** Encrypted full-tunnel connection VPN'de sonlanır; destinations VPN'in egress'ini görür. VPN normalde source, timing ve destinations'ı ilişkilendirebilir.

**Pros:** hızlı ve basittir; local passive observation'a karşı koruma sağlar; stable veya shared exits sunar; controlled red-team egress için uygundur.

**Cons:** trust tek noktada yoğunlaşır; billing/login telemetry bulunur; kill-switch/DNS/IPv6 failures oluşabilir; shared exits sıklıkla reputation-blocked olur.

**Procedure:** (1) provider, owner, jurisdiction, retention ve assessment policy'yi belirleyin; (2) signed official client'ı kurun; (3) full tunnel, always-on ve fail-closed davranışı etkinleştirin; (4) DNS ve IPv6'yı bilinçli şekilde route edin; (5) owned endpoint'te observed IPv4/IPv6/DNS'yi doğrulayın; (6) tunnel'ı durdurup yeniden bağlanın ve clear fallback olmadığını doğrulayın.<sup>[[1]](#references)</sup>

**Detection:** Local networks VPN infrastructure'a giden uzun encrypted flow'ları görür; providers authentication/connection records tutar; destinations ASN/reputation ile account, TLS/browser ve behavior correlation kullanır.

## Self-hosted VPN or rented VPS egress

**Mechanics:** Operator, WireGuard/OpenVPN gateway'ini kontrol eder veya traffic'i rented server üzerinden forward eder.

**Pros:** öngörülebilir yüksek hız; allowlist'e alınabilir fixed address; custom logging/firewall; iyi incident control.

**Cons:** anonymity set küçüktür; cloud tenant, payment, source login, API ve image history operator'ı bağlar; distinctive new server kolayca cluster edilir.

**Procedure:** (1) engagement-specific organization project oluşturun; (2) supported image ve fixed address provision edin; (3) management'i MFA/key-based administration ile sınırlandırın; (4) full-tunnel egress ve DNS yapılandırın; (5) mümkün olduğunda yalnızca scoped destinations'a izin verin; (6) leak/failure behavior'ı test edin; (7) controller audit records'ı saklayın; (8) teardown sırasında credentials ve resources'ı yok edin.

**Detection:** Hosting ASN, first-seen address, certificate/service fingerprint ve scanning behavior correlate edilir; cloud owners control-plane, console, billing ve flow logs kullanır.

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics:** Application, proxy'den TCP stream açmasını ister; SOCKS, sürümüne bağlı olarak name resolution ve UDP de taşıyabilir; SSH stream'leri tek bir encrypted session içinde forward eder.

**Pros:** hafif, per-application ve hızlıdır; chaining ve segmented networks'e erişim için kullanışlıdır.

**Cons:** Applications proxy'yi bypass edebilir; DNS leak olabilir; proxy adjacent endpoints'ı görür; browser state kalır; open proxies trap veya compromised system olabilir.

**Procedure:** (1) proxy'yi owned host üzerinde deploy edin; (2) authentication isteyin ve source/destination'ı kısıtlayın; (3) disposable application profile yapılandırın; (4) gerektiğinde remote DNS resolution sağlayın; (5) owned DNS/HTTP endpoint ile doğrulayın; (6) workload için direct egress'i block edin; (7) proxy credentials'ı inceleyip rotate edin.

**Detection:** Tunnel-capable processes, CONNECT/SOCKS negotiation, long SSH sessions ve application ile uyumsuz destinations belirlenir; proxy logs stream'leri yeniden oluşturur.

## URL-rewriting web proxy and browser proxy extension

**Mechanics:** Website destination'ı fetch eder ve links/forms'u kendi origin'i üzerinden rewrite eder veya extension browser requests'ı proxy'ye yönlendirir. Destination service'i görür; service ise TLS termination sonrasında plaintext'i okuyabilir, content inject edebilir veya saklayabilir.

**Pros:** system-wide client gerekmez; simple browsing için hızlıdır; VPN installation mümkün olmayan yerlerde çalışır.

**Cons:** Proxy credentials/content okuyabilir, downloads'ı rewrite edebilir ve user'ları fingerprint edebilir; scripts/WebSockets/downloads bypass edebilir; browser extension geniş privileges'a sahiptir; anonymity set küçüktür ve sıkça block edilir.

**Procedure:** (1) yalnızca authorized testing için organization-operated proxy kullanın; (2) personal accounts olmayan disposable browser'da isolate edin; (3) password entry ve sensitive downloads'ı yasaklayın; (4) owned page'deki her subresource'un proxy üzerinden çözümlendiğini doğrulayın; (5) WebSocket, download ve form behavior'ı test edin; (6) kullanım sonrası extension/profile'ı kaldırın.

**Detection:** Destination proxy'yi loglar; enterprise proxy/DNS ve extension inventory service'i tanımlar; content-security/reporting veya owned canary subresources direct bypass'ı gösterir; proxy logs user session'ı targets'a map eder.

## Multi-hop proxy or provider multi-hop VPN

**Mechanics:** Entry source'u görür; bir veya daha fazla traversal relay, onu destination'ı gören exit'ten ayırır.

**Pros:** Normalde hiçbir relay iki ucu birlikte bilmez; tek node'un failure/seizure'ı daha az bilgi açığa çıkarır; geography esnektir.

**Cons:** Shared administration/logs split'i bozar; latency, timing correlation ve DNS route sorunları vardır; daha fazla failure oluşur; aynı account/payment tüm hop'ları birleştirebilir.

**Procedure:** (1) her hop'un hangi observer'ı ortadan kaldırdığını tanımlayın; (2) separation önemliyse independently administered owned/approved relays kullanın; (3) workload'dan yalnızca entry access'i zorlayın; (4) her relay'nin yalnızca next hop'a erişebildiğinden emin olun; (5) her layer'deki logs'u doğrulayın; (6) her hop'u durdurup fail-closed behavior'ı doğrulayın. [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) ile reproduce edin.

**Detection:** Adjacent NetFlow timing/volume, repeated proxy handshakes ve common controller infrastructure correlate edilir; operator geography exit'ten çıkarılmamalıdır.

## Split-knowledge application relay and OHTTP

**Mechanics:** Client, stateless HTTP message'ı gateway'e encrypt eder ve relay üzerinden gönderir. Relay client IP'yi görür fakat request'i görmez; gateway request'i görür fakat normalde yalnızca relay IP'sini görür.

**Pros:** Supported requests için güçlü ve auditable privacy partition; general anonymity networks'ten daha düşük overhead.

**Cons:** Arbitrary browsing değildir; cookies/authentication yeniden link kurabilir; relay/gateway collusion ve traffic analysis devam eder; application bunu implement etmelidir.

**Procedure:** (1) RFC 9458'i açıkça destekleyen application seçin; (2) gateway keys'i official configuration path üzerinden doğrulayın; (3) stable per-user fields kullanmayın; (4) yalnızca supported stateless request gönderin; (5) relay, gateway ve target logs'u karşılaştırın; (6) direct fallback olmadan key rotation/failure'ı test edin.<sup>[[2]](#references)</sup>

**Detection:** Enterprise endpoints initiating process ve OHTTP relay'i açığa çıkarır; gateways malformed/replayed traffic'i tespit eder; timing ve stable payload/account fields requests'ı correlate edebilir.

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics:** HTTP Extended CONNECT over TLS/QUIC, UDP veya IP packets'ı proxy üzerinden taşır. Modern VPN-like tunnel kurabilir ve transport'u HTTP/3 ile blend edebilir; ancak proxy observer olarak kalır.<sup>[[3]](#references)</sup>

**Pros:** Efficient multiplexing/roaming; UDP veya full IP destekler; modern HTTP infrastructure üzerinden deploy edilir.

**Cons:** Anonymity network değildir; proxy/account source ve destinations'ı görür; QUIC/HTTP fingerprints ve well-known paths endpoints/providers tarafından görülebilir.

**Procedure:** (1) RFC 9298/9484 support'u belgeleyen client/service kullanın; (2) proxy certificate/configuration'ı authenticate edin; (3) allowed target routes tanımlayın; (4) path içinde encrypted DNS etkinleştirin; (5) owned endpoints'a karşı UDP, TCP, IPv6 ve failover'ı doğrulayın; (6) proxy request ve flow logs'u inceleyin.

**Detection:** Endpoints client process ve virtual interface'i görür; networks proxy'ye giden sustained QUIC/TLS'yi sınıflandırabilir; proxy logs CONNECT target/path'i ve assigned routes'ı açığa çıkarır.

## Tor Browser

**Mechanics:** Tor guard, middle ve exit relays seçer; layered encryption her relay'nin görünümünü sınırlar. Tor Browser fingerprinting'e direnmek üzere standardize edilmiş browser sağlar.

**Pros:** Büyük public anonymity set; hiçbir ordinary relay iki ucu bilmez; server işletmeden destination unlinkability.

**Cons:** Daha yavaştır; TCP-focused'tur; exit reputation/blocks vardır; logins ve disclosures user'ı tanımlar; low-latency timing correlation sürer.

**Procedure:** (1) Tor Browser'ı project'ten download edip verify edin; (2) defaults'ı koruyun ve extensions kullanmayın; (3) uygun security level seçin; (4) ayrı identity/session oluşturun; (5) identifying accounts ve external active documents'tan kaçının; (6) HTTPS veya authenticated onion services kullanın; (7) exit'i yalnızca owned endpoint ile doğrulayın.<sup>[[4]](#references)</sup>

**Detection:** Local networks bridge/transport kullanılmadığında known guard traffic'i tanımlayabilir; destinations exits ve Tor Browser behavior'ı görür; end-to-end observers timing/volume correlate eder.

## Tor bridges and pluggable transports

**Mechanics:** Non-public bridge public guard'ın yerini alır; obfs4, Snowflake veya WebTunnel ilk-hop transport'u simple blocking/probing'e dirençli hâle getirir.

**Pros:** Censorship'u aşar ve obvious public-relay destinations'ı gizler; entry sonrasında Tor circuit korunur.

**Cons:** Transport patterns/bridge discovery mümkün kalır; performance değişkendir; accounts veya global timing'e karşı ek protection sağlamaz.

**Procedure:** (1) Önce direct Tor'u deneyin; (2) Tor Browser Connection settings'te built-in supported transport seçin veya official bridge isteyin; (3) random binaries/lists kullanmayın; (4) bağlanıp benign test çalıştırın; (5) reconnect ve clock'ı test edin; (6) diğer browser settings'i standard tutun.<sup>[[5]](#references)</sup>

**Detection:** Censors destination discovery, protocol/flow classification ve active probing kullanır; defenders circumvention use'u compromise'dan ayırmalı ve endpoint process/context'e dayanmalıdır.

## VPN before Tor and Tor before VPN

**Mechanics:** VPN-before-Tor, direct Tor use'u access ISP'den gizler fakat source'u VPN'e açar. Tor-before-VPN, VPN'e post-Tor traffic verir ve çoğu zaman stable customer/tunnel identity oluşturur.

**Pros:** Doğru tasarlanırsa belirli bir observer'ı ortadan kaldırır; bir layer'ı block eden networks'e erişebilir.

**Cons:** Complexity, uncommon fingerprint, leaks, reduced anonymity set ve false confidence; Tor Project combinations'ı advanced kabul eder.<sup>[[6]](#references)</sup>

**Procedure:** (1) kaldırılan ve eklenen observer'ı yazın; (2) disposable environment kullanın; (3) yalnızca intended outer path'i oluşturun; (4) firewall routes'ı enforce edin; (5) DNS/IPv4/IPv6 ve her failure order'ı doğrulayın; (6) iki provider'ın visibility'sini karşılaştırın; (7) ölçülebilir avantaj yoksa stack'i bırakın.

**Detection:** Local/VPN/Tor observers farklı adjacent layers görür; timing end-to-end kalır; unusual nested tunnel fingerprints ve provider accounts sessions'ı bağlayabilir.

## Onion service

**Mechanics:** Client ve service rendezvous'a Tor circuits kurar; service IP gizlenir ve exit kullanılmaz.

**Pros:** Source ve service location protection; end-to-end onion authentication; public inbound port yoktur; optional client authorization.

**Cons:** Updates/analytics/errors origin leak edebilir; onion key critical'dır; application identity/timing ve host compromise devam eder.

**Procedure:** (1) application'ı isolate edin ve yalnızca loopback/socket'e bind edin; (2) supported Tor kurun; (3) official instructions ile v3 onion service yapılandırın; (4) stable identity gerekiyorsa key'i protect/back up edin; (5) closed use için client authorization ekleyin; (6) third-party fetches'i kaldırın; (7) origin'e external erişilemediğini doğrulayın.<sup>[[7]](#references)</sup>

**Detection:** Host/network defenders Tor process/configuration ve outbound circuits'ı bulur; application errors, DNS, certificates veya third-party resources origin'i açığa çıkarabilir.

## I2P internal services

**Mechanics:** I2P, overlay içindeki destinations için ayrı unidirectional inbound/outbound tunnels kullanır; public-Internet outproxies trust point ekler.

**Pros:** Decentralized internal publishing; official exit dependency yoktur; inbound/outbound paths ayrıdır.

**Cons:** General web replacement değildir; ecosystem daha küçüktür; long-running peer behavior vardır; outproxy public browsing'i görebilir.

**Procedure:** (1) official source'tan kurun; (2) dedicated context kullanın; (3) integration/bandwidth stabilization'a izin verin; (4) owned I2P-native service'e erişin; (5) açıkça gerekmedikçe outproxies kullanmayın; (6) shutdown'ın direct fallback vermediğini doğrulayın; (7) local peer ve service logs'u inceleyin.<sup>[[8]](#references)</sup>

**Detection:** Local networks long-lived peer traffic ve bootstrap behavior'ı görür; endpoints router/application processes'i açığa çıkarır; outproxies exits'i loglar.

## Mixnets

**Mechanics:** Fixed-size packets, batching, delay, reordering ve cover traffic timing correlation'ı azaltır; gateways applications'ı bridge eder.

**Pros:** Low-latency proxies'ye göre timing analysis'e daha dirençlidir; asynchronous messages/transactions için kullanışlıdır.

**Cons:** Latency, bandwidth overhead, daha küçük deployment ve application limits; gateway/account metadata kalabilir.

**Procedure:** (1) maintained client ve supported application seçin; (2) actual threat model'i okuyun; (3) separate compartment'ta kurun; (4) owned endpoint'e benign data gönderin; (5) latency/reliability ve reply path'i ölçün; (6) gateway failure'ı test edin; (7) yalnızca hız için delays/cover traffic'i disable etmeyin.<sup>[[9]](#references)</sup>

**Detection:** Endpoints client'ı tanımlar; access networks gateways/packet cadence'i sınıflandırabilir; gateways ve exits adjacent roles'u görür, broader correlation için daha uzun statistical windows gerekir.

## GNUnet anonymous file sharing

**Mechanics:** GNUnet publish/search/download requests'ı peers üzerinden route edebilir ve anonymity level'a göre cover traffic ekleyebilir. Documentation, default level 1'in cover traffic gerektirmediği ve powerful traffic analysis'in origin'i belirleyebileceği konusunda uyarır.<sup>[[10]](#references)</sup>

**Pros:** Decentralized, application-native anonymous sharing; tunable cover-traffic requirement.

**Cons:** Ordinary anonymous web access değildir; performance/storage cost; peer ve traffic-analysis limitations; GNUnet VPN documentation IP overlay'in iyi anonymity sağlamadığını söyler.

**Procedure:** (1) maintained official build kurun; (2) test peer'i isolate edin; (3) bandwidth/storage'ı sınırlandırın; (4) seçilen anonymity level ile harmless unique test file publish edin; (5) başka owned peer'den retrieve edin; (6) cover-traffic ve latency'yi kaydedin; (7) IP VPN component'inin equivalent anonymity sağladığını iddia etmeyin.

**Detection:** Peer bootstrap, overlay traffic, local datastore/process ve file identifiers; broad observer traffic volume'u cover traffic'e karşı analiz edebilir.

## Encrypted DNS, ODoH and ECH

**Mechanics:** DoH/DoT/DoQ resolver'a encrypt eder; ODoH client address'i proxy ve resolver arasında böler; ECH inner TLS ClientHello/server name'i encrypt eder.

**Pros:** Bazı local observers için plaintext DNS/SNI'ı kaldırır; ODoH source/query knowledge'ı partition eder.

**Cons:** IP-anonymity path değildir; resolver/proxy/server roles'u korur; destination IP/timing/volume ve endpoint kalır; fallback leak edebilir.

**Procedure:** (1) DNS'in OS, application veya tunnel tarafından yönetileceğini seçin; (2) strict encrypted mode veya supported ODoH etkinleştirin; (3) unique owned domain test edin; (4) clear query olmadığını local capture ile doğrulayın; (5) resolver failure'ı test edip intended behavior'ı doğrulayın; (6) ECH için server diagnostics'in inner ClientHello acceptance gösterdiğini doğrulayın.<sup>[[11]](#references)</sup>

**Detection:** Endpoint/resolver logs queries'i açığa çıkarır; networks encrypted-resolver endpoints ve destination flows'ı tanımlar; ECH state path üzerinde gizli olsa bile endpoints/CDN tarafından görünür.

## Split-provider privacy relay

**Mechanics:** iCloud Private Relay gibi products client'ı bilen ingress ve destination'ı bilen independently operated egress kullanır; coarse region handling uygulanır.

**Pros:** Low-friction split knowledge; hızlıdır; supported traffic için integrated DNS/web protection sağlar.

**Cons:** Product/application scope sınırlıdır; account/platform provider customer'ı yine tanımlar; arbitrary system anonymity değildir; collusion/legal ve timing risks vardır.

**Procedure:** (1) desteklenen exact applications ve traffic types'ı doğrulayın; (2) uygun olduğunda dedicated platform context altında etkinleştirin; (3) region behavior seçin; (4) Safari/DNS ve unsupported applications'ı ayrı test edin; (5) destination address'i inceleyin; (6) network switching/failure'ı test edin.<sup>[[12]](#references)</sup>

**Detection:** Access ingress'i görür; destination egress'i görür; platform/relay logs ve account records kendi layer'larını kapsar; unsupported applications normal paths'i açığa çıkarır.

## Remote browser, VDI, RDP or organization jump host

**Mechanics:** Browsing/tool execution remote system'de gerçekleşir; destination onun egress'ini görürken workspace provider operator connection'ı ve control plane'i görür.

**Pros:** Hızlıdır; risky content'i isolate eder; stable controlled egress, disposable state ve strong organizational audit sağlar.

**Cons:** Provider/admin session/account'ı görebilir; screen/clipboard/file channels leak edebilir; remote browser fingerprint unique olabilir; workspace owner'a karşı anonymous değildir.

**Procedure:** (1) engagement başına organization-owned workspace oluşturun; (2) MFA isteyin ve administration'ı kısıtlayın; (3) clipboard/upload/download'ı disable veya constrain edin; (4) approved fixed egress üzerinden route edin; (5) personal IdP/sync kullanmayın; (6) yalnızca reviewed evidence export edin; (7) workspace ve credentials'ı schedule'a göre yok edin.

**Detection:** Provider ve IdP logs user'ı session'a map eder; destinations workspace egress/browser'ı cluster eder; enterprise defenders remote-control protocols ve anomalous cloud sessions'ı tanımlar.

## Public or guest Wi-Fi

**Mechanics:** Traffic venue NAT'inden veya orada başlatılan tunnel'dan çıkar.

**Pros:** Yüksek hız ve shared non-home address; dedicated infrastructure gerekmez.

**Cons:** Venue association/DHCP/portal, camera, purchase ve location evidence; hostile peers/APs; terms ve physical risk.

**Procedure:** (1) Guests'e sunulan access'i alın ve SSID'yi staff ile doğrulayın; (2) patched low-trust device kullanın; (3) sharing/auto-join'ı disable edin ve private MAC etkinleştirin; (4) portal'ı reused identity olmadan tamamlayın; (5) fail-closed VPN/Tor path başlatın; (6) tethered traffic'i doğrulayın; (7) network'ü forget edin.

**Detection:** Venue AP, MAC, DHCP, portal ve time'ı correlate eder; destination venue/tunnel'ı görür; investigators physical ve device evidence'ı birleştirir. Access control'ü asla bypass etmeyin.

## Travel router

**Mechanics:** Operator-owned router venue Wi-Fi/Ethernet'e katılır ve enforced tunnel policy'li isolated internal network sağlar.

**Pros:** Workstations'ı isolate eder; central kill switch/DNS; consistent client network; privileged endpoints'ı local broadcasts'tan korur.

**Cons:** Router stable radio/DHCP fingerprint olur; attack surface ekler; captive portals ve tethering tunnel'ı bypass edebilir.

**Procedure:** (1) supported firmware'i update edin; (2) unique management credentials ayarlayın ve WAN admin/WPS/UPnP'yi disable edin; (3) izin verilen yerde private upstream MAC yapılandırın; (4) separate internal SSID oluşturun; (5) full-tunnel DNS/IPv6 firewall policy enforce edin; (6) portal, reconnect ve tunnel failure'ı test edin.

**Detection:** Venue router association ve traffic shape'i görür; local RF/DHCP fingerprinting router'ı tanımlar; VPN provider venue source'u görür.

## Cellular, prepaid SIM and eSIM

**Mechanics:** Modem carrier radio access kullanır ve genellikle carrier NAT arkasındadır; VPN/Tor layer destination-visible exit'i değiştirebilir.

**Pros:** Local wired/Wi-Fi network'ten bağımsızdır; mobil ve hızlıdır; authorized drops için useful backhaul.

**Cons:** Carrier subscriber/eSIM, IMSI, IMEI, cells, time ve assigned ports'u bilir; registration laws değişir; personal phone ile co-location devices'ı bağlar.

**Procedure:** (1) service'i gerekli accurate details ile lawfully alın; (2) organization-owned separate modem/device kullanın; (3) exercise controller ile kaydedin; (4) unrelated radios/accounts'ı disable edin; (5) approved tunnel oluşturun; (6) tethered clients'ın gerçekten tunnel'ı izlediğini test edin; (7) travel öncesi provider ve retention assumptions'ı doğrulayın.<sup>[[13]](#references)</sup>

**Detection:** Carrier records ve RF location; enterprise USB/PCI/MDM inventory ve rogue-hotspot surveys; destination/tunnel timing.

## Satellite Internet and satellite downlink abuse

**Mechanics:** Normal service registered terminal/provider kullanır. Eski one-way DVB-S abuse, beam içindeki receiver'ın legitimate subscriber'a adreslenmiş unencrypted downlink traffic'i görmesine ve outbound requests için başka path kullanmasına izin veriyordu.

**Pros:** Wide footprint; independent last mile; historical one-way abuse C2'yi subscriber geography'sine yanlış atfedebilirdi.

**Cons:** Equipment/RF/provider records; latency ve coverage; modern bidirectional systems farklıdır; outbound path ve asymmetric routing evidence olarak kalır.

**Procedure:** Lawful access için owned terminal register edin ve gerektiğinde traffic'i tunnel edin. Historical Turla behavior'ı emulate etmek için synthetic one-way packet captures'ı RF-free lab içinde replay edin ve request yapmamış host'a verilen reply'ı analysts'in fark edip etmediğini test edin; live satellite traffic intercept etmeyin.<sup>[[14]](#references)</sup>

**Detection:** Provider/terminal telemetry, RF direction finding, impossible/asymmetric flow, RTT/routing inconsistency ve malware configuration.

## Residential/mobile proxy or consented proxyware

**Mechanics:** Backconnect gateway consumer broadband/mobile exits atar; exits sticky veya rotating olabilir. Supply consensual, deceptively bundled veya malicious olabilir.

**Pros:** Hızlıdır; geographic choice; consumer ASN bazı hosting blocks'ları aşar; large pools.

**Cons:** Provenance/consent ve legal risk; broker customer'ı görür; infected exits victims'a zarar verir; rotation anomalies oluşturur; pahalı ve unreliable'dır.

**Procedure:** Emulation için yalnızca documented, informed-consent organization-owned agents kullanın: (1) test endpoints enroll edin; (2) owners/IPs inventory'sini tutun; (3) gateway yapılandırın; (4) sticky/per-request modes rotate edin; (5) yalnızca owned target'a gönderin; (6) gateway/exit/target logs'u karşılaştırın; (7) tüm agents'ı kaldırın.

**Detection:** Impossible travel, rapid IP/ASN changes boyunca stable browser/account, backconnect protocols, proxyware process/network artifacts ve broker/controller relations.

## ORB, botnet and compromised edge-device relays

**Mechanics:** Leased veya compromised routers/IoT/servers access, traversal ve exit roles oluşturur; fleet olarak yönetilir. Birden fazla APT customer aynı fleet'i paylaşabilir.

**Pros:** Borrowed reputation/geography; short-lived exits; resilient multi-hop mesh; weak direct actor-to-IP link.

**Cons:** Criminal victimization; implant/controller ve fleet patterns; intermediary seizure; inconsistent performance; operator/customer service records.

**Procedure:** Gerçek devices'ı asla compromise etmeyin. [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) kullanın: (1) isolated entry/transit/target networks oluşturun; (2) owned dual-homed relay containers ekleyin; (3) yalnızca bir test port forward edin; (4) benign request gönderin; (5) target'ın yalnızca exit'i gördüğünü doğrulayın; (6) exit'i rotate edin; (7) named assets'ın tümünü tear down edin.<sup>[[15]](#references)</sup>

**Detection:** Topology, ports/services, controller relations, implant fingerprints ve node lifecycle izlenir; edge configuration/flow/integrity telemetry merkezileştirilir; exit IP actor ile eşitlenmemelidir.

## CDN redirector, domain fronting and domainless fronting

**Mechanics:** Public edge yalnızca belirli grammar'a uyan traffic'i forward eder; fronting, intermediary izin verdiğinde benign outer SNI ve farklı inner HTTP authority veya blank SNI kullanır.

**Pros:** Back-end'i gizler/korur; fast global edge; destination'ı shared service ile blend eder; rapid cutover.

**Cons:** CDN tüm routing ve tenant'ı görür; birçok provider cross-tenant fronting'i yasaklar; SNI/Host/process/flow ve account artifacts kalır; configuration reuse campaigns'ı cluster eder.

**Procedure:** Yalnızca owned reverse proxy'de [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging) ile reproduce edin: local certificate/edge oluşturun, mismatched Host'u owned target'a route edin, SNI ve Host loglayın, normal/mismatched requests gönderin, ardından containers'ı kaldırın.<sup>[[16]](#references)</sup>

**Detection:** SNI/ECH/Host/`:authority` endpoint veya terminating edge'de karşılaştırılır; initiating process, tenant/origin, request grammar ve flow cadence birleştirilir.

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics:** DDNS stable name'i update eder; DGA changing candidate names üretir; fast flux service addresses'ı low TTL ile rotate eder; double flux ayrıca name servers'ı da rotate eder.

**Pros:** Resilient discovery; rapid infrastructure replacement; controller'ı birçok node arkasında gizler.

**Cons:** DNS centralized telemetry üretir; entropy/NXDOMAIN/churn; low TTL ve broad ASN patterns; registration ve authoritative infrastructure kalır.

**Procedure:** [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry) kullanın: owned zone'u RFC 5737 addresses ve five-second TTL döndürecek şekilde sunun, tekrar tekrar query edin, synthetic epoch'i değiştirin ve analytics'i doğrulayın. Test records'ı third parties'e yönlendirmeyin.<sup>[[17]](#references)</sup>

**Detection:** Sliding-window unique answers/ASNs, median TTL, geography, authoritative churn, DGA NXDOMAIN/lexical/temporal clusters ve process follow-on; legitimate CDNs context ile hariç tutulur.

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics:** Public post, repository, document, object veya feed encoded current endpoint/task içerir. Client results'ı başka channel üzerinden döndürebilir.

**Pros:** Allowed high-reputation service; TLS; binary değiştirmeden endpoint rotation; asymmetric tasking simple flow correlation'ı zorlaştırır.

**Cons:** Stable object/account/API identifiers; provider records; endpoint decode/follow-on sequence; content seize veya change edilebilir.

**Procedure:** [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence) kullanın: encoded pointer'ı owned container'da host edin, short-lived client ile fetch/decode edin, ikinci owned service'e contact edin, iki log'u koruyun ve teardown yapın.

**Detection:** Unusual process → stable object read → decode → new destination sequence correlate edilir; content hash/preserve edin ve yalnızca domain değil full object paths saklayın.

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics:** Functions/short-lived jobs provider NAT veya front arkasında çalışır; logical service stable kalırken instances ve addresses rotate eder.

**Pros:** Rapid deployment/destruction; provider-scale shared egress; little local disk; elastic regional routing.

**Cons:** Tenant, role, API, image, secret, invocation, billing ve front-to-origin logs durable'dır; cold-start ve platform fingerprints; provider policy.

**Procedure:** (1) organization-owned exercise tenant kullanın; (2) yalnızca owned endpoint'i isteyen benign function deploy edin; (3) project/role/image/config'i kaydedin; (4) birkaç instance üzerinden invoke edin; (5) target IPs'i audit/request IDs ile karşılaştırın; (6) log retention'ı test edin; (7) function, roles ve secrets'ı kaldırın.

**Detection:** Cloud audit/invocation logs, unusual role creation, shared egress plus stable request grammar, image/layer ve secret reuse, front-origin correlation.

## Authorized on-site drop

**Mechanics:** Inventoried small computer local wired/Wi-Fi ve outbound VPN/cellular rendezvous kullanır ve local source olarak görünür.

**Pros:** Realistic internal-origin testing; yüksek hız; NAC, physical inventory ve egress controls test edilebilir.

**Cons:** Physical discovery/theft; serial/MAC/USB/DHCP/PoE/RF ve camera evidence; loss credentials'ı açığa çıkarabilir.

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) izleyin: (1) exact written placement authority alın; (2) serial, MAC, photo, location ve retrieval time kaydedin; (3) signed minimal image ve short-lived mutual credentials kullanın; (4) outbound-only destinations/capabilities'i sınırlandırın; (5) server-side quarantine ve bandwidth limits ekleyin; (6) SOC visibility ve loss response'u test edin; (7) geri alın, required evidence'ı koruyun ve agreed lifecycle policy kapsamında sanitize edin. Unconsenting venue içinde asla saklamayın.

**Detection:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera ve physical inspection.

## Nearest-neighbor wireless pivot

**Mechanics:** Actor, target'ın radio range'i içindeki host'u control eder ve target Wi-Fi credentials kullanarak boundary'yi remotely geçer. APT28 bu yöntemi nearby compromised organizations ile kullandı.<sup>[[18]](#references)</sup>

**Pros:** Operator travel gerekmez; target local radio source görür; yalnızca Internet entry'ye uygulanan controls bypass edilir.

**Cons:** Nearby compromised/owned dual-radio host ve valid access gerekir; RADIUS/NAC/AP ve neighbor endpoint evidence; signal/device anomalies.

**Procedure:** Yalnızca [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) ile reproduce edin: owned pivot'ı neighbor ve target lab SSIDs'ye join edin, yalnızca bir service forward edin, iki AP/pivot logs'u toplayın, ardından EAP-TLS/device posture etkinleştirip ikinci attempt'in başarısız olduğunu doğrulayın.

**Detection:** RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login ve physical presence correlate edilir; nearby endpoints simultaneous radios, forwarding ve tunnels için aranır.

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics:** Traffic, tek interactive Internet session yerine local peers, asynchronous gateways, removable media veya scheduled queues üzerinden ilerler.

**Pros:** Disruption/censorship sırasında çalışır; delayed/batched delivery simple timing'i zayıflatır; local communication için central last mile gerekmez.

**Cons:** High latency; small anonymity set; custody/physical metadata; malicious peers; data sonunda onu gören gateway'e ulaşır.

**Procedure:** (1) isolated owned three-node mesh veya file queue oluşturun; (2) content'i end to end encrypt/authenticate edin; (3) origin'den direct Internet routes'ı kaldırın; (4) controlled delay sonrasında benign file relay edin; (5) yalnızca gateway'in owned destination'a contact ettiğini doğrulayın; (6) custody/timestamps'ı karşılaştırın; (7) required evidence'ı koruyup approved closeout'ta temporary media/queues'ı sanitize edin.

**Detection:** Endpoint file/process activity, peer-radio links, removable-media audit, queue/gateway periodicity ve content identifiers. Longer correlation windows interactive-flow analysis'in yerini alır.

## TURN relay and forced-relay WebRTC

**Mechanics:** Traversal Using Relays around NAT (TURN), public relay address allocate eder ve client ile peers arasında UDP, TCP veya TLS traffic taşır. ICE policy direct candidate'ı expose etmek yerine relay use'u force edebilir. TURN reachability çözer, general anonymity'yi değil: server client'ı authenticate eder ve allocations, peers, time ve volume'u görür.<sup>[[19]](#references)</sup>

**Pros:** Widely implemented; restrictive NAT'i yönetir; mobile WebRTC destekler; relay-only policy doğru enforce edilirse peer client's direct transport address'ını almaz.

**Cons:** TURN operator iki adjacent side'ı görür; application identity, media fingerprint ve signaling kalır; relay-only bandwidth ve latency maliyetlidir; misconfiguration host veya server-reflexive candidates toplayabilir.

**Procedure:** (1) TLS ve short-lived credentials'lı organization-owned TURN service deploy edin; (2) realms, peers, ports, quotas ve expiration'ı kısıtlayın; (3) test application'ı relay-only ICE olarak ayarlayın; (4) owned peer'i arayın; (5) `getStats()` ve packet capture ile yalnızca relay candidates'ın media taşıdığını doğrulayın; (6) relay failure'ı test edip direct fallback olmadığını doğrulayın; (7) allocation logs'u engagement için saklayın.

**Detection:** Signaling, browser process ve TURN allocations session'ı relay'e bağlar; networks TURN ports veya TLS endpoints'a sustained flows görür; peer allocated relay'i görür. **Captured node:** Application state ve ephemeral TURN credentials realm ve rendezvous service'i açığa çıkarabilir. Exposure'ı per-device, short-lived credentials ile azaltın ve operator authentication'ı yalnızca controller'da tutun.

## Outbound-only rendezvous or reverse overlay

**Mechanics:** NAT arkasındaki node, organization-controlled broker'a authenticated connection başlatır. Operator broker'a ayrı authenticate olur; broker narrow management channel'ı authorize eder. Inbound port forwarding veya direct operator-to-node route gerekmez.

**Pros:** NAT ve captive last miles arkasında stable; central revocation ve audit; field-node address changes operator discovery gerektirmez; operator identity node credential'dan ayrılır.

**Cons:** Broker high-value correlation point olur; periodic keepalives tanınabilir; broad tunnel unsafe pivot olabilir; broker kaybı management'ı bitirir.

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous) izleyin: one scoped device identity issue edin, yalnızca owned broker ve approved management service'e izin verin, authenticated keepalive kullanın, fail-closed routing enforce edin, address changes ve reboot recovery'yi test edin ve loss drill sırasında identity'yi revoke edin. WireGuard, gerçekten gerektiğinde 25-second persistent keepalive'i broadly useful NAT interval olarak belgeler.<sup>[[20]](#references)</sup>

**Detection:** Broker ve identity-provider logs iki tarafı map eder; access network repeated encrypted destination/cadence görür; endpoint inventory overlay agent'ı gösterir. **Captured node:** Device key, broker name, tunnel addresses ve cached task data'nın açığa çıktığını varsayın. Operator private key, personal account veya reusable controller token içermemelidir.

## Pull mailbox, message queue or object-store rendezvous

**Mechanics:** Field workload authenticated mailbox'ı signed, pre-approved jobs için poll eder ve bounded results post eder. Operator queue'ya separate control plane üzerinden yazar; aralarında interactive socket yoktur.

**Pros:** Intermittent links'i tolere eder; timing ve addressing'i ayırır; quotas ve schemas capability'yi sınırlar; centralized audit/revocation kolaydır.

**Cons:** Polling cadence ve stable object/queue names system'i fingerprint eder; provider logs producer ve consumer'ı birleştirir; delayed control; captured queued data exercise'i açığa çıkarabilir.

**Procedure:** (1) engagement queue ve device identity oluşturun; (2) signed schema of benign, explicitly scoped jobs tanımlayın; (3) message TTL, maximum result size ve rate ayarlayın; (4) node'un yalnızca kendi queue'sunu pull ve result prefix'ine write edebilmesini sağlayın; (5) offline accumulation, duplicate delivery ve revocation'ı test edin; (6) immutable access logs'u merkezileştirin; (7) retention requirements karşılandığında queue'yu silin.

**Detection:** Unusual process'lerden periodic API calls, stable bucket/object/queue paths, identical user-agent/TLS behavior ve fetch-then-new-connection sequence aranır. **Captured node:** Local cache pending jobs ve object names'i açığa çıkarabilir; cache'i encrypted, bounded ve disposable tutun; authoritative controller logs'u koruyun.

## Dual-uplink failover and connection migration

**Mechanics:** Approved field node iki independent uplink'e sahiptir; örneğin venue Ethernet/Wi-Fi ve organization cellular. Overlay veya message broker üzerinden routes değişirken control session'ı korur. Bu availability engineering'dir, anonymity değildir.

**Pros:** Provider, AP veya captive-portal failure'dan kurtulur; planned maintenance destekler; suspect path hızlıca isolate edilebilir.

**Cons:** İki provider iki location/account record oluşturur; simultaneous use correlation'ı kolaylaştırır; failover sırasında route ve DNS leaks; cellular co-location evidence kalır.

**Procedure:** (1) Her iki organization-owned interface ve provider'ı register edin; (2) owned endpoints'a deterministic route priorities ve health checks atayın; (3) DNS ve management'ı overlay'e bind edin; (4) secondary path'in inbound traffic kabul etmesini engelleyin; (5) her path'i unplug edip session recovery, source policy ve direct destination access olmadığını doğrulayın; (6) unplanned path change için alert oluşturun; (7) data use ve roaming limits'i document edin.

**Detection:** Aynı device certificate, request grammar ve timing ASNs boyunca correlate edilir; local inventory iki radio'yu görür; carriers/venues kendi records'larını tutar. **Captured node:** Both SIM/device identifiers ve known SSIDs görünür olabilir; organization assets kullanın ve node'u personal devices ile co-locate/pair etmeyin.

## Organization private APN or managed cellular tunnel

**Mechanics:** Carrier private APN enrolled SIM'leri private routed domain'e yerleştirir veya traffic'i enterprise gateway'e tunnel eder. Device'ı public mobile Internet'ten ayırır fakat carrier veya contracting organization'dan gizlemez.

**Pros:** Stable private addressing; carrier-level enrollment ve traffic policy; public inbound exposure yoktur; authorized remote appliances için kullanışlıdır.

**Cons:** Subscriber, IMSI/IMEI, cell ve billing attribution güçlüdür; procurement lead time ve cost; carrier/gateway outage; operator'a karşı anonymous değildir.

**Procedure:** (1) APN'i assessment organization adına contract edin; (2) yalnızca registered SIMs ve gateway prefixes'i whitelist edin; (3) application-layer mutual authentication ekleyin; (4) APN route'unu rendezvous ve update services ile sınırlandırın; (5) SIM removal, roaming, public-Internet breakout ve revocation'ı test edin; (6) carrier ve gateway records'u izleyin; (7) closeout'ta her SIM'i cancel veya quarantine edin.

**Detection:** Carrier inventory ve cell telemetry, APN gateway flows, SIM/IMEI mismatch ve enterprise asset records. **Captured node:** Storage encrypted olsa bile SIM ve modem contract'ı tanımlar; capture resilience deniability değil rapid suspension ve narrow authorization demektir.

## Long-range point-to-point wireless bridge

**Mechanics:** Directional Wi-Fi veya başka licensed/unlicensed point-to-point radio iki owner-approved site'ı bağlar; Internet egress remote site'tadır. Commercial proxy kullanmadan apparent IP location'ı değiştirebilir.

**Pros:** High throughput; intermediate wired carriers'tan bağımsız; controllable RF ve routing; segmentation ve remote-site monitoring testleri için kullanışlı.

**Cons:** Line-of-sight, spectrum, landlord ve regulatory constraints; distinctive RF emissions ve hardware; iki endpoint physical evidence'tır; weather/power/alignment stability'yi etkiler.

**Procedure:** (1) iki site için written permission alın ve spectrum/power rules'ı doğrulayın; (2) approved parameters dışına transmit etmeden path'i survey edin; (3) authenticated encryption ve management VLAN kullanın; (4) bridge'i owned rendezvous veya test subnet ile sınırlandırın; (5) failover, alignment, power recovery ve RF containment'ı test edin; (6) iki radio'yu label/inventory edin; (7) exercise sonrası kaldırın ve configuration reset'i doğrulayın.

**Detection:** RF surveys, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic ve remote-site egress logs. **Captured node:** Configuration peer ve management domain'i açığa çıkarır; unique exercise credentials kullanın, personal management accounts kullanmayın ve peer-key'leri hızlıca revoke edin.

## Consented cooperative or community exit

**Mechanics:** Volunteers veya partner organizations published policy altında knowingly relays çalıştırır. Traffic shared community pool'dan çıkar; coordination layer abuse ve revocation'ı account eder.

**Pros:** Diverse non-cloud networks; explicit consent proxyware'dan daha güvenlidir; shared governance trust'ı dağıtabilir; research ve censorship-resilience studies için kullanışlıdır.

**Cons:** Small pools ve membership records anonymity'yi azaltır; exit operators complaints alır ve traffic metadata görür; malicious participants, variable uptime ve jurisdiction differences.

**Procedure:** (1) acceptable-use ve logging policy publish edin; (2) her operator'dan informed opt-in alın; (3) unique relay identity issue edin ve destinations/rates'i kısıtlayın; (4) abuse handling ve one-action revocation sağlayın; (5) testing sırasında yalnızca owned endpoints'a authorized traffic gönderin; (6) churn ve correlation exposure'ı ölçün; (7) consent sona erdiğinde relay'i temiz şekilde kaldırın.

**Detection:** Membership/control-plane records, relay certificates, common software fingerprint ve exit behavior pool'u tanımlar. **Captured node:** Relay configuration cooperative'i tanımlayabilir fakat client identities içermemelidir; client-to-session accountability authorized controller'da access control altında tutulmalıdır.

## IPv6 temporary addresses and prefix rotation

**Mechanics:** IPv6 privacy extensions, her outbound connection'da stable address'in reuse edilmemesi için temporary interface identifiers oluşturur. Provider prefix changes rotation ekleyebilir; fakat delegated prefix, subscriber record ve upper-layer fingerprint kalır.<sup>[[21]](#references)</sup>

**Pros:** Stable interface identifier ile passive long-term tracking'i azaltır; common operating systems'e built-in'dir; relay overhead yoktur.

**Cons:** Source anonymity değildir; ISP ve local network prefix/device'ı bilir; DNS, accounts ve browser state sessions'ı bağlar; address churn allowlists ve logging'i zorlaştırır.

**Procedure:** (1) owned client'te current stable ve temporary addresses'ı inceleyin; (2) third-party spoofing yerine OS-supported privacy-address default'ı etkinleştirin; (3) address lifetimes boyunca owned IPv6 endpoint'e tekrar tekrar request edin; (4) inbound services'ın yalnızca intended stable addresses'e bind olduğunu doğrulayın; (5) DHCPv6/RA/neighbor ve precise endpoint logs'u saklayın; (6) her IPv6 address için VPN/firewall behavior'ı test edin.

**Detection:** Bir address'i bir device kabul etmek yerine delegated prefix, layer-2 identity, neighbor discovery, account ve endpoint telemetry correlate edilir. **Captured node:** Network profiles ve interface identifiers kalır; temporary addressing bir passive identifier'ı önler, forensic attribution'ı değil.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics:** Pluggable transport, first Tor connection'ın görünümünü veya bridge'e ulaşma biçimini değiştirir. Snowflake short-lived volunteer WebRTC proxies kullanır; WebTunnel ordinary HTTPS'e benzer; obfs4 simple protocol identification ve active probing'e direnir; meek supported web infrastructure üzerinden relay eder. Bunlar Tor'a censorship-circumvention transports'tır, extra end-to-end anonymity layers değildir.<sup>[[22]](#references)</sup>

**Pros:** Direct Tor veya known relays block edildiğinde kullanışlıdır; Snowflake stable public bridge address'tan kaçınır; maintained Tor clients içine entegredir; destination ordinary Tor properties almaya devam eder.

**Cons:** Lower veya variable performance; broker/front/bridge ve local network farklı metadata görür; transport fingerprints ve blocking mümkündür; volunteer proxy Tor'un yerini almaz ve application plaintext'i için trusted kabul edilmemelidir.

**Procedure:** (1) official Tor Browser veya supported Tor client'ı install/verify edin; (2) Connection/Bridges'te built-in transport seçin; (3) yalnızca owned diagnostic page'e bağlanın; (4) page'in Snowflake/WebTunnel peer'i değil Tor exit gördüğünü doğrulayın; (5) bootstrap ve performance'ı karşılaştırın; (6) transport failure'ı test edip client'ın silently direct bağlanmadığını doğrulayın; (7) test sonrası standard supported configuration'a dönün.

**Detection:** Censor destination allowlists, TLS/WebRTC behavior, broker discovery ve flow analysis'i birleştirebilir; endpoints Tor ve transport configuration'ı açığa çıkarır. **Capture-resilient OPSEC:** Standard client kullanın, personal browser state'i içine kopyalamayın ve bridge/broker history'nin recoverable olduğunu varsayın. **Monitoring:** Tor bootstrap logs, unexpected direct DNS/connection attempts ve controller-side owned-page observations izlenmelidir; transport failure discovery kanıtı değildir.

## Refraction networking or decoy routing

**Mechanics:** Cooperating network operator, allowed decoy'a yöneltilmiş gibi görünen traffic içinde covert signal tespit eder ve flow'u circumvention proxy'ye divert eder. Deployment network path'te infrastructure gerektirir; client innocent website seçerek bunu tek başına oluşturamaz.<sup>[[23]](#references)</sup>

**Pros:** Apparent destination censor için collateral damage olmadan block edilmesi zor olabilir; public bridge address dağıtılması gerekmez; on-path-assisted circumvention için useful research model.

**Cons:** Specialized ISP/transit participation; deployability/performance routing'e bağlıdır; client-to-decoy flow ve proxy-side activity kalır; global/cooperating observer timing correlate edebilir.

**Procedure:** Uninvolved networks üzerinden signal göndermeyin. Architecture'ı isolated lab'da reproduce edin: (1) owned client, router, decoy ve proxy namespaces oluşturun; (2) benign tagged test request kullanın; (3) owned router'ın yalnızca tag'i proxy'ye redirect etmesini sağlayın; (4) pre/post-routing tuples ve request IDs loglayın; (5) ordinary ve signaled flows'u karşılaştırın; (6) false positives ve removal'ı test edin; (7) lab routes'ı yok edin.

**Detection:** Authorized network operators routing divergence, unusual client hello/tag behavior ve decoy-versus-back-end flow discrepancies'i inceleyebilir. **Capture-resilient OPSEC:** Research client yalnızca test keys ve documentation addresses tutmalıdır. **Monitoring:** Signed lab-router decisions ile proxy arrivals karşılaştırılmalıdır; signaling tespit edilip edilmediğini anlamak için production transit providers probe edilmemelidir.

## Content-addressed gateway or cached peer retrieval

**Mechanics:** HTTP gateway IPFS content identifier (CID)'yi cache veya peers'ten retrieve eder ve verifiable content'i client'a döndürür. Original publisher final reader yerine gateway veya peers'ı görebilir; gateway reader IP ve requested CID'yi görür. Native peer-to-peer retrieval client'ı peers ve DHT/routing participants'a açar.<sup>[[24]](#references)</sup>

**Pros:** Caches publisher ve reader'ı ayırabilir; immutable content hash ile verify edilir; replicated data tek host failure'ından kurtulur; HTTP clients native peer stack gerektirmez.

**Cons:** Public CIDs ve gateway logs interests'i açığa çıkarır; first retrieval timing publisher ve reader'ı correlate edebilir; malicious web content ve path-style same-origin hazards; public gateways best-effort'tur ve abuse'u yasaklar.

**Procedure:** (1) harmless test file'ı owned private IPFS swarm veya owned gateway'e publish edin; (2) CID'yi kaydedin; (3) separate owned HTTP gateway üzerinden subdomain isolation ile retrieve edin; (4) bytes'ı CID'ye karşı verify edin; (5) caching sonrası tekrarlayın; (6) publisher, peer ve gateway logs'u karşılaştırın; (7) retention sona erdiğinde unpin edip test content'i kaldırın.

**Detection:** Gateways source/CID loglar; DHT ve peer connections retrieval'ı gösterir; endpoint history ve file hashes content'i tanımlar. **Capture-resilient OPSEC:** Read-only field client'ta private publishing key saklamayın ve sensitive content'i content addressing öncesi encrypt edin. **Monitoring:** Unexpected pinning, peer-set change, allowlist dışı CID requests veya gateway account notices için alert oluşturun.

## Private information retrieval service

**Mechanics:** Private Information Retrieval (PIR), stated single- veya multi-server threat model altında client'ın database'den bir record retrieve ederken selected index'i server'dan cryptographically gizlemesini sağlar. Bounded dataset içindeki query selection'ı korur; general web access veya IP anonymity değildir.<sup>[[25]](#references)</sup>

**Pros:** Strong application-specific query privacy; measurable leakage model; key directories, blocklists veya small public databases için useful; exact lookup terms'i açıklama ihtiyacını azaltabilir.

**Cons:** Computation/bandwidth overhead; relay ile combine edilmezse server connection time/IP'yi öğrenir; dataset version, response size ve application state users'ı partition edebilir; implementation maturity değişir.

**Procedure:** (1) synthetic owned database üzerinde audited PIR implementation deploy edin; (2) dataset version ve parameters publish edin; (3) identical request sizes ile birkaç index retrieve edin; (4) correctness'ı local verify edin; (5) server logs'u karşılaştırın ve index'in bulunmadığını doğrulayın; (6) malicious/truncated responses ve version mismatch'i test edin; (7) exact privacy assumption'ı document edin ve bunu anonymous browsing olarak adlandırmayın.

**Detection:** Networks service use ve volume'u görür; endpoint telemetry client ve final record use'u açığa çıkarır; compromised server datasets veya timing'i manipulate edebilir. **Capture-resilient OPSEC:** Client'ta yalnızca public database parameters ve bounded cache tutun. **Monitoring:** Signed dataset roots, fixed request shapes, error-rate changes ve server-key rotations doğrulanmalıdır.

## Constrained server-side fetcher, preview or rendering service

**Mechanics:** Remote service URL fetch veya render eder ve screenshot, metadata veya sanitized content döndürür. Destination fetcher address'i görür; service requester, URL ve result'ı görür. Link-preview bots, security scanners veya third-party URL fetchers'ı kötüye kullanmak authorized proxy use değildir.

**Pros:** Active content'i workstation'dan isolate eder; destination controlled fetcher fingerprint görür; file type, size, destination ve rendering limits enforce edilebilir; disposable execution environment.

**Cons:** Service request knowledge'ın tamamına sahiptir; account/API/billing records; SSRF ve data-exfiltration risk; scripts, authentication ve interactive sites çalışmayabilir; unique URLs requester ve fetch'i correlate eder.

**Procedure:** (1) strict allowlist'i owned test domains olan organization-owned fetcher deploy edin; (2) private, link-local, metadata ve redirect-to-unapproved addresses'ı block edin; (3) methods, redirects, bytes ve render time'ı cap edin; (4) credentials/cookies'i strip edin; (5) owned URL submit edin; (6) requester, fetcher ve target logs'u karşılaştırın; (7) render instance'ı yok edin ve central audit'i policy'ye göre saklayın.

**Detection:** Target service ASN/fingerprint'i görür; provider/controller logs requester'ı URL'ye map eder; endpoint process/API calls submission'ı gösterir. **Capture-resilient OPSEC:** Arbitrary destination authority olmayan short-lived project token kullanın. **Monitoring:** Allowlist denials, redirect violations, controller job ID'siz fetches ve provider abuse notices için alert.

## Anycast rendezvous pool

**Mechanics:** Multiple organization-controlled nodes stable service address'i advertise veya front eder; routing yakın instance'ı seçer. Anycast availability'yi artırır ve individual back-end'i client'tan gizler; operator tüm instances'ı kontrol eder ve service address stable'dır.<sup>[[26]](#references)</sup>

**Pros:** Resilient regional ingress; bir instance failure'ında field reconfiguration gerekmez; DDoS/load distribution; central policy sessions'ı known nodes arasında taşıyabilir.

**Cons:** BGP/CDN ve provider records organization'ı tanımlar; path changes stateful sessions'ı bozabilir; monitoring client location'a göre farklıdır; stable address kolayca block veya reputation-cluster edilir.

**Procedure:** Provider-supported organization project veya isolated routing lab kullanın: (1) iki identical authenticated health endpoint deploy edin; (2) documented service address expose edin; (3) session state'i edge yerine broker'da tutun; (4) bir node'u withdraw edip reconnection'ı doğrulayın; (5) certificate, policy ve log consistency'yi test edin; (6) unauthorized origin/region için alert oluşturun; (7) closeout'ta advertisements ve credentials'ı kaldırın.

**Detection:** BGP/RPKI/history, provider tenancy, certificates ve identical service behavior pool'u tanımlar. **Capture-resilient OPSEC:** Edge yalnızca regional service identity tutmalı; operator veya fleet-enrollment key tutmamalıdır. **Monitoring:** Her region'ı authorized monitors'tan probe edin, route origin ve configuration digest'i karşılaştırın; unexpected origin'i incident kabul edin.

## QUIC migration and Multipath TCP continuity

**Mechanics:** QUIC connection IDs NAT rebinding veya address changes boyunca client session'ı canlı tutabilir; Multipath TCP tek reliable byte stream'i multiple subflows üzerinden taşıyabilir. Wi-Fi/cellular transitions boyunca continuity geliştirir; fakat common peer eski ve yeni paths'i görür ve cross-path correlation'ı kolaylaştırabilir.<sup>[[27]](#references)</sup>

**Pros:** Uplink changes sırasında faster recovery; application session restart gerekmez; MPTCP resilience ve throughput'u birleştirebilir; approved field nodes için değerlidir.

**Cons:** Anonymity değildir; peer migration/subflows'ı görür; connection identifiers ve simultaneous traffic paths'i bağlar; middlebox/carrier support değişir; duplicated provider records exposure'ı artırır.

**Procedure:** (1) supported transport'u yalnızca owned field client ve rendezvous arasında enable edin; (2) application'ı IP'den bağımsız authenticate edin; (3) approved Wi-Fi üzerinde bounded transfer başlatın; (4) organization cellular'a geçin; (5) path validation, data integrity ve clear/direct fallback olmadığını doğrulayın; (6) idle timeout ve return'ü test edin; (7) her path transition için broker records saklayın.

**Detection:** Peer address migration veya MPTCP subflows'ı doğrudan görür; access providers kendi kısmını görür; connection IDs, TLS identity ve timing ikisini bağlar. **Capture-resilient OPSEC:** Yalnızca device-scoped session material saklayın ve resumable state'i hızlı expire edin. **Monitoring:** Impossible path changes, simultaneous unapproved networks, migration storms ve quarantine sonrası resumption için alert.

## Managed CI/CD or ephemeral automation runner egress

**Mechanics:** Organization-owned workflow hosted runner üzerinde bounded network check çalıştırır. Destination cloud runner address'i görür; platform repository, actor, workflow, token, log ve billing attribution'ı tutar. Bu provider'dan anonymity değil, accountable egress ile remote execution'dır.<sup>[[28]](#references)</sup>

**Pros:** Disposable clean environment; reproducible job definition; inbound connection yoktur; geographically distributed availability checks için kullanışlıdır; strong controller audit.

**Cons:** Platform ve organization initiator'ı tanımlar; broad workflow tokens ve untrusted pull requests tehlikelidir; shared IP reputation; logs/artifacts secrets veya target data tutabilir.

**Procedure:** (1) assessment için private organization repository ve environment oluşturun; (2) yalnızca manually approved, fixed benign jobs'ı owned endpoints'a izin verin; (3) minimal read-only workflow permissions ve production secrets olmamasını sağlayın; (4) check'i çalıştırın; (5) workflow, provider ve target records'ı karşılaştırın; (6) artifacts'ın credentials içermediğini doğrulayın; (7) environment token'ı silin ve required audit'i saklayın.

**Detection:** Provider audit ve workflow logs direct attribution sağlar; targets runner ASNs/ranges ve stable request grammar'ı tanımlar. **Capture-resilient OPSEC:** Field-device, signing, wallet veya cloud-administrator secrets'ı runner variables içine koymayın. **Monitoring:** Branch/environment approval isteyin ve workflow edits, fork execution, secret reads ve unexpected destinations için alert oluşturun.

## Non-IP local first hop to an owned gateway

**Mechanics:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio veya serial/optical link nearby sensor'dan owner-approved Internet gateway'e bounded messages taşır. Field device'ın Internet route'u yoktur; tek egress gateway'dir. Radio range ve protocol limits bunu telemetry/store-and-forward design yapar, interactive anonymous Internet yapmaz.

**Pros:** Smallest field device'tan Internet stack ve credentials'ı kaldırır; low power; gateway policy'yi merkezileştirir; temporary dead zones'u bridge edebilir.

**Cons:** RF/physical discovery, pairing ve device identifiers; small bandwidth/range; gateway tüm messages'ı bağlar; spectrum ve encryption restrictions değişir; capture queued data'yı açığa çıkarabilir.

**Procedure:** (1) site ve spectrum approval alın; (2) bir owned sensor'ı bir owned gateway ile unique keys kullanarak pair edin; (3) signed fixed-size message types, TTL ve rate tanımlayın; (4) sensor'a default IP route vermeyin; (5) gateway'in yalnızca owned collector'a forward etmesini sağlayın; (6) replay, range loss ve gateway outage'ı test edin; (7) iki device'ı inventory edip geri alın.

**Detection:** RF survey, pairing database, physical inspection ve gateway process/flow logs path'i açığa çıkarır. **Capture-resilient OPSEC:** Sensor yalnızca pairwise key ve bounded encrypted queue tutmalı; operator, Wi-Fi, cellular veya controller credentials tutmamalıdır. **Monitoring:** New peers, sequence rollback, key failure, unusual RF rate ve unregistered gateway üzerinden gelen messages için alert.

## Capture/compromise exposure matrix

Bu table yukarıdaki her family için capture-resilience check uygular. “Minimize”, authorized assets üzerindeki secrets ve blast radius'u azaltmak demektir; evidence'ı silmek veya investigation'dan gizlenmek anlamına gelmez.

| Technique family | A captured endpoint/relay can reveal | Minimum authorized control |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | bilinen networks, DHCP/portal history, MACs, tunnel peer | ayrı organization device; supported ise private MAC; personal accounts yok; controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostnames, keys, routes, logs ve adjacent hop | engagement başına one identity; short TTL; narrow routes; broker-side revocation; master keys yok |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration, application identifiers ve cached requests | payload identifiers'ı minimize edin; approved config pin edin; bounded cache; strict no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | installed software, bridge/onion material, local state ve peer history | standard client; separate service keys; encrypted minimal state; compromised service identity rotate edin |
| Remote browser/VDI/jump host | workspace token, clipboard/files ve remote tenant | gateway'de phishing-resistant MFA; transfer channels disabled; rapid session revocation |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/terminal identity, provider ve approximate location | organization contract; personal co-location yok; narrow APN/overlay policy; provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity, controller/next hop, cached traffic | yalnızca consented/owned nodes; signed agent; per-node credential; controller-held participant mapping |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API tokens, deployment ve billing references | dedicated project; least-privilege role; short-lived deploy token; provider audit centrally retained |
| Dead drop, pull mailbox, store-and-forward | object names, queue, cached jobs/results ve custody data | signed bounded jobs; TTL; encrypted cache; separate producer identity; immutable server logs |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, physical placement artifacts | written placement; unique device identity; operator secret yok; tamper/state telemetry; revoke and recover |
| TURN, reverse overlay, dual-uplink | realm/broker, device credential, peer/route ve uplink profiles | outbound-only narrow service; short-lived device credential; independent operator login; fail-closed paths |
| IPv6 temporary addressing | profiles, prefix history ve endpoint/application state | yalnızca anti-tracking olarak değerlendirin; network logs'u koruyun; endpoint compartmentation ile pair edin |
| Pluggable transport/refraction lab | bridge/broker/decoy settings, Tor state ve research keys | standard client veya isolated lab; personal browser state yok; production signaling yok |
| IPFS/PIR/fetcher | requested CID/query client, cached content, gateway veya service token | encrypted bounded cache; public-only parameters; short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service nodes, connection IDs, resumable state ve bilinen her path | regional identity only; short resumption lifetime; central route/session revocation |
| Managed CI/CD runner | repository, workflow, provider token, logs ve artifacts | least-privilege workflow; production/field/wallet secrets yok; environment approval |
| Non-IP local hop | radio peer, pairwise key, queued messages ve gateway identity | unique pairwise key; fixed message schema; Wi-Fi/cellular/operator credential yok |

## Monitoring possible discovery for every access family

Hiçbir client-side test investigator veya defender'ın izlediğini kanıtlamaz. Engagement'ın sahip olduğu systems üzerindeki changes'ı izleyin, controller/client ile corroborate edin ve observers'ı probe etmek yerine stop edin. Aşağıdaki rows yukarıdaki her technique'i kapsar; bunları [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise) ile birleştirin.

| Covered techniques | Safe controller-side signals | Quarantine/stop condition |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session, public tuple, BSSID/cell/path change, provider notice | unapproved network/SIM/device, unexplained relocation veya provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication, tunnel state, route/DNS leaks, new admin/API event, complaint | duplicate/stolen credential, unknown administrator, direct fallback veya out-of-scope egress |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation, key/config version, unsupported direct connection, error/replay rate | key mismatch, direct fallback, unknown realm/peer veya provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state, circuit failure, onion descriptor/service health ve owned canary page | personal-account crossover, unexpected non-Tor connection veya compromised service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, queue age/sequence, gateway arrival, radio association ve content hash | unknown peer/gateway, sequence rollback, unauthorized content veya missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session, workflow/image/config change, new token use, artifact/export ve cloud audit | unknown login/workflow edit, secret read, unexpected destination veya project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory, DNS/edge/object access, controller graph, job signature ve TTL | unknown node/origin/object writer, unsigned/replayed job, topology escape from lab |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat, boot/config hash, enclosure state, AP/switch context, duplicate identity | moved/opened node, unexpected boot/hash/path, sentinel use veya site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix, connection ID/subflows, path-validation ve broker session | impossible migration, simultaneous unapproved paths veya session resumption after revoke |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, peer/gateway change, redirect/allowlist denial | unexpected pin/query/destination, unsigned dataset root veya provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision, proxy arrival, BGP/RPKI origin, regional config digest | production-path signal, unknown route origin, region/config inconsistency |

## Choosing and testing a path

1. Kaldırılacak observer'ı ve gizlenecek data'yı adlandırın.
2. Bunu kaldıran en az complex family'yi seçin.
3. Source, entry, traversal, exit, DNS, account ve payment observers'ı çizin.
4. Ayrı endpoint/application identity kullanın.
5. IPv4, IPv6, DNS, WebRTC/application bypass ve destination view'u doğrulayın.
6. Her hop'u bozun ve failure'ın closed olduğunu doğrulayın.
7. Kontrol ettiğiniz her component'teki logs'u karşılaştırın.
8. Residual timing, provider, endpoint ve physical links'i kaydedin.

## References

- [1] [EFF — Sizin için doğru VPN'i seçme](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — HTTP'de UDP Proxy'leme](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor protections](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Tor'un engelini kaldırma](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Tor Browser'ı VPN ile kullanma](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion services overview](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonymous file sharing](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Zorunlu SIM registration](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: NAT and Firewall Traversal Persistence](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — IPv6'da Stateless Address Autoconfiguration için Temporary Address Extensions](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports and bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — project and deployment research](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — HTTP Gateway concepts and request lifecycle](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Private Information Retrieval overview](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Operation of Anycast Services](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — QUIC connection migration](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
