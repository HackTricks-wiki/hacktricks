# Offensive Privacy, Attribution Evasion ve OPSEC

{{#include ../banners/hacktricks-training.md}}

Bu bölüm privacy konusunu red team, intrusion operator ve bu operatorü yeniden yapılandırmaya çalışan defender perspektifinden inceler. **Anonymity yalnızca bir IP adresini gizlemek değildir.** Olgun operasyonlar; attribution graph içinde birleştirilebilecek kişileri, endpoint'leri, hesapları, infrastructure'ı, network path'lerini, payload'ları ve ödemeleri birbirinden ayırır.

Materyal, government ve APT operasyonlarında raporlanan teknikleri özellikle içerir: operational-relay-box (ORB) network'leri, ele geçirilmiş edge device'lar, residential exit'ler, redirector katmanları, fast flux, domain fronting, dead-drop resolver'lar, yakındaki wireless pivot'lar, covert drop device'lar, satellite-link abuse, false persona'lar ve financial layering. Her teknik şu şekilde sunulur:

1. operasyonel amaç ve ATT&CK eşlemesi;
2. mekanizma ve trust boundary'ler;
3. her observer'ın hâlâ kaydedebileceği şeyler;
4. tekniği bozan hatalar ve kalıcı artifact'ler;
5. defensive telemetry, analytics ve mitigation'lar; ve
6. sahibi olunan veya açıkça scope'u belirlenmiş infrastructure kullanılarak gerçekleştirilen yetkili bir emulation.

Bu nedenle bu bölüm hem offensive tradecraft reference hem de defender's attribution manual'dır. Amaç advanced behavior'ı anlaşılır ve test edilebilir hâle getirmektir; tek bir commercial service'in operatorü görünmez yaptığını iddia etmek değil.

**Research cutoff:** 8 September 2026. Provider availability, product behavior, sanctions, cash/prepaid thresholds, SIM-registration rules ve crypto regulation sık sık değişir; bunlara güvenmeden önce tekrar doğrulayın.

{% hint style="danger" %}
Bir tekniği anlamak, onu uygulama yetkisi vermez. Sayfalar; compromised router'lar, bir komşunun Wi-Fi'ı, hidden device'lar, stolen identity'ler ve laundering gibi criminal abuse örneklerini mechanism-and-detection seviyesinde açıklar. Reproduction adımları yalnızca sahibi olunan lab system'lerini, synthetic identity'leri ve test asset'lerini kullanır. Asla üçüncü bir tarafa erişmeyin, KYC veya sanctions kontrollerinden kaçınmayın ya da criminal proceeds'i gizlemeyin. Unauthorized access, US CFAA, UK Computer Misuse Act ve Directive 2013/40/EU'yu uygulayan AB üyesi devlet yasaları dahil olmak üzere birçok jurisdiction'da suç sayılır.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
{% endhint %}

## Adversary objective map

| Adversary objective | Technique families | Principal defensive question |
|---|---|---|
| Operator'ın origin'ini gizlemek | VPN/Tor, external ve multi-hop proxy'ler, residential/mobile exit'ler, ORB'ler, satellite link'leri | Last-hop address bir actor asset'i mi, farkında olmayan bir victim mı, yoksa kısa ömürlü bir relay mi? |
| Gerçek C2'yi keşfedilemez tutmak | redirector'lar, CDN'ler, domain fronting, dead-drop resolver'lar, dynamic DNS, fast flux | IP/domain rotation sonrasında hangi stable behavior varlığını sürdürüyor? |
| Trust ve reputation ödünç almak | compromised server'lar, router'lar, cloud ve web-service account'ları, domain shadowing | Reputable bir asset historical baseline'ından farklı mı davranıyor? |
| Fiziksel veya network boundary'yi aşmak | nearest-neighbor Wi-Fi pivot'ları, on-site drop'lar, rogue peripheral'lar, cellular backhaul | Hangi yeni radio, device, switchport veya outbound tunnel ortaya çıktı? |
| Human'ı operation'dan ayırmak | persona'lar, account/device compartmentation, cover communication'lar, procurement separation | Hangi recovery field, browser, schedule, language, payment veya admin event persona'ları birbirine bağlıyor? |
| Funding ve cash-out'u belirsizleştirmek | mule/nominee'ler, prepaid value, mixer'lar, CoinJoin, peel chain'ler, chain hopping, OTC broker'lar | On-chain ve off-chain identity record'ları nerede yeniden birleşiyor? |

En yakın ATT&CK resource-development ve C2 kavramları **Acquire Infrastructure (T1583)**, **Compromise Infrastructure (T1584)**, **Establish/Compromise Accounts (T1585/T1586)**, **Proxy (T1090)**, **Dynamic Resolution (T1568)** ve **Web Service (T1102)**'dir.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

## Privacy, pseudonymity, anonymity ve security

| Goal | Meaning | Typical failure |
|---|---|---|
| **Confidentiality** | Dış taraflar içeriği okuyamaz | Metadata yine tarafları belirler |
| **Privacy** | Information disclosure yalnızca gerekli olanla sınırlıdır | Provider beklenenden daha fazla data saklar |
| **Pseudonymity** | Activity, legal identity ile public olarak ilişkilendirilmemiş stable bir identity kullanır | Recovery email, payment, IP, photo veya writing style bağlantı kurar |
| **Anonymity** | Observer, actor'ı anlamlı bir başkaları kümesinden ayırt edemez | Login, fingerprint, timing, location veya transaction correlation kümeyi küçültür |
| **Unlinkability** | İki action güvenilir biçimde aynı actor'a atfedilemez | Reused identifier'lar, eşzamanlı activity veya shared infrastructure bunları birleştirir |
| **Security** | System'ler compromise'a karşı dirençlidir | Secure ancak tanımlanmış bir account anonymous olmaya devam etmez |

Bu özellikler observer'a özgüdür. Bir merchant card number'ı görmeyebilir; issuer ise customer'ı ve transaction'ı hâlâ bilir. Bir website home IP yerine Tor exit görebilir; ancak account login user'ı hemen tanımlayabilir.

## Observer ile başlayın

Tool seçmeden önce şunları yazın:

1. **Assets:** identity, location, browsing destination'ları, message content'leri, social graph, payment detail'leri, client name, red-team source infrastructure veya stored evidence.
2. **Observers:** local Wi-Fi operator'ı, ISP/mobile carrier, VPN, Tor entry/exit, DNS resolver, website, ad network, cloud host, payment issuer, merchant, exchange, counterparty'ler, employer veya government.
3. **Correlation handles:** IP address, account/recovery field'ları, phone number, device identifier'ları, cookie'ler, browser fingerprint, time zone, payment instrument, shipping address, writing style, transaction graph, physical presence ve camera'lar.
4. **Capability ve time:** passive commercial tracking, provider'lara subpoena gönderebilen, endpoint'leri ele geçirebilen veya connection'ın iki ucunu da izleyebilen targeted observer'dan farklıdır.
5. **Failure cost:** embarrassment, account suspension, client harm, financial loss, physical danger veya legal exposure.

Ardından sürdürülebilir en küçük control set'ini seçin. Rutin olarak bypass edilen karmaşık bir plan, tutarlı biçimde kullanılan daha basit bir plandan daha zayıftır.

## Quick decision table

| Need | Sensible starting point | What it **does not** solve |
|---|---|---|
| ISP/local network'ten browsing metadata'sını gizlemek | Reputable VPN veya Tor Browser | Account'lar, cookie'ler, device fingerprint, endpoint compromise |
| Daha güçlü web anonymity | Tor Browser; amnesic session için Tails | Global traffic correlation, personal disclosure'lar, physical observation |
| Kalıcı compartmentalized work | Whonix veya Qubes-Whonix; ayrı qube/profile'lar | Hypervisor/host compromise, behavior linking identities |
| Hızlı authorized red-team egress | Client-provided jump host veya engagement-specific VPS/VPN | Provider/customer attribution; scope ve cloud policy yükümlülükleri |
| Merchant'ın card number'a maruz kalmasını azaltmak | Issuer virtual card veya tokenized wallet | Issuer/network bilgisi, shipping, account ve device data |
| Point-of-sale payment data'sını azaltmak | Kabul edilen yerlerde lawfully obtained cash | CCTV, receipt'ler, withdrawal trail, cash limit'leri |
| Public-chain crypto privacy'sini geliştirmek | Own wallet/node, new address'ler, coin control, Tor, supported PayJoin | Exchange/KYC, counterparty record'ları, permanent-chain analysis |
| On-chain amount/receiver/sender confidentiality için varsayılan seçenek | Ayrı wallet context'leri ve network privacy ile Monero | Acquisition/off-ramp record'ları, endpoint compromise, merchant/shipping data |

## Core rules

- **Activity başlamadan önce context'leri ayırın.** Account'lar, device'lar ve payment'lar zaten ilişkilendirildikten sonra separation'ı sonradan uygulamak geçmişi nadiren geri alır.
- **Kendinizi uniqueness yaratacak şekilde customize etmeyin.** Browser fingerprinting, cookie'ler silinse veya IP değişse bile activity'yi correlate edebilir; daha büyük anonymity set'lerine sahip standard configuration'lar genellikle tercih edilmelidir.<sup>[[5]](#references)</sup>
- **Endpoint'i koruyun.** Network anonymity, unlocked, infected veya seized bir device'ı kurtaramaz.
- **Content'i encrypt edin ve metadata'yı minimize edin.** End-to-end encryption message content'ini korur; ancak kimin iletişim kurduğunu, ne zaman, nereden veya hangi device ile iletişim kurduğunu zorunlu olarak korumaz.
- **Provider'ları observer olarak değerlendirin.** VPN'ler, email service'leri, cloud host'lar, exchange'ler, payment issuer'ları ve alias forwarder'lar activity'nin farklı bölümlerini görür.
- **Doğrulanabilir claim'leri tercih edin.** “Military-grade” marketing yerine protocol documentation, reproducible software, public audit'ler, retention detayları ve transparency report'ları arayın.
- **Düzenli olarak yeniden değerlendirin.** Service'ler, yasalar, threat actor'lar ve default'lar değişir.

## Offensive-first section map

- [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) — pros, cons, deployment/emulation steps, detection, capture exposure ve controller-side discovery monitoring içeren 48 access-path family.
- [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) — pros, cons, lawful workflow'lar, detection, capture exposure ve compromise monitoring içeren 48 payment family.
- [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) — owner-approved drop'lar için stable outbound rendezvous, dual-uplink recovery, secret minimization, capture drill'leri ve discovery/compromise monitoring.
- [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) — ORB'ler, multi-hop/residential relay'ler, redirector'lar, fronting, fast flux, domain shadowing, web service'ler ve persona infrastructure.
- [Covert Physical and Wireless Access](covert-physical-wireless-access.md) — nearest-neighbor attack'ler, public access, drop device'lar, cellular backhaul ve satellite abuse.
- [Government and APT Case Studies](government-and-apt-case-studies.md) — yeniden yapılandırılmış public case'ler ve bunları ortaya çıkaran telemetry.
- [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md) — payment layering'ın nasıl çalıştığı, neden başarısız olduğu ve investigator'ların onu nasıl takip ettiği.
- [Attribution, Detection and Countermeasures](attribution-detection-and-countermeasures.md) — cross-layer detection model'i ve pratik hunting logic.
- [Authorized Adversary-Emulation Labs](authorized-adversary-emulation-labs.md) — owned network'ler ve synthetic data kullanılarak tekrarlanabilir exercise'ler.

## Operator fundamentals and supporting guides

- [Threat Modeling & Identity Separation](threat-modeling-and-identity-separation.md)
- [Network Privacy & Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md)
- [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md)
- [Privacy Operating Systems](privacy-operating-systems.md)
- [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md)
- [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)
- [Private Digital Payments](private-digital-payments.md)
- [Cryptocurrency Privacy](cryptocurrency-privacy.md)
- [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md)
- [Reproducible Privacy Testing](reproducible-privacy-testing.md)
- [Operational Privacy Playbooks](operational-privacy-playbooks.md)

## Guide and verification index

| Technique | Deployment guide | Verification/failure test |
|---|---|---|
| Tüm Internet-access technique family'leri | [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) | Technique başına detection ve [reproducible labs](authorized-adversary-emulation-labs.md) |
| Tüm payment technique family'leri | [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) | Technique başına detection ve [synthetic payment lab](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Owner-approved physical field node | [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) | Capture drill, off-device state monitoring ve suspected-discovery runbook |
| ORB'ler, residential relay'ler, fronting, fast flux ve dead drop'lar | [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) | [Owned emulation labs](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) |
| Nearest-neighbor Wi-Fi, drop'lar, cellular ve satellite path'leri | [Covert Physical and Wireless Access](covert-physical-wireless-access.md) | [Owned wireless-pivot lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) |
| Cross-layer infrastructure ve operator attribution | [Attribution, Detection and Countermeasures](attribution-detection-and-countermeasures.md) | [Exercise report template](authorized-adversary-emulation-labs.md#exercise-report-template) |
| Peel chain'ler, mixer'lar, chain hopping, nominee'ler ve OTC conversion | [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md) | [Synthetic transaction graph](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Identity/browser compartment | [Threat Modeling & Identity Separation](threat-modeling-and-identity-separation.md) | [Browser and OS tests](reproducible-privacy-testing.md#browser-compartment-test) |
| VPN, Tor, guest Wi-Fi, travel router, cellular | [Network Privacy & Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md) | [Network-path test](reproducible-privacy-testing.md#network-path-test) |
| Split relay'ler, OHTTP, namespace'ler, bridge'ler, onion'lar, I2P | [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) | [Tor/onion and route tests](reproducible-privacy-testing.md#tor-and-onion-service-test) |
| Tails, Whonix ve Qubes | [Privacy Operating Systems](privacy-operating-systems.md) | [OS isolation test](reproducible-privacy-testing.md#operating-system-isolation-test) |
| Signal, SimpleX, Briar, OnionShare ve encrypted file'lar | [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md) | [Communications/file tests](reproducible-privacy-testing.md#communications-metadata-test) |
| Authorized red-team egress/drop node'ları | [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) | [Accountability drill](reproducible-privacy-testing.md#authorized-red-team-accountability-drill) |
| Cash, prepaid ve virtual card'lar | [Private Digital Payments](private-digital-payments.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |
| Bitcoin, PayJoin/CoinJoin, Lightning ve Monero | [Cryptocurrency Privacy](cryptocurrency-privacy.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |
| Silent Payments, Zcash, Taler ve federated e-cash | [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |

## References

- [1] [EFF Surveillance Self-Defense — Güvenlik Planınız](https://ssd.eff.org/module/your-security-plan)
- [2] [US Code, 18 USC §1030 — Bilgisayarlarla bağlantılı dolandırıcılık ve ilgili faaliyetler](https://uscode.house.gov/view.xhtml?req=title:18%20section:1030%20edition:prelim)
- [3] [UK Computer Misuse Act 1990, section 1](https://www.legislation.gov.uk/ukpga/1990/18/section/1)
- [4] [EUR-Lex — Information system'lerine yönelik saldırılar hakkında Directive 2013/40/EU](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32013L0040)
- [5] [W3C — Web Specifications'ta Browser Fingerprinting'i Azaltma](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [MITRE ATT&CK — Acquire Infrastructure (T1583) ve Compromise Infrastructure (T1584)](https://attack.mitre.org/techniques/T1584/)
- [7] [MITRE ATT&CK — Proxy (T1090)](https://attack.mitre.org/techniques/T1090/)
{{#include ../banners/hacktricks-training.md}}
