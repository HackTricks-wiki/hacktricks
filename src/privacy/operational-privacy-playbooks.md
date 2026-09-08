# Operasyonel Privacy Playbook'ları

{{#include ../banners/hacktricks-training.md}}

Bu playbook'lar bu bölümün geri kalanındaki kontrolleri bir araya getirir. Bunlar garanti değil, başlangıç noktalarıdır: yeni bir gözlemci, hesap, cihaz, konum, ödeme, dosya veya karşı taraf workflow'a girdiğinde threat model'i güncelleyin.

## Evrensel preflight

1. Meşru amacı ve neyin **kimden** gizli kalması gerektiğini yazın.
2. Faaliyetin temas edeceği kimlikleri, cihazları, ağları, hesapları, ödeme kanallarını, karşı tarafları, fiziksel konumları ve verileri kaydedin.
3. Olası en güçlü gözlemciyi ve başarısızlığın sonucunu belirleyin.
4. Yetkilendirmeyi, geçerli hukuku, provider koşullarını ve kurumsal politikayı doğrulayın.
5. Güvenlik, incident response, muhasebe ve audit için neyin kurum içinde ilişkilendirilebilir kalması gerektiğine karar verin.
6. İşe yarayan en küçük compartment'ı seçin; kullanmadan önce recovery ve shutdown yollarını oluşturun.
7. IP/DNS/IPv6, browser identity, document metadata, payment statement ve notification leakage dahil olmak üzere compartment'ı kontrollü bir service'e karşı test edin.

Ayrıntılı model için [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md) bölümüne bakın.

## Günlük privacy baseline'ı

Amaç: anonymous olmaya çalışmadan commercial tracking, account takeover ve gereksiz exposure'ı azaltmak.

- Full-disk encryption, automatic updates, screen lock ve mevcutsa secure boot özelliklerine sahip, bakımı yapılan bir OS kullanın.
- Öncelikle password manager, recovery email ve phishing-resistant MFA/security keys yapılandırmalarını düzenleyin.
- App permissions, location history, advertising identifiers, cloud sync ve third-party account connections ayarlarını gözden geçirin.
- Az sayıda extension, tracking protection ve HTTPS kullanan mainstream bir browser kullanın; work/personal/high-risk browsing için ayrı profile'lar oluşturun.
- İlişkiye göre private relay alias'ları veya farklı email address'ler kullanın; yalnızca optional olduğu durumlarda personal phone number kullanmayın.
- İçerik için end-to-end encrypted messaging kullanmayı tercih edin; ancak katılımcıların, zamanlamanın, grupların ve endpoint'lerin metadata olarak kaldığını unutmayın.
- Metadata'yı dosyalardan bilinçli şekilde kaldırın ve yayınlamadan önce original dosyayı değil, exported copy'yi inceleyin.
- Ödeme credential compartmentalization için virtual-card veya wallet token'larını kullanın; bunlara anonymous demeyin.
- Encrypted recovery material'ı backup'layın ve restoration'ı test edin.

## Pseudonymous publication

Amaç: casual reader'ların ve platformların bir yayını civil identity ile kolayca ilişkilendirmesini önlemek. Bu yöntem, yetenekli ve hedefli bir investigation'ı engellemez.

1. Platformun, hosting provider'ın, okuyucuların, contact'ların, local network'ün, payment provider'ın veya legal process'in threat model içinde olup olmadığını belirleyin.
2. Temiz bir baseline'dan dedicated endpoint/account context oluşturun. Personal browser sync, cloud documents, contact upload ve notification preview'larını devre dışı bırakın.
3. Pseudonymous account'ı seçilen network compartment üzerinden oluşturun. Username'leri, avatar'ları, recovery channel'larını, writing boilerplate'ını veya personal identity-provider login'ini yeniden kullanmayın.
4. Destination unlinkability hızdan daha önemliyse Tor Browser kullanın; extension eklemeyin, boyutunu/özelliklerini aşırı değiştirmeyin veya indirilen dokümanları online durumdayken ordinary desktop session içinde açmayın.
5. Personal template name'lerini, revision author'larını, printer path'lerini, GPS/EXIF'i, thumbnail'leri veya hidden layer'ları gömmeyen bir process ile taslak hazırlayın. Bir copy export edin ve uygun metadata tool'larıyla inceleyin.
6. İçeriği self-identifying fact'lar açısından kontrol edin: benzersiz tarihler, workplace details, local weather/time zone, yansımalar, background audio, linguistic habits ve önceki yayınlardan yeniden kullanılan text.
7. Ayrı bir reply channel kullanın. Her direct contact'ı, attachment'ı ve link'i olası bir correlation veya phishing attempt olarak değerlendirin.
8. Para söz konusuysa yalnızca gerekli verileri açığa çıkaran lawful method'u kullanın. Okuyucular bilmese bile platformun ve regulated intermediary'nin payee'yi biliyor olabileceğini varsayın.
9. Yayınlayın, ardından farklı bir clean context'ten public result'ı inceleyin. Platformun ne eklediğini veya dönüştürdüğünü kaydedin.
10. Sabit bir behavioral fingerprint oluşturmuyorsa planlı bir cadence sürdürün; compartment'ı sessizce yeniden kullanmak yerine retire edin.

Serious journalism, activism, domestic abuse veya state-level risk için deneyimli bir digital-security organization'dan tailored help alın; static checklist, local law'u veya live adversary'yi modelleyemez.

## Authorized red-team engagement

Amaç: authorization, control ve incident response'u korurken operator'ların personal identity'lerini ve home network'lerini target telemetry'nin dışında tutmak.

### Start window'dan önce

- ROE infrastructure annex'i, target'ları/exclusion'ları, source range'leri, tarihleri, emergency stop'u ve third-party/provider permission'larını kesinleştirin.
- Dedicated operator profile veya VM, engagement secret'ları, evidence store, cloud project, domain'ler ve budget ayırın.
- Client-provided egress veya organization-controlled fixed bastion kullanmayı tercih edin. Full-tunnel IPv4/IPv6/DNS davranışını ve fail-closed policy'yi test edin.
- Operator ile public infrastructure arasındaki mapping'i exercise controller veya üzerinde anlaşılmış escrow contact ile saklayın.
- Rate limit'leri, destination allowlist'lerini ve destructive, wireless, physical, phishing veya credential-collection action'ları için ayrı approval sürecini oluşturun.
- Organization-controlled payment rail kullanın ve approval'ları kurum içinde kaydedin.

### Engagement sırasında

- Approved endpoint ve tunnel üzerinden başlayın; assessment traffic'ten önce observed egress'i doğrulayın.
- Personal account'ları, cihazları, phone number'ları, repository'leri, SSH/GPG key'lerini ve cloud sync'i compartment'ın dışında tutun.
- Gereksiz client content toplamadan operator/job, start/stop, source, scoped destination ve configuration change bilgilerini log'layın.
- Scope belirsizliği, beklenmeyen third-party system'ler, provider abuse notification, safety impact, kayıp equipment veya controller contact kaybı durumunda durun.
- Bir komşunun Wi-Fi'ı, çalınmış credential'lar, onaylanmamış SIM/account veya bir venue'da gizlenmiş hardware ile asla doğaçlama yapmayın.

### Engagement sonunda

- Job'ları ve C2'yi durdurun; approved drop device'ları geri alın; token'ları, credential'ları ve certificate'ları revoke edin.
- Infrastructure'ı, domain'leri, source address'leri, expense'leri, data'yı ve provider case'lerini inventory ile karşılaştırın.
- Client data'yı contract'a göre return/delete/retain edin, gerekli minimum audit evidence'ı koruyun ve shutdown'ı ikinci bir operator'a doğrulatın.

Tam build ve teardown guide için [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) bölümüne bakın.

## Lawful private purchase or donation

Amaç: issuer, accounting, tax ve sanctions yükümlülüklerini yerine getirirken merchant'a veya public'e yapılan disclosure'ı en aza indirmek.

1. Kimin neyi öğrenmemesi gerektiğini listeleyin: public audience, merchant, payment intermediary, employer/family account delegate, delivery service veya blockchain observer.
2. Local rules'u, recipient/counterparty'yi, provider terms'ü, cash limit'lerini ve recordkeeping ihtiyaçlarını kontrol edin.
3. Rail'i seçin:
- payment-network record olmadan kabul edilen lawful local payment'lar için cash;
- online credential separation için regulated virtual/merchant-specific card;
- acquisition, ledger, wallet backend, network, counterparty ve later-spend link'lerini analiz ettikten sonra cryptocurrency.
4. Gerekli truthful detail'ları kullanın ve yalnızca optional loyalty/marketing information'ı vermeyin. Başka bir kişinin identity/address bilgisini kullanmayın veya bir transaction'ı threshold etrafında bölmeyin.
5. Merchant browser/account context'ini ayırın ve ilgisiz social login, loyalty veya personal recovery channel'larından kaçının.
6. Statement'larda, receipt'lerde, notification'larda, shipping'de ve public donor list'lerinde ne göründüğünü doğrulayın.
7. Gerekli receipt/tax/authorization evidence'ı encrypted olarak saklayın; disposable payment credential'larını refund window sonrasında revoke edin.

[Private Digital Payments](private-digital-payments.md) ve [Cryptocurrency Privacy](cryptocurrency-privacy.md) bölümlerine bakın.

## Travel and untrusted networks

Amaç: user tarafından yönetilmeyen ağlarda data'yı ve account'ları korumaktır; unauthorized activity'yi gizlemek değildir.

- Cihazları güncelleyin ve gerekli credential'ları/map'leri seyahatten önce indirin.
- Stored data'yı azaltın; full-disk encryption, strong unlock, remote-recovery planning ve legal advice'a uygun powered-off border/physical-risk procedure'ları kullanın.
- Venue SSID'sini/captive portal'ını doğrulayın. Uygun olduğunda personal hotspot kullanmayı tercih edin; ancak cellular subscriber ve location record'larını unutmayın.
- Organizational data için full/forced approved VPN kullanın; tethered device'ların bunu paylaştığını doğrulayın ve IPv6/DNS davranışını test edin.
- Client isolation ve tekrarlanabilir policy için travel router kullanın; bunu anonymity guarantee olarak görmeyin.
- Public USB charging'i, borrowed computer'ları, public printer'ları ve shared meeting-room system'lerini ayrı threat'ler olarak değerlendirin.
- Physical presence, radio identifier'lar, portal login, camera'lar ve payment/location record'larının ziyareti correlate edebileceğini varsayın.

Karşılaştırma ve setup ayrıntıları [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md) bölümündedir.

## Failure and exposure response

Bir compartment leak yaşadığında veya ilişkilendirilmiş olabileceğinde:

1. Devam etmek zararı artırıyorsa faaliyeti durdurun; uygun olduğunda engagement emergency stop'u kullanın.
2. Hassas data'yı yaymadan gerekli evidence'ı koruyun. Exact time'ı, observed indicator'ı ve affected asset'ları kaydedin.
3. Uygun owner/controller/security contact'ı bilgilendirin. Privacy narrative'i korumak için incident'ı gizlemeyin.
4. Session'ları, token'ları, payment credential'larını ve infrastructure access'i revoke edin; secret'ları known-clean endpoint'ten rotate edin.
5. Hangi edge'lerin bağlantı oluşturduğunu belirleyin: endpoint, account recovery, network, payment, metadata, content, behavior, counterparty veya physical presence.
6. Etkilenen compartment'ın tamamını burned olarak değerlendirin. Yalnızca username'i veya exit IP'yi değiştirmeyin.
7. Breach, provider, client, financial ve legal notification yükümlülüklerini yerine getirin.
8. Link'e neden olan process'i değiştirdikten sonra yeniden build edin; control'ü belgeleyin ve test edin.

## Periodic audit

- [ ] Threat model ve legal/provider assumption'ları belirlenmiş bir takvimde gözden geçirildi.
- [ ] Cihazlar, account'lar, alias'lar, domain'ler, network path'leri ve payment credential'ları inventory'ye alındı.
- [ ] Recovery path'leri beklenmedik şekilde compartment'lar arasında geçiş yapmıyor.
- [ ] Full-tunnel, DNS, IPv6 ve fail-closed davranışı test edildi.
- [ ] Public file'lar ve profile'lar metadata/content reuse açısından kontrol edildi.
- [ ] Wallet node'ları/backend'leri ve crypto protocol assumption'ları güncel kalıyor.
- [ ] Log'lar ve receipt'ler minimal, encrypted, access-controlled ve retention süresi içinde.
- [ ] Eski compartment'lar ve engagement infrastructure tamamen retired edildi.
{{#include ../banners/hacktricks-training.md}}
