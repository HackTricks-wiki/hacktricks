# Operasyonel Gizlilik Playbook'ları

Bu playbook'lar bu bölümün geri kalanındaki kontrolleri bir araya getirir. Bunlar garanti değil, başlangıç noktalarıdır: iş akışına yeni bir gözlemci, hesap, cihaz, konum, ödeme, dosya veya karşı taraf girdiğinde tehdit modelini güncelleyin.

## Evrensel ön kontrol

1. Meşru amacı ve neyin **kimden** gizli kalması gerektiğini yazın.
2. Faaliyetin temas edeceği kimlikleri, cihazları, ağları, hesapları, ödeme kanallarını, karşı tarafları, fiziksel konumları ve verileri kaydedin.
3. Olası en güçlü gözlemciyi ve başarısızlığın sonucunu belirleyin.
4. Yetkilendirmeyi, geçerli hukuku, provider şartlarını ve kurumsal politikayı doğrulayın.
5. Güvenlik, olay müdahalesi, muhasebe ve denetim açısından içeride hangi bilgilerin ilişkilendirilebilir kalması gerektiğine karar verin.
6. İşe yarayan en küçük compartment'ı seçin; kullanımdan önce kurtarma ve kapatma yollarını oluşturun.
7. IP/DNS/IPv6, browser kimliği, belge metadata'sı, ödeme ekstresi ve bildirim leak'leri dahil olmak üzere compartment'ı kontrollü bir service'e karşı test edin.

Ayrıntılı modeli [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md) bölümünde kullanın.

## Günlük gizlilik temeli

Amaç: anonim olmaya çalışmadan ticari tracking'i, account takeover'ı ve gereksiz ifşayı azaltmak.

- Tam disk encryption, automatic updates, screen lock ve mevcutsa secure boot özelliklerine sahip, bakımı yapılan bir OS kullanın.
- Önce password manager'ı, recovery email'i ve phishing-resistant MFA/security key'leri düzenleyin.
- App izinlerini, location history'yi, advertising identifier'ları, cloud sync'i ve third-party account bağlantılarını gözden geçirin.
- Az sayıda extension'a, tracking protection'a ve HTTPS'e sahip mainstream bir browser kullanın; iş, kişisel ve yüksek riskli browsing için ayrı profile'lar kullanın.
- İlişkiye göre private relay alias'ları veya farklı email adresleri kullanın; yalnızca isteğe bağlı olduğu durumlarda kişisel telefon numarası kullanmayın.
- İçerik için end-to-end encrypted messaging'i tercih edin; ancak katılımcıların, zamanlamanın, grupların ve endpoint'lerin metadata olarak kalacağını unutmayın.
- Dosyalardan metadata'yı bilinçli olarak kaldırın ve yayınlamadan önce orijinali değil, export edilmiş kopyayı inceleyin.
- Ödeme credential compartmentalization için virtual-card veya wallet token'larını kullanın; bunlara anonymous demeyin.
- Encrypted recovery materyalini yedekleyin ve geri yüklemeyi test edin.

## Pseudonymous publication

Amaç: sıradan okuyucuların ve platformların bir yayını civil identity ile kolayca ilişkilendirmesini önlemek. Bu, yetenekli ve hedefli bir investigation'ı engellemez.

1. Platformun, hosting provider'ın, okuyucuların, contacts'ların, local network'ün, payment provider'ın veya legal process'in tehdit modelinde olup olmadığını belirleyin.
2. Temiz bir baseline'dan özel bir endpoint/account context oluşturun. Personal browser sync'i, cloud documents'ı, contact upload'ı ve notification preview'larını devre dışı bırakın.
3. Pseudonymous account'ı seçilen network compartment üzerinden oluşturun. Username'leri, avatar'ları, recovery channel'larını, writing boilerplate'ını veya personal identity-provider login'ini yeniden kullanmayın.
4. Destination unlinkability hızdan daha önemli olduğunda Tor Browser kullanın; extension eklemeyin, boyutunu veya özelleştirmelerini aşırı değiştirmeyin ve indirilen belgeleri online durumdaki ordinary desktop session'ında açmayın.
5. Personal template adlarını, revision author'larını, printer path'lerini, GPS/EXIF'i, thumbnail'ları veya gizli layer'ları gömmeyen bir process ile taslak hazırlayın. Bir kopya export edin ve uygun metadata tool'larıyla inceleyin.
6. İçeriği self-identifying facts açısından kontrol edin: benzersiz tarihler, workplace ayrıntıları, yerel hava durumu/time zone, reflections, background audio, linguistic habits ve önceki yayınlardan text reuse.
7. Ayrı bir reply channel kullanın. Her direct contact'ı, attachment'ı ve link'i olası bir correlation veya phishing attempt olarak değerlendirin.
8. Para söz konusuysa yalnızca gerekli verileri açığa çıkaran lawful method'u kullanın. Okuyucular bilmese bile platformun ve regulated intermediary'nin payee'yi biliyor olabileceğini varsayın.
9. Yayınlayın, ardından farklı bir clean context'ten public result'ı inceleyin. Platformun ne eklediğini veya dönüştürdüğünü kaydedin.
10. Stable behavioral fingerprint oluşturmuyorsa planlı bir cadence sürdürün; compartment'ı sessizce yeniden amaçlandırmak yerine kullanımdan kaldırın.

Ciddi journalism, activism, domestic abuse veya state-level risk için deneyimli bir digital-security organization'dan kişiye özel yardım alın; static checklist yerel hukuku veya canlı bir adversary'yi modelleyemez.

## Authorized red-team engagement

Amaç: authorization, control ve incident response'u korurken operator'ların personal identity'lerini ve home network'lerini target telemetry'den uzak tutmak.

### Başlangıç penceresinden önce

- ROE infrastructure annex'i, target/exclusion'ları, source range'leri, tarihleri, emergency stop'u ve third-party/provider izinlerini kesinleştirin.
- Özel bir operator profile'ı veya VM'yi, engagement secret'larını, evidence store'u, cloud project'i, domain'leri ve bütçeyi ayırın.
- Client tarafından sağlanan egress'i veya organization-controlled fixed bastion'ı tercih edin. Full-tunnel IPv4/IPv6/DNS davranışını ve fail-closed policy'yi test edin.
- Operator ile public infrastructure arasındaki eşleştirmeyi exercise controller veya üzerinde anlaşılmış escrow contact ile saklayın.
- Rate limit'leri, destination allowlist'lerini ve destructive, wireless, physical, phishing veya credential-collection action'ları için ayrı approval sürecini oluşturun.
- Organization-controlled payment rail kullanın ve approval'ları içeride kaydedin.

### Engagement sırasında

- Approved endpoint ve tunnel'dan başlayın; assessment traffic'inden önce gözlemlenen egress'i doğrulayın.
- Personal account'ları, cihazları, telefon numaralarını, repository'leri, SSH/GPG key'lerini ve cloud sync'i compartment'ın dışında tutun.
- Gereksiz client content toplamadan operator/job, başlangıç/bitiş, source, kapsam dahilindeki destination ve configuration change bilgilerini log'layın.
- Scope belirsizliğinde, beklenmeyen third-party system'lerde, provider abuse notification'da, safety impact'te, ekipman kaybında veya controller contact'ının kaybında durun.
- Bir komşunun Wi-Fi'ı, çalınmış credential'lar, onaylanmamış SIM/account veya bir mekanda gizlenmiş hardware ile asla doğaçlama yapmayın.

### Engagement sonunda

- Job'ları ve C2'yi durdurun; onaylanmış drop device'ları geri alın; token'ları, credential'ları ve certificate'ları revoke edin.
- Infrastructure'ı, domain'leri, source address'leri, masrafları, verileri ve provider case'lerini inventory ile karşılaştırın.
- Client data'yı sözleşmeye göre iade edin/silin/saklayın, gerekli minimum audit evidence'ı koruyun ve ikinci bir operator'e kapatmayı doğrulatın.

Tam build ve teardown guide için [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) bölümüne bakın.

## Lawful private purchase or donation

Amaç: issuer, muhasebe, vergi ve sanctions yükümlülüklerini yerine getirirken merchant'a veya kamuya yapılan ifşayı en aza indirmek.

1. Kimlerin neyi öğrenmemesi gerektiğini listeleyin: public audience, merchant, payment intermediary, employer/family account delegate, delivery service veya blockchain observer.
2. Yerel kuralları, recipient/counterparty'yi, provider şartlarını, cash limit'lerini ve recordkeeping ihtiyaçlarını kontrol edin.
3. Rail'i seçin:
- ödeme ağı kaydı olmayan, kabul edilen lawful local payment'lar için cash;
- online credential separation için regulated virtual/merchant-specific card;
- acquisition, ledger, wallet backend, network, counterparty ve later-spend link'lerini analiz ettikten sonra cryptocurrency.
4. Gerekli gerçek bilgileri kullanın ve yalnızca isteğe bağlı loyalty/marketing bilgilerini vermeyin. Başka bir kişinin identity/address bilgisini kullanmayın veya bir işlemi threshold etrafında bölmeyin.
5. Merchant browser/account context'ını ayırın ve ilgisiz social login, loyalty veya personal recovery channel'larından kaçının.
6. Statement'larda, receipt'lerde, notification'larda, shipping'de ve public donor list'lerinde ne göründüğünü doğrulayın.
7. Gerekli receipt/tax/authorization evidence'ını encrypted biçimde saklayın; disposable payment credential'larını refund window sonrasında revoke edin.

[Private Digital Payments](private-digital-payments.md) ve [Cryptocurrency Privacy](cryptocurrency-privacy.md) bölümlerine bakın.

## Travel and untrusted networks

Amaç: kullanıcı tarafından yönetilmeyen ağlarda data ve account'ları korumak; unauthorized activity'yi gizlemek değil.

- Cihazları güncelleyin ve gerekli credential'ları/map'leri seyahatten önce indirin.
- Saklanan data'yı azaltın; full-disk encryption, güçlü unlock, remote-recovery planning ve legal advice'a uygun powered-off border/physical-risk prosedürleri kullanın.
- Venue SSID'sini/captive portal'ı doğrulayın. Uygun olduğunda personal hotspot'ı tercih edin; ancak cellular subscriber ve location record'larını unutmayın.
- Organizational data için full/forced approved VPN kullanın; tethered device'ların bunu paylaştığını doğrulayın ve IPv6/DNS davranışını test edin.
- Travel router'ı anonymity guarantee olarak değil, client isolation ve tekrarlanabilir policy için kullanın.
- Public USB charging'i, ödünç bilgisayarları, public printer'ları ve ortak meeting-room system'lerini ayrı tehditler olarak değerlendirin.
- Physical presence'ın, radio identifier'ların, portal login'inin, kameraların ve payment/location record'larının ziyareti correlate edebileceğini varsayın.

Karşılaştırma ve kurulum ayrıntıları [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md) bölümündedir.

## Failure and exposure response

Bir compartment leak olduğunda veya ilişkilendirilmiş olabileceğinde:

1. Devam etmek zararı artıracaksa faaliyeti durdurun; uygun olduğunda engagement emergency stop'u kullanın.
2. Hassas verileri yaymadan gerekli evidence'ı koruyun. Kesin zamanı, gözlemlenen indicator'ı ve etkilenen asset'leri kaydedin.
3. Uygun owner/controller/security contact'ını bilgilendirin. Privacy narrative'i korumak için incident'ı gizlemeyin.
4. Session'ları, token'ları, payment credential'larını ve infrastructure access'i revoke edin; secret'ları known-clean endpoint'ten rotate edin.
5. Hangi edge'lerin bağlantı kurduğunu belirleyin: endpoint, account recovery, network, payment, metadata, content, behavior, counterparty veya physical presence.
6. Etkilenen compartment'ın tamamını burned kabul edin. Yalnızca username'i veya exit IP'yi değiştirmeyin.
7. Breach, provider, client, financial ve legal notification yükümlülüklerini yerine getirin.
8. Yalnızca bağlantıya neden olan process'i değiştirdikten sonra yeniden build edin; control'ü belgeleyin ve test edin.

## Periodic audit

- [ ] Threat model ve legal/provider varsayımları, tarih belirlenmiş bir schedule'a göre gözden geçirildi.
- [ ] Cihazlar, hesaplar, alias'lar, domain'ler, network path'leri ve payment credential'ları inventory'ye alındı.
- [ ] Recovery path'ler beklenmedik şekilde compartment'lar arasında geçiş yapmıyor.
- [ ] Full-tunnel, DNS, IPv6 ve fail-closed davranışı test edildi.
- [ ] Public file'lar ve profile'lar metadata/content reuse açısından kontrol edildi.
- [ ] Wallet node/backend'leri ve crypto protocol varsayımları güncel kalıyor.
- [ ] Log'lar ve receipt'ler minimum düzeyde, encrypted, access-controlled ve retention süresi içinde.
- [ ] Eski compartment'lar ve engagement infrastructure tamamen kullanımdan kaldırıldı.
