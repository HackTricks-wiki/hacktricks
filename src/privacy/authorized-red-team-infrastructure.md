# Yetkilendirilmiş Red-Team Altyapısı

{{#include ../banners/hacktricks-training.md}}

Dayanıklı saha cihazları için [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) tasarımını ve şüpheli keşif runbook'unu kullanın.

Profesyonel bir red team için amaç, hesap verebilirlikten muafiyet değil, **kontrollü attribution** sağlamaktır. Hedef, bir operatörün ev IP adresini veya kişisel hesaplarını kolayca görmemelidir; ancak engagement sahibi kaynağı belirleyebilmeli, operasyonu durdurabilmeli, abuse bildirimlerini ele alabilmeli, kanıtları koruyabilmeli ve yetkilendirmeyi kanıtlayabilmelidir.

Bu sayfa, yasal bir engagement için deployment temelidir. Taklit edilmesi amaçlanan adversary tradecraft için (compromised ORB'ler, residential relay'ler, fronting, dead drop'lar ve yakındaki wireless pivot'lar dahil) [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) ve [Government and APT Case Studies](government-and-apt-case-studies.md) ile başlayın, ardından gerekli telemetry'yi [authorized labs](authorized-adversary-emulation-labs.md) içinde yeniden oluşturun.

NIST, rules of engagement'i (ROE), tanımlanmış testing faaliyetlerine yetki veren önceden belirlenmiş kısıtlamalar olarak tanımlar.<sup>[[1]](#references)</sup> Privacy architecture bu yetkiyi genişletemez.

## Bir egress pattern'i seçin

| Pattern | En iyi kullanım | Hedefin gördüğü | Provider/local observer'ın gördüğü | Accountability |
|---|---|---|---|---|
| Client-provided VPN/jump host | Çoğu assessment | Client adres aralığı | Client kimliği ve operatör erişimi | En güçlü |
| Red-team organization bastion | Tekrarlanabilir kontrollü egress | Organization aralığı | Hosting provider ve organization | Güçlü |
| Engagement-specific VPS | Client'ları/campaign'leri izole etme | VPS adresi | Host hesabı, billing, control-plane ve access log'ları | Belgelenmişse güçlü |
| Approved commercial VPN | Provider ve ROE tarafından izin verilen research/scanning | Paylaşımlı/dedicated VPN egress | VPN hesabı ve source connection | Orta |
| Tor Browser | Destination unlinkability gerektiren web research | Tor exit | Local network Tor/bridge'i görür; destination Tor'u görür | Allowlisted source attribution için uygun değil |
| Client-approved on-site drop | Internal simulation | Saha cihazı/adresi | Site network ve remote tunnel provider | Envantere kayıtlıysa güçlü |
| Lawful guest Wi-Fi | Düşük riskli administrative/research kullanımı | Venue public IP'si veya tunnel egress | Venue, ISP, VPN/Tor | Zayıf ve fiziksel olarak gözlemlenebilir |

Çoğu çalışma için client tarafından sağlanan veya organization tarafından kontrol edilen sabit bir egress, consumer anonymity service'lerinden daha güvenli ve hızlıdır. Ayrıca savunmacıların exercise tasarımına göre bilinen source range'leri allowlist'e almasına, izlemesine veya kasıtlı olarak **allowlist'e almamasına** olanak tanır.

## ROE infrastructure annex

Deployment öncesinde şunları kaydedin:

- yetkilendirme veren ve alan legal entity'ler;
- kesin hedefler ve açık exclusions;
- başlangıç/bitiş zamanları, time zone ve izin verilen technique'ler;
- source IP'ler, autonomous-system/provider adları, domain'ler, redirector'lar, mail infrastructure ve saha cihazı identifier'ları;
- phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence veya third-party service'lere izin verilip verilmediği;
- client ve provider approvals; varsa pre-notification reference dahil;
- emergency stop phrase, 24/7 client ve provider abuse contact'ları ve maksimum response time;
- toplanabilecek data class'ları, encryption, access, retention ve deletion;
- evidence ve logging requirements; public infrastructure ile operatör arasındaki mapping'i kimin tuttuğu dahil;
- teardown, domain expiration, certificate revocation, credential rotation, device recovery ve final attestation.

Public IP'lerin ve domain'lerin gerçekten authorizing party tarafından kontrol edildiğini veya açıkça scope'a dahil edildiğini doğrulayın. NIST SP 800-115, testing öncesinde public target address'lerin organization'ın yetki alanında olduğunun doğrulanmasını önerir.<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **Bir engagement account/project oluşturun:** Accurate billing ve ownership details kullanarak red-team organization altında oluşturun. Role'leri, API key'leri, budget'ları ve audit log'larını diğer client'lardan ayırın.
2. **Her provider policy'sini kontrol edin.** Cloud, VPS, CDN, domain, email ve VPN provider'larının kuralları farklıdır. Örneğin AWS, belirtilen assessment'lara izin verir; ancak hosted C2/covert simulation'lar için önceden approval gerektirir ve listelenen faaliyetleri yasaklar.<sup>[[3]](#references)</sup>
3. **Sabit egress address'leri tahsis edin** ve bunları ROE annex'e ekleyin. Hızlı IP/resource cycling'den kaçının; bu, incident response'u zorlaştırır ve provider policy'sini ihlal edebilir.
4. **Management'ı harden edin:** yalnızca key kullanan SSH veya identity-aware management plane, phishing-resistant MFA, ayrı admin network, least privilege, patched image'lar, public admin port'larının bulunmaması ve encrypted secret storage.
5. **Operator endpoint'ten bastion'a full-tunnel path oluşturun.** DNS ve IPv6'yı bilinçli şekilde route edin ve tunnel kapandığında firewall deny uygulayın.
6. **Mümkün olduğunda outbound destination ve port'ları** authorized scope ile sınırlandırın. Scanner'ları rate-limit edin ve irreversible/destructive technique'leri ayrı bir approval gate arkasına alın.
7. **Surveillance için değil accountability için log tutun:** operator authentication, configuration change'leri, start/stop, source address, scoped destination ve tool/job identifier'ları. Exercise tarafından gerekli kılınmadıkça ve data plan tarafından korunmadıkça payload/credential capture'dan kaçının.
8. **Organization'ın sahip olduğu kontrollü bir endpoint üzerinden doğrulama yapın:** gözlemlenen IPv4/IPv6, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect ve provider abuse contact.
9. **Attribution map'i güvenli şekilde** exercise controller'a veya üzerinde anlaşılmış bir escrow contact'a paylaşın. Blind detection testin parçasıysa bunu target team'e yayınlamayın.

### Architecture
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
Bir VPS yalnızca hedef açısından pseudonymous'dur. Host; iletişim, faturalandırma, kimlik, kaynak IP, API, cihaz, konum ve kullanım kayıtlarına sahip olabilir; yalnızca müşteri tarafından görülebilen AWS CloudTrail geçmişi bile yönetim faaliyetlerini açığa çıkarabilir.<sup>[[4]](#references)</sup> Hosting için cryptocurrency ile ödeme yapmak bu kayıtları silmez.

## Domain'ler ve sertifikalar

- Kuruluşa ait, engagement'a özel bir registrar hesabı kullanın.
- Registrar lock, desteklenen yerlerde DNSSEC, MFA/security keys ve yalnızca onaylanan dönem için auto-renew özelliğini etkinleştirin.
- Kamuya açık görünürlüğü azaltmak için registration privacy kullanın; registrant bilgilerini yanlış göstermek için kullanmayın. ICANN policy, kamuya açık gösterim redacted veya proxied olsa bile registrar'ların registration data toplamasını gerektirir.<sup>[[5]](#references)</sup>
- İlişkisiz tarafları hukuka aykırı biçimde taklit eden adlardan kaçının. Typosquatting/lookalike domain'ler için client ve provider'ın açık onayı gerekir.
- DNS, sertifikalar, CDN/redirector configuration ve operator'ları veya client'ları leak edebilecek third-party analytics envanterini çıkarın.
- Teardown sırasında kayıtları kaldırın, sertifikaları/token'ları revoke edin, üzerinde anlaşılmış kanıtları koruyun ve domain'in savunma amacıyla tutulup tutulmayacağına karar verin.

## Authorized on-site drop nodes

Bir Raspberry Pi veya benzeri appliance, yalnızca mülk/ağ sahibi ve client exact placement ile davranışını açıkça onayladığında kabul edilebilir. Güvenli bir plan:

1. Cihaz serial'ını, MAC/private-MAC policy'yi, fotoğrafı, sahibini, tam onaylı konumu, güç kaynağını, retrieval deadline'ını ve tamper contact'ını kaydedin.
2. Minimal signed image, encrypted secrets, read-only veya recoverable storage, host firewall, pratik olduğu yerlerde automatic security updates kullanın ve default credentials kullanmayın.
3. Yalnızca adı belirtilmiş bir engagement endpoint'ine outbound-only communication yapılandırın. Unauthenticated listener expose etmeyin.
4. Destination'ları ve capability'leri allowlist'e alın. Packet capture, credential collection, wireless impersonation ve lateral movement işlemlerinin her biri açıkça authorize edilmelidir.
5. Mutual authentication, short-lived keys, remote kill, health reporting ve bandwidth limits kullanın.
6. Kayıp veya hırsızlığın yeniden kullanılabilir credential'ları ya da client data'yı açığa çıkarmamasını sağlayın.
7. Retrieval ve secure wipe/decommission işlemlerini takvime ekleyin; imzalı bir recovery record alın.

Sahibinin/operator'ın yazılı izni olmadan bir café, hotel, shared office, komşunun mülkü veya public venue'de hardware saklamayın.

## Guest networks ve travel routers

Yetkili bir scenario guest access gerektiriyorsa:

- SSID'yi ve acceptable-use policy'yi venue/client ile doğrulayın;
- Privileged workstation'ı izole etmek için organization-owned travel router veya low-trust bridge device kullanın;
- Captive portal'ları privileged workstation dışında tamamlayın;
- Assessment traffic'inden önce approved tunnel'ı başlatın;
- Tethered device'ların gerçekten bu tunnel'ı kullandığını doğrulayın;
- Venue'nun radio association, portal, physical presence ve camera/payment records'ı ilişkilendirebileceğini varsayın;
- Access control'ü asla bypass etmeyin, başka bir device'ı clone etmeyin, Wi-Fi'ye saldırmayın veya equipment bırakmayın.

## Operational separation

- Her endpoint compartment, cloud project, secrets set, domain group, redirector set ve evidence store için tek bir client/engagement kullanın.
- Onaylanmış organization systems dışında personal email, browser sync, phone number, cloud drive, SSH/GPG key, code-signing identity veya payment reimbursement kullanmayın.
- Exercise design fingerprinting'i kabul etmediği sürece distinctive payload configuration, callback paths, certificates veya public repositories'yi client'lar arasında yeniden kullanmayın.
- Infrastructure için bir kill date ve budget alert belirleyin. Orphaned systems hem client hem de Internet için risk oluşturur.
- Kazaları araştırmak için yeterli internal attribution'ı koruyun. “No logs” genellikle professional evidence ve safety obligations ile bağdaşmaz.

## Defenders'tan blind, controller'a attributable

Exercise objective bir allowlist'i test etmek yerine detection'ı ölçmek olduğunda, operation'ı unaccountable hale getirmeden target SOC blind kalabilir:

1. Exercise controller her public source, domain, certificate ve on-site device'ı approve eder, ancak listeyi SOC'dan gizler.
2. Controller, source-to-engagement/operator map'ini two-person emergency access içeren ayrı bir encrypted vault'ta saklar.
3. Her operator job; scope, time window, source compartment ve irreversible job identifier içeren signed manifest alır. Normal operation sırasında target'ın manifest'i görmesi gerekmez.
4. Bastion audit events, controller storage'a chained veya append-only olarak gönderilir; böylece bir operator incident sonrasında attribution'ı sessizce yeniden yazamaz.
5. 24/7 provider-abuse contact, client'ı public olarak açıklamadan authorization'ı doğrulayan bir verification phrase/reference bulundurur.
6. Her path, assessment C2'ye, target network'e veya tek bir operator account'una bağlı olmayan bir out-of-band stop channel uygular.
7. Live testing'den önce her source'tan benign canaries gönderin. Controller'ın bunları ROE response time içinde resolve edip stop edebildiğini doğrulayın.
8. Exercise sonrasında SOC telemetry'yi controller ledger ile karşılaştırın, source list'i açıklayın ve missed/incorrect detections'ı açıklayın.

Anti-forensics, log destruction, compromised relays veya false subscriber identities eklemeyin. Bunlar accountable testing'i geliştirmek yerine ortadan kaldırır.

## Teardown checklist

- [ ] Exercise controller stop işlemini onaylar.
- [ ] C2, tunnels, redirectors, mail, VPN ve scheduled jobs devre dışı bırakılır.
- [ ] On-site device'lar fiziksel olarak geri alınır ve mutabakatı yapılır.
- [ ] Tokens, API keys, SSH keys, certificates ve captured credentials revoke/rotate edilir.
- [ ] DNS ve cloud resources kaldırılır veya defensive retention için transfer edilir.
- [ ] Client data sözleşmeye uygun olarak iade edilir, tutulur veya yok edilir.
- [ ] Gerekli financial, audit ve authorization records encrypted ve access-controlled olarak tutulur.
- [ ] Provider abuse cases kapatılır ve client'a final source indicators verilir.
- [ ] İkinci bir operator hiçbir infrastructure'ın aktif kalmadığını doğrular.

## References

- [1] [NIST CSRC — Rules of Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Penetration Testing için Customer Support Policy](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Privacy Notice](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Registration Data Policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
