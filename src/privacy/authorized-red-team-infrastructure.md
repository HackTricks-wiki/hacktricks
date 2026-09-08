# Authorized Red-Team Infrastructure

For durable on-site devices, use the [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) design and suspected-discovery runbook.

Professional bir Red Team için amaç, hesap verebilirlikten muafiyet değil, **kontrollü attribution** sağlamaktır. Hedef, bir operatörün ev IP adresini veya kişisel hesaplarını basitçe görememeli; ancak engagement sahibi kaynağı belirleyebilmeli, operasyonu durdurabilmeli, abuse raporlarını ele alabilmeli, kanıtları koruyabilmeli ve yetkilendirmeyi kanıtlayabilmelidir.

Bu sayfa, hukuka uygun bir engagement için deployment temelidir. Bu sayfanın taklit etmeyi amaçladığı adversary tradecraft için (compromised ORB'ler, residential relay'ler, fronting, dead drop'lar ve yakındaki wireless pivot'lar dahil) [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) ve [Government and APT Case Studies](government-and-apt-case-studies.md) ile başlayın; ardından gerekli telemetry'yi [authorized labs](authorized-adversary-emulation-labs.md) içinde yeniden oluşturun.

NIST, rules of engagement'i (ROE), tanımlı testing faaliyetleri için yetki veren önceden belirlenmiş kısıtlamalar olarak tanımlar.<sup>[[1]](#references)</sup> Privacy architecture bu yetkiyi genişletemez.

## Bir egress pattern seçin

| Pattern | En uygun kullanım | Hedefin gördüğü | Provider/local observer'ın gördüğü | Accountability |
|---|---|---|---|---|
| Client-provided VPN/jump host | Çoğu assessment | Client address range | Client identity ve operator access | En güçlü |
| Red-team organization bastion | Tekrarlanabilir kontrollü egress | Organization range | Hosting provider ve organization | Güçlü |
| Engagement-specific VPS | Client'ları/campaign'leri izole etme | VPS address | Host account, billing, control-plane ve access log'ları | Belgelenmişse güçlü |
| Approved commercial VPN | Provider ve ROE tarafından izin verilen research/scanning | Paylaşılan/dedicated VPN egress | VPN account ve source connection | Orta |
| Tor Browser | Destination unlinkability gerektiren web research | Tor exit | Local network Tor/bridge'i görür; destination Tor'u görür | Allowlisted source attribution için uygun değil |
| Client-approved on-site drop | Internal simulation | On-site device/address | Site network ve remote tunnel provider | Envantere alınmışsa güçlü |
| Lawful guest Wi-Fi | Düşük riskli administrative/research kullanımı | Venue public IP veya tunnel egress | Venue, ISP, VPN/Tor | Zayıf ve fiziksel olarak gözlemlenebilir |

Çoğu çalışma için client-provided veya organization-controlled fixed egress, consumer anonymity service'lerinden daha güvenli ve hızlıdır. Ayrıca defender'ların exercise design'a göre bilinen source range'leri allowlist etmesine, izlemesine veya kasıtlı olarak **allowlist etmemesine** olanak tanır.

## ROE infrastructure annex

Deployment öncesinde kaydedin:

- authorization veren ve alan legal entity'ler;
- kesin target'lar ve açık exclusions;
- başlangıç/bitiş zamanları, time zone ve izin verilen technique'ler;
- source IP'leri, autonomous-system/provider adları, domain'ler, redirector'lar, mail infrastructure ve on-site device identifier'ları;
- phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence veya third-party service'lere izin verilip verilmediği;
- client ve provider approval'ları; varsa pre-notification reference dahil;
- emergency stop phrase, 24/7 client ve provider abuse contact'ları ve maksimum response time;
- toplanabilecek data class'ları, encryption, access, retention ve deletion;
- evidence ve logging gereksinimleri; public infrastructure ile operator arasındaki mapping'i kimin tuttuğu dahil;
- teardown, domain expiration, certificate revocation, credential rotation, device recovery ve final attestation.

Public IP'lerin ve domain'lerin gerçekten authorizing party tarafından kontrol edildiğini veya açıkça scope'a dahil edildiğini doğrulayın. NIST SP 800-115, testing öncesinde public target address'lerinin organization'ın yetki alanında olduğunun doğrulanmasını önerir.<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **Bir engagement account/project oluşturun:** Doğru billing ve ownership ayrıntılarını kullanarak red-team organization altında oluşturun. Roller, API key'ler, budget'lar ve audit log'larını diğer client'lardan ayırın.
2. **Her provider policy'sini kontrol edin.** Cloud, VPS, CDN, domain, email ve VPN provider'larının farklı kuralları vardır. Örneğin AWS, belirtilen assessment'lara izin verir; ancak hosted C2/covert simulation'lar için önceden approval ister ve listelenen faaliyetleri yasaklar.<sup>[[3]](#references)</sup>
3. **Fixed egress address'leri ayırın** ve bunları ROE annex'e ekleyin. Hızlı IP/resource cycling'den kaçının; bu, incident response'u zorlaştırır ve provider policy'sini ihlal edebilir.
4. **Management'ı harden edin:** yalnızca key kullanan SSH veya identity-aware management plane, phishing-resistant MFA, ayrı admin network, least privilege, patched image'lar, public admin port'larının olmaması ve encrypted secret storage kullanın.
5. **Operator endpoint'ten bastion'a full-tunnel path oluşturun.** DNS ve IPv6'yı bilinçli şekilde route edin ve tunnel kapalıyken firewall deny uygulayın.
6. **Mümkün olduğunda outbound destination ve port'ları authorized scope ile sınırlandırın.** Scanner'ları rate-limit edin ve geri döndürülemez/destructive technique'leri ayrı bir approval gate arkasına koyun.
7. **Surveillance için değil accountability için log tutun:** operator authentication, configuration change'leri, start/stop, source address, scoped destination ve tool/job identifier'ları. Exercise tarafından gerekli kılınmadıkça ve data plan tarafından korunmadıkça payload/credential capture'dan kaçının.
8. **Organization tarafından sahip olunan kontrollü bir endpoint üzerinden doğrulama yapın:** gözlemlenen IPv4/IPv6, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect ve provider abuse contact'ı.
9. **Attribution map'i güvenli biçimde** exercise controller veya üzerinde anlaşılmış bir escrow contact ile paylaşın. Blind detection testin parçasıysa bunu target team'e yayınlamayın.

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
Bir VPS yalnızca hedef açısından pseudonymous'tır. Host; iletişim, faturalandırma, kimlik, source-IP, API, cihaz, konum ve kullanım kayıtlarına sahip olabilir; yalnızca müşterinin görebildiği AWS CloudTrail geçmişi bile yönetim faaliyetlerini açığa çıkarabilir.<sup>[[4]](#references)</sup> Hosting ücretini cryptocurrency ile ödemek bu kayıtları ortadan kaldırmaz.

## Domainler ve sertifikalar

- Kuruluşun sahip olduğu, engagement'a özel bir registrar hesabı kullanın.
- Destekleniyorsa registrar lock, DNSSEC, MFA/security keys ve yalnızca onaylanan dönem için auto-renew özelliğini etkinleştirin.
- Kamuya açık görünürlüğü azaltmak için registration privacy kullanın; registrant bilgilerini yanlış beyan etmek için kullanmayın. ICANN policy, kamuya açık görüntüleme redacted veya proxied olsa bile registrar'ların registration data toplamasını gerektirir.<sup>[[5]](#references)</sup>
- İlgisiz tarafları hukuka aykırı şekilde taklit eden adlardan kaçının. Typosquatting/lookalike domainler için client ve provider'ın açık onayı gerekir.
- Operator'ları veya client'ları leak edebilecek DNS, sertifikalar, CDN/redirector configuration ve third-party analytics envanterini çıkarın.
- Teardown sırasında kayıtları kaldırın, sertifikaları/token'ları revoke edin, üzerinde anlaşılan evidence'ı koruyun ve domainin defensively retained edilip edilmeyeceğine karar verin.

## Yetkili on-site drop node'ları

Bir Raspberry Pi veya benzer appliance, yalnızca mülk/network sahibi ve client exact placement ile davranışını açıkça yetkilendirdiğinde kabul edilebilir. Güvenli bir plan:

1. Cihaz serial'ını, MAC/private-MAC policy'yi, fotoğrafı, sahibi, tam olarak onaylanan konumu, güç kaynağını, retrieval deadline'ını ve tamper contact'ı kaydedin.
2. Minimal signed image, encrypted secrets, read-only veya recoverable storage, host firewall, pratik olduğu durumlarda automatic security updates kullanın ve default credentials kullanmayın.
3. Yalnızca adı belirtilmiş bir engagement endpoint'ine outbound-only communication yapılandırın. Unauthenticated listener açmayın.
4. Destinations ve capabilities için allowlist kullanın. Packet capture, credential collection, wireless impersonation ve lateral movement işlemlerinin her biri açıkça yetkilendirilmelidir.
5. Mutual authentication, short-lived keys, remote kill, health reporting ve bandwidth limits kullanın.
6. Kayıp veya hırsızlığın yeniden kullanılabilir credentials ya da client data açığa çıkarmamasını sağlayın.
7. Retrieval ve secure wipe/decommission işlemlerini takvime ekleyin; imzalı bir recovery record alın.

Sahibinin/operator'ın yazılı izni olmadan hardware'ı bir café, hotel, shared office, komşunun mülkü veya public venue'da saklamayın.

## Guest networkler ve travel router'lar

Yetkili bir senaryo guest access gerektiriyorsa:

- SSID ve acceptable-use policy'yi venue/client ile doğrulayın;
- Privileged workstation'ı izole etmek için organization-owned travel router veya low-trust bridge device kullanın;
- Captive portal'ları privileged workstation dışında tamamlayın;
- Assessment traffic başlamadan önce approved tunnel'ı başlatın;
- Tethered device'ların gerçekten bu tunnel'ı kullandığını doğrulayın;
- Venue'nun radio association, portal, physical presence ve camera/payment records bilgilerini correlate edebileceğini varsayın;
- Access control'ü asla bypass etmeyin, başka bir device'ı clone etmeyin, Wi-Fi'ı attack etmeyin veya equipment'ı geride bırakmayın.

## Operational separation

- Her client/engagement için ayrı endpoint compartment, cloud project, secrets set, domain group, redirector set ve evidence store kullanın.
- Onaylanan organization systems dışında personal email, browser sync, phone number, cloud drive, SSH/GPG key, code-signing identity veya payment reimbursement kullanmayın.
- Exercise design fingerprinting'i kabul etmediği sürece distinctive payload configuration, callback paths, certificates veya public repositories'yi client'lar arasında yeniden kullanmayın.
- Infrastructure için bir kill date ve budget alert belirleyin. Orphaned systems hem client hem de Internet için risk oluşturur.
- Kazaları araştırmak için yeterli internal attribution'ı koruyun. “No logs” genellikle professional evidence ve safety obligations ile uyumsuzdur.

## Defenders için blind, controller'a attributable

Exercise objective bir allowlist'i test etmek yerine detection'ı ölçmek olduğunda target SOC, operation'ı unaccountable hale getirmeden blind kalabilir:

1. Exercise controller her public source, domain, certificate ve on-site device'ı onaylar ancak listeyi SOC'tan gizli tutar.
2. Controller, source-to-engagement/operator map'ini two-person emergency access ile ayrı bir encrypted vault'ta saklar.
3. Her operator job; scope, time window, source compartment ve irreversible job identifier içeren signed manifest alır. Target'ın normal operation sırasında manifesti görmesi gerekmez.
4. Bastion audit event'leri chained hale getirilir veya append-only olarak controller storage'a gönderilir; böylece bir operator incident sonrasında attribution'ı sessizce yeniden yazamaz.
5. 24/7 provider-abuse contact, client'ı public olarak ifşa etmeden authorization'ı doğrulayan bir verification phrase/reference bulundurur.
6. Her path, assessment C2'ye, target network'e veya tek bir operator account'una bağlı olmayan bir out-of-band stop channel uygular.
7. Live testing'den önce her source'tan benign canary gönderin. Controller'ın bunları ROE response time içinde resolve edip durdurabildiğini doğrulayın.
8. Exercise sonrasında SOC telemetry'yi controller ledger ile karşılaştırın, source list'i açıklayın ve missed/incorrect detection'ları açıklayın.

Anti-forensics, log destruction, compromised relays veya false subscriber identities eklemeyin. Bunlar accountable testing'i iyileştirmek yerine bozar.

## Teardown checklist

- [ ] Exercise controller stop'u onaylar.
- [ ] C2, tunnels, redirectors, mail, VPN ve scheduled jobs devre dışı bırakılır.
- [ ] On-site device'lar fiziksel olarak geri alınır ve mutabakatı yapılır.
- [ ] Tokens, API keys, SSH keys, certificates ve captured credentials revoke/rotate edilir.
- [ ] DNS ve cloud resources kaldırılır veya defensive retention için transfer edilir.
- [ ] Client data, contract'a uygun şekilde iade edilir, retained edilir veya yok edilir.
- [ ] Gerekli financial, audit ve authorization records encrypted ve access-controlled olarak korunur.
- [ ] Provider abuse case'leri kapatılır ve client'a final source indicators iletilir.
- [ ] İkinci bir operator, hiçbir infrastructure'ın active kalmadığını doğrular.

## References

- [1] [NIST CSRC — Rules of Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Information Security Testing and Assessment için Teknik Kılavuz](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Penetration Testing için Customer Support Policy](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Privacy Notice](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Registration Data Policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
