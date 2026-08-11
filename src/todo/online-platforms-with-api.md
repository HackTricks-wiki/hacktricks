# API'li Online Platformlar

{{#include ../banners/hacktricks-training.md}}

Bu servisler reconnaissance, reputation, breach veya enrichment iş akışlarını destekler. API'leri, kotaları, fiyatlandırmaları ve izin verilen kullanımları sık sık değişir; müşteri tanımlayıcılarını veya hassas verileri göndermeden önce güncel vendor dokümantasyonunu ve engagement yetkilendirmesini doğrulayın.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Bir IP adresinin şüpheli veya kötü amaçlı etkinlikle ilişkilendirilip ilişkilendirilmediğini sorgulayın. Erişim için hesap veya API key gerekebilir.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Bir IP adresinin, kullanıcı adının veya e-posta adresinin otomatik hesap kaydı ya da bildirilen diğer bot etkinlikleriyle ilişkilendirilip ilişkilendirilmediğini kontrol edin.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Profesyonel e-posta adreslerini ve domain ile ilişkili iletişim kalıplarını bulun ve doğrulayın. Request limitlerini ve izin verilen kullanımları güncel planda kontrol edin.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

IP adresleri ve domainlerle ilişkili threat-intelligence göstergelerini ve etkinlikleri arayın.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Bir e-posta adresini, domaini veya şirketi mevcut business/profile verileriyle enrich edin. Kapsam, erişim ve privacy kısıtlamaları mevcut ürüne ve plana bağlıdır.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Web sitelerinde gözlemlenen teknolojileri belirleyin ve seçilen planın izin verdiği durumlarda historical veya relationship verilerini edinin.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Bir IP adresinin şüpheli veya kötü amaçlı etkinlikle ilişkili olup olmadığını kontrol edin. Güncel API planlarını ve limitlerini doğrulayın.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Domainler, URL'ler veya IP adresleri için FortiGuard categorization ve threat intelligence verilerini sorgulayın. Kullanılabilirlik servise göre değişir.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Bir IP adresinin bildirilen spam etkinliği nedeniyle listelenip listelenmediğini kontrol edin.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Bir domainin reputation bilgisini servisin community verilerine ve diğer sinyallerine göre alın.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Bir IP adresi için geolocation, ASN, organization ve ilgili metadata bilgilerini edinin. Kotalar için güncel planı kontrol edin.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Bu platform; historical resolution'lar, IP'lerle veya name server'larla ilişkili domainler ve ilgili kayıtlar gibi DNS ve infrastructure intelligence bilgileri sağlar. Historical DNS, önceki bir origin adresini ortaya çıkarabilir; ancak CDN'i güvenilir şekilde bypass etmez ve doğrulanmalıdır.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Bir e-posta adresini, domaini veya şirket adını mevcut identity ve business attribute'larıyla enrich edin. Kişisel verileri authorization ve privacy gereksinimlerine uygun şekilde işleyin.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

RiskIQ'nun PassiveTotal yetenekleri Microsoft Defender Threat Intelligence'a taşındı. Ürün erişimi, API'ler ve korunan işlevler değişmiştir; bu nedenle legacy PassiveTotal varsayımları yerine Microsoft'un güncel dokümantasyonunu kullanın.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Servisin access control mekanizmalarına tabi olarak domainleri, IP adreslerini, e-posta adreslerini ve index'lenmiş historical veya leak verilerini arayın.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Threat-intelligence ve reputation verileri için IP adreslerini ve diğer göstergeleri arayın.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Internet scanning ve yaygın servis etkinliği gözlemleri için IP adreslerini veya aralıklarını arayın. Güncel trial ve community-access koşullarını kontrol edin.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Bir IP adresi, host veya search query için internet-scan ve servis bilgilerini alın. API erişimi hesap planına bağlıdır.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Host, certificate, domain ve internet-service dataset'lerini arayın; data model'i ve kapsamı Shodan'ınkinden farklıdır.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Provider'ın herkese açık olarak gözlemlenen cloud-storage object ve bucket index'ini keyword ile arayın.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

E-posta adresleri, kullanıcı adları, domainler ve ilgili kayıtlar için index'lenmiş breach verilerini arayın. Yalnızca authorization ile kullanın ve breach verilerinin gereksiz şekilde açığa çıkarılmasından kaçının.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Bir e-posta adresinin veya başka bir terimin geçtiği index'lenmiş paste içeriklerini arayın. Entegrasyon öncesinde servisin hâlâ kullanılabilir olduğunu doğrulayın.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Bir e-posta adresi için reputation ve risk sinyallerini alın.

## GhostProject (historical) <sup>[[24]](#references)</sup>

Historical olarak leak e-posta/şifre verilerinde arama sunduğunu duyurmuştur. Servisi high-risk üçüncü taraf işleme olarak değerlendirin ve kullanmadan önce kullanılabilirliğini, yasallığını ve authorization durumunu doğrulayın.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

IP adresleri ve ilgili asset'ler için internet-scan, exposure ve threat-intelligence verilerini edinin.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Bir e-posta adresinin veya doğrulanmış bir domainin bilinen breach'lerde görünüp görünmediğini kontrol edin. Ayrı Pwned Passwords servisi, password hash'lerini prefix ile kontrol eder; plaintext password'leri **açığa çıkarmaz**.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

IP geolocation, data-center, ASN, proxy/VPN ve ilgili enrichment alanlarını alın. Kotalar güncel plana bağlıdır.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Seçili data point'lerle IP geolocation ve OSINT odaklı enrichment sağlar. Ticari kullanım için güncel koşulları kontrol edin.


[DNSDumpster](https://dnsdumpster.com/) DNS-reconnaissance sonuçları sağlar.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) site, hosting ve internet-infrastructure intelligence bilgileri sağlar.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) online subdomain-discovery arayüzü sağlar.<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [BotScout API](https://botscout.com/api.htm)
- [3] [Hunter API](https://hunter.io/api-documentation)
- [4] [AlienVault OTX API](https://otx.alienvault.com/api)
- [5] [Clearbit](https://dashboard.clearbit.com/)
- [6] [BuiltWith](https://builtwith.com/)
- [7] [FraudGuard](https://fraudguard.io/)
- [8] [FortiGuard Labs](https://www.fortiguard.com/)
- [9] [SpamCop](https://www.spamcop.net/)
- [10] [Web of Trust](https://www.mywot.com/)
- [11] [IPinfo](https://ipinfo.io/)
- [12] [SecurityTrails](https://securitytrails.com/)
- [13] [FullContact](https://www.fullcontact.com/)
- [14] [Microsoft Defender Threat Intelligence](https://learn.microsoft.com/en-us/defender/threat-intelligence/what-is-microsoft-defender-threat-intelligence-defender-ti)
- [15] [Intelligence X](https://intelx.io/)
- [16] [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
- [17] [GreyNoise](https://www.greynoise.io/)
- [18] [Shodan](https://www.shodan.io/)
- [19] [Censys](https://censys.com/)
- [20] [GrayHatWarfare](https://buckets.grayhatwarfare.com/)
- [21] [DeHashed](https://www.dehashed.com/)
- [22] [psbdmp](https://psbdmp.ws/)
- [23] [EmailRep](https://emailrep.io/)
- [24] [Cornell research — Compromised Credentials'ı Kontrol Etme Protokolleri (GhostProject'i içerir)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../banners/hacktricks-training.md}}
