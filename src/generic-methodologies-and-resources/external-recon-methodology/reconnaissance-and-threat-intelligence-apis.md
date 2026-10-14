# Keşif ve Tehdit İstihbaratı API'leri

{{#include ../../banners/hacktricks-training.md}}

Bu hizmetler keşif, itibar, breach veya zenginleştirme iş akışlarını destekler. API'leri, kotaları, fiyatlandırmaları ve izin verilen kullanım biçimleri sık sık değişir; müşteri tanımlayıcılarını veya hassas verileri göndermeden önce güncel sağlayıcı belgelerini ve engagement yetkilendirmesini doğrulayın. Varlık keşfi sırası için [External Recon Methodology](README.md) sayfasına bakın.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Bir IP adresinin şüpheli veya kötü amaçlı etkinliklerle ilişkilendirilip ilişkilendirilmediğini sorgulayın. Erişim için hesap veya API key gerekebilir.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Bir IP adresinin, kullanıcı adının veya e-posta adresinin otomatik hesap kaydı ya da bildirilen diğer bot etkinlikleriyle ilişkilendirilip ilişkilendirilmediğini kontrol edin.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Profesyonel e-posta adreslerini ve alan adıyla ilgili iletişim örüntülerini bulun ve doğrulayın. İstek limitleri ve izin verilen kullanımlar için mevcut planı kontrol edin.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

IP adresleri ve alan adlarıyla ilişkili tehdit istihbaratı göstergelerini ve etkinlikleri arayın.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Bir e-posta adresini, alan adını veya şirketi mevcut iş/profil verileriyle zenginleştirin. Kapsam, erişim ve gizlilik kısıtlamaları mevcut ürüne ve plana bağlıdır.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Web sitelerinde gözlemlenen teknolojileri belirleyin ve seçilen planın izin verdiği durumlarda geçmiş veya ilişki verilerini alın.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Bir IP adresinin şüpheli veya kötü amaçlı etkinliklerle ilişkilendirilip ilişkilendirilmediğini kontrol edin. Mevcut API planlarını ve limitlerini doğrulayın.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Alan adları, URL'ler veya IP adresleri için FortiGuard kategorilendirmesini ve tehdit istihbaratını sorgulayın. Kullanılabilirlik hizmete göre değişir.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Bir IP adresinin bildirilen spam etkinlikleri nedeniyle listelenip listelenmediğini kontrol edin.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Bir alan adının, hizmetin topluluk verilerine ve diğer sinyallerine dayalı itibarını alın.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Bir IP adresi için coğrafi konum, ASN, kuruluş ve ilgili meta verileri alın. Kotalar için mevcut planı kontrol edin.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Bu platform; geçmişteki DNS çözümlemeleri, IP'lerle veya name server'larla ilişkilendirilmiş alan adları ve ilgili kayıtlar gibi DNS ve altyapı istihbaratı sağlar. Geçmiş DNS verileri daha önce kullanılmış bir origin adresini ortaya çıkarabilir; ancak CDN'yi güvenilir biçimde atlatmaz ve doğrulanmalıdır.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Bir e-posta adresini, alan adını veya şirket adını mevcut kimlik ve iş nitelikleriyle zenginleştirin. Kişisel verileri yetkilendirme ve gizlilik gerekliliklerine uygun şekilde işleyin.

## RiskIQ / Microsoft Defender Threat Intelligence (eski üründen geçiş) <sup>[[14]](#references)</sup>

RiskIQ'nun PassiveTotal özellikleri Microsoft Defender Threat Intelligence'a geçti. Ürüne erişim, API'ler ve korunan işlevler değiştiğinden eski PassiveTotal varsayımları yerine Microsoft'un güncel belgelerini kullanın.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Hizmetin erişim kontrollerine tabi olarak alan adlarını, IP adreslerini, e-posta adreslerini ve dizine eklenmiş geçmiş verileri veya leak edilmiş verileri arayın.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Tehdit istihbaratı ve itibar verileri için IP adreslerini ve diğer göstergeleri arayın.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

İnternet taraması ve yaygın hizmet etkinliklerine ilişkin gözlemler için IP adreslerini veya aralıklarını arayın. Mevcut deneme ve topluluk erişimi koşullarını kontrol edin.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Bir IP adresi, host veya arama sorgusu için internet taraması ve hizmet bilgilerini alın. API erişimi hesap planına bağlıdır.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Host, sertifika, alan adı ve internet hizmeti veri kümelerinde arama yapın; veri modeli ve kapsamı Shodan'dan farklıdır.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Sağlayıcının herkese açık olarak gözlemlenen cloud-storage nesneleri ve bucket'ları dizininde anahtar kelimeyle arama yapın.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Dizine eklenmiş breach verilerinde e-posta adreslerini, kullanıcı adlarını, alan adlarını ve ilgili kayıtları arayın. Yalnızca yetkilendirmeyle kullanın ve breach verilerinin gereksiz yere açığa çıkmasını önleyin.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Dizine eklenmiş paste içeriklerinde bir e-posta adresinin veya başka bir terimin geçip geçmediğini arayın. Entegrasyon yapmadan önce hizmetin hâlâ kullanılabilir olduğunu doğrulayın.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Bir e-posta adresi için itibar ve risk sinyallerini alın.

## GhostProject (geçmişteki hizmet) <sup>[[24]](#references)</sup>

Geçmişte leak edilmiş e-posta/parola verilerinde arama yapma olanağı sunduğu belirtiliyordu. Bu hizmeti yüksek riskli bir üçüncü taraf veri işleme hizmeti olarak değerlendirin; kullanmadan önce erişilebilirliğini, yasallığını ve gerekli yetkilendirmeyi doğrulayın.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

IP adresleri ve ilgili varlıklar için internet taraması, maruziyet ve tehdit istihbaratı verileri alın.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Bir e-posta adresinin veya doğrulanmış alan adının bilinen breach'lerde yer alıp almadığını kontrol edin. Ayrı Pwned Passwords hizmeti parola hash'lerini öneklerine göre kontrol eder; düz metin parolaları **açığa çıkarmaz**.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

IP coğrafi konumu, veri merkezi, ASN, proxy/VPN ve ilgili zenginleştirme alanlarını alın. Kotalar mevcut plana bağlıdır.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Seçili veri noktalarıyla IP coğrafi konumu ve OSINT odaklı zenginleştirme sağlar. Ticari kullanıma ilişkin güncel koşulları kontrol edin.


[DNSDumpster](https://dnsdumpster.com/) DNS keşif sonuçları sağlar.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) site, hosting ve internet altyapısı istihbaratı sağlar.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) çevrimiçi bir subdomain keşif arayüzü sağlar.<sup>[[31]](#references)</sup>

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
- [24] [Cornell araştırması — Ele Geçirilmiş Kimlik Bilgilerini Kontrol Etme Protokolleri (GhostProject dâhil)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../../banners/hacktricks-training.md}}
