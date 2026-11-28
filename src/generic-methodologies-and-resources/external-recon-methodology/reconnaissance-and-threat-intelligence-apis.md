# Keşif ve Tehdit İstihbaratı API'leri

{{#include ../../banners/hacktricks-training.md}}

Bu hizmetler keşif, itibar, breach veya zenginleştirme iş akışlarını destekler. API'leri, kotaları, fiyatlandırmaları ve izin verilen kullanım şekilleri sık sık değişir; müşteri tanımlayıcıları veya hassas veriler göndermeden önce sağlayıcının güncel belgelerini ve görev için verilen yetkiyi doğrulayın. Varlık keşif sırası için [External Recon Methodology](README.md) sayfasına bakın.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Bir IP adresinin şüpheli veya kötü amaçlı etkinlikle ilişkilendirilip ilişkilendirilmediğini sorgulayın. Erişim için hesap veya API anahtarı gerekebilir.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Bir IP adresinin, kullanıcı adının veya e-posta adresinin otomatik hesap kaydı ya da bildirilen diğer bot etkinlikleriyle ilişkilendirilip ilişkilendirilmediğini kontrol edin.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Profesyonel e-posta adreslerini ve alan adıyla ilişkili iletişim kalıplarını bulun ve doğrulayın. İstek sınırları ve izin verilen kullanımlar için güncel planı kontrol edin.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

IP adresleri ve alan adlarıyla ilişkili tehdit istihbaratı göstergelerini ve etkinlikleri arayın.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Bir e-posta adresini, alan adını veya şirketi mevcut iş/profil verileriyle zenginleştirin. Kapsam, erişim ve gizlilik kısıtlamaları güncel ürüne ve plana bağlıdır.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Web sitelerinde gözlemlenen teknolojileri belirleyin; seçilen planın izin verdiği durumlarda geçmiş veya ilişki verilerini alın.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Bir IP adresinin şüpheli veya kötü amaçlı etkinlikle ilişkili olup olmadığını kontrol edin. Güncel API planlarını ve sınırlarını doğrulayın.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Alan adları, URL'ler veya IP adresleri için FortiGuard sınıflandırmalarını ve tehdit istihbaratını sorgulayın. Kullanılabilirlik hizmete göre değişir.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Bir IP adresinin bildirilen spam etkinliği nedeniyle listeye alınıp alınmadığını kontrol edin.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Hizmetin topluluk verilerine ve diğer sinyallere dayalı olarak bir alan adının itibarını alın.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Bir IP adresi için coğrafi konum, ASN, kuruluş ve ilgili meta verileri alın. Kotalar için güncel planı kontrol edin.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Bu platform, geçmiş çözümlemeler, IP'lerle veya ad sunucularıyla ilişkili alan adları ve ilgili kayıtlar gibi DNS ve altyapı istihbaratı sağlar. Geçmiş DNS verileri önceki bir origin adresini ortaya çıkarabilir; ancak CDN'i güvenilir biçimde atlatmaz ve doğrulanmalıdır.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Bir e-posta adresini, alan adını veya şirket adını mevcut kimlik ve iş nitelikleriyle zenginleştirin. Kişisel verileri yetki ve gizlilik gerekliliklerine uygun şekilde işleyin.

## RiskIQ / Microsoft Defender Threat Intelligence (eski sistem geçişi) <sup>[[14]](#references)</sup>

RiskIQ'nun PassiveTotal özellikleri Microsoft Defender Threat Intelligence'a geçiş yaptı. Ürün erişimi, API'ler ve korunan işlevler değiştiğinden, eski PassiveTotal varsayımları yerine Microsoft'un güncel belgelerini kullanın.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Hizmetin erişim denetimlerine tabi olarak alan adlarını, IP adreslerini, e-posta adreslerini ve indekslenmiş geçmiş veya leak verilerini arayın.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Tehdit istihbaratı ve itibar verileri için IP adreslerini ve diğer göstergeleri arayın.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

İnternet taramalarına ve yaygın hizmet etkinliklerine ilişkin gözlemler için IP adreslerini veya aralıklarını arayın. Güncel deneme ve topluluk erişimi koşullarını kontrol edin.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Bir IP adresi, host veya arama sorgusu için internet taraması ve hizmet bilgilerini alın. API erişimi hesap planına bağlıdır.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Host, sertifika, alan adı ve internet hizmeti veri kümelerinde arama yapın; veri modeli ve kapsamı Shodan'dan farklıdır.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Sağlayıcının herkese açık olarak gözlemlenmiş cloud-storage nesneleri ve bucket'ları dizininde anahtar kelimeyle arama yapın.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

E-posta adresleri, kullanıcı adları, alan adları ve ilgili kayıtlar için indekslenmiş breach verilerinde arama yapın. Yalnızca yetkiyle kullanın ve breach verilerini gereksiz yere açığa çıkarmaktan kaçının.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Bir e-posta adresinin veya başka bir terimin geçtiği indekslenmiş paste içeriklerinde arama yapın. Entegrasyona almadan önce hizmetin hâlâ kullanılabilir olduğunu doğrulayın.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Bir e-posta adresine ilişkin itibar ve risk sinyallerini alın.

## GhostProject (geçmişte hizmet vermiş) <sup>[[24]](#references)</sup>

Geçmişte leak edilmiş e-posta/şifre verilerinde arama yapma olanağı sunduğunu duyurmuştu. Hizmeti, üçüncü tarafların yüksek riskli veri işlemesi olarak değerlendirin; kullanmadan önce erişilebilirliğini, yasallığını ve yetki durumunu doğrulayın.

## BinaryEdge (hizmet dışı) <sup>[[25]](#references)</sup>

IP adresleri ve ilişkili varlıklar için internet taraması, maruziyet ve tehdit istihbaratı verileri sunuyordu. Sitesi artık Coalition geçiş bildirimine yönlendiriyor ve API isteklerini reddediyor; bu nedenle hizmeti kullanılamaz kabul edin.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Bir e-posta adresinin veya doğrulanmış bir alan adının bilinen breach'lerde yer alıp almadığını kontrol edin. Ayrı Pwned Passwords hizmeti, önek üzerinden şifre hash'lerini kontrol eder; düz metin şifreleri **açığa çıkarmaz**.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

IP coğrafi konumu, veri merkezi, ASN, proxy/VPN ve ilgili zenginleştirme alanlarını alın. Kotalar güncel plana bağlıdır.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Seçili veri noktalarıyla IP coğrafi konumu ve OSINT odaklı zenginleştirme sağlar. Ticari kullanım için güncel koşulları kontrol edin.

### [NetAPI](https://netapi.com/) <sup>[[32]](#references)</sup>
Bir alan adını (kayıt kuruluşu, kayıt ve sona erme tarihleri, ad sunucuları, barındırma IP'si ve ülkesi) veya bir IP adresini (üzerinde barındırılan diğer alan adları) sorgulayın ve bir alan adının ya da IP'nin ücretsiz ele geçirilmiş varlık listelerinde olup olmadığını kontrol edin: kimlik avı ve sinkhole'a yönlendirilmiş malware alan adları ile son 48 saatte honeypot sensörlerine saldıran adresler. Web sorgulamaları ve ele geçirilmiş varlık kontrol API'si hesap gerektirmez; sorgulamalara API erişimi ücretli plan gerektirir.


[DNSDumpster](https://dnsdumpster.com/) DNS keşif sonuçları sağlar.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) site, barındırma ve internet altyapısı istihbaratı sağlar.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) çevrimiçi bir alt alan adı keşif arayüzü sağlar.<sup>[[31]](#references)</sup>

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
- [24] [Cornell research — Protocols for Checking Compromised Credentials (includes GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
- [32] [NetAPI API documentation](https://netapi.com/help/api/)

{{#include ../../banners/hacktricks-training.md}}
