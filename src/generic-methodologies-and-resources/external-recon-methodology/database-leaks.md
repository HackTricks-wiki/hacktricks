# Veritabanı leaks

{{#include ../../banners/hacktricks-training.md}}

## Veri İhlali Arama Motorları

İhlal veya itibar verilerini ararken API erişimi ve hizmete özel uyarılar için [Keşif ve Tehdit İstihbaratı API'leri kataloğuna](reconnaissance-and-threat-intelligence-apis.md) bakın.

- [GreyNoise Visualizer](https://viz.greynoise.io/) - IP'leri ve CIDR'leri arayın; tarayıcı etkinliğini etiketlere, CVE'lere ve metadata'ya göre sorgulayın.<sup>[[1]](#references)</sup>
- [DeHashed](https://www.dehashed.com/) - Açığa çıkmış verileri kullanıcı adlarına, e-posta adreslerine, IP adreslerine ve diğer arama ölçütlerine göre arayın; izleme ve API de sunulur.<sup>[[2]](#references)</sup>
- [Have I Been Pwned?](https://haveibeenpwned.com/) - Bir e-posta adresinin bilinen veri ihlallerinde veya paste kayıtlarında yer alıp almadığını kontrol edin; bildirimler ve API de sunulur.<sup>[[3]](#references)</sup>
- [ScamSearch](https://scamsearch.io/) - Bildirilen dolandırıcı kayıtlarını profil fotoğrafına, e-postaya, kullanıcı adına, telefon numarasına, kripto adresine veya web sitesine göre arayın.<sup>[[4]](#references)</sup>
- [Intelligence X](https://intelx.io/) - E-posta adresleri, alan adları, URL'ler, IP'ler ve CIDR'ler gibi arama ölçütlerini dizinlenmiş kaynaklarda arayın.<sup>[[5]](#references)</sup>
- [SpyCloud](https://spycloud.com/check-your-exposure/) - Bir iş e-postasının veya alan adının açığa çıkmış kimlik bilgilerini, infostealer bulaşmış kimlikleri ve çalınmış oturum çerezlerini kontrol edin.<sup>[[6]](#references)</sup>
- [WeLeakInfo](https://weleakinfo.io/) - Sızdırılmış veritabanlarını alan adlarına, adlara, e-postalara, kimlik numaralarına, telefonlara, IP'lere, URL'lere veya hash'lere göre arayın.<sup>[[7]](#references)</sup>
- [BreachDirectory](https://breachdirectory.org/) - E-postanızın veya kullanıcı adınızın ele geçirilip geçirilmediğini kontrol edin.
- [LeakCheck](https://leakcheck.io/) - Açığa çıkmış e-posta, kullanıcı adı, telefon, hash veya alan adı verilerini arayın ve yeni kayıtları izleyin.<sup>[[8]](#references)</sup>
- [Findemail.io](https://findemail.io/) - Belirli bir şirketin e-posta adreslerini bulun.
- [Library of Leaks](https://search.libraryofleaks.org/) - Leak veri kümeleri de dahil olmak üzere herkese açık belgelerde, şirketlerde ve kişilerde arama yapın.<sup>[[9]](#references)</sup>
- [LeakRadar](https://leakradar.io/) - Sızdırılmış kimlik bilgilerini e-postaya, alan adına veya ham dizeye göre arayın ve yeni ifşaları izleyin.<sup>[[10]](#references)</sup>
- [InfoStealers](https://infostealers.info/en/info) - Bulaşmış cihazlardan alınan infostealer kayıtlarını arayın ve yeni verileri izleyin.<sup>[[11]](#references)</sup>
- [Leak-Lookup](https://leak-lookup.com/) - Veri ihlallerinde arama yapın ve kimlik bilgisi ifşalarını izleyin.<sup>[[12]](#references)</sup>
- [Scylla.so](https://scylla.so/) - Topluluk tarafından yürütülen veritabanı ihlali arama motoru.
- [Leaked.domains](https://leaked.domains/) - Sızdırılmış kimlik bilgilerini ve ilişkili kayıtları alan adına, e-postaya, kullanıcı adına, parolaya, IP'ye ve diğer arama ölçütlerine göre arayın.<sup>[[13]](#references)</sup>
- [WhiteIntel](https://whiteintel.io/) - Dark web etkinliğini, kimlik bilgisi leak'lerini, infostealer verilerini ve marka anılmalarını izleyin.<sup>[[14]](#references)</sup>
- [PSBDMP](https://psbdmp.ws/) - Pastebin dökümlerini arama ve izleme platformu.

## Data leak'leri saymak için araçlar

- [Leaker](https://github.com/vflame6/leaker) - E-posta, kullanıcı adı, alan adı, anahtar kelime veya telefon numarasına göre birden fazla çevrimiçi kaynağı arayan pasif leak keşif CLI aracı.<sup>[[15]](#references)</sup>

## References

- [1] [GreyNoise Visualizer'ı kullanma](https://docs.greynoise.io/docs/using-the-greynoise-visualizer)
- [2] [DeHashed](https://www.dehashed.com/)
- [3] [Pwned olup olmadığımı kontrol et](https://haveibeenpwned.com/)
- [4] [Küresel Dolandırıcı Veritabanı - ScamSearch](https://scamsearch.io/)
- [5] [Intelligence X](https://intelx.io/)
- [6] [İfşa Durumunuzu Kontrol Edin - SpyCloud](https://spycloud.com/check-your-exposure/)
- [7] [WeLeakInfo](https://weleakinfo.io/)
- [8] [Veri İhlali Arama Motoru - LeakCheck](https://leakcheck.io/)
- [9] [Library of Leaks](https://search.libraryofleaks.org/)
- [10] [LeakRadar](https://leakradar.io/)
- [11] [OSINT InfoStealers.Info](https://infostealers.info/en/info)
- [12] [Leak-Lookup - Veri İhlali Arama Motoru](https://leak-lookup.com/)
- [13] [Leaked.Domains - Evrensel Arama](https://leaked.domains/)
- [14] [WhiteIntel - Dark Web İstihbarat ve İzleme Platformu](https://whiteintel.io/)
- [15] [vflame6/leaker](https://github.com/vflame6/leaker)
{{#include ../../banners/hacktricks-training.md}}
