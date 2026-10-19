# VSAT İleri Bağlantı Sinyali Enjeksiyonu

{{#include ../../banners/hacktricks-training.md}}

Bir VSAT terminali, uydu downlink'ini normalde operatörün hub'ından gelen trafik olarak kabul eder. DVB-RCS sisteminde bu forward link hem kullanıcı IP paketlerini hem de modem kontrol mesajlarını taşıyabilir. Alıcı bir mesajı işlemeden önce kimliğini doğrulamıyorsa, yerel olarak enjekte edilen bir sinyal radyo ile kontrol düzlemi arasındaki güven sınırını aşabilir. Bu, **terminalde downlink enjeksiyonudur**; uyduya uplink yapmak veya downlink'i pasif olarak dinlemek değildir. Gösterilen sonucun ne olacağı yalnızca DVB-RCS'ye değil, modemin protokol uygulamasına ve mesaj kimlik doğrulamasına bağlıdır.<sup>[[1]](#references)[[2]](#references)</sup>

## RF yalıtımlı bir laboratuvarda test edin

Size ait bir terminali, firmware'ini ve modemin alım girişine uygun zayıflatıcılarla bağlanmış bir SDR'yi ya da RF yalıtımlı bir düzenek kullanın. Canlı bir uydu kanalında yayın yapmayın. Önce terminalde yapılandırılmış başlangıç taşıyıcısını, sembol hızını ve population ID'yi kaydedin; bunlar forward-link edinimine yardımcı olur.<sup>[[1]](#references)[[3]](#references)</sup> DVB-RCS edinim zinciri, RCS Map Table'ı (RMT) bulmak için Network Information Table'ı (NIT), ardından forward-link sinyal akışlarını bulmak için Program Association Table'ı (PAT) ve Program Map Table'ı (PMT) kullanır. Veri akışına ulaşmadan önce terminal birden fazla transport-stream taşıyıcısına yeniden ayar yapabilir.<sup>[[3]](#references)</sup>

1. Hedefin başlangıç transport stream'ini çözümleyin veya yeniden oluşturun; NIT, RMT, service ID'leri, packet ID'leri (PID'ler) ve clock-reference işleyişini inceleyin. Standardı hedefin parser'ı ve loglarıyla karşılaştırın; satıcıya özgü sıralama veya descriptor'lar, aksi hâlde geçerli bir akışın kabul edilmesini engelleyebilir.
2. Laboratuvar vericisinde zararsız bir UDP probe'unu `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q` biçiminde kapsülleyin ve SDR sink üzerinden yalıtılmış alım yoluna gönderin. Transport stream'in Program Clock Reference (PCR) değerini byte hızıyla tutarlı tutun; aksi hâlde modem probe'u işlemeden önce senkronizasyonunu kaybedebilir.
3. Size ait bir dahili endpoint'te hem **demodülatör kilidini** hem de probe'un alındığını doğrulayın. Tek başına kilit, yalnızca fiziksel katmanın dalga biçimini kabul ettiğini gösterir. Ardından, bir image yüklemeden veya servis yapılandırmasını değiştirmeden, kimlik doğrulaması olmayan yönetim ya da güncelleme *sinyallemesinin* açığa çıkıp çıkmadığını kontrol edin.

Yayımlanan MDM2200 vakasında DVB-RCS/MPE/MPEG-TS için bir GNU Radio source module ve DVB-S2 modülasyonu için `gr-dtv` kullanılmıştır. Modem, hedefe özgü başlatma ayrıntıları gerektiriyordu: PAT/PMT'den önce bir SDT, tablo ID'si `0x3E` olan bir RCS content descriptor ve GSE/4CPM modu için `0x01` değerinde bir RMT private byte. Bu değerlerin başka bir terminalde çalışacağını varsaymayın.<sup>[[1]](#references)</sup> Araştırmacılar ayrıca kendi düzeneklerinde multicast MPE paketlerinin alıcı modemlere ulaştığını gözlemledi; dolayısıyla hedefleme, bilinen bir unicast MAC adresiyle sınırlı değildi.<sup>[[1]](#references)</sup> Ayrı bir analizde incelenen sistemde korumasız kontrol ve yazılım güncelleme sinyallemesi bulundu; ancak bu bulgu her uygulama için ayrıca doğrulanmalıdır.<sup>[[2]](#references)</sup>

Kullanıcı trafiği için kullanılan bir IPsec veya VPN tüneli, daha önceki DVB-RCS sinyallemesinin ya da modemin kendi güncelleme parser'ının kimliğini doğrulamaz. Yetkili bir değerlendirmede, radyo enjeksiyonunun engellendiğinin kanıtı olarak güvenli bir kullanıcı tünelini kabul etmek yerine **kullanıcı IP'sinin**, **forward-link kontrolünün** ve **bakım/kurtarma** trafiğinin kriptografik korumasını ayrı ayrı değerlendirin.<sup>[[1]](#references)[[2]](#references)</sup>

İlk I/Q incelemesi için [radyo sinyali analizine](../hardware-hacking/radio.md) bakın. Kart üzerindeki firmware ve parser incelemesi için [firmware analizine](../firmware-analysis/) bakın. Diğer arayüzler için [Radio Hacking genel bakışına](./) dönün.

## References

- [1] [Bisping et al. - VSAT Uydu Modemlerine Yönelik Kablosuz Sinyal Enjeksiyonu Saldırıları (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold et al. - VSAsTer: Mevcut VSAT Sistemi Uygulamalarındaki Yerleşik Güvenlik Sorunlarının Ortaya Çıkarılması (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 - Uydu dağıtım sistemleri için DVB etkileşim kanalı](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
