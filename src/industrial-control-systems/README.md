# Industrial Control Systems Hacking

{{#include ../banners/hacktricks-training.md}}

## Bu Bölüm Hakkında

Bu bölüm, endüstriyel kontrol sistemi (ICS) bileşenlerini, mimarilerini, protokollerini ve güvenlik değerlendirme yöntemlerini tanıtır. ICS, fiziksel süreçleri izleyen veya bu süreçlerde değişikliklere neden olan programlanabilir sistem ve cihazları kapsayan daha geniş operasyonel teknoloji (OT) alanının bir parçasıdır. Yaygın örnekler arasında denetleyici kontrol ve veri toplama (SCADA) sistemleri, dağıtık kontrol sistemleri (DCS'ler) ve programlanabilir lojik denetleyiciler (PLC'ler) bulunur.<sup>[[1]](#references)</sup>

Bu ortamlardaki güvenlik çalışmaları; süreç güvenliği, güvenilirlik, kullanılabilirlik, deterministik çalışma ve ekipman yaşam döngüleri gibi geleneksel BT'den farklı gereksinimleri dikkate almalıdır. Teknik açıdan geçerli bir güvenlik kontrolü, fiziksel süreci aksatıyorsa yine de uygun olmayabilir; bu nedenle test ve iyileştirme çalışmaları sistem sahibi ve operasyon personeliyle koordine edilmelidir.<sup>[[1]](#references)</sup>

Sistemin ele geçirilmesi veya yanlışlıkla kesintiye uğratılması üretimi durdurabilir, ekipmana zarar verebilir, tehlikeli maddelerin salınmasına, çevrenin zarar görmesine, yaralanmalara veya can kaybına yol açabilir. Bu olası fiziksel etkiler nedeniyle, aktif testlerden önce kontrol edilen süreci ve güvenli çalışma sınırlarını anlamak gerekir.<sup>[[1]](#references)</sup>

Birçok OT dağıtımı, ekipmanların uzun hizmet ömrü ve değişikliklerin operasyonel ve güvenlik testleri gerektirmesi nedeniyle eski işletim sistemlerini, uygulamaları ve protokolleri kullanmaya devam eder. Bazı protokoller modern kimlik doğrulama veya şifreleme olmadan tasarlanmıştır ve satıcı desteği ya da bakım pencereleri yama uygulamayı kısıtlayabilir; doğrudan yükseltmeler mümkün olmadığında ağ segmentasyonu, erişim denetimi ve izleme ile bu riskleri azaltın.<sup>[[1]](#references)</sup>

## Değerlendirme Öncelikleri

Kontrol edilen süreci, sistem sınırlarını, ağ topolojisini, varlıkları, veri akışlarını, güven ilişkilerini ve harici bağlantıları anlayarak başlayın. Benzer cihaz türleri farklı tesislerde farklı işlevlere hizmet edebilir; bu nedenle bir dağıtımın mimarisinin veya etki modelinin başka bir dağıtım için de geçerli olduğunu varsaymayın.<sup>[[1]](#references)</sup>

Mümkün olduğunda pasif keşfi ve mevcut mühendislik belgelerini tercih edin. Her türlü aktif tarama veya exploitation, güvenlik kısıtlarını, bakım pencerelerini, kurtarma prosedürlerini ve durdurma koşullarını tanımlayan onaylı bir test planına uygun şekilde yürütülmelidir. Bulgular hem siber güvenlik etkisi hem de fiziksel süreç üzerindeki olası etkileri açısından değerlendirilmelidir.<sup>[[1]](#references)</sup>

Aynı mimari bilgisi; varlık envanteri, ağ segmentasyonu, izleme, olay müdahalesi ve riske dayalı güvenlik açığı yönetimi gibi savunma faaliyetlerini de destekler.<sup>[[1]](#references)</sup>

## Protokol giriş noktaları

- [Modbus testi](../network-services-pentesting/pentesting-modbus.md), Modbus TCP'yi, seri varyantları, işlev kodlarını ve register erişimini kapsar.
- [OPC UA testi](../network-services-pentesting/4840-pentesting-opc-ua.md), endüstriyel veri alışverişi hizmetini kapsar.
- [BACnet testi](../network-services-pentesting/47808-udp-bacnet.md), bina otomasyonu kontrol ağlarını kapsar.

## References

- [1] [NIST SP 800-82 Rev. 3 - Operasyonel Teknoloji (OT) Güvenliği Rehberi](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../banners/hacktricks-training.md}}
