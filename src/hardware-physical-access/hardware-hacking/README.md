# Donanım Hackleme

{{#include ../../banners/hacktricks-training.md}}

Bir cihaza fiziksel erişiminiz varsa, kartın veya sinyallerin sunduğu arayüzlerle başlayın: [UART seri konsolları](uart.md), [JTAG/SWD hata ayıklama erişimi](jtag.md), [I²C](i2c.md) ve [SPI flash](spi.md) veri yolları. [Yan kanal analizi](side_channel_analysis.md) ve [hata enjeksiyonu](fault_injection_attacks.md) farklı ölçüm ve sinyal bozma görevlerini ele alır; [radyo sinyali analizi](radio.md) ise kablosuz bir giriş noktasını kapsar. Araçları bağlamadan önce hedefin elektrik seviyelerini ve ilgili bölümde belirtilen kısıtlamaları kontrol edin.

## JTAG

JTAG (IEEE 1149.1), bir cihazın G/Ç pinlerinin çevresine yerleştirilen hücreler aracılığıyla sınır taraması testini destekler. Birçok işlemci, aynı Test Access Port (TAP) üzerinden üreticiye özgü hata ayıklama işlevleri de sunar; sınır taraması ve CPU hata ayıklama, JTAG'ın birbiriyle ilişkili kullanımlarıdır, eş anlamlı değildir.<sup>[[1]](#references)</sup>

JTAG standardı, **sınır taraması yapmak için belirli komutlar** tanımlar. Bunlardan bazıları şunlardır:

- **BYPASS**, bir tarama zincirindeki diğer cihazlara en az ek yükle erişmek için tek bitlik bypass yazmacını seçer.
- **SAMPLE/PRELOAD**, normal çalışma sırasında pin değerlerini yakalar ve başka bir talimat uygulanmadan önce sınır tarama yazmacına önceden değer yükleyebilir.
- **EXTEST**, pin durumlarını ayarlar ve okur.

Ayrıca aşağıdaki gibi başka komutları da destekleyebilir:

- Bir cihazı tanımlamak için **IDCODE**
- Cihazın dahili testi için **INTEST**

JTAGulator gibi bir araç kullandığınızda bu talimatlarla karşılaşabilirsiniz.

### Test Access Port

**Test Access Port (TAP)**, bir bileşenin JTAG test mantığına erişim sağlar. Dört sinyal gereklidir; `TRST` ise isteğe bağlıdır:<sup>[[1]](#references)</sup>

- Test clock girişi (**TCK**) TCK, TAP denetleyicisinin ne sıklıkta tek bir işlem yapacağını (başka bir deyişle, durum makinesinde bir sonraki duruma geçeceğini) belirleyen **saat sinyalidir**.
- Test mode select (**TMS**) girişi TMS, **sonlu durum makinesini** kontrol eder. Her saat darbesinde cihazın JTAG TAP denetleyicisi TMS pinindeki gerilimi kontrol eder. Gerilim belirli bir eşiğin altındaysa sinyal düşük kabul edilir ve 0 olarak yorumlanır; belirli bir eşiğin üzerindeyse sinyal yüksek kabul edilir ve 1 olarak yorumlanır.
- Test data girişi (**TDI**), seri talimatları veya test verilerini seçili TAP yazmacına kaydırır. IEEE 1149.1, TAP aktarım davranışını tanımlarken üreticiler isteğe bağlı talimatları ve hata ayıklama yazmaçlarını tanımlar.
- Test data çıkışı (**TDO**), **çipten veri gönderen** pindir.
- Test reset (**TRST**) girişi: İsteğe bağlı TRST, sonlu durum makinesini **bilinen, güvenli bir duruma** sıfırlar. Alternatif olarak TMS beş ardışık saat döngüsü boyunca 1'de tutulursa, TRST pininin yaptığı gibi sıfırlama gerçekleştirilir; bu nedenle TRST isteğe bağlıdır.

Bazen bu pinleri PCB üzerinde işaretlenmiş olarak bulabilirsiniz. Bazı durumlarda ise onları **bulmanız** gerekebilir.

### JTAG pinlerini belirleme

JTAG portlarını tespit etmek için hızlı, bu iş için özel olarak tasarlanmış ancak görece pahalı bir seçenek olan **JTAGulator**, UART pin çıkışlarını da belirleyebilir.<sup>[[2]](#references)</sup>

Bu cihazda kart üzerindeki test noktalarına bağlanabilen **24 kanal** bulunur. **IDCODE** ve **BYPASS** taramalarıyla olası pin kombinasyonlarını dener ve tespit edilen JTAG sinyallerine karşılık gelen kanalları bildirir.

JTAG pin çıkışlarını belirlemenin daha ucuz ama çok daha yavaş bir yolu, Arduino uyumlu bir mikrodenetleyiciye yüklenen [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) aracını kullanmaktır.

**JTAGenum** ile önce, tarama için kullanılacak mikrodenetleyici pinlerini tanımlayın. Pin çıkışlarını inceleyin, ardından bu pinleri hedef karttaki olası test noktalarına bağlayın.<sup>[[3]](#references)</sup>

JTAG pinlerini belirlemenin **üçüncü yolu**, PCB'yi bilinen bir ayak izi için **incelemektir**. Bazı kartlarda **Tag-Connect** ayak izi bulunur; ancak Tag-Connect, JTAG, SWD, UART veya başka bir arayüz taşıyabilen bir konektör sistemidir. Tek başına pinlerin JTAG olduğunu kanıtlamaz. Bileşen veri sayfaları ve süreklilik ölçümleri, gerçek sinyalleri belirlemenize yardımcı olabilir.<sup>[[5]](#references)</sup>

## SDW

SWD, Arm'ın iki pinli, paket tabanlı hata ayıklama arayüzüdür.<sup>[[4]](#references)</sup>

Arayüz, veri için çift yönlü **SWDIO** ve saat sinyali için **SWCLK** kullanır. Birçok cihaz, ortak pinler üzerinden SWD ile JTAG arasında seçim yapılmasına olanak tanıyan bir **Serial Wire/JTAG Debug Port (SWJ-DP)** uygular.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 çalışma grubu — JTAG ve sınır taraması](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator belgeleri](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino ile JTAG pinlerini belirleme](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Çok cihazlı sistemler için düşük pin sayılı hata ayıklama arayüzleri](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Hata ayıklama ve programlama kablosu ayak izleri](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
