# Donanım Hacking

{{#include ../../banners/hacktricks-training.md}}

Bir cihaza fiziksel erişiminiz varsa, kartının veya sinyallerinin sunduğu arayüzlerden başlayın: [UART seri konsolları](uart.md), [JTAG/SWD debug erişimi](jtag.md), [I²C](i2c.md) ve [SPI flash](spi.md) veri yolları. [Yan kanal analizi](side_channel_analysis.md) ve [hata enjeksiyonu](fault_injection_attacks.md) farklı ölçüm ve glitching görevlerine yöneliktir; [radyo sinyali analizi](radio.md) ise kablosuz bir giriş noktasını ele alır. Hedefe özgü RFID/NFC, sub-GHz, kızılötesi, BLE, LoRaWAN ve iButton prosedürleri için [Radio Hacking ve Yakınlık Arayüzleri](../radio-hacking/README.md) bölümünü kullanın. Araçları bağlamadan önce hedefin elektrik seviyelerini ve ilgili bölümdeki kısıtlamaları kontrol edin.

## JTAG

JTAG (IEEE 1149.1), bir cihazın I/O pinlerinin etrafına yerleştirilen hücreler aracılığıyla boundary-scan testini destekler. Birçok işlemci, aynı Test Access Port (TAP) üzerinden üreticiye özgü debug işlevleri de sunar; boundary scan ve CPU debugging, JTAG'ın ilişkili kullanımlarıdır, eş anlamlıları değildir.<sup>[[1]](#references)</sup>

JTAG standardı, **boundary scan gerçekleştirmek için belirli komutlar** tanımlar. Bunlardan bazıları şunlardır:

- **BYPASS**, tarama zincirindeki diğer cihazlara en az ek yükle erişilebilmesi için tek bitlik bir bypass register'ı seçer.
- **SAMPLE/PRELOAD**, normal çalışma sırasında pin değerlerini yakalar ve başka bir talimattan önce boundary-scan register'ına önceden değer yükleyebilir.
- **EXTEST**, pin durumlarını ayarlar ve okur.

Ayrıca şu komutları da destekleyebilir:

- Bir cihazı tanımlamak için **IDCODE**
- Cihazın dahili testi için **INTEST**

JTAGulator gibi bir araç kullandığınızda bu talimatlarla karşılaşabilirsiniz.

### Test Access Port

**Test Access Port (TAP)**, bir bileşenin JTAG test mantığına erişim sağlar. Dört sinyal gereklidir; `TRST` ise isteğe bağlıdır:<sup>[[1]](#references)</sup>

- Test clock input (**TCK**) TCK, TAP denetleyicisinin ne sıklıkta tek bir eylem gerçekleştireceğini (başka bir deyişle, durum makinesinde bir sonraki duruma geçeceğini) belirleyen **clock** sinyalidir.
- Test mode select (**TMS**) input TMS, **sonlu durum makinesini** kontrol eder. Her clock vuruşunda cihazın JTAG TAP denetleyicisi, TMS pinindeki gerilimi kontrol eder. Gerilim belirli bir eşiğin altındaysa sinyal düşük kabul edilir ve 0 olarak yorumlanır; belirli bir eşiğin üzerindeyse sinyal yüksek kabul edilir ve 1 olarak yorumlanır.
- Test data input (**TDI**), seçili TAP register'ına seri talimat veya test verisi kaydırır. IEEE 1149.1, TAP aktarım davranışını tanımlarken üreticiler isteğe bağlı talimatları ve debug register'larını tanımlar.
- Test data output (**TDO**) TDO, **çipten veri gönderen** pindir.
- Test reset (**TRST**) input İsteğe bağlı TRST, sonlu durum makinesini **bilinen ve geçerli bir duruma** sıfırlar. Alternatif olarak, TMS beş ardışık clock döngüsü boyunca 1 seviyesinde tutulursa TRST pinindekiyle aynı şekilde reset işlemi başlatılır; bu nedenle TRST isteğe bağlıdır.

Bazen bu pinleri PCB üzerinde işaretlenmiş olarak bulabilirsiniz. Bazı durumlarda ise onları **bulmanız** gerekebilir.

### JTAG pinlerini belirleme

JTAG portlarını tespit etmek için hızlı, bu iş için özel olarak tasarlanmış ancak görece pahalı bir seçenek, UART pin dizilimlerini de belirleyebilen **JTAGulator**'dır.<sup>[[2]](#references)</sup>

Kart üzerindeki test noktalarına bağlanabilen **24 kanalı** vardır. Aday pin kombinasyonlarını **IDCODE** ve **BYPASS** taramalarıyla sıralar ve tespit edilen JTAG sinyallerine karşılık gelen kanalları bildirir.

JTAG pin dizilimlerini belirlemenin daha ucuz ama çok daha yavaş bir yolu, Arduino uyumlu bir mikrodenetleyiciye yüklenen [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) aracını kullanmaktır.

**JTAGenum** ile önce pinleri belirlemek için kullanılacak yoklama mikrodenetleyicisinin pinlerini tanımlayın. Pin dizilimine bakın, ardından bu pinleri hedef karttaki aday test noktalarına bağlayın.<sup>[[3]](#references)</sup>

JTAG pinlerini belirlemenin **üçüncü yolu**, bilinen bir footprint olup olmadığını görmek için **PCB'yi incelemektir**. Bazı kartlarda **Tag-Connect** footprint'i bulunur; ancak Tag-Connect, JTAG, SWD, UART veya başka bir arayüz taşıyabilen bir konektör sistemidir. Tek başına pinlerin JTAG olduğunu kanıtlamaz. Bileşen veri sayfaları ve süreklilik ölçümleri, gerçek sinyalleri belirlemenize yardımcı olabilir.<sup>[[5]](#references)</sup>

## SDW

SWD, Arm'ın iki pinli, paket tabanlı debug arayüzüdür.<sup>[[4]](#references)</sup>

Arayüzde veri için çift yönlü **SWDIO**, clock için **SWCLK** kullanılır. Birçok cihaz, paylaşılan pinlerde SWD ile JTAG arasında seçim yapılmasına olanak tanıyan bir **Serial Wire/JTAG Debug Port (SWJ-DP)** uygular.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 çalışma grubu — JTAG ve boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator belgeleri](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino ile JTAG pinlerini belirleme](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Çok cihazlı sistemler için düşük pin sayılı debug arayüzleri](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Debug ve programlama kablosu footprint'leri](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
