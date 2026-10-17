# Donanım Hacking

{{#include ../../banners/hacktricks-training.md}}

Bir cihaza fiziksel erişiminiz varsa, kartının veya sinyallerinin sunduğu arayüzlerle başlayın: [UART serial consoles](uart.md), [JTAG/SWD debug access](jtag.md), [CoreSight instruction tracing](arm-coresight-instruction-tracing.md), [I²C](i2c.md) ve [SPI flash](spi.md) bus'ları. [Side-channel analysis](side_channel_analysis.md) ve [fault injection](fault_injection_attacks.md), farklı ölçüm ve glitching görevlerini ele alır; [radio signal analysis](radio.md) ise kablosuz bir giriş noktası sunar. Hedefe özgü RFID/NFC, sub-GHz, infrared, BLE, LoRaWAN ve iButton prosedürleri için [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md) sayfasına bakın. Araçları bağlamadan önce hedefin elektrik seviyelerini ve ilgili bölümdeki kısıtlamaları kontrol edin.

## JTAG

JTAG (IEEE 1149.1), bir cihazın I/O pinlerinin çevresine yerleştirilmiş hücreler aracılığıyla boundary-scan testini destekler. Birçok işlemci, aynı Test Access Port (TAP) üzerinden üreticiye özgü debug işlevleri de sunar; boundary scan ve CPU debugging, JTAG'ın birbiriyle ilişkili kullanımlarıdır ancak eş anlamlı değildir.<sup>[[1]](#references)</sup>

JTAG standardı, **boundary scan gerçekleştirmeye yönelik belirli komutlar** tanımlar. Bunlar arasında şunlar bulunur:

- **BYPASS**, bir scan chain'deki diğer cihazlara en az ek yükle erişmek için tek bitlik bir bypass register seçer.
- **SAMPLE/PRELOAD**, normal çalışma sırasında pin değerlerini yakalar ve başka bir instruction'dan önce boundary-scan register'ına önceden değer yükleyebilir.
- **EXTEST**, pin durumlarını ayarlar ve okur.

Ayrıca aşağıdaki gibi başka komutları da destekleyebilir:

- Bir cihazı tanımlamak için **IDCODE**
- Cihazın dahili testi için **INTEST**

JTAGulator gibi bir araç kullandığınızda bu instruction'larla karşılaşabilirsiniz.

### Test Access Port

**Test Access Port (TAP)**, bir bileşenin JTAG test mantığına erişim sağlar. Dört sinyal gereklidir; `TRST` ise isteğe bağlıdır:<sup>[[1]](#references)</sup>

- Test clock input (**TCK**) TCK, TAP denetleyicisinin ne sıklıkta tek bir işlem gerçekleştireceğini (başka bir deyişle, durum makinesinde bir sonraki duruma geçeceğini) belirleyen **clock** sinyalidir.
- Test mode select (**TMS**) input TMS, **sonlu durum makinesini** kontrol eder. Her clock vuruşunda cihazın JTAG TAP denetleyicisi, TMS pinindeki voltajı kontrol eder. Voltaj belirli bir eşiğin altındaysa sinyal düşük kabul edilip 0 olarak yorumlanır; belirli bir eşiğin üzerindeyse yüksek kabul edilip 1 olarak yorumlanır.
- Test data input (**TDI**), seri instruction veya test verisini seçili TAP register'ına kaydırır. IEEE 1149.1, TAP veri aktarım davranışını tanımlarken üreticiler isteğe bağlı instruction'ları ve debug register'larını tanımlar.
- Test data output (**TDO**) **çipten veri gönderen** pindir.
- Test reset (**TRST**) input İsteğe bağlı TRST, sonlu durum makinesini **bilinen ve geçerli bir duruma** sıfırlar. Alternatif olarak TMS beş ardışık clock döngüsü boyunca 1'de tutulursa sıfırlama gerçekleşir; TRST pini de aynı işlemi yaptığından isteğe bağlıdır.

Bazen bu pinleri PCB üzerinde işaretlenmiş olarak bulabilirsiniz. Bazı durumlarda ise onları **bulmanız** gerekebilir.

### JTAG pinlerini belirleme

JTAG portlarını tespit etmek için hızlı, bu iş için tasarlanmış ancak görece pahalı bir seçenek **JTAGulator**'dır. Bu araç UART pin dizilimlerini de belirleyebilir.<sup>[[2]](#references)</sup>

Kart üzerindeki test noktalarına bağlanabilen **24 kanalı** vardır. **IDCODE** ve **BYPASS** taramalarıyla olası pin kombinasyonlarını dener ve tespit edilen JTAG sinyallerine karşılık gelen kanalları bildirir.

JTAG pin dizilimlerini belirlemenin daha ucuz ama çok daha yavaş bir yolu, Arduino uyumlu bir mikrodenetleyiciye yüklenen [**JTAGenum**](https://github.com/cyphunk/JTAGenum) aracını kullanmaktır.

**JTAGenum** kullanırken önce tarama için kullanılacak mikrodenetleyici pinlerini belirleyin. Pin dizilimine bakın, ardından bu pinleri hedef karttaki olası test noktalarına bağlayın.<sup>[[3]](#references)</sup>

JTAG pinlerini belirlemenin **üçüncü yolu**, PCB'de bilinen bir footprint olup olmadığını **incelemektir**. Bazı kartlarda **Tag-Connect** footprint'i bulunur. Ancak Tag-Connect, JTAG, SWD, UART veya başka bir arayüz taşıyabilen bir konektör sistemidir; tek başına pinlerin JTAG olduğunu kanıtlamaz. Bileşen veri sayfaları ve süreklilik ölçümleri, gerçek sinyalleri belirlemenize yardımcı olabilir.<sup>[[5]](#references)</sup>

## SDW

SWD, Arm'ın iki pinli, paket tabanlı debug arayüzüdür.<sup>[[4]](#references)</sup>

Arayüz, veri için çift yönlü **SWDIO**, clock içinse **SWCLK** kullanır. Birçok cihaz, paylaşılan pinlerde SWD ile JTAG arasında seçim yapılmasını sağlayan bir **Serial Wire/JTAG Debug Port (SWJ-DP)** uygular.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 çalışma grubu — JTAG ve boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator belgeleri](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAG pinlerini belirleme](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Çok cihazlı sistemler için düşük pin sayılı debug arayüzleri](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Debug ve programlama kablosu footprint'leri](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
