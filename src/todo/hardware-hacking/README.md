# Donanım Hacking'i

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG (IEEE 1149.1), bir cihazın I/O pinlerinin çevresine yerleştirilen hücreler aracılığıyla boundary-scan testini destekler. Birçok işlemci, aynı Test Access Port (TAP) üzerinden üreticiye özgü debug işlevleri de sunar; boundary scan ve CPU debugging, JTAG'in birbiriyle ilişkili kullanımlarıdır ancak eş anlamlı değildir.<sup>[[1]](#references)</sup>

JTAG standardı, **boundary scan gerçekleştirmek için özel komutlar** tanımlar. Bunlar şunları içerir:

- **BYPASS**, bir scan chain içindeki diğer cihazlara minimum ek yükle erişilebilmesi için tek bitlik bir bypass register seçer.
- **SAMPLE/PRELOAD**, normal çalışma sırasında pin değerlerini yakalar ve başka bir instruction'dan önce boundary-scan register'ını önceden yükleyebilir.
- **EXTEST**, pin durumlarını ayarlar ve okur.

Ayrıca şu komutları da destekleyebilir:

- Bir cihazı tanımlamak için **IDCODE**
- Cihazın dahili testi için **INTEST**

JTAGulator gibi bir araç kullandığınızda bu instruction'larla karşılaşabilirsiniz.

### Test Access Port

**Test Access Port (TAP)**, bir bileşenin JTAG test logic'ine erişim sağlar. Dört sinyal gereklidir ve `TRST` isteğe bağlıdır:<sup>[[1]](#references)</sup>

- Test clock input (**TCK**) TCK, TAP controller'ın tek bir action'ı ne sıklıkta gerçekleştireceğini, başka bir deyişle state machine'de bir sonraki state'e ne zaman geçeceğini belirleyen **clock** sinyalidir.
- Test mode select (**TMS**) input TMS, **finite state machine**'i kontrol eder. Her clock çevriminde cihazın JTAG TAP controller'ı, TMS pinindeki gerilimi kontrol eder. Gerilim belirli bir eşikten düşükse sinyal low kabul edilir ve 0 olarak yorumlanır; belirli bir eşikten yüksekse sinyal high kabul edilir ve 1 olarak yorumlanır.
- Test data input (**TDI**), seri instruction'ı veya test verisini seçili TAP register'ına kaydırır. IEEE 1149.1, TAP transfer davranışını tanımlar; vendor'lar ise optional instruction'ları ve debug register'larını tanımlar.
- Test data output (**TDO**) TDO, **chip'ten dışarı data gönderen** pindir.
- Test reset (**TRST**) input İsteğe bağlı TRST, finite state machine'i **bilinen ve güvenli bir state'e** sıfırlar. Alternatif olarak TMS beş ardışık clock çevrimi boyunca 1 seviyesinde tutulursa reset tetiklenir; bu işlem TRST pininin yaptığıyla aynıdır. Bu nedenle TRST isteğe bağlıdır.

Bazen bu pinleri PCB üzerinde işaretlenmiş olarak bulabilirsiniz. Diğer durumlarda ise onları **bulmanız** gerekebilir.

### JTAG pinlerini tanımlama

JTAG portlarını tespit etmek için hızlı, amaca özel ancak nispeten pahalı bir seçenek, UART pinout'larını da tanımlayabilen **JTAGulator**'dır.<sup>[[2]](#references)</sup>

Cihazda, board üzerindeki test noktalarına bağlanabilen **24 kanal** bulunur. **IDCODE** ve **BYPASS** scan'lerini kullanarak aday pin kombinasyonlarını sıralar ve tespit edilen JTAG sinyallerine karşılık gelen kanalları bildirir.

JTAG pinout'larını tanımlamanın daha ucuz ancak çok daha yavaş bir yolu, Arduino uyumlu bir microcontroller'a yüklenen [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) aracını kullanmaktır.

**JTAGenum** ile önce enumeration için kullanılacak probing microcontroller pinlerini tanımlayın. Pinout'una bakın, ardından bu pinleri hedef board üzerindeki aday test noktalarına bağlayın.<sup>[[3]](#references)</sup>

JTAG pinlerini tanımlamanın **üçüncü yolu**, bilinen bir footprint için **PCB'yi incelemektir**. Bazı board'lar **Tag-Connect** footprint'i sunar. Ancak Tag-Connect, JTAG, SWD, UART veya başka bir interface taşıyabilen bir connector system'dir; tek başına pinlerin JTAG olduğunu kanıtlamaz. Component datasheet'leri ve continuity ölçümleri, gerçek sinyallerin tanımlanmasını sağlar.<sup>[[5]](#references)</sup>

## SDW

SWD, Arm'ın iki pinli, packet tabanlı debug interface'idir.<sup>[[4]](#references)</sup>

Interface, data için çift yönlü **SWDIO** ve clock için **SWCLK** kullanır. Birçok cihaz, ortak pinler üzerinden SWD ve JTAG arasında seçim yapılmasına olanak tanıyan bir **Serial Wire/JTAG Debug Port (SWJ-DP)** uygular.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 çalışma grubu — JTAG ve boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator dokümantasyonu](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAG pin enumeration](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Çok cihazlı sistemler için düşük pin sayılı debug interface'leri](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Debug ve programming cable footprint'leri](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
