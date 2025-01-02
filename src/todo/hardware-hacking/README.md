# Donanım Hackleme

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG, bir sınır taraması gerçekleştirmeyi sağlar. Sınır taraması, gömülü sınır tarama hücreleri ve her pin için kayıtlar da dahil olmak üzere belirli devreleri analiz eder.

JTAG standardı, **sınır taramaları gerçekleştirmek için belirli komutlar** tanımlar, bunlar arasında şunlar bulunur:

- **BYPASS**, belirli bir çipi diğer çiplerden geçmeden test etmenizi sağlar.
- **SAMPLE/PRELOAD**, cihaz normal çalışma modundayken giren ve çıkan verilerin bir örneğini alır.
- **EXTEST**, pin durumlarını ayarlar ve okur.

Ayrıca aşağıdaki gibi diğer komutları da destekleyebilir:

- **IDCODE**, bir cihazı tanımlamak için
- **INTEST**, cihazın iç testleri için

JTAGulator gibi bir araç kullandığınızda bu talimatlarla karşılaşabilirsiniz.

### Test Erişim Noktası

Sınır taramaları, dört telli **Test Erişim Noktası (TAP)** testlerini içerir; bu, bir bileşene entegre edilmiş **JTAG test destek** işlevlerine erişim sağlayan genel amaçlı bir porttur. TAP, aşağıdaki beş sinyali kullanır:

- Test saat girişi (**TCK**) TCK, TAP denetleyicisinin tek bir eylem gerçekleştireceği sıklığı tanımlayan **saat**'tir (diğer bir deyişle, durum makinesinde bir sonraki duruma geçiş yapar).
- Test modu seçimi (**TMS**) girişi TMS, **sonlu durum makinesini** kontrol eder. Saatin her vuruşunda, cihazın JTAG TAP denetleyicisi TMS pinindeki voltajı kontrol eder. Voltaj belirli bir eşik değerinin altındaysa, sinyal düşük kabul edilir ve 0 olarak yorumlanır; voltaj belirli bir eşik değerinin üzerindeyse, sinyal yüksek kabul edilir ve 1 olarak yorumlanır.
- Test veri girişi (**TDI**) TDI, **veriyi çipe tarama hücreleri aracılığıyla gönderen** pindir. Her satıcı, bu pin üzerinden iletişim protokolünü tanımlamaktan sorumludur, çünkü JTAG bunu tanımlamaz.
- Test veri çıkışı (**TDO**) TDO, **veriyi çipten dışarı gönderen** pindir.
- Test sıfırlama (**TRST**) girişi Opsiyonel TRST, sonlu durum makinesini **bilinen iyi bir duruma** sıfırlar. Alternatif olarak, TMS beş ardışık saat döngüsü boyunca 1'de tutulursa, TRST pininin yaptığı gibi bir sıfırlama tetikler; bu nedenle TRST opsiyoneldir.

Bazen bu pinlerin PCB'de işaretlendiğini bulabilirsiniz. Diğer durumlarda, **bulmanız** gerekebilir.

### JTAG pinlerini tanımlama

JTAG portlarını tespit etmenin en hızlı ama en pahalı yolu, bu amaç için özel olarak oluşturulmuş bir cihaz olan **JTAGulator** kullanmaktır (bununla birlikte **UART pinout'larını da tespit edebilir**).

**24 kanala** sahiptir ve bu kanalları kartın pinlerine bağlayabilirsiniz. Ardından, **IDCODE** ve **BYPASS** sınır tarama komutlarını göndererek tüm olası kombinasyonların **BF saldırısını** gerçekleştirir. Bir yanıt alırsa, her JTAG sinyaline karşılık gelen kanalı görüntüler.

JTAG pinout'larını tanımlamanın daha ucuz ama çok daha yavaş bir yolu, bir Arduino uyumlu mikrodenetleyiciye yüklenmiş [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) kullanmaktır.

**JTAGenum** kullanarak, önce **numune alma** cihazının pinlerini tanımlamanız gerekir. Cihazın pinout diyagramına atıfta bulunmanız ve ardından bu pinleri hedef cihazınızdaki test noktalarıyla bağlamanız gerekir.

JTAG pinlerini tanımlamanın **üçüncü yolu**, PCB'yi bir pinout için **incelemektir**. Bazı durumlarda, PCB'ler **Tag-Connect arayüzünü** sağlama kolaylığı gösterebilir; bu, kartın bir JTAG konektörüne sahip olduğunun açık bir göstergesidir. O arayüzün nasıl göründüğünü [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/) adresinde görebilirsiniz. Ayrıca, PCB'deki çip setlerinin **veri sayfalarını** incelemek, JTAG arayüzlerine işaret eden pinout diyagramlarını ortaya çıkarabilir.

## SDW

SWD, hata ayıklama için tasarlanmış ARM'a özgü bir protokoldür.

SWD arayüzü, **iki pin** gerektirir: JTAG’ın **TDI ve TDO pinlerine** eşdeğer olan iki yönlü **SWDIO** sinyali ve **TCK**'ya eşdeğer olan **SWCLK**. Birçok cihaz, hedefe ya bir SWD ya da JTAG probu bağlamanızı sağlayan birleşik bir JTAG ve SWD arayüzü olan **Seri Tel veya JTAG Hata Ayıklama Portu (SWJ-DP)**'yi destekler.

{{#include ../../banners/hacktricks-training.md}}
