# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG, boundary scan gerçekleştirmeye olanak tanır. Boundary scan, her pin için gömülü boundary-scan hücreleri ve register'lar dahil olmak üzere belirli devreleri analiz eder.

JTAG standardı, **boundary scan gerçekleştirmek için belirli komutlar** tanımlar. Bunlar arasında şunlar bulunur:

- **BYPASS**, diğer chip'lerden geçme yükü olmadan belirli bir chip'i test etmenize olanak tanır.
- **SAMPLE/PRELOAD**, cihaz normal çalışma modundayken cihaza giren ve çıkan verilerin bir örneğini alır.
- **EXTEST**, pin durumlarını ayarlar ve okur.

Ayrıca şu komutlar gibi diğer komutları da destekleyebilir:

- Bir cihazı tanımlamak için **IDCODE**
- Cihazın dahili testi için **INTEST**

JTAGulator gibi bir araç kullandığınızda bu talimatlarla karşılaşabilirsiniz.

### Test Access Port

Boundary scan, genel amaçlı bir port olan dört telli **Test Access Port (TAP)** testlerini içerir. Bu port, bir bileşene yerleşik **JTAG test desteği** işlevlerine erişim sağlar. TAP aşağıdaki beş sinyali kullanır:

- Test clock input (**TCK**) TCK, TAP controller'ın tek bir eylemi ne sıklıkla gerçekleştireceğini, yani state machine'de bir sonraki duruma ne zaman geçeceğini tanımlayan **clock** sinyalidir.
- Test mode select (**TMS**) input TMS, **finite state machine**'i kontrol eder. Her clock vuruşunda cihazın JTAG TAP controller'ı TMS pinindeki voltajı kontrol eder. Voltaj belirli bir eşik değerinin altındaysa sinyal low kabul edilir ve 0 olarak yorumlanır; voltaj belirli bir eşik değerinin üzerindeyse sinyal high kabul edilir ve 1 olarak yorumlanır.
- Test data input (**TDI**) TDI, **scan cells üzerinden chip'e veri gönderen** pindir. JTAG bunu tanımlamadığından her vendor bu pin üzerinden iletişim protokolünü tanımlamaktan sorumludur.
- Test data output (**TDO**) TDO, **chip'ten veri gönderen** pindir.
- Test reset (**TRST**) input İsteğe bağlı TRST, finite state machine'i **bilinen ve düzgün bir duruma** sıfırlar. Alternatif olarak TMS beş ardışık clock cycle boyunca 1 seviyesinde tutulursa, TRST pininin yapacağı şekilde reset işlemini başlatır; TRST'nin isteğe bağlı olmasının nedeni budur.

Bazen bu pinleri PCB üzerinde işaretlenmiş olarak bulabilirsiniz. Diğer durumlarda ise bunları **bulmanız** gerekebilir.

### Identifying JTAG pins

JTAG portlarını tespit etmenin en hızlı, ancak en pahalı yolu, özellikle bu amaç için oluşturulmuş bir cihaz olan **JTAGulator** kullanmaktır (ancak **UART pinout'larını da tespit edebilir**).

Cihazda, board pinlerine bağlayabileceğiniz **24 kanal** bulunur. Ardından **IDCODE** ve **BYPASS** boundary scan komutlarını göndererek tüm olası kombinasyonlar üzerinde bir **BF attack** gerçekleştirir. Bir yanıt alırsa her JTAG sinyaline karşılık gelen kanalı görüntüler.

JTAG pinout'larını belirlemenin daha ucuz ancak çok daha yavaş bir yolu, Arduino uyumlu bir microcontroller üzerine yüklenen [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) kullanmaktır.

**JTAGenum** kullanırken öncelikle enumeration için kullanacağınız **probing** cihazının pinlerini tanımlamanız gerekir. Cihazın pinout şemasına başvurmanız ve ardından bu pinleri hedef cihazınızdaki test noktalarına bağlamanız gerekir.

JTAG pinlerini belirlemenin **üçüncü yolu**, pinout'lardan birini bulmak için **PCB'yi incelemektir**. Bazı durumlarda PCB'ler, board'un bir JTAG connector'ına da sahip olduğunun açık bir göstergesi olan **Tag-Connect interface**'ini uygun şekilde sunabilir. Bu interface'in nasıl göründüğünü [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/) adresinde görebilirsiniz. Ayrıca, **PCB üzerindeki chipset'lerin datasheet'lerini incelemek**, JTAG interface'lerine işaret eden pinout şemalarını ortaya çıkarabilir.

## SDW

SWD, debugging için tasarlanmış ARM'e özgü bir protokoldür.

SWD interface'i **iki pin** gerektirir: JTAG'in **TDI ve TDO pinleri ile bir clock** sinyaline eşdeğer olan çift yönlü **SWDIO** sinyali ve JTAG'deki **TCK**'ye eşdeğer olan **SWCLK**. Birçok cihaz, hedefe SWD veya JTAG probe'larından birini bağlamanızı sağlayan, JTAG ve SWD'yi birleştiren **Serial Wire or JTAG Debug Port (SWJ-DP)**'yi destekler.

{{#include ../../banners/hacktricks-training.md}}
