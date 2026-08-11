# UART

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

UART, ortak bir saat sinyali olmadan çerçevelenmiş bir bit akışını aktaran asenkron bir seri interface'tir. Logic-level UART'ı RS-232 ile karıştırmayın: RS-232 farklı, çoğunlukla negatif voltaj seviyeleri kullanır ve bir transceiver gerektirir.<sup>[[1]](#references)[[3]](#references)</sup>

Genellikle UART idle durumundayken hat yüksek seviyede (mantıksal 1 değerinde) tutulur. Ardından bir data transferinin başladığını belirtmek için transmitter, receiver'a bir start bit gönderir; bu sırada sinyal düşük seviyede (mantıksal 0 değerinde) tutulur. Sonra transmitter, gerçek mesajı içeren beş ila sekiz data bitini gönderir; bunu configuration'a bağlı olarak isteğe bağlı bir parity biti ve bir veya iki stop biti (mantıksal 1 değerinde) izler. Error checking için kullanılan parity biti pratikte nadiren görülür. Stop biti (veya bitleri), transmission'ın sonunu belirtir.

En yaygın configuration 8N1'dir: sekiz data biti, parity yok ve bir stop biti. UART, en düşük anlamlı data bitini önce gönderir; bu nedenle ASCII `C` (`0x43`) 8N1'de şu şekilde iletilir: start `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: En yaygın configuration'a 8N1 diyoruz: sekiz data biti, parity yok ve bir stop biti. Örneğin ASCII'de C karakterini veya 0x43'ü göndermek isteseydik, bu 8N1 UART'ta](<../../images/image (764).png>)

UART ile iletişim kurmak için hardware araçları:

- USB-to-serial adapter
- CP2102 veya PL2303 chip'lerine sahip adapter'lar
- Bus Pirate, Adafruit FT232H, Shikra veya Attify Badge gibi multipurpose tool

### UART Ports'larını Belirleme

Tipik bir debug header'ı **TX**, **RX** ve **GND** pinlerini sunar; ayrıca bir **Vcc/Vref** pini, reset veya flow-control pinleri de bulunabilir. Vcc bir UART sinyali değildir ve normalde yalnızca bir voltage reference olarak kullanılmalıdır; board'un schematic'i ve current gereksinimleri bilinmiyorsa power source olarak bağlanmamalıdır.<sup>[[2]](#references)[[3]](#references)</sup>

Cihaz **power off** durumundayken ve bağlantısı kesilmiş halde başlayın:

- Bilinen bir ground plane, connector shield veya supply ground'a karşı continuity mode kullanarak **GND**'yi belirleyin. Power verilmiş bir board'da continuity/resistance mode'u asla kullanmayın.
- Target'a power vermeden önce DC-voltage mode'a geçin. Logic voltage'ı belirlemek için aday pinleri ground'a göre ölçün. Sabit bir rail Vcc/Vref olabilir; bağlamanın güvenli olduğunu varsaymayın.
- Boot sırasında aday pinleri logic analyzer veya oscilloscope ile gözlemleyin. **TX** genellikle idle durumunda high olur ve framed data burst'leri gösterir. Multimeter ortalama bir dalgalanma gösterebilir ancak framing veya baud rate'i doğrulayamaz.
- **RX** idle durumda kalabilir ve yalnızca TX'e bitişik olduğu için güvenli şekilde belirlenemez. PCB'yi izleyin, SoC datasheet'ine başvurun veya onu sürmeden önce high-impedance analyzer kullanın.

TX ve RX'in yerlerini değiştirmek normalde iletişim kurulmasını engeller; power, ground veya signal level'larını karıştırmak target'a ya da adapter'a kalıcı hasar verebilir. Önce ground'u bağlayın ve **receive-only** olarak başlayın (target TX'i adapter RX'e bağlayın).

Manufacturer'lar header'ı kaldırabilir, series resistor'larını takılmamış bırakabilir, console'u firmware'de devre dışı bırakabilir veya yalnızca TX'i dışarı çıkarabilir. Yakındaki test pad'lerini ve resistor footprint'lerini SoC'ye kadar izleyin ve yalnızca electrical level'ı doğruladıktan sonra geçici bir high-impedance bağlantı ekleyin. Bir warranty'nin mevcut olması, erişilebilir bir UART'ın bulunması gerektiği anlamına gelmez.

### UART Baud Rate'ini Belirleme

Doğru baud rate'i belirlemenin en kolay yolu **TX pin'inin output'unu incelemek ve data'yı okumayı denemektir**. Aldığınız data okunabilir değilse, data okunabilir hale gelene kadar bir sonraki olası baud rate'e geçin. Bunu bir USB-to-serial adapter veya Bus Pirate gibi bir multipurpose device ve [baudrate.py](https://github.com/devttys0/baudrate/) gibi bir helper script ile yapabilirsiniz. En yaygın baud rate'ler 9600, 38400, 19200, 57600 ve 115200'dür.

> [!CAUTION]
> Bu protocol'de bir device'ın TX'ini diğer device'ın RX'ine bağlamanız gerektiğini unutmayın!

## CP210X UART to TTY Adapter

CP210x USB-to-UART bridge'leri birçok prototyping board'unda ve ucuz adapter'larda bulunur. Yaygın module'ler GND, RXD ve TXD'nin yanında supply pin'lerini de dışarı çıkarır, ancak header'ları ve I/O level'ları değişiklik gösterir. Gerçek voltage'ı board design'ından veya data sheet'ten doğrulayın. Genellikle yalnızca GND'yi, adapter RX'i target TX'e ve receive-only validation'dan sonra adapter TX'i target RX'e bağlayın. Adapter'ın 5 V/3.3 V supply pin'ini, bunu bilerek power verdiğiniz ve target'ın bu voltage'ı tolere ettiği doğrulanmadıkça bağlamayın.<sup>[[3]](#references)</sup>

Adapter algılanmıyorsa CP210X driver'larının host system'e kurulu olduğundan emin olun. Adapter algılanıp bağlandıktan sonra picocom, minicom veya screen gibi tool'lar kullanılabilir.

Linux/MacOS system'lerine bağlı device'ları listelemek için:
```
ls /dev/
```
UART arayüzüyle temel etkileşim için aşağıdaki komutu kullanın:
```
picocom /dev/<adapter> --baud <baudrate>
```
minicom için yapılandırmak üzere aşağıdaki komutu kullanın:
```
minicom -s
```
`Serial port setup` seçeneğinde baudrate ve cihaz adı gibi ayarları yapılandırın.

Yapılandırmadan sonra UART konsolunu açmak için `minicom` çalıştırın.

## UART Arduino UNO R3 Üzerinden (Çıkarılabilir Atmel 328p Chip Kartları)

UART Serial to USB adapter'ları mevcut değilse Arduino UNO R3 hızlı bir hack ile kullanılabilir. Arduino UNO R3 genellikle her yerde bulunabildiğinden bu, zamandan büyük ölçüde tasarruf sağlayabilir.

Arduino UNO R3'ün kart üzerinde yerleşik bir USB to Serial adapter'ı vardır. UART bağlantısı elde etmek için Atmel 328p microcontroller chip'ini karttan çıkarın. Bu hack, Atmel 328p'nin karta lehimlenmediği Arduino UNO R3 varyantlarında çalışır (bu modelde SMD version kullanılır). Arduino'nun RX pinini (Digital Pin 0) UART Interface'inin TX pinine, Arduino'nun TX pinini (Digital Pin 1) ise UART interface'inin RX pinine bağlayın.

Arduino IDE'deki **Serial Monitor**'u veya hedef baud rate'te çalışan özel bir terminali kullanın. Classic Uno R3 serial sinyalleri 5 V logic seviyesindedir; bu nedenle bunları 3.3 V veya daha düşük voltajlı bir hedefe bağlamadan önce level shifter ya da divider kullanın.

## Bus Pirate

Aşağıdaki transcript, UART output'u izlemek için legacy Bus Pirate firmware interface'ini kullanır. Daha yeni Bus Pirate firmware sürümleri `m uart`, `{`/`}`, `monitor` veya `bridge` gibi komutları kullanır; yüklü sürümün documentation'ına başvurun.<sup>[[2]](#references)</sup>
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
## UART Konsolu ile Firmware Dump Alma

Bir UART konsolu, önyükleme günlüklerine ve bazen bir bootloader'a veya işletim sistemi shell'ine çalışma zamanı erişimi sağlar. Salt okunur bir konsol bile bellek eşlemelerini, flash sürücülerini, boot argümanlarını, partition düzenlerini ve firmware sürümlerini ortaya çıkarabilir. Firmware SPI NOR/NAND, eMMC veya başka bir cihazda bulunabilir; genellikle bir EEPROM'dan yürütülmez ve bağlı kalıcı bir dosya sistemine yazılan dosyalar yeniden başlatma sonrasında mutlaka kaybolmaz.

Birkaç acquisition yöntemi vardır ve SPI bölümü harici flash'tan doğrudan okumaları kapsar. Bootloader zaten güvenli bir okuma komutu sağlıyorsa console-assisted acquisition daha az müdahaleci olabilir; ancak herhangi bir boot kesintisi veya flash komutu kullanılabilirliği etkileyebilir. Bu nedenle özgün durumu kaydedin ve yazma/silme işlemlerinden kaçının.

Console-assisted firmware dumping genellikle bir bootloader'ın kesilmesiyle başlar. Gömülü Linux cihazlarının çoğu **Das U-Boot** kullanır, ancak diğerleri proprietary bootloader kullanabilir veya interactive console'u devre dışı bırakabilir.

Interactive bootloader'ı test etmek için hedef cihaz kapalıyken UART receive path'i ve terminali bağlayın, logging'i başlatın ve cihazı açın. Görüntülenen autoboot prompt'unu takip edin; kullanılan build'e bağlı olarak kesme işlemi bir tuş, kısa bir dizi gerektirebilir veya tamamen devre dışı bırakılmış olabilir.

Kesme başarılı olursa, adreslere erişmeden önce ilgili vendor'ın memory ve storage layout'unu anlamak için `help`, `printenv` ve salt okunur discovery komutlarını kullanın.

U-Boot'ta `md`, otomatik olarak “EEPROM”u değil, **adreslenebilir belleği** görüntüler. Önce doğru eşlenmiş adresi belirlemek veya bir flash bölgesini RAM'e yüklemek için `mtd list`, `sf probe`, `mmc info`, `part list`, environment variables ve boot logs gibi board-specific komutları kullanın. Ardından bilinen bir aralığı byte-by-byte görüntüleyin:<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
Başlamadan önce seri çıkışı kaydedin. `md.b` çıktısı adresleri ve bir ASCII sütununu içerir; bu nedenle ham bir ROM görüntüsü değil, metinsel bir gösterimdir.

Adres ve ASCII sütunlarını kaldırın, yalnızca onaltılık bayt alanlarını birleştirin ve bunları ikili veriye dönüştürün (örneğin `xxd -r -p` ile). Analizden önce beklenen bayt sayısını doğrulayın ve bir hash kaydedin:
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Binwalk daha sonra yeniden oluşturulan binary içindeki bilinen imzaları tanımlar. Konsol verileri güvenilir şekilde aktaramadığında, uygun SPI/eMMC/NAND arayüzü üzerinden doğrudan flash okuması genellikle daha hızlıdır ve hataya daha az açıktır.

U-Boot kesmeyi devre dışı bırakabilir, üreticiye özgü bir tuş dizisi gerektirebilir veya memory/flash komutlarını kilitleyebilir. Karakterleri körü körüne göndermek yerine autoboot istemini ve boot logunu izleyin. Konsola müdahale edilemiyorsa boot logunu saklayın ve non-invasive bir firmware acquisition yöntemine geçin.

## References

- [1] [Microchip PIC32 Family Reference Manual - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate documentation - UART mode and electrical limits](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C data sheet](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot documentation - `md` memory-display command](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
