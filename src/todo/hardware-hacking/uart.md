# UART

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

UART bir serial protocol'dür; yani verileri bileşenler arasında her seferinde bir bit olacak şekilde aktarır. Bunun aksine, parallel communication protocol'leri verileri birden fazla kanal üzerinden eş zamanlı olarak iletir. Yaygın serial protocol'ler arasında RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express ve USB bulunur.

Genellikle UART idle durumundayken hat high (mantıksal 1 değerinde) tutulur. Ardından bir data transfer'ının başladığını belirtmek için transmitter receiver'a bir start bit gönderir ve bu sırada sinyal low (mantıksal 0 değerinde) tutulur. Sonra transmitter, gerçek mesajı içeren beş ila sekiz data bit'i gönderir; bunu configuration'a bağlı olarak isteğe bağlı bir parity bit'i ve bir veya iki stop bit'i (mantıksal 1 değerinde) izler. Error checking için kullanılan parity bit'i pratikte nadiren görülür. Stop bit'i (veya bit'leri) transmission'ın sonunu belirtir.

En yaygın configuration'a 8N1 adını veririz: sekiz data bit'i, parity yok ve bir stop bit'i. Örneğin, C karakterini veya ASCII'de 0x43'ü 8N1 UART configuration'ında göndermek isteseydik, şu bit'leri gönderirdik: 0 (start bit'i); 0, 1, 0, 0, 0, 0, 1, 1 (binary biçimde 0x43 değeri) ve 0 (stop bit'i).

![UART: En yaygın configuration'a 8N1 adını veririz: sekiz data bit'i, parity yok ve bir stop bit'i. Örneğin, C karakterini veya ASCII'de 0x43'ü 8N1 UART](<../../images/image (764).png>) configuration'ında göndermek isteseydik

UART ile iletişim kurmak için hardware araçları:

- USB-to-serial adapter
- CP2102 veya PL2303 chip'lerine sahip adapter'lar
- Bus Pirate, Adafruit FT232H, Shikra veya Attify Badge gibi multipurpose tool

### UART Port'larını Belirleme

UART'ın 4 port'u vardır: **TX** (Transmit), **RX** (Receive), **Vcc** (Voltage) ve **GND** (Ground). PCB üzerinde **`TX`** ve **`RX`** harfleri **yazılı** şekilde 4 port bulabilirsiniz. Ancak herhangi bir indication yoksa, bunları bir **multimeter** veya **logic analyzer** kullanarak kendiniz bulmanız gerekebilir.

Cihaz kapalıyken bir **multimeter** ile:

- **GND** pin'ini belirlemek için **Continuity Test** mode'unu kullanın; siyah probu ground'a bağlayın ve multimeter'dan bir ses duyana kadar kırmızı probla test edin. PCB üzerinde birden fazla GND pin'i bulunabilir; bu nedenle UART'a ait olanı bulmuş veya bulamamış olabilirsiniz.
- **VCC port'unu** belirlemek için **DC voltage mode**'unu seçin ve voltage'u 20 V'a ayarlayın. Siyah prob ground üzerinde, kırmızı prob pin üzerinde olmalıdır. Cihaza güç verin. Multimeter sabit olarak 3.3 V veya 5 V ölçerse Vcc pin'ini bulmuşsunuzdur. Başka voltage'lar alırsanız diğer port'larla tekrar deneyin.
- **TX** **port'unu** belirlemek için **DC voltage mode**'unda voltage'u 20 V'a kadar ayarlayın; siyah prob ground üzerinde, kırmızı prob pin üzerinde olmalı ve cihaza güç verilmelidir. Voltage'un birkaç saniye boyunca fluctuating yaptığını ve ardından Vcc değerinde stabilize olduğunu görürseniz büyük olasılıkla TX port'unu bulmuşsunuzdur. Bunun nedeni, cihaz açılırken bazı debug data'ları göndermesidir.
- **RX port'u**, diğer 3 port'a en yakın olan port'tur; en düşük voltage fluctuation'ına ve tüm UART pin'leri arasındaki en düşük overall değere sahiptir.

TX ve RX port'larını karıştırabilirsiniz; hiçbir şey olmaz. Ancak GND ve VCC port'unu karıştırırsanız circuit'ü yakabilirsiniz.

Bazı target cihazlarda UART port'u, manufacturer tarafından RX veya TX'in ya da her ikisinin disable edilmesiyle devre dışı bırakılmıştır. Bu durumda circuit board üzerindeki bağlantıları trace etmek ve bir breakout point bulmak faydalı olabilir. UART'ın detection edilmediğini ve circuit'in kırıldığını doğrulamaya yönelik güçlü bir ipucu, cihaz warranty'sini kontrol etmektir. Cihaz bir warranty ile gönderilmişse manufacturer bazı debug interface'lerini (bu durumda UART) bırakır ve bu nedenle debug sırasında UART'ı tekrar bağlayabilmek için bağlantısını kesmiş olmalıdır. Bu breakout pin'leri soldering veya jumper wire'lar kullanılarak bağlanabilir.

### UART Baud Rate'ini Belirleme

Doğru baud rate'i belirlemenin en kolay yolu **TX pin'inin output'una bakmak ve data'yı okumayı denemektir**. Aldığınız data okunabilir değilse, data okunabilir hale gelene kadar sıradaki olası baud rate'e geçin. Bunu bir USB-to-serial adapter veya Bus Pirate gibi bir multipurpose device ve [baudrate.py](https://github.com/devttys0/baudrate/) gibi bir helper script ile birlikte kullanabilirsiniz. En yaygın baud rate'ler 9600, 38400, 19200, 57600 ve 115200'dür.

> [!CAUTION]
> Bu protocol'de bir cihazın TX'ini diğer cihazın RX'ine bağlamanız gerektiğini unutmamak önemlidir!

## CP210X UART to TTY Adapter

CP210X Chip, Serial Communication için NodeMCU (esp8266 ile) gibi birçok prototyping board'unda kullanılır. Bu adapter'lar nispeten ucuzdur ve target'ın UART interface'ine bağlanmak için kullanılabilir. Cihazın 5 pin'i vardır: 5V, GND, RXD, TXD, 3.3V. Herhangi bir damage'ı önlemek için voltage'u target tarafından desteklenen değere bağladığınızdan emin olun. Son olarak Adapter'ın RXD pin'ini target'ın TXD'sine, Adapter'ın TXD pin'ini de target'ın RXD'sine bağlayın.

Adapter detection edilmiyorsa CP210X driver'larının host system'a kurulu olduğundan emin olun. Adapter detection edilip bağlandıktan sonra picocom, minicom veya screen gibi tool'lar kullanılabilir.

Linux/MacOS system'lerine bağlı cihazları listelemek için:
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

Yapılandırmadan sonra UART Console'u başlatmak için `minicom` komutunu kullanın.

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

UART Serial to USB adapterleri mevcut değilse Arduino UNO R3 hızlı bir hack ile kullanılabilir. Arduino UNO R3 genellikle her yerde bulunabildiğinden bu yöntem çok zaman kazandırabilir.

Arduino UNO R3'ün kendi kartı üzerinde yerleşik bir USB to Serial adapter bulunur. UART bağlantısı elde etmek için Atmel 328p microcontroller chip'ini karttan çıkarmanız yeterlidir. Bu hack, Atmel 328p'nin karta lehimlenmediği Arduino UNO R3 varyantlarında çalışır (SMD version kullanılır). Arduino'nun RX pinini (Digital Pin 0) UART Interface'in TX pinine, Arduino'nun TX pinini (Digital Pin 1) ise UART interface'in RX pinine bağlayın.

Son olarak, Serial Console'u kullanmak için Arduino IDE kullanılması önerilir. Menüdeki `tools` bölümünden `Serial Console` seçeneğini seçin ve baud rate'i UART interface'e göre ayarlayın.

## Bus Pirate

Bu senaryoda, programın tüm çıktısını Serial Monitor'a gönderen Arduino'nun UART iletişimini sniff edeceğiz.
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
## UART Console ile Firmware Dump Etme

UART Console, runtime environment içinde underlying firmware ile çalışmak için harika bir yöntem sunar. Ancak UART Console erişimi read-only olduğunda, birçok kısıtlamaya yol açabilir. Birçok embedded device'ta firmware, EEPROM'larda depolanır ve volatile memory'ye sahip processor'larda çalıştırılır. Bu nedenle firmware read-only tutulur; çünkü üretim sırasında kullanılan original firmware EEPROM'un kendisindedir ve volatile memory nedeniyle yeni dosyalar kaybolur. Bu yüzden embedded firmware'lerle çalışırken firmware dump etmek değerli bir işlemdir.

Bunu yapmanın birçok yolu vardır ve SPI bölümü, çeşitli cihazlarla firmware'i doğrudan EEPROM'dan extract etme yöntemlerini kapsar. Ancak firmware'i fiziksel cihazlar ve external interactions kullanarak dump etmek riskli olabileceğinden, öncelikle UART ile firmware dump etmeyi denemeniz önerilir.

UART Console'dan firmware dump etmek için öncelikle bootloader'lara erişim sağlamak gerekir. Birçok popüler vendor, Linux'u yüklemek için bootloader olarak uboot (Universal Bootloader) kullanır. Bu nedenle uboot'a erişim sağlamak gereklidir.

boot bootloader'a erişmek için UART portunu computer'a bağlayın, Serial Console araçlarından herhangi birini kullanın ve device'a giden power supply bağlantısını kesik tutun. Kurulum hazır olduğunda Enter Key'e basılı tutun. Son olarak device'a power supply bağlantısını yapın ve boot etmesini bekleyin.

Bunu yapmak, uboot'un yüklenmesini interrupt edecek ve bir menu sunacaktır. uboot command'lerini anlamanız ve bunları listelemek için help menu'sünü kullanmanız önerilir. Bu, `help` command'i olabilir. Farklı vendor'lar farklı configuration'lar kullandığından, her birini ayrı ayrı anlamak gerekir.

Genellikle firmware dump etmek için kullanılan command şudur:
```
md
```
bu, "memory dump" anlamına gelir. Bu işlem belleği (EEPROM Content) ekrana döker. Memory dump işlemini yakalamak için prosedüre başlamadan önce Serial Console çıktısını günlüğe kaydetmeniz önerilir.

Son olarak, log dosyasındaki tüm gereksiz verileri ayıklayın, dosyayı `filename.rom` olarak kaydedin ve içeriği çıkarmak için binwalk kullanın:
```
binwalk -e <filename.rom>
```
Bu, hex dosyasında bulunan imzalara göre EEPROM'un olası içeriklerini listeleyecektir.

Bununla birlikte, kullanılıyor olsa bile uboot'un her zaman unlocked olmayabileceğini belirtmek gerekir. Enter Key herhangi bir işlem yapmıyorsa Space Key vb. farklı tuşları deneyin. Bootloader locked durumdaysa ve kesintiye uğramıyorsa bu yöntem işe yaramaz. uboot'un cihaz için bootloader olup olmadığını kontrol etmek için cihaz açılırken UART Console üzerindeki çıktıyı kontrol edin. Açılış sırasında uboot ifadesi geçebilir.

{{#include ../../banners/hacktricks-training.md}}
