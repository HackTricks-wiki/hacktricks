# UART

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

UART, ortak bir saat kullanmadan çerçevelenmiş bir bit akışı aktaran asenkron bir seri arayüzdür. Mantık seviyeli UART'ı RS-232 ile karıştırmayın: RS-232 farklı, çoğu zaman negatif gerilim seviyeleri kullanır ve bir alıcı-verici gerektirir.<sup>[[1]](#references)[[3]](#references)</sup>

Genellikle UART boşta durumdayken hat yüksek seviyede (mantıksal 1 değerinde) tutulur. Ardından, veri aktarımının başladığını belirtmek için verici alıcıya bir başlangıç biti gönderir; bu sırada sinyal düşük seviyede (mantıksal 0 değerinde) tutulur. Sonra verici, gerçek mesajı içeren beş ila sekiz veri biti gönderir; bunu yapılandırmaya bağlı olarak isteğe bağlı bir eşlik biti ve bir veya iki dur biti (mantıksal 1 değerinde) izler. Hata denetiminde kullanılan eşlik biti uygulamada nadiren görülür. Dur biti (veya bitleri) aktarımın sonunu belirtir.

En yaygın yapılandırma 8N1'dir: sekiz veri biti, eşlik biti yok ve bir dur biti. UART, en düşük anlamlı veri bitini önce gönderir; bu nedenle ASCII `C` (`0x43`) şu şekilde iletilir: başlangıç `0`; veri `1, 1, 0, 0, 0, 0, 1, 0`; dur `1`.<sup>[[1]](#references)</sup>

![UART: En yaygın yapılandırmaya 8N1 diyoruz: sekiz veri biti, eşlik biti yok ve bir dur biti. Örneğin, 8N1 UART ile C karakterini veya ASCII'deki 0x43 değerini göndermek isteseydik](<../../images/image (764).png>)

UART ile iletişim kurmak için kullanılan donanım araçları:

- USB-seri adaptörü
- CP2102 veya PL2303 çipli adaptörler
- Bus Pirate, Adafruit FT232H, Shikra veya Attify Badge gibi çok amaçlı araçlar

### UART Portlarını Belirleme

Tipik bir hata ayıklama başlığı **TX**, **RX** ve **GND** pinlerini sunar; ayrıca **Vcc/Vref** pini, sıfırlama veya akış denetimi pinleri de bulunabilir. Vcc bir UART sinyali değildir ve kartın şeması ile akım gereksinimleri bilinmediği sürece normalde yalnızca gerilim referansı olarak kullanılmalı, güç kaynağı olarak bağlanmamalıdır.<sup>[[2]](#references)[[3]](#references)</sup>

Cihazı **kapalı** ve bağlantısı kesilmiş durumdayken başlayın:

- Bilinen bir toprak düzlemine, konnektör kılıfına veya besleme toprağına göre süreklilik modunda **GND** pinini belirleyin. Enerjili bir kartta süreklilik/direnç modunu asla kullanmayın.
- Hedefe güç vermeden önce multimetreyi DC gerilim moduna alın. Mantık gerilimini belirlemek için olası pinleri toprağa göre ölçün. Sabit bir gerilim hattı Vcc/Vref olabilir; güvenli olduğunu varsaymayın.
- Önyükleme sırasında olası pinleri bir mantık analizörü veya osiloskopla gözlemleyin. **TX** genellikle boşta yüksek seviyededir ve çerçevelenmiş veri patlamaları gösterir. Multimetre ortalama dalgalanmayı gösterebilir, ancak çerçevelemeyi veya baud hızını doğrulayamaz.
- **RX** boşta kalabilir; yalnızca TX pininin yanında bulunduğu için güvenli biçimde tanımlanamaz. PCB izlerini takip edin, SoC veri sayfasına başvurun veya pini sürmeden önce yüksek empedanslı bir analizör kullanın.

TX ve RX pinlerinin yerini değiştirmek normalde iletişim kurulmasını engeller; güç, toprak veya sinyal seviyelerini karıştırmak hedefe ya da adaptöre kalıcı hasar verebilir. Önce toprağı bağlayın ve **yalnızca alım** ile başlayın (hedef TX pinini adaptör RX pinine bağlayın).

Üreticiler başlığı eklemeyebilir, seri dirençleri takılmamış bırakabilir, konsolu firmware'de devre dışı bırakabilir veya yalnızca TX pinini sunabilir. Yakındaki test pad'lerini ve direnç yuvalarını SoC'ye kadar takip edin ve yalnızca elektriksel seviyeyi doğruladıktan sonra geçici, yüksek empedanslı bir bağlantı ekleyin. Garanti bulunması, erişilebilir bir UART'ın mutlaka mevcut olduğu anlamına gelmez.

### UART Baud Hızını Belirleme

Doğru baud hızını belirlemenin en kolay yolu **TX pininin çıkışına bakıp veriyi okumaya çalışmaktır**. Aldığınız veri okunamıyorsa, veri okunabilir hâle gelene kadar sıradaki olası baud hızını deneyin. Bunun için bir USB-seri adaptörü veya Bus Pirate gibi çok amaçlı bir cihazı [baudrate.py](https://github.com/devttys0/baudrate/) gibi bir yardımcı betikle birlikte kullanabilirsiniz. En yaygın baud hızları 9600, 38400, 19200, 57600 ve 115200'dür.

> [!CAUTION]
> Bu protokolde bir cihazın TX pinini diğer cihazın RX pinine bağlamanız gerektiğini unutmayın!

### SCPI ile Önyükleme Sırasında UART Yakalamayı Otomatikleştirme

Önyükleme çıktısı kısaysa veya TX pad'i henüz bilinmiyorsa, güç kaynağını ve osiloskobu elle çalıştırmak yerine yeniden başlatmaları otomatikleştirin. Akım sınırlamalı programlanabilir bir güç kaynağını hedefin doğrulanmış güç girişine bağlayın. Her olası TX pad'ini ortak topraklı, yüksek empedanslı bir osiloskop girişiyle yoklayın; pad'i sürmeyin.<sup>[[5]](#references)</sup>

VISA, seri veya Ethernet enstrüman oturumlarını açarken SCPI çıkış, tetikleme ve dalga biçimi okumayı kontrol eder.<sup>[[5]](#references)[[6]](#references)</sup> `pyvisa` ve `pyvisa-py` paketlerini (seri VISA kaynakları için ayrıca `pyserial`) yükleyin; `ResourceManager('@py')` Python arka ucunu açıkça seçer.<sup>[[5]](#references)[[7]](#references)</sup> Kaynak dizelerini ve komutları kullanılan enstrümanların destekledikleriyle değiştirin.<sup>[[5]](#references)</sup>

Rigol MSO5000 örneğinde, karta güç vermeden önce tek seferlik düşen kenar tetiklemesini kurun: boşta yüksek seviyede olan UART TX, başlangıç biti için önce düşer.<sup>[[5]](#references)</sup> Tetikleme eşiğini ölçülen boşta ve düşük seviyelerin arasına ayarlayın; zaman tabanını ilgilendiğiniz önyükleme aralığını kapsayacak şekilde ayarlayın.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD`, sürekli yakalamalarda tekrarlanan kenarları bastırabilir; ancak tek seferlik yakalamanın gerçekten tamamlandığını kontrol etmenin yerini tutmaz.<sup>[[5]](#references)</sup> Aşağıdaki kod bir önyüklemeyi yakalar ve işaretsiz bayt örneklerini ölçeklendirme meta verileriyle birlikte kaydeder; zaman aşımı durumunda sonsuza kadar beklemek yerine hedefin gücünü keser.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>PyVISA ile açılış ve tek seferlik UART dalga biçimi yakalama</summary>

```python
import time
from pathlib import Path
import pyvisa

rm = pyvisa.ResourceManager('@py')
psu = rm.open_resource('ASRL/dev/ttyUSB0::INSTR')
scope = rm.open_resource('TCPIP::192.0.2.10::INSTR')
psu.baud_rate = 115200
scope.timeout = 5000
try:
    print(psu.query('*IDN?').strip(), scope.query('*IDN?').strip())
    psu.write('OUTP OFF')
    psu.write('SOUR:VOLT 3.3')
    psu.write('SOUR:CURR 0.5')
    for cmd in (':CHAN1:DISP ON', ':CHAN1:SCAL 0.5',
                ':TIM:MAIN:SCAL 0.05', ':TRIG:MODE EDGE',
                ':TRIG:EDGE:SOUR CHAN1', ':TRIG:EDGE:LEV 1.5',
                ':TRIG:EDGE:SLOP NEG'):
        scope.write(cmd)
    scope.write(':SING')
    psu.write('OUTP ON')
    deadline = time.monotonic() + 30
    while scope.query(':TRIG:STAT?').strip() != 'STOP':
        if time.monotonic() >= deadline:
            raise TimeoutError('No single-shot trigger')
        time.sleep(0.5)
    scope.write(':WAV:SOUR CHAN1')
    scope.write(':WAV:MODE RAW')
    scope.write(':WAV:FORM BYTE')
    preamble = scope.query(':WAV:PRE?').strip()
    points = int(preamble.split(',')[2])
    scope.write(f':WAV:POIN {points}')
    scope.write(':WAV:STAR 1')
    scope.write(f':WAV:STOP {points}')
    scope.timeout = 120000
    raw = scope.query_binary_values(':WAV:DATA?', datatype='B', container=bytes)
    if len(raw) != points:
        raise ValueError('Incomplete waveform; use instrument-specific batch reads')
    Path('capture.bin').write_bytes(raw)
    Path('capture_preamble.txt').write_text(preamble + '\n')
finally:
    psu.write('OUTP OFF')
    scope.close()
    psu.close()
    rm.close()
```

</details>

Pad taraması için probu hareket ettirdikten sonra tek çekimi tekrarlayın veya besleme oturumunu açık tutup çıkışını bir açılış bekleme süresi ve kapalı kalma aralığıyla döngüye sokun. Her açılıştan önce osiloskobu yeniden kurun; böylece her dosya tek bir açılışa ve tek bir pada karşılık gelir.<sup>[[5]](#references)</sup>

Rigol ön eki `<format>,<type>,<points>,<count>,<xincrement>,...` biçimindedir.<sup>[[6]](#references)</sup> **Üçüncü** değer, makalede belirtildiği gibi örnekleme hızı değil, nokta sayısıdır.<sup>[[5]](#references)[[6]](#references)</sup> Verilen örnekte `25,000,000` nokta ve `xincrement = 2e-8` saniye, 25 MSa/s değil, `1 / xincrement = 50,000,000` örnek/saniye anlamına gelir.<sup>[[5]](#references)[[6]](#references)</sup> Ön eki ikili dosyayla birlikte saklayın ve okunan uzunluğun `<points>` ile eşleştiğini kontrol edin; kılavuz, büyük kayıtlar için segmentli/toplu okumaları belgeliyor.<sup>[[6]](#references)</sup>

Yakalanan sinyali çözümlemek için `capture.bin` dosyasını PulseView'a **Raw Analog Data Without Header** olarak aktarın, işaretsiz 8 bitlik (`U8`) değerleri seçin ve `xincrement` değerinden hesaplanan örnekleme hızını girin.<sup>[[5]](#references)[[6]](#references)</sup> Analog kanala **Logic via Threshold** uygulayın ve düşük ile yüksek örnek değerleri arasında bir eşik seçin.<sup>[[5]](#references)</sup> Baud hızını tahmin etmek için temiz bir start-bit genişliği ölçün (57,600 baud için yaklaşık 17.36 µs); ardından PulseView'ın UART decoder'ını uygulayın ve birkaç frame'in tutarlı biçimde çözümlendiğini doğrulayın.<sup>[[5]](#references)</sup> Tek başına düşen bir kenar, bir pad'in UART olduğunu kanıtlamaz.

## CP210X UART to TTY Adapter

CP210x USB-to-UART köprüleri birçok prototipleme kartında ve ucuz adaptörde bulunur. Yaygın modüllerde GND, RXD ve TXD'nin yanında besleme pinleri bulunur; ancak header'ları ve I/O seviyeleri farklılık gösterir. Gerçek voltajı kart tasarımından veya veri sayfasından doğrulayın. Genellikle yalnızca GND'yi ve adaptör RX'ini hedef TX'e bağlayın; yalnızca salt alım doğrulamasından sonra adaptör TX'ini hedef RX'e bağlayın. Bilerek, bu voltaja dayanabildiği bilinen bir hedefe güç vermediğiniz sürece adaptörün 5 V/3.3 V besleme pinini bağlamayın.<sup>[[3]](#references)</sup>

Adaptör algılanmıyorsa CP210X sürücülerinin ana sistemde kurulu olduğundan emin olun. Adaptör algılanıp bağlandıktan sonra picocom, minicom veya screen gibi araçlar kullanılabilir.

Linux/MacOS sistemlerine bağlı cihazları listelemek için:

```
ls /dev/
```

UART arayüzüyle temel etkileşim için aşağıdaki komutu kullanın:

```
picocom /dev/<adapter> --baud <baudrate>
```

minicom'u yapılandırmak için aşağıdaki komutu kullanın:

```
minicom -s
```

`Serial port setup` seçeneğinde baud hızı ve cihaz adı gibi ayarları yapılandırın.

Yapılandırma sonrasında UART konsolunu açmak için `minicom` komutunu çalıştırın.

## Arduino UNO R3 Üzerinden UART (Çıkarılabilir Atmel 328p Çipli Kartlar)

UART Serial to USB adaptörleri mevcut değilse, Arduino UNO R3 hızlı bir hack ile kullanılabilir. Arduino UNO R3 genellikle her yerde bulunduğundan, bu yöntem zamandan tasarruf sağlayabilir.

Arduino UNO R3'ün kart üzerinde yerleşik bir USB-Serial adaptörü vardır. UART bağlantısı kurmak için Atmel 328p mikrodenetleyici çipini karttan çıkarın. Bu hack, Atmel 328p'nin karta lehimlenmediği (SMD sürümünün kullanıldığı) Arduino UNO R3 varyantlarında çalışır. Arduino'nun RX pinini (Digital Pin 0) UART arayüzünün TX pinine, Arduino'nun TX pinini (Digital Pin 1) UART arayüzünün RX pinine bağlayın.

Hedef baud hızında Arduino IDE **Serial Monitor**'ü veya özel bir terminali kullanın. Klasik Uno R3'ün seri sinyalleri 5 V mantık seviyesindedir; bu nedenle bunları 3,3 V veya daha düşük voltajlı bir hedefe bağlamadan önce bir seviye dönüştürücü veya gerilim bölücü kullanın.

## Bus Pirate

Aşağıdaki transcript, UART çıkışını izlemek için eski Bus Pirate firmware arayüzünü kullanır. Daha yeni Bus Pirate firmware sürümlerinde `m uart`, `{`/`}`, `monitor` veya `bridge` gibi komutlar kullanılır; yüklü sürüme ait belgelere bakın.<sup>[[2]](#references)</sup>

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

## UART Konsoluyla Firmware Dökümü Alma

UART konsolu, önyükleme günlüklerine ve bazen bir bootloader'a ya da işletim sistemi kabuğuna çalışma zamanı erişimi sağlar. Salt okunur bir konsol bile bellek eşlemelerini, flash sürücülerini, önyükleme argümanlarını, bölüm düzenlerini ve firmware sürümlerini ortaya çıkarabilir. Firmware, SPI NOR/NAND, eMMC veya başka bir aygıtta bulunabilir; genellikle EEPROM'dan çalıştırılmaz ve bağlanmış kalıcı bir dosya sistemine yazılan dosyalar yeniden başlatmada mutlaka silinmez.

Birden fazla edinim yöntemi vardır ve SPI bölümü harici flash'tan doğrudan okumayı ele alır. Bootloader'da güvenli bir okuma komutu zaten varsa, konsol destekli edinim daha az müdahaleci olabilir; ancak önyüklemenin kesilmesi veya flash komutları kullanılabilirliği etkileyebilir. Bu nedenle özgün durumu kaydedin ve yazma/silme işlemlerinden kaçının.

Konsol destekli firmware dökümü genellikle önyükleme sürecini kesintiye uğratarak başlar. Gömülü Linux aygıtlarının çoğu **Das U-Boot** kullanır, ancak bazıları tescilli bootloader'lar kullanır veya etkileşimli konsolu devre dışı bırakır.

Etkileşimli bir bootloader olup olmadığını test etmek için hedef kapalıyken UART alım hattını ve terminali bağlayın, günlük kaydını başlatın ve aygıtı açın. Görüntülenen otomatik önyükleme istemini izleyin; kullanılan yapıya bağlı olarak önyüklemeyi kesmek için bir tuşa, kısa bir tuş dizisine basmak gerekebilir veya bu özellik tamamen devre dışı olabilir.

Kesinti başarılı olursa, adreslere erişmeden önce üreticiye özgü bellek ve depolama düzenini anlamak için `help`, `printenv` ve salt okunur keşif komutlarını kullanın.

U-Boot'ta `md`, **adreslenebilir belleği** görüntüler; otomatik olarak “EEPROM'u” değil. Önce doğru eşlenmiş adresi belirlemek veya bir flash bölgesini RAM'e yüklemek için `mtd list`, `sf probe`, `mmc info`, `part list` gibi karta özgü komutları, ortam değişkenlerini ve önyükleme günlüklerini kullanın. Ardından bilinen bir aralığı bayt bayt görüntüleyin:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Başlamadan önce seri çıktıyı kaydedin. `md.b` çıktısı adresleri ve bir ASCII sütununu içerir; bu nedenle ham bir ROM imajı değil, metinsel bir gösterimdir.

Adres ve ASCII sütunlarını çıkarın, yalnızca onaltılık bayt alanlarını birleştirin ve ikili veriye dönüştürün (örneğin, `xxd -r -p` ile). Analizden önce beklenen bayt sayısını doğrulayın ve bir hash kaydedin:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk daha sonra yeniden oluşturulan binary içindeki bilinen imzaları tespit eder. Konsol verileri güvenilir biçimde aktaramıyorsa, uygun SPI/eMMC/NAND arayüzü üzerinden doğrudan flash okuması genellikle daha hızlıdır ve hataya daha az açıktır.

U-Boot kesmeyi devre dışı bırakabilir, üreticiye özgü bir tuş dizisi gerektirebilir veya bellek/flash komutlarını kilitleyebilir. Karakterleri düşünmeden göndermek yerine autoboot istemini ve boot logunu izleyin. Konsol kesilemiyorsa boot logunu saklayın ve müdahalesiz bir firmware edinme yöntemine geçin.

## References

- [1] [Microchip PIC32 Ailesi Referans Kılavuzu - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate belgeleri - UART modu ve elektriksel sınırlar](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C veri sayfası](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot belgeleri - `md` bellek görüntüleme komutu](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — Tersine Mühendisler için SCPI ve Donanım Enstrümantasyonu, Bölüm 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Rigol MSO5000 Programlama Kılavuzu](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Backend'i yapılandırma](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
{{#include ../../banners/hacktricks-training.md}}
