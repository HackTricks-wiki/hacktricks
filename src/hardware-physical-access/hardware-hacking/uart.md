# UART

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

UART, ortak bir saat sinyali olmadan çerçevelenmiş bit akışı aktaran asenkron bir seri arayüzdür. Mantık seviyeli UART'ı RS-232 ile karıştırmayın: RS-232 farklı, çoğu zaman negatif gerilim seviyeleri kullanır ve bir alıcı-verici gerektirir.<sup>[[1]](#references)[[3]](#references)</sup>

Genellikle UART boşta durumdayken hat yüksek seviyede (mantıksal 1 değerinde) tutulur. Ardından veri aktarımının başladığını bildirmek için verici, sinyali düşük seviyede (mantıksal 0 değerinde) tuttuğu bir başlangıç biti gönderir. Sonra verici, gerçek mesajı içeren beş ila sekiz veri biti gönderir; bunu yapılandırmaya bağlı olarak isteğe bağlı bir parity biti ve bir ya da iki dur biti (mantıksal 1 değerinde) izler. Hata denetimi için kullanılan parity biti pratikte nadiren görülür. Dur biti (veya bitleri) iletimin sonunu belirtir.

En yaygın yapılandırma 8N1'dir: sekiz veri biti, parity yok ve bir dur biti. UART, veri bitlerini en önemsiz bit önce olacak şekilde gönderir; bu nedenle ASCII `C` (`0x43`) şu şekilde iletilir: başlangıç `0`; veri `1, 1, 0, 0, 0, 0, 1, 0`; dur `1`.<sup>[[1]](#references)</sup>

![UART: En yaygın yapılandırmaya 8N1 denir: sekiz veri biti, parity yok ve bir dur biti. Örneğin, C karakterini veya ASCII'deki 0x43 değerini 8N1 UART ile göndermek isteseydik](<../../images/image (764).png>)

UART ile iletişim kurmak için donanım araçları:

- USB-seri adaptörü
- CP2102 veya PL2303 yongalı adaptörler
- Bus Pirate, Adafruit FT232H, Shikra veya Attify Badge gibi çok amaçlı araçlar

### UART Portlarını Belirleme

Tipik bir debug başlığı **TX**, **RX** ve **GND** pinlerini sunar; ayrıca bir **Vcc/Vref** pini, reset veya akış denetimi pinleri de olabilir. Vcc bir UART sinyali değildir ve kartın şeması ile akım gereksinimleri bilinmediği sürece normalde yalnızca gerilim referansı olarak kullanılmalı, güç kaynağı olarak bağlanmamalıdır.<sup>[[2]](#references)[[3]](#references)</sup>

Cihaz **kapalıyken** ve bağlantısı kesilmiş durumdayken başlayın:

- Bilinen bir toprak düzlemine, konektör kılıfına veya güç kaynağı toprağına karşı süreklilik modunda **GND** pinini belirleyin. Enerjili bir kartta süreklilik/direnç modunu asla kullanmayın.
- Hedefe güç vermeden önce DC gerilim moduna geçin. Mantık gerilimini belirlemek için olası pinleri toprağa göre ölçün. Sabit bir hat Vcc/Vref olabilir; bağlamanın güvenli olduğunu varsaymayın.
- Açılış sırasında olası pinleri logic analyzer veya osiloskopla gözlemleyin. **TX** genellikle boşta yüksek seviyededir ve çerçevelenmiş veri patlamaları gösterir. Multimetre ortalama dalgalanmayı gösterebilir ancak çerçevelemeyi veya baud hızını doğrulayamaz.
- **RX** boşta kalabilir ve yalnızca TX'e bitişik olduğu için güvenli bir şekilde belirlenemez. PCB izlerini takip edin, SoC veri sayfasına başvurun veya pini sürmeden önce yüksek empedanslı bir analyzer kullanın.

TX ve RX'in yerini değiştirmek genellikle iletişim kurulmasını engeller; güç, toprak veya sinyal seviyelerini karıştırmak hedefe ya da adaptöre kalıcı hasar verebilir. Önce toprağı bağlayın ve **yalnızca alma** modunda başlayın (hedef TX'i adaptör RX'ine bağlayın).

Üreticiler başlığı hiç koymayabilir, seri dirençleri takmadan bırakabilir, firmware'de konsolu devre dışı bırakabilir veya yalnızca TX'i sunabilir. Yakındaki test pad'lerini ve direnç yerleşimlerini SoC'ye kadar izleyin ve geçici, yüksek empedanslı bir bağlantıyı yalnızca elektrik seviyesini doğruladıktan sonra ekleyin. Garanti bulunması, erişilebilir bir UART'ın mutlaka var olduğu anlamına gelmez.

### Düşük seviyede görünen bir TX pad'ini kurtarma

İlk osiloskop kaydında düşük seviyede kalan, TX olarak etiketlenmiş bir pad UART olmadığı sonucuna varmak için yeterli değildir. Hedefin mantık gerilimini ve ortak toprağı doğruladıktan sonra zayıf bir pull-up deneyin (belgelenmiş örnekte **3.3 V'a 10 kΩ** kullanılmıştır) ve düğmelere basarken veya cihazı açarken kaydı tekrarlayın. Yalnızca doğrulanmış hedef mantık hattını kullanın; pull-up'ı bilinmeyen veya aktif olarak sürülen bir sinyale bağlamayın. Çerçevelenmiş geçişler görünürse, pad'i seri adaptöre yalnızca alma modunda bağlamadan önce baud hızını tahmin etmek için temiz bitlerin en kısa süresini ölçün. Bu yöntem örnekte 115200 baud hızında düğme olayı kayıtlarını kurtardı, ancak firmware dökümünü açığa çıkarmadı.<sup>[[8]](#references)</sup>

### UART Baud Hızını Belirleme

Doğru baud hızını belirlemenin en kolay yolu **TX pininin çıkışına bakmak ve veriyi okumaya çalışmaktır**. Aldığınız veri okunabilir değilse, veri okunabilir hâle gelene kadar sıradaki olası baud hızını deneyin. Bunu yapmak için USB-seri adaptörü veya Bus Pirate gibi çok amaçlı bir cihazı [baudrate.py](https://github.com/devttys0/baudrate/) gibi bir yardımcı betikle birlikte kullanabilirsiniz. En yaygın baud hızları 9600, 38400, 19200, 57600 ve 115200'dür.

> [!CAUTION]
> Bu protokolde bir cihazın TX pinini diğer cihazın RX pinine bağlamanız gerektiğini unutmayın!

### SCPI ile Açılış Sırasında UART Yakalamayı Otomatikleştirme

Açılış çıktısı kısaysa veya TX pad'i hâlâ bilinmiyorsa, güç kaynağını ve osiloskobu elle çalıştırmak yerine tekrarlanan açılışları otomatikleştirin. Akım sınırlamalı programlanabilir bir güç kaynağını hedefin doğrulanmış güç girişine bağlayın. Her olası TX pad'ini ortak toprakla birlikte yüksek empedanslı osiloskop girişi kullanarak ölçün; pad'i sürmeyin.<sup>[[5]](#references)</sup>

VISA, seri veya Ethernet enstrüman oturumlarını açarken SCPI çıkışı, tetiklemeyi ve dalga biçimi okumayı kontrol eder.<sup>[[5]](#references)[[6]](#references)</sup> `pyvisa` ve `pyvisa-py` paketlerini (seri VISA kaynakları için ayrıca `pyserial`) yükleyin; `ResourceManager('@py')` Python backend'ini açıkça seçer.<sup>[[5]](#references)[[7]](#references)</sup> Kaynak dizelerini ve komutları kullanılan enstrümanların destekledikleriyle değiştirin.<sup>[[5]](#references)</sup>

Rigol MSO5000 örneğinde, karta güç vermeden önce tek seferlik bir düşen kenar tetiklemesi kurun: boşta yüksek seviyede olan UART TX, başlangıç biti için önce düşer.<sup>[[5]](#references)</sup> Tetikleme eşiğini ölçülen boşta ve düşük seviyeler arasına ayarlayın ve zaman tabanını ilgilenilen açılış aralığını kapsayacak şekilde ayarlayın.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD`, sürekli yakalamalarda yinelenen kenarları bastırabilir ancak tek seferlik bir yakalamanın gerçekten tamamlandığını kontrol etmenin yerini tutmaz.<sup>[[5]](#references)</sup> Aşağıdaki yöntem bir açılışı yakalar ve hem işaretsiz bayt örneklerini hem de bunların ölçekleme meta verilerini kaydeder; zaman aşımında sonsuza kadar beklemek yerine hedefin gücünü kapatır.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>PyVISA ile açılışta güç verme ve tek seferlik UART dalga biçimi yakalama</summary>

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

Bir pad taraması için, probu hareket ettirdikten sonra tek çekimli yakalamayı tekrarlayın veya besleme oturumunu açık tutup çıkışı bir açılış bekleme süresi ve kapalı kalma aralığıyla döngüye alın. Her güç açılışından önce osiloskopu yeniden kurun; böylece her dosya tek bir açılışa ve tek bir pad'e karşılık gelir.<sup>[[5]](#references)</sup>

Rigol önsözü `<format>,<type>,<points>,<count>,<xincrement>,...` biçimindedir.<sup>[[6]](#references)</sup> **Üçüncü** değer örnekleme hızı değil, nokta sayısıdır; makalede aksi belirtilmiştir.<sup>[[5]](#references)[[6]](#references)</sup> Örnekte `25,000,000` nokta ve `xincrement = 2e-8` saniye, `1 / xincrement = 50,000,000` örnek/saniye anlamına gelir; 25 MSa/s değil.<sup>[[5]](#references)[[6]](#references)</sup> Önsözü ikili dosyayla birlikte saklayın ve okunan uzunluğun `<points>` ile eşleştiğini kontrol edin; kılavuz, büyük kayıtlar için segmentli/toplu okumaları belgeliyor.<sup>[[6]](#references)</sup>

Yakalanan sinyali çözmek için `capture.bin` dosyasını PulseView'da **Raw Analog Data Without Header** olarak içe aktarın, işaretsiz 8 bitlik (`U8`) değerleri seçin ve `xincrement` değerinden hesaplanan örnekleme hızını girin.<sup>[[5]](#references)[[6]](#references)</sup> Analog kanala **Logic via Threshold** uygulayın ve düşük ile yüksek örnek değerleri arasında bir eşik seçin.<sup>[[5]](#references)</sup> Baud hızını tahmin etmek için temiz bir başlangıç biti genişliğini ölçün (57,600 baud için yaklaşık 17.36 µs); ardından PulseView'ın UART çözücüsünü uygulayın ve birkaç çerçevenin tutarlı biçimde çözüldüğünü doğrulayın.<sup>[[5]](#references)</sup> Tek başına düşen kenar, bir pad'in UART olduğunu kanıtlamaz.

## CP210X UART - TTY Adaptörü

CP210x USB-UART köprüleri birçok prototipleme kartında ve ucuz adaptörde bulunur. Yaygın modüllerde GND, RXD ve TXD'nin yanı sıra besleme pinleri de bulunur, ancak başlıkları ve I/O seviyeleri değişiklik gösterir. Gerçek voltajı kart tasarımından veya veri sayfasından doğrulayın. Genellikle yalnızca GND'yi ve adaptör RX'ini hedef TX'e bağlayın; yalnızca alım yönünde doğrulama yaptıktan sonra adaptör TX'ini hedef RX'e bağlayın. Bilerek, bu voltaja dayanabildiği bilinen bir hedefe güç sağlamıyorsanız adaptörün 5 V/3.3 V besleme pinini bağlamayın.<sup>[[3]](#references)</sup>

Adaptör algılanmıyorsa, CP210X sürücülerinin ana sistemde yüklü olduğundan emin olun. Adaptör algılanıp bağlandıktan sonra picocom, minicom veya screen gibi araçlar kullanılabilir.

Linux/MacOS sistemlerine bağlı aygıtları listelemek için:

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

Baudrate ve cihaz adı gibi ayarları `Serial port setup` seçeneğinden yapılandırın.

Yapılandırmanın ardından UART konsolunu açmak için `minicom` çalıştırın.

## Arduino UNO R3 Üzerinden UART (Çıkarılabilir Atmel 328p Çipli Kartlar)

UART Seri-USB adaptörleri yoksa Arduino UNO R3, hızlı bir hack ile kullanılabilir. Arduino UNO R3 genellikle her yerde bulunduğundan bu, çok zaman kazandırabilir.

Arduino UNO R3'ün kendi kartı üzerinde yerleşik bir USB-Seri adaptörü vardır. UART bağlantısı kurmak için Atmel 328p mikrodenetleyici çipini karttan çıkarın. Bu hack, Atmel 328p'nin karta lehimlenmediği Arduino UNO R3 varyantlarında çalışır (bu kartlarda SMD sürümü kullanılır). Arduino'nun RX pinini (Dijital Pin 0) UART arayüzünün TX pinine, Arduino'nun TX pinini (Dijital Pin 1) ise UART arayüzünün RX pinine bağlayın.

Hedef baudrate'de Arduino IDE **Serial Monitor**'ü veya özel bir terminali kullanın. Klasik Uno R3'ün seri sinyalleri 5 V lojik seviyesindedir; bu nedenle bunları 3,3 V veya daha düşük voltajlı bir hedefe bağlamadan önce seviye dönüştürücü ya da gerilim bölücü kullanın.

## Bus Pirate

Aşağıdaki oturum kaydı, UART çıkışını izlemek için eski Bus Pirate firmware arayüzünü kullanır. Daha yeni Bus Pirate firmware sürümlerinde `m uart`, `{`/`}`, `monitor` veya `bridge` gibi komutlar kullanılır; kurulu sürümün belgelerine başvurun.<sup>[[2]](#references)</sup>

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

UART konsolu, önyükleme günlüklerine ve bazen bir bootloader'a veya işletim sistemi kabuğuna çalışma zamanı erişimi sağlar. Salt okunur bir konsol bile bellek eşlemelerini, flash sürücülerini, önyükleme argümanlarını, bölüm düzenlerini ve firmware sürümlerini ortaya çıkarır. Firmware SPI NOR/NAND, eMMC veya başka bir aygıtta bulunabilir; genellikle EEPROM'dan çalıştırılmaz ve bağlı kalıcı bir dosya sistemine yazılan dosyalar yeniden başlatıldığında mutlaka silinmez.

Birkaç edinim yöntemi vardır ve SPI bölümü harici flash'tan doğrudan okuma yöntemlerini ele alır. Bootloader zaten güvenli bir okuma komutu sunuyorsa konsol destekli edinim daha az müdahaleci olabilir; ancak önyüklemeyi kesintiye uğratmak veya flash komutu kullanmak erişilebilirliği etkileyebilir. Bu nedenle ilk durumu kaydedin ve yazma/silme işlemlerinden kaçının.

Konsol destekli firmware dökümü alma işlemi genellikle bir bootloader'ın önyüklemesini keserek başlar. Gömülü Linux aygıtlarının çoğunda **Das U-Boot** kullanılır; ancak başka aygıtlar tescilli bootloader'lar kullanabilir veya etkileşimli konsolu devre dışı bırakabilir.

Etkileşimli bir bootloader olup olmadığını test etmek için, hedef aygıt kapalıyken UART alım yolunu ve terminali bağlayın, günlük kaydını başlatın ve aygıtı açın. Görüntülenen otomatik önyükleme istemini izleyin; derlemeye bağlı olarak önyüklemeyi kesmek için bir tuşa veya kısa bir tuş dizisine basmak gerekebilir ya da bu özellik tamamen devre dışı bırakılmış olabilir.

Önyüklemeyi kesmeyi başarırsanız, adreslere erişmeden önce `help`, `printenv` ve salt okunur keşif komutlarını kullanarak ilgili üreticinin bellek ve depolama düzenini anlayın.

U-Boot'ta `md`, **adreslenebilir belleği** görüntüler; otomatik olarak “EEPROM”u görüntülemez. Önce karta özgü `mtd list`, `sf probe`, `mmc info`, `part list` gibi komutları, ortam değişkenlerini ve önyükleme günlüklerini kullanarak doğru eşlenmiş adresi belirleyin veya bir flash bölgesini RAM'e yükleyin. Ardından bilinen bir aralığı bayt bayt görüntüleyin:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Başlamadan önce seri çıkışı kaydedin. `md.b` çıktısı adresleri ve bir ASCII sütununu içerir; bu nedenle ham bir ROM imajı değil, metinsel bir gösterimdir.

Adres ve ASCII sütunlarını çıkarın, yalnızca onaltılık bayt alanlarını birleştirin ve bunları ikili veriye dönüştürün (örneğin `xxd -r -p` ile). Analizden önce beklenen bayt sayısını doğrulayın ve bir hash kaydedin:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk, yeniden oluşturulan binary içindeki bilinen imzaları bulur. Konsol verileri güvenilir şekilde aktaramadığında, uygun SPI/eMMC/NAND arayüzü üzerinden doğrudan flash okuması genellikle daha hızlıdır ve hataya daha az açıktır.

U-Boot kesme işlemini devre dışı bırakabilir, satıcıya özgü bir tuş dizisi gerektirebilir veya bellek/flash komutlarını kilitleyebilir. Tuşlara gelişigüzel basmak yerine autoboot istemini ve açılış günlüğünü izleyin. Konsol kesilemiyorsa açılış günlüğünü saklayın ve müdahalesiz bir firmware edinme yöntemine geçin.

## References

- [1] [Microchip PIC32 Ailesi Başvuru Kılavuzu - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate belgeleri - UART modu ve elektriksel sınırlar](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C veri sayfası](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot belgeleri - `md` bellek görüntüleme komutu](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — Tersine Mühendisler için SCPI ve Donanım Enstrümantasyonu, Bölüm 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Rigol MSO5000 Programlama Kılavuzu](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Backend yapılandırma](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
- [8] [VoidStar Security — Donanım Hacking Bilgilerini Tazeleme, Bölüm 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
