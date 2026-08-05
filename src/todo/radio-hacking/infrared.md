# Kızılötesi

{{#include ../../banners/hacktricks-training.md}}

## Kızılötesi Nasıl Çalışır <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Kızılötesi ışık insanlar tarafından görülemez**. IR dalga boyu **0,7 ile 1000 mikron** arasındadır. Ev tipi kumandalar veri iletimi için bir IR sinyali kullanır ve 0,75..1,4 mikron dalga boyu aralığında çalışır. Kumandadaki bir microcontroller, infrared LED'in belirli bir frekansta yanıp sönmesini sağlayarak dijital sinyali IR sinyaline dönüştürür.<sup>[[1]](#references)</sup>

IR sinyallerini almak için bir **photoreceiver** kullanılır. Bu bileşen **IR ışığını, zaten dijital sinyal olan gerilim darbelerine dönüştürür**. Genellikle alıcının içinde, **yalnızca istenen dalga boyunun geçmesine izin veren** ve gürültüyü kesen **koyu renkli bir ışık filtresi** bulunur.

### IR Protocols Çeşitleri <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocols 3 faktörde farklılık gösterir:

- bit encoding
- veri yapısı
- taşıyıcı frekansı — genellikle 36..38 kHz aralığında

#### Bit encoding yöntemleri <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bitler, darbeler arasındaki boşluğun süresi modüle edilerek kodlanır. Darbenin kendi genişliği sabittir.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bitler, darbe genişliği modüle edilerek kodlanır. Darbe paketinden sonraki boşluğun genişliği sabittir.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Bu yöntem Manchester encoding olarak da bilinir. Mantıksal değer, darbe paketi ile boşluk arasındaki geçişin polaritesiyle belirlenir. "Boşluktan darbe paketine geçiş" mantıksal "0"ı, "darbe paketinden boşluğa geçiş" ise mantıksal "1"i belirtir.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Öncekilerin ve diğer egzotik yöntemlerin birleşimi**

> [!TIP]
> Birkaç cihaz türü için **universal olmaya çalışan** IR protocols vardır. En ünlüleri RC5 ve NEC'tir. Ne yazık ki, en ünlü olmaları **en yaygın oldukları anlamına gelmez**. Kendi ortamımda yalnızca iki NEC kumandasıyla karşılaştım ve hiç RC5 kumandası görmedim.
>
> Üreticiler, aynı cihaz aralığında bile (örneğin TV-box'larda) kendi benzersiz IR protocols'lerini kullanmayı sever. Bu nedenle farklı şirketlerin kumandaları ve bazen aynı şirketin farklı modellerine ait kumandalar, aynı türdeki diğer cihazlarla çalışamaz.

### Bir IR sinyalini inceleme

Kumandanın IR sinyalinin nasıl göründüğünü görmenin en güvenilir yolu bir osiloskop kullanmaktır. Osiloskop alınan sinyali demodüle etmez veya tersine çevirmez; yalnızca sinyali "olduğu gibi" görüntüler. Bu, test ve debugging için kullanışlıdır. Beklenen sinyali NEC IR protocol örneği üzerinden göstereceğim.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Genellikle encoded bir paketin başlangıcında bir preamble bulunur. Bu, alıcının gain seviyesini ve arka planı belirlemesini sağlar. Örneğin Sharp gibi preamble içermeyen protocols de vardır.

Ardından veri iletilir. Yapı, preamble ve bit encoding yöntemi belirli protocol tarafından belirlenir.

**NEC IR protocol**, kısa bir komut ve düğmeye basılı tutulduğu sürece gönderilen bir repeat code içerir. Hem komut hem de repeat code başlangıçta aynı preamble'a sahiptir.

NEC **command**, preamble'a ek olarak, cihazın ne yapılması gerektiğini anlamasını sağlayan bir address byte ve command-number byte içerir. İletimin bütünlüğünü kontrol etmek için address ve command-number byte'ları ters değerleriyle çoğaltılır. Komutun sonunda ek bir stop biti bulunur.

**repeat code**, preamble'dan sonra stop biti olan bir "1" içerir.

**Mantıksal "0" ve "1"** için NEC, Pulse Distance Encoding kullanır: önce bir darbe paketi iletilir ve ardından uzunluğu bitin değerini belirleyen bir duraklama gelir.

### Klimalar

Diğer kumandaların aksine, **klimalar yalnızca basılan düğmenin kodunu iletmez**. Ayrıca bir düğmeye basıldığında **tüm bilgileri de iletirler**; böylece **klima cihazı ile kumandanın senkronize olması** sağlanır.\
Bu, 20ºC'ye ayarlanmış bir cihazın bir kumandayla 21ºC'ye yükseltilmesini ve ardından sıcaklığı hâlâ 20ºC olarak tutan başka bir kumanda kullanıldığında, cihazın sıcaklığı 21ºC'de olduğunu düşünerek 22ºC yerine tekrar 21ºC'ye "yükseltmesini" önler.

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

Infrared ile Flipper Zero kullanarak attack gerçekleştirebilirsiniz:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

Yakın tarihli academic research (EvilScreen, 2022), Infrared'i Bluetooth veya Wi-Fi ile birleştiren **multi-channel kumandaların modern smart-TV'leri tamamen hijack etmek için kötüye kullanılabileceğini** gösterdi. Attack, yüksek ayrıcalıklı IR service code'larını authenticated Bluetooth packet'larıyla birleştirerek channel-isolation'ı aşar ve fiziksel erişim olmadan arbitrary app launch, microphone activation veya factory-reset işlemlerine izin verir. Farklı vendor'lara ait sekiz ana akım TV'nin — ISO/IEC 27001 uyumluluğu iddiasındaki bir Samsung modeli de dahil — savunmasız olduğu doğrulandı. Mitigation, vendor firmware fix'leri uygulanmasını veya kullanılmayan IR receiver'larının tamamen devre dışı bırakılmasını gerektirir.<sup>[[2]](#references)</sup>

### IR LEDs ile Air-Gapped Data Exfiltration (aIR-Jumper family)

Security camera'lar, router'lar ve hatta malicious USB stick'ler genellikle **night-vision IR LEDs** içerir. Research, malware'in bu LED'leri modüle ederek (basit OOK ile <10–20 kbit/s) **duvarlar ve pencereler üzerinden, onlarca metre uzağa yerleştirilmiş harici bir kameraya secret'ları exfiltrate edebileceğini** gösteriyor. Işık görünür spectrum'un dışında olduğundan operatörler bunu nadiren fark eder. Counter-measures:

* Hassas alanlardaki IR LED'leri fiziksel olarak shield edin veya çıkarın
* Camera LED duty-cycle'ını ve firmware integrity'yi izleyin
* Pencerelere ve surveillance camera'lara IR-cut filter uygulayın

Bir attacker, güvenli olmayan camera'lara data flashing yoluyla network'e command **infiltrate** etmek için güçlü IR projector'lar da kullanabilir.

### Flipper Zero 1.0 ile Long-Range Brute-Force & Extended Protocols

Firmware 1.0 (Eylül 2024), **düzinelerce ek IR protocol ve isteğe bağlı harici amplifier module** ekledi. Universal-remote brute-force mode ile birleştirildiğinde Flipper, yüksek güçlü bir diode kullanarak 30 m'ye kadar çoğu public TV/AC cihazını devre dışı bırakabilir veya yeniden yapılandırabilir.

---

## Tooling & Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – learning, replay ve dictionary-bruteforce mode'larına sahip taşınabilir transceiver (yukarıya bakın).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – ucuz DIY analyser/transmitter. `Arduino-IRremote` library'siyle birleştirin (v4.x >40 protocol destekler).
* **Logic analyser**'lar (Saleae/FX2) – protocol bilinmediğinde raw timing'leri yakalar.
* **IR-blaster'lı smartphone'lar** (ör. Xiaomi) – hızlı field test için kullanışlıdır ancak range sınırlıdır.

### Software

* **`Arduino-IRremote`** – aktif olarak sürdürülen C++ library:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – raw capture'ları içe aktaran, protocol'ü otomatik olarak tanımlayan ve Pronto/Arduino code üreten GUI decoder'ları.
* **LIRC / ir-keytable (Linux)** – command line üzerinden IR alır ve inject eder:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* Gerekmiyorsa public space'lerde kullanılan cihazlardaki IR receiver'larını devre dışı bırakın veya üzerlerini kapatın.
* Smart-TV'ler ile kumandalar arasında *pairing* veya cryptographic check'ler uygulayın; ayrıcalıklı "service" code'larını izole edin.
* Optical covert channel'ları kesmek için classified area'ların çevresine IR-cut filter veya continuous-wave detector yerleştirin.
* Kontrol edilebilir IR LED'ler sunan camera/IoT appliance'larının firmware integrity'sini izleyin.

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen: Smart TV hijacking via remote control mimicry](https://arxiv.org/abs/2210.03014)

{{#include ../../banners/hacktricks-training.md}}
